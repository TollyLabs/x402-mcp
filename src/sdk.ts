// tolly-x402 buyer SDK: discover → validate → inspect price → enforce spending policy →
// authorize → invoke → recover. It never signs a 402 it was not configured to accept.
//
// At most one payment per invoke, enforced by the CHAIN, not by trusting the server: every
// authorization the SDK signs for one invoke (first try, network retries, re-signs after an
// expired quote) uses the SAME EIP-3009 nonce, and a USDC (from, nonce) can be used once ever.
// So even a malicious server can collect at most one of them. The budget counts every invoke
// that signed anything, and is never "released" on the server's say-so.
//
//   const client = new TollyX402Client({
//     baseUrl: "https://agent.tollylabs.com",
//     signer: privateKeyToAccount(key),          // or a browser wallet, see walletSigner()
//     policy: { network: "eip155:5042002", maxPerCallAtomic: 50_000n, budgetAtomic: 1_000_000n },
//   });
//   const { result, jobId, jobToken } = await client.invoke("wallet.balances.v1", { network, wallet });
//   // Another seller's service routed by TOLLY (one all-in price, paid to TOLLY):
//   await client.invokeRouted(routeId, { query: { q: "x" } }, { maxAmountAtomic, payTo });
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from "@x402/core/http";
import type { PaymentPayload, PaymentRequired, PaymentRequirements } from "@x402/core/types";
import {
  appendPaymentIdentifierToExtensions,
  generatePaymentId,
} from "@x402/extensions/payment-identifier";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

/** Arc USDC through its ERC-20 interface (6 decimals), on mainnet and testnet. */
export const ARC_USDC = "0x3600000000000000000000000000000000000000";
/** The longest authorization lifetime the SDK will sign, whatever a server asks for. */
export const MAX_AUTHORIZATION_SECONDS = 600;

/** What the SDK needs to sign: an address and EIP-712 typed-data signing. Nothing else. */
export interface PaymentSigner {
  readonly address: `0x${string}`;
  signTypedData(message: {
    domain: Record<string, unknown>;
    types: Record<string, unknown>;
    primaryType: string;
    message: Record<string, unknown>;
  }): Promise<`0x${string}`>;
}

export interface SpendingPolicy {
  /** CAIP-2 network the buyer pays on, e.g. "eip155:5042" (Arc) or "eip155:5042002" (testnet). */
  network: string;
  /** Payment asset; defaults to Arc USDC. */
  asset?: string;
  /** If set, refuse any 402 whose payee differs. */
  payTo?: string;
  /** Hard cap per call, in atomic units (USDC: 6 decimals; 50_000n = 0.05). */
  maxPerCallAtomic: bigint;
  /** Hard cap for this client's lifetime, in atomic units. Counts every invoke that signed. */
  budgetAtomic: bigint;
  /** Origins this client may pay. Defaults to the baseUrl's origin only. */
  allowedOrigins?: string[];
  /** Overall time budget per invoke (including waiting for settlement). Default 60 s. */
  timeoutMs?: number;
  /** Network-level retries per invoke (each reuses the same authorization). Default 3. */
  maxAttempts?: number;
}

export interface ServiceInfo {
  id: string;
  title: string;
  semantics: string;
  availability: string;
  purchasable: boolean;
  unavailableReason: string | null;
  inputSchema: Record<string, unknown>;
  outputSchema: Record<string, unknown>;
  payment: {
    scheme: string;
    network: string;
    asset: string;
    decimals: number;
    amountAtomic: string;
  } | null;
  example?: unknown;
  [k: string]: unknown;
}

export interface Purchase<T> {
  result: T;
  jobId: string;
  /** Capability to read this job's status, result and receipt later. Keep it. */
  jobToken: string;
  /** The settlement transaction that paid for this result. */
  transaction: string | null;
  amountAtomic: string;
  /** The logical operation id; pass it to invoke() again to resume without paying twice. */
  paymentId: string;
}

/** What a routed purchase forwards to the seller: the method, a query string and a JSON body. */
export interface RoutedRequest {
  /** Default: POST when a body is given, else GET. */
  method?: "GET" | "POST";
  /** Query parameters appended to the seller's resource URL. */
  query?: Record<string, string>;
  /** JSON body, POST only. */
  body?: unknown;
}

/** One paid HTTP request: where it goes and what it carries. */
interface Target {
  label: string;
  path: string;
  method: "GET" | "POST";
  body?: string;
  /** Routed answers are the seller's bytes: a non-JSON answer comes back as {contentType, text}. */
  routed?: boolean;
}

interface PurchaseOptions {
  paymentId?: string;
  /** Refuse (before signing) any offer above this, e.g. the price the catalog showed. */
  maxAmountAtomic?: bigint;
  /** Refuse (before signing) any offer to another payee (on top of policy.payTo). */
  payTo?: string;
}

export type X402ErrorCode =
  | "policy_rejected"
  | "invalid_input"
  | "not_purchasable"
  | "payment_failed"
  | "job_failed"
  | "timeout"
  | "http_error";

export interface X402ErrorDetails {
  jobId?: string;
  jobToken?: string;
  /** Resume with invoke(..., { paymentId }) — never a second payment. */
  paymentId?: string;
  status?: number;
  body?: unknown;
}

export class X402Error extends Error {
  constructor(
    readonly code: X402ErrorCode,
    message: string,
    /**
     * Whether money may have moved, as far as the SDK can tell. "unknown" means: the server
     * holds a valid authorization; resume with details.paymentId or recover with the job token.
     * The SDK never treats a server's "not charged" as proof (see spentAtomic).
     */
    readonly charged: boolean | "unknown" = false,
    readonly details: X402ErrorDetails = {},
  ) {
    super(message);
  }
}

export interface ClientOptions {
  baseUrl: string;
  signer: PaymentSigner;
  policy: SpendingPolicy;
  /** Inject a fetch (tests, custom agents). Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  /** Mark calls as non-organic demand (e.g. "test" while integrating). */
  trafficClass?: "test" | "demo" | "probe";
  /**
   * Validate input against the published schema before calling (default true). Browsers with a
   * strict Content-Security-Policy (no 'unsafe-eval') should pass false: the schema compiler
   * generates code, and the server validates for free before asking for payment anyway.
   */
  validateLocally?: boolean;
}

const AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

export class TollyX402Client {
  private readonly base: string;
  private readonly fetcher: typeof fetch;
  private readonly policy: Required<Omit<SpendingPolicy, "payTo">> & { payTo?: string };
  /** Created on first local validation only (schema compilation needs eval; see validateLocally). */
  private ajv: Ajv2020 | undefined;
  private readonly validators = new Map<string, ValidateFunction>();
  /** Only address + signTypedData are ever used, even if a richer client was passed. */
  private readonly signer: PaymentSigner;
  private committed = 0n;

  constructor(private readonly opts: ClientOptions) {
    this.base = opts.baseUrl.replace(/\/$/, "");
    this.fetcher = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.policy = {
      asset: ARC_USDC,
      allowedOrigins: [new URL(this.base).origin],
      timeoutMs: 60_000,
      maxAttempts: 3,
      ...opts.policy,
    };
    if (this.policy.maxPerCallAtomic <= 0n || this.policy.budgetAtomic <= 0n) {
      throw new Error("spending limits must be positive");
    }
    if (!this.policy.allowedOrigins.includes(new URL(this.base).origin)) {
      throw new Error("baseUrl's origin must be in policy.allowedOrigins");
    }
    const s = opts.signer;
    this.signer = { address: s.address, signTypedData: (m) => s.signTypedData(m) };
  }

  /**
   * Worst-case exposure so far: the price of every invoke that signed an authorization. It is
   * never reduced on a server's word; one invoke can settle at most once (same nonce).
   */
  get spentAtomic(): bigint {
    return this.committed;
  }

  async listServices(): Promise<ServiceInfo[]> {
    const r = await this.get("/v1/services");
    return (r as { services: ServiceInfo[] }).services;
  }

  async getService(id: string): Promise<ServiceInfo> {
    return (await this.get(`/v1/services/${encodeURIComponent(id)}`)) as ServiceInfo;
  }

  /** Checks input against the service's published schema, without any network call to pay. */
  async validate(
    id: string,
    input: unknown,
  ): Promise<{ ok: true } | { ok: false; errors: unknown[] }> {
    let v = this.validators.get(id);
    if (!v) {
      if (!this.ajv) {
        this.ajv = new Ajv2020({ allErrors: true, strict: false });
        addFormats.default(this.ajv);
      }
      v = this.ajv.compile((await this.getService(id)).inputSchema);
      this.validators.set(id, v);
    }
    return v(input) ? { ok: true } : { ok: false, errors: v.errors ?? [] };
  }

  /** Asks for the price of exactly this request (an unpaid call; nothing is charged). */
  async quote(id: string, input: unknown): Promise<PaymentRequirements> {
    const required = await this.challenge(serviceTarget(id, input));
    return this.acceptableOffer(required, this.committed);
  }

  /**
   * Buys one result. Throws X402Error; `charged` says whether money may have moved. Pass the
   * same `paymentId` to resume an earlier invoke (e.g. after a timeout) without a second payment.
   */
  async invoke<T = unknown>(
    id: string,
    input: unknown,
    opts: {
      paymentId?: string;
      /** Refuse (before signing) any offer above this, e.g. the price the catalog showed. */
      maxAmountAtomic?: bigint;
    } = {},
  ): Promise<Purchase<T>> {
    if (this.opts.validateLocally !== false) {
      const check = await this.validate(id, input);
      if (!check.ok) {
        throw new X402Error("invalid_input", "input does not match the service schema", false, {
          body: check.errors,
        });
      }
    }
    return this.purchase<T>(serviceTarget(id, input), opts);
  }

  /**
   * Buys another seller's service routed by TOLLY (GET|POST /v1/routed/:routeId/invoke): the
   * buyer pays TOLLY one all-in price and gets the seller's answer back, with the same policy,
   * single-payment guarantee, recovery and refunds as invoke(). Pass the catalog's all-in price
   * as `maxAmountAtomic` and TOLLY's payee as `payTo`: any other offer is refused before signing.
   * A non-JSON answer is returned as { contentType, text }.
   */
  async invokeRouted<T = unknown>(
    routeId: string,
    request: RoutedRequest = {},
    opts: PurchaseOptions = {},
  ): Promise<Purchase<T>> {
    if (!/^[0-9a-f]{16}$/.test(routeId))
      throw new X402Error("invalid_input", `not a route id: ${routeId}`);
    const method = request.method ?? (request.body !== undefined ? "POST" : "GET");
    if (method === "GET" && request.body !== undefined)
      throw new X402Error("invalid_input", "a GET request carries no body");
    const query = new URLSearchParams(request.query ?? {}).toString();
    return this.purchase<T>(
      {
        label: `routed ${routeId}`,
        path: `/v1/routed/${routeId}/invoke${query ? `?${query}` : ""}`,
        method,
        ...(method === "POST" ? { body: JSON.stringify(request.body ?? {}) } : {}),
        routed: true,
      },
      opts,
    );
  }

  private async purchase<T>(target: Target, opts: PurchaseOptions): Promise<Purchase<T>> {
    const deadline = Date.now() + this.policy.timeoutMs;
    const paymentId = opts.paymentId ?? generatePaymentId("tolly_");
    // One nonce for every authorization this invoke signs: the chain lets at most one settle.
    const nonce = randomNonce();
    let required = await this.challenge(target);
    let offer = this.acceptableOffer(required, this.committed, opts.payTo);
    const amount = BigInt(offer.amount);
    if (opts.maxAmountAtomic !== undefined && amount > opts.maxAmountAtomic) {
      throw new X402Error(
        "policy_rejected",
        `asked ${amount} atomic, above this call's ceiling of ${opts.maxAmountAtomic}`,
        false,
      );
    }
    const payee = offer.payTo.toLowerCase();
    // Committed for good once we sign. Synchronous with the check above: concurrent invokes
    // on one client cannot both pass the budget.
    this.committed += amount;

    let header = await this.sign(required, offer, paymentId, nonce);
    let lastError: unknown;
    for (let attempt = 1; attempt <= this.policy.maxAttempts && Date.now() < deadline; attempt++) {
      let res: Response;
      try {
        res = await this.send(target, { "PAYMENT-SIGNATURE": header });
      } catch (err) {
        lastError = err; // network failure: retry the SAME authorization
        continue;
      }
      if (res.status === 200) return this.finish<T>(res, offer.amount, paymentId, target);
      if (res.status === 202) {
        const body = (await res.json()) as { jobId: string };
        const token = res.headers.get("X-Job-Token") ?? "";
        return this.awaitResult<T>(body.jobId, token, offer.amount, paymentId, deadline, target);
      }
      const body = (await safeJson(res)) as { error?: string; charged?: boolean } | null;
      if (res.status === 402 && body?.error === "quote_expired") {
        // The quote lapsed before use. Re-sign for the new quote with the SAME nonce, the same
        // price and the same payee; anything else is refused.
        required = this.decodeRequired(res);
        const fresh = this.acceptableOffer(required, this.committed - amount, opts.payTo);
        if (BigInt(fresh.amount) !== amount || fresh.payTo.toLowerCase() !== payee) {
          throw new X402Error(
            "policy_rejected",
            "price or payee changed between quote and payment; not re-signing",
            "unknown",
            { paymentId },
          );
        }
        offer = fresh;
        header = await this.sign(required, offer, paymentId, nonce);
        continue;
      }
      if (res.status === 429 && body?.charged === false) {
        // Refused before anything was recorded (e.g. routing_blocked): final, nothing moved.
        throw new X402Error("http_error", body.error ?? "HTTP 429", false, {
          status: 429,
          body,
          paymentId,
        });
      }
      if (res.status === 503 || res.status === 429 || res.status === 504) {
        lastError = new Error(`HTTP ${res.status}`);
        await sleep(Number(res.headers.get("Retry-After") ?? "1") * 1000);
        continue;
      }
      const jobId = res.headers.get("X-Job-Id") ?? undefined;
      const jobToken = res.headers.get("X-Job-Token") ?? undefined;
      const code: X402ErrorCode =
        res.status === 402 ? "payment_failed" : res.status === 502 ? "job_failed" : "http_error";
      throw new X402Error(code, body?.error ?? `HTTP ${res.status}`, body?.charged ?? "unknown", {
        status: res.status,
        body,
        paymentId,
        ...(jobId ? { jobId } : {}),
        ...(jobToken ? { jobToken } : {}),
      });
    }
    throw new X402Error(
      "timeout",
      `gave up: ${String(lastError ?? "deadline reached")}`,
      "unknown",
      { paymentId },
    );
  }

  /** Fetches a paid result again (e.g. after a lost response), with the job token. */
  async recover<T = unknown>(jobId: string, jobToken: string): Promise<T> {
    const res = await this.fetcher(`${this.base}/v1/jobs/${jobId}/result`, {
      headers: { "X-Job-Token": jobToken },
      redirect: "error",
    });
    if (res.status !== 200) {
      throw new X402Error("http_error", `recover: HTTP ${res.status}`, "unknown", {
        status: res.status,
        body: await safeJson(res),
        jobId,
        jobToken,
      });
    }
    return (await res.json()) as T;
  }

  async receipt(jobId: string, jobToken: string): Promise<Record<string, unknown>> {
    const res = await this.fetcher(`${this.base}/v1/receipts/${jobId}`, {
      headers: { "X-Job-Token": jobToken },
      redirect: "error",
    });
    if (!res.ok)
      throw new X402Error("http_error", `receipt: HTTP ${res.status}`, "unknown", {
        status: res.status,
      });
    return (await res.json()) as Record<string, unknown>;
  }

  // -------------------------------------------------------------------------------------------

  private async challenge(target: Target): Promise<PaymentRequired> {
    const res = await this.send(target, {});
    if (res.status === 402) return this.decodeRequired(res);
    const body = await safeJson(res);
    if (res.status === 503)
      throw new X402Error("not_purchasable", `${target.label} is not purchasable`, false, {
        status: 503,
        body,
      });
    if (res.status === 400 || res.status === 422) {
      throw new X402Error("invalid_input", "input rejected by the service", false, {
        status: res.status,
        body,
      });
    }
    throw new X402Error("http_error", `expected 402, got ${res.status}`, false, {
      status: res.status,
      body,
    });
  }

  private decodeRequired(res: Response): PaymentRequired {
    const header = res.headers.get("PAYMENT-REQUIRED");
    if (!header) throw new X402Error("http_error", "402 without PAYMENT-REQUIRED header");
    return decodePaymentRequiredHeader(header);
  }

  /**
   * The spending policy: the only gate between a 402 and a signature. `alreadyCommitted` is
   * the budget use to check against (the caller excludes its own reservation on a re-sign).
   * `payTo` narrows the payee for this call only, on top of the policy's.
   */
  private acceptableOffer(
    required: PaymentRequired,
    alreadyCommitted: bigint,
    payTo?: string,
  ): PaymentRequirements {
    const p = this.policy;
    const resource = required.resource?.url;
    if (resource && !p.allowedOrigins.includes(new URL(resource).origin)) {
      throw new X402Error("policy_rejected", `refusing to pay for ${resource}: origin not allowed`);
    }
    const offer = required.accepts.find(
      (a) =>
        a.scheme === "exact" &&
        a.network === p.network &&
        a.asset.toLowerCase() === p.asset.toLowerCase() &&
        (!p.payTo || a.payTo.toLowerCase() === p.payTo.toLowerCase()) &&
        (!payTo || a.payTo.toLowerCase() === payTo.toLowerCase()),
    );
    if (!offer)
      throw new X402Error("policy_rejected", "no offer on the allowed network/asset/payee");
    // Only plain EIP-3009 (no Permit2 / approvals), and only short-lived authorizations.
    const method = offer.extra?.assetTransferMethod;
    if (method !== undefined && method !== "eip3009") {
      throw new X402Error("policy_rejected", `refusing transfer method ${String(method)}`);
    }
    if (!(offer.maxTimeoutSeconds > 0 && offer.maxTimeoutSeconds <= MAX_AUTHORIZATION_SECONDS)) {
      throw new X402Error(
        "policy_rejected",
        `refusing an authorization valid for ${offer.maxTimeoutSeconds}s`,
      );
    }
    if (typeof offer.extra?.name !== "string" || typeof offer.extra?.version !== "string") {
      throw new X402Error("policy_rejected", "offer lacks the token's EIP-712 domain");
    }
    const amount = BigInt(offer.amount);
    if (amount <= 0n) throw new X402Error("policy_rejected", "non-positive price");
    if (amount > p.maxPerCallAtomic) {
      throw new X402Error(
        "policy_rejected",
        `price ${amount} exceeds the per-call cap ${p.maxPerCallAtomic}`,
      );
    }
    if (alreadyCommitted + amount > p.budgetAtomic) {
      throw new X402Error(
        "policy_rejected",
        `price ${amount} would exceed the budget (${alreadyCommitted} of ${p.budgetAtomic} used)`,
      );
    }
    return offer;
  }

  /** Signs an EIP-3009 TransferWithAuthorization ourselves, so we control the nonce. */
  private async sign(
    required: PaymentRequired,
    offer: PaymentRequirements,
    paymentId: string,
    nonce: `0x${string}`,
  ): Promise<string> {
    const chainId = Number(this.policy.network.split(":")[1]);
    const now = Math.floor(Date.now() / 1000);
    const authorization = {
      from: this.signer.address,
      to: offer.payTo as `0x${string}`,
      value: offer.amount,
      validAfter: "0",
      validBefore: String(now + Math.min(offer.maxTimeoutSeconds, MAX_AUTHORIZATION_SECONDS)),
      nonce,
    };
    const signature = await this.signer.signTypedData({
      domain: {
        name: offer.extra.name as string,
        version: offer.extra.version as string,
        chainId,
        verifyingContract: offer.asset,
      },
      types: AUTHORIZATION_TYPES as unknown as Record<string, unknown>,
      primaryType: "TransferWithAuthorization",
      message: {
        ...authorization,
        value: BigInt(authorization.value),
        validAfter: BigInt(authorization.validAfter),
        validBefore: BigInt(authorization.validBefore),
      },
    });
    const payload: PaymentPayload = {
      x402Version: 2,
      ...(required.resource ? { resource: required.resource } : {}),
      accepted: offer,
      payload: { signature, authorization },
      extensions: appendPaymentIdentifierToExtensions(
        { ...(required.extensions ?? {}) },
        paymentId,
      ),
    };
    return encodePaymentSignatureHeader(payload);
  }

  private async finish<T>(
    res: Response,
    amountAtomic: string,
    paymentId: string,
    target: Target,
  ): Promise<Purchase<T>> {
    const settle = res.headers.get("PAYMENT-RESPONSE");
    return {
      result: (await readResult(res, target)) as T,
      jobId: res.headers.get("X-Job-Id") ?? "",
      jobToken: res.headers.get("X-Job-Token") ?? "",
      transaction: settle ? decodePaymentResponseHeader(settle).transaction : null,
      amountAtomic,
      paymentId,
    };
  }

  private async awaitResult<T>(
    jobId: string,
    jobToken: string,
    amountAtomic: string,
    paymentId: string,
    deadline: number,
    target: Target,
  ): Promise<Purchase<T>> {
    while (Date.now() < deadline) {
      const res = await this.fetcher(`${this.base}/v1/jobs/${jobId}/result`, {
        headers: { "X-Job-Token": jobToken },
        redirect: "error",
      });
      if (res.status === 200) {
        const receipt = await this.receipt(jobId, jobToken).catch(() => null);
        const settlement = receipt?.settlement as { transaction?: string } | undefined;
        return {
          result: (await readResult(res, target)) as T,
          jobId,
          jobToken,
          transaction: settlement?.transaction ?? null,
          amountAtomic,
          paymentId,
        };
      }
      if (res.status !== 202) {
        const body = (await safeJson(res)) as { error?: string; charged?: boolean } | null;
        throw new X402Error(
          res.status === 402 ? "payment_failed" : "job_failed",
          body?.error ?? `HTTP ${res.status}`,
          body?.charged ?? "unknown",
          { status: res.status, body, jobId, jobToken, paymentId },
        );
      }
      await sleep(1_000);
    }
    throw new X402Error(
      "timeout",
      "settlement still pending; recover later with jobId/jobToken",
      "unknown",
      {
        jobId,
        jobToken,
        paymentId,
      },
    );
  }

  private async get(path: string): Promise<unknown> {
    const res = await this.fetcher(`${this.base}${path}`, { redirect: "error" });
    if (!res.ok)
      throw new X402Error("http_error", `GET ${path}: HTTP ${res.status}`, false, {
        status: res.status,
      });
    return res.json();
  }

  private send(target: Target, headers: Record<string, string>): Promise<Response> {
    return this.fetcher(`${this.base}${target.path}`, {
      method: target.method,
      ...(target.body !== undefined ? { body: target.body } : {}),
      // Never let a redirect carry our signed payment to another origin.
      redirect: "error",
      headers: {
        ...(target.body !== undefined ? { "content-type": "application/json" } : {}),
        ...(this.opts.trafficClass ? { "X-Traffic-Class": this.opts.trafficClass } : {}),
        ...headers,
      },
    });
  }
}

/** Adapts a viem WalletClient (e.g. a browser wallet) to the signer the SDK needs. */
export function walletSigner(wallet: {
  account: { address: `0x${string}` } | undefined;
  signTypedData(args: never): Promise<`0x${string}`>;
}): PaymentSigner {
  const account = wallet.account;
  if (!account) throw new Error("wallet has no account connected");
  return {
    address: account.address,
    signTypedData: (m) => wallet.signTypedData({ account, ...m } as never),
  };
}

function serviceTarget(id: string, input: unknown): Target {
  return {
    label: id,
    path: `/v1/services/${encodeURIComponent(id)}/invoke`,
    method: "POST",
    body: JSON.stringify(input),
  };
}

/** TOLLY's own results are JSON; a routed seller's answer may be anything (text, CSV …). */
async function readResult(res: Response, target: Target): Promise<unknown> {
  if (!target.routed) return res.json();
  const type = res.headers.get("content-type") ?? "";
  const text = await res.text();
  if (/json/i.test(type)) {
    try {
      return JSON.parse(text);
    } catch {
      // A seller labelled it JSON but it is not: hand it back as text.
    }
  }
  return { contentType: type || null, text };
}

function randomNonce(): `0x${string}` {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

async function safeJson(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, Math.min(ms, 10_000)));
}
