// Agent wallet spending rules on chain: AgentSpendPolicy "account payer" mode
// (docs/os/AGENT_SPEND_POLICY.md, section 6).
//
// When TOLLY_AGENT_WALLET (the agent's Tokenbound account, its "TBA") and TOLLY_SPEND_POLICY (the
// policy's address, a pin) are set, and the NFT's owner enabled the policy for this server's key
// (BUYER_PRIVATE_KEY, the "hot key"), x402 payments are made FROM the TBA, not from the hot key:
//   1. preauthorize: the hot key asks the policy to register the exact USDC transfer (payee,
//      amount, validBefore at most 1 hour ahead, a random nonce); the policy checks its caps and
//      allowlists and charges today's budget; this server waits for the receipt;
//   2. the x402 payment carries `from = TBA` and the 97-byte contract signature that names the
//      policy as signer: USDC asks the TBA, the TBA asks the policy, which says yes for exactly
//      that registered authorization;
//   3. if the payment did not happen (charged false), cancelPreauthorization refunds the budget.
// ACP client actions (create, set provider/budget, fund, reject) go through policy.execute and
// executeBatch, so the TBA is the escrow's client; approve + fund is one batch.
//
// Before the first send it checks over the user's own RPC (TOLLY_RPC_URL): the chain is the
// payment chain, USDC has 6 decimals, the policy has code (and the pinned code hash, when
// TOLLY_SPEND_POLICY_CODEHASH is set) and budgets Arc USDC, and the TBA is an ERC-6551 account on
// this chain. The policy's own caps are the hard limit; this server's caps (TOLLY_X402_MAX_PER_CALL,
// TOLLY_X402_BUDGET) still apply first. The hot key only pays gas (USDC on Arc).
import {
  ARC_USDC,
  type Authorization,
  agentSpendPolicyAbi,
  authorizationDigest,
  ERC6551_REGISTRY,
  encodeAcceptKey,
  encodeCancelPreauthorization,
  encodeExecute,
  encodeExecuteBatch,
  encodePreauthorize,
  explainPolicyError,
  LEAK_BOUND_TEXT,
  MAX_AUTH_WINDOW_SECONDS,
  type PolicyCall,
  type PolicyState,
  readPolicyState,
  registryAbi,
  STATUS_TEXT,
  TOKENBOUND_ACCOUNT_PROXY,
  verifySpendPolicyDeployment,
  x402PolicySignature,
} from "./spend-policy.js";
import {
  type Address,
  BaseError,
  createPublicClient,
  createWalletClient,
  defineChain,
  getAddress,
  type Hex,
  HttpRequestError,
  http,
  isAddressEqual,
  keccak256,
  type PublicClient,
  parseAbi,
  TimeoutError,
  type TransactionReceipt,
} from "viem";
import type { PrivateKeyAccount } from "viem/accounts";

export const ARC_CHAIN_IDS = new Set([5042, 5042002]);
const ERC1167_PREFIX = "363d3d373d3d3d363d73";
/** Below this much native USDC (6-decimal units) the hot key cannot pay a policy transaction's gas. */
const MIN_GAS_ATOMIC = 1_000n;
const ERC20 = parseAbi(["function decimals() view returns (uint8)"]);
const ACCOUNT = parseAbi([
  "function token() view returns (uint256 chainId, address tokenContract, uint256 tokenId)",
]);

const usd = (a: bigint) => `${a / 1_000_000n}.${(a % 1_000_000n).toString().padStart(6, "0")}`;

export class PolicyError extends Error {
  constructor(
    readonly code: string,
    message: string,
    /** True when a transaction may have reached the network (its outcome is unknown or mined). */
    readonly sent = false,
  ) {
    super(message);
  }
}

/** What the policy mode needs from a chain: reads (viem), and sends signed by the hot key. */
export interface PolicyChain {
  pub: Pick<
    PublicClient,
    "getChainId" | "getCode" | "readContract" | "getBalance" | "call" | "waitForTransactionReceipt"
  >;
  /**
   * Signs and broadcasts {to, data} from the hot key, returning the hash. Throws an error with
   * `beforeNetwork: true` when nothing can have reached the network.
   */
  send(tx: { to: Address; data: Hex }): Promise<Hex>;
}

/** A PolicyChain over JSON-RPC, signing with the hot key. */
export function rpcPolicyChain(rpcUrl: string, account: PrivateKeyAccount, chainId: number) {
  const chain = defineChain({
    id: chainId,
    name: "Arc",
    nativeCurrency: { name: "USDC", symbol: "USDC", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  });
  const pub = createPublicClient({ chain, transport: http(rpcUrl, { timeout: 15_000 }) });
  const wallet = createWalletClient({
    account,
    chain,
    transport: http(rpcUrl, { timeout: 15_000 }),
  });
  return {
    pub: pub as unknown as PolicyChain["pub"],
    send: async (tx: { to: Address; data: Hex }) => {
      let raw: Hex;
      try {
        const req = await wallet.prepareTransactionRequest({ ...tx, value: 0n, chain, account });
        raw = await wallet.signTransaction(req as never);
      } catch (err) {
        throw Object.assign(err as Error, { beforeNetwork: true });
      }
      const hash = keccak256(raw);
      try {
        await wallet.sendRawTransaction({ serializedTransaction: raw });
      } catch (err) {
        const unknown =
          err instanceof BaseError
            ? err.walk((e) => e instanceof TimeoutError || e instanceof HttpRequestError)
            : null;
        if (!unknown) throw Object.assign(err as Error, { beforeNetwork: true });
        throw Object.assign(err as Error, { hash });
      }
      return hash;
    },
  } satisfies PolicyChain;
}

export interface PolicySettings {
  policy: Address;
  /** The agent's Tokenbound account (TOLLY_AGENT_WALLET). */
  tba: Address;
  /** This server's key (BUYER_PRIVATE_KEY's address). */
  hot: Address;
  chainId: number;
  /** TOLLY_SPEND_POLICY_CODEHASH, lower case, or null. */
  codehash: Hex | null;
  usdc?: Address;
  /**
   * TOLLY_X402_PAY_TO, when set: a payee this server may pay besides the policy's tollyPayee.
   * No other payee is ever preauthorized (the policy also allows TollyACP as a counterparty, and
   * USDC transferred straight to the escrow contract is lost).
   */
  payTo?: Address;
}

/** One paid call's preauthorizations: what to cancel if the payment does not happen. */
export interface PolicyCallRecord {
  /** Highest amount this call may authorize (the reserved price). */
  ceiling: bigint;
  /** Registered (mined) preauthorizations. */
  registered: Authorization[];
  /** A preauthorize transaction whose outcome is unknown was sent. */
  unknown: boolean;
  /** The authorizations whose preauthorize transaction has an unknown outcome. */
  uncertain?: Authorization[];
}

export type PolicyMode =
  | { mode: "account"; state: PolicyState }
  | { mode: "fallback"; state: PolicyState; why: string }
  /** The owner's rules exist and say "stop" (paused, expired, locked, x402 off, cut off). */
  | { mode: "stopped"; state: PolicyState; why: string };

/**
 * States in which the owner has not (yet) set rules for this key: payments may fall back to the
 * float or the hot key's own USDC. In every other non-active state the owner's rules exist and
 * stop the key, and paying through another route would go around that decision.
 */
const FALLBACK_STATES = new Set(["not_configured", "awaiting_accept", "owner_changed"]);

export class AgentPolicy {
  private verified: Promise<{ tollyPayee: Address }> | null = null;
  /** One policy transaction at a time from this process (nonces). */
  private queue: Promise<unknown> = Promise.resolve();
  private readonly usdc: Address;

  constructor(
    private readonly chain: PolicyChain,
    readonly s: PolicySettings,
  ) {
    if (isAddressEqual(s.hot, s.tba))
      throw new Error(
        "TOLLY_AGENT_WALLET is the buyer key's own address; name the agent's account",
      );
    if (isAddressEqual(s.policy, s.tba) || isAddressEqual(s.policy, s.hot))
      throw new Error("TOLLY_SPEND_POLICY must be the AgentSpendPolicy contract");
    this.usdc = s.usdc ?? ARC_USDC;
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  /** The chain, USDC, the pinned policy and the TBA, checked over the user's RPC before any send. */
  verify(): Promise<{ tollyPayee: Address }> {
    this.verified ??= (async () => {
      const { pub } = this.chain;
      const id = await pub.getChainId();
      if (id !== this.s.chainId || !ARC_CHAIN_IDS.has(id))
        throw new PolicyError(
          "wrong_chain",
          `TOLLY_RPC_URL is chain ${id}; the spending policy needs Arc chain ${this.s.chainId} (TOLLY_X402_NETWORK). Nothing sent.`,
        );
      const d = Number(
        await pub.readContract({ address: this.usdc, abi: ERC20, functionName: "decimals" }),
      );
      if (d !== 6)
        throw new PolicyError("wrong_token", `USDC at ${this.usdc} reports ${d} decimals, not 6.`);
      let v: Awaited<ReturnType<typeof verifySpendPolicyDeployment>>;
      try {
        v = await verifySpendPolicyDeployment(
          pub,
          { address: this.s.policy, codehash: this.s.codehash },
          this.usdc,
        );
      } catch (err) {
        throw new PolicyError(
          "wrong_policy",
          `TOLLY_SPEND_POLICY check failed: ${(err as Error).message}. Nothing sent.`,
        );
      }
      // The agent's wallet must be an ERC-6551 account (an ERC-1167 proxy with the 128-byte
      // footer) bound to a token on this chain: the payer of every x402 payment in this mode.
      const code = ((await pub.getCode({ address: this.s.tba })) ?? "0x").toLowerCase();
      if (code.length !== 2 + 173 * 2 || !code.startsWith(`0x${ERC1167_PREFIX}`))
        throw new PolicyError(
          "wrong_wallet",
          `TOLLY_AGENT_WALLET ${this.s.tba} is not an ERC-6551 token-bound account on chain ${id}. Nothing sent.`,
        );
      const [tokenChain, tokenContract, tokenId] = (await pub.readContract({
        address: this.s.tba,
        abi: ACCOUNT,
        functionName: "token",
      })) as readonly [bigint, Address, bigint];
      if (Number(tokenChain) !== id)
        throw new PolicyError(
          "wrong_wallet",
          `TOLLY_AGENT_WALLET is bound to a token on chain ${tokenChain}, not ${id}. Nothing sent.`,
        );
      // And it is the registry's account for that NFT (TOLLY's Tokenbound proxy, salt 0): a
      // look-alike contract that merely answers token() is refused.
      const derived = (await pub.readContract({
        address: ERC6551_REGISTRY,
        abi: registryAbi,
        functionName: "account",
        args: [TOKENBOUND_ACCOUNT_PROXY, `0x${"0".repeat(64)}`, tokenChain, tokenContract, tokenId],
      })) as Address;
      if (!isAddressEqual(derived, this.s.tba))
        throw new PolicyError(
          "wrong_wallet",
          `TOLLY_AGENT_WALLET is not the ERC-6551 registry account of its NFT. Nothing sent.`,
        );
      return { tollyPayee: v.tollyPayee };
    })();
    this.verified.catch(() => {
      this.verified = null; // a network error is retried next time; a wrong setting fails again
    });
    return this.verified;
  }

  async state(extraPayees: string[] = []): Promise<PolicyState> {
    const { tollyPayee } = await this.verify();
    return readPolicyState(this.chain.pub, {
      policy: this.s.policy,
      tba: this.s.tba,
      key: this.s.hot,
      payees: [tollyPayee, ...extraPayees],
    });
  }

  /**
   * Account payer when the policy is active for (TBA, hot key) and allows x402; the fallback when
   * the owner has not set rules for this key yet; otherwise stopped (the owner's rules say no).
   */
  async mode(): Promise<PolicyMode> {
    const state = await this.state();
    if (state.status === "active" && state.config.allowPreauth) return { mode: "account", state };
    if (FALLBACK_STATES.has(state.status))
      return { mode: "fallback", state, why: STATUS_TEXT[state.status] };
    return {
      mode: "stopped",
      state,
      why:
        state.status === "active"
          ? "the spending rules do not allow x402 payments (allowPreauth is off)"
          : STATUS_TEXT[state.status],
    };
  }

  private async gasOk() {
    const wei = await this.chain.pub.getBalance({ address: this.s.hot });
    return wei / 1_000_000_000_000n >= MIN_GAS_ATOMIC;
  }

  async status(acp: Address | null) {
    const state = await this.state(acp ? [acp] : []);
    const c = state.config;
    const [gas, tbaUsdc] = await Promise.all([
      this.gasOk(),
      this.chain.pub.readContract({
        address: this.usdc,
        abi: parseAbi(["function balanceOf(address) view returns (uint256)"]),
        functionName: "balanceOf",
        args: [this.s.tba],
      }) as Promise<bigint>,
    ]);
    return {
      mode:
        state.status === "active" && c.allowPreauth
          ? "account payer: x402 payments are made from the agent's wallet through the policy"
          : FALLBACK_STATES.has(state.status)
            ? "fallback: payments use the allowance float or this key's own USDC"
            : "stopped: the owner's spending rules stop payments (none are made from the float or this key either)",
      status: state.status,
      status_text: STATUS_TEXT[state.status],
      policy: this.s.policy,
      agent_wallet: this.s.tba,
      hot_key: getAddress(this.s.hot),
      agent_wallet_usdc: usd(tbaUsdc),
      ...(c.owner !== "0x0000000000000000000000000000000000000000"
        ? {
            per_payment_cap_usdc: usd(c.perTxCap),
            daily_cap_usdc: usd(c.dailyCap),
            spent_today_usdc: usd(state.spentToday),
            left_today_usdc: usd(state.remainingToday),
            expires_at: c.expiresAt ? new Date(c.expiresAt * 1000).toISOString() : null,
            x402_allowed: c.allowPreauth,
            payees: state.payees.map((p) => ({ address: p.address, allowed: p.allowed })),
          }
        : {}),
      gas_ok: gas,
      ...(state.status === "awaiting_accept"
        ? {
            next: "Call tolly_policy_accept once to accept the owner's rules (one transaction, gas only).",
          }
        : {}),
      worst_case_if_key_leaks: LEAK_BOUND_TEXT,
      note: "On Arc the gas coin is USDC: this key pays the gas of each preauthorization (about 0.01 USDC or less) from its own balance.",
    };
  }

  /** acceptKey from the hot key: the second step of the owner's grant. */
  accept() {
    return this.serial(async () => {
      const state = await this.state();
      if (state.status !== "awaiting_accept")
        throw new PolicyError(
          state.status === "active" ? "already_accepted" : `not_${state.status}`,
          state.status === "active"
            ? "Already accepted: the policy is active for this key."
            : `Nothing to accept: ${STATUS_TEXT[state.status]}`,
        );
      const r = await this.sendChecked(this.s.policy, encodeAcceptKey(this.s.tba));
      const after = await this.state();
      return {
        status: after.status,
        status_text: STATUS_TEXT[after.status],
        transaction: r.transactionHash,
      };
    });
  }

  /**
   * Simulates the call from the hot key first (a policy refusal is explained and nothing is
   * sent), then sends it and waits for the receipt. PolicyError.sent says whether it may have
   * reached the network.
   */
  private async sendChecked(to: Address, data: Hex): Promise<TransactionReceipt> {
    try {
      await this.chain.pub.call({ account: this.s.hot, to, data });
    } catch (err) {
      throw new PolicyError(
        "policy_refused",
        explainPolicyError(err) ??
          `The transaction would fail: ${String((err as Error).message).slice(0, 200)}`,
      );
    }
    if (!(await this.gasOk()))
      throw new PolicyError(
        "no_gas",
        "This hot key has no USDC for gas. Send it a little USDC once (0.10 is plenty). Nothing sent.",
      );
    let hash: Hex;
    try {
      hash = await this.chain.send({ to, data });
    } catch (err) {
      const before = (err as { beforeNetwork?: unknown }).beforeNetwork === true;
      throw new PolicyError(
        before ? "send_failed" : "send_unknown",
        `${before ? "Not sent" : "Sent, outcome unknown"}: ${String((err as Error).message).slice(0, 200)}`,
        !before,
      );
    }
    let receipt: TransactionReceipt;
    try {
      receipt = await this.chain.pub.waitForTransactionReceipt({ hash, timeout: 60_000 });
    } catch {
      throw new PolicyError(
        "send_unknown",
        `Transaction ${hash} was sent; its receipt did not arrive in time.`,
        true,
      );
    }
    if (receipt.status !== "success")
      throw new PolicyError("reverted", `Transaction ${hash} reverted.`, true);
    return receipt;
  }

  /**
   * The x402 signer for one paid call: its address is the TBA (x402's `from`). Signing registers
   * the exact authorization with the policy (one transaction, waited for) and returns the
   * contract signature. Anything that is not exactly a USDC TransferWithAuthorization from the
   * TBA on this chain, within this call's ceiling and the policy's window, is refused unsigned.
   */
  signerFor(record: PolicyCallRecord) {
    const self = this;
    return {
      address: this.s.tba,
      async signTypedData(m: {
        domain: Record<string, unknown>;
        types: Record<string, unknown>;
        primaryType: string;
        message: Record<string, unknown>;
      }): Promise<Hex> {
        const d = m.domain;
        if (
          m.primaryType !== "TransferWithAuthorization" ||
          d.name !== "USDC" ||
          d.version !== "2" ||
          Number(d.chainId) !== self.s.chainId ||
          typeof d.verifyingContract !== "string" ||
          !isAddressEqual(d.verifyingContract as Address, self.usdc)
        )
          throw new PolicyError(
            "not_usdc_authorization",
            "Refused: only a USDC (name USDC, version 2) TransferWithAuthorization on this chain is paid from the agent's wallet.",
          );
        const msg = m.message;
        const a: Authorization = {
          from: getAddress(String(msg.from)),
          to: getAddress(String(msg.to)),
          value: BigInt(msg.value as bigint),
          validAfter: BigInt(msg.validAfter as bigint),
          validBefore: BigInt(msg.validBefore as bigint),
          nonce: String(msg.nonce) as Hex,
        };
        const now = BigInt(Math.floor(Date.now() / 1000));
        if (!isAddressEqual(a.from, self.s.tba))
          throw new PolicyError("wrong_payer", "Refused: the payer is not the agent's wallet.");
        if (a.value <= 0n || a.value > record.ceiling)
          throw new PolicyError(
            "above_ceiling",
            `Refused: ${usd(a.value)} USDC is above this call's price ${usd(record.ceiling)}.`,
          );
        if (
          a.validAfter > now ||
          a.validBefore <= now ||
          a.validBefore > now + BigInt(MAX_AUTH_WINDOW_SECONDS)
        )
          throw new PolicyError(
            "bad_window",
            "Refused: the authorization must be valid now and expire within an hour.",
          );
        if (!/^0x[0-9a-fA-F]{64}$/.test(a.nonce))
          throw new PolicyError("bad_nonce", "Refused: the nonce is not 32 bytes.");
        // Only TOLLY's payee (the policy's own tollyPayee) or the pinned TOLLY_X402_PAY_TO: the
        // policy also allows TollyACP as a counterparty, and a 402 naming it would send the
        // agent's USDC straight into the escrow contract, where it is lost.
        const { tollyPayee } = await self.verify();
        const payees = [tollyPayee, ...(self.s.payTo ? [self.s.payTo] : [])];
        if (!payees.some((p) => isAddressEqual(p, a.to)))
          throw new PolicyError(
            "wrong_payee",
            `Refused: ${a.to} is not TOLLY's payee (${payees.join(", ")}).`,
          );
        return self.serial(async () => {
          // The digest the policy will register must be the one this typed data hashes to, on
          // this chain's USDC domain (checked on chain, so a wrong domain is caught before a send).
          const onChain = (await self.chain.pub.readContract({
            address: self.s.policy,
            abi: agentSpendPolicyAbi,
            functionName: "authorizationDigest",
            args: [a.from, a.to, a.value, a.validAfter, a.validBefore, a.nonce],
          })) as Hex;
          if (
            onChain.toLowerCase() !==
            authorizationDigest(self.s.chainId, a, self.usdc).toLowerCase()
          )
            throw new PolicyError(
              "domain_mismatch",
              "Refused: USDC's domain on this chain is not name USDC, version 2.",
            );
          // A re-sign for a new quote (its nonce is bound to that quote, so it differs): every
          // earlier authorization of this call is withdrawn first, so at most one of them can
          // ever settle and no charge is counted twice. If one cannot be withdrawn (already
          // used, or its outcome is unknown), nothing new is signed.
          if (record.unknown)
            throw new PolicyError(
              "send_unknown",
              "An earlier preauthorization of this call has an unknown outcome; not signing another.",
              true,
            );
          for (const prior of [...record.registered]) {
            await self.sendChecked(self.s.policy, encodeCancelPreauthorization(prior));
            record.registered = record.registered.filter((x) => x !== prior);
          }
          try {
            await self.sendChecked(self.s.policy, encodePreauthorize(a));
          } catch (err) {
            if (err instanceof PolicyError && err.sent) {
              if (err.code === "reverted") {
                // Mined but reverted: nothing registered, nothing charged.
              } else {
                record.unknown = true;
                record.uncertain = [...(record.uncertain ?? []), a];
              }
            }
            throw err;
          }
          record.registered.push(a);
          return x402PolicySignature(self.s.policy);
        });
      },
    };
  }

  /**
   * Cancels preauthorizations that did not settle, refunding today's budget. One that USDC
   * already used (settled) cannot be cancelled: the result says so.
   */
  cancel(auths: Authorization[]) {
    return this.serial(async () => {
      const out: { nonce: Hex; cancelled: boolean; reason?: string }[] = [];
      for (const a of auths) {
        try {
          await this.sendChecked(this.s.policy, encodeCancelPreauthorization(a));
          out.push({ nonce: a.nonce, cancelled: true });
        } catch (err) {
          out.push({
            nonce: a.nonce,
            cancelled: false,
            reason: (err as Error).message.slice(0, 200),
          });
        }
      }
      return out;
    });
  }

  /**
   * Runs calls from the TBA through the policy (execute for one, executeBatch for several),
   * simulated first. For ACP client actions.
   */
  execute(calls: PolicyCall[]) {
    return this.serial(async () => {
      await this.verify();
      const data =
        calls.length === 1
          ? encodeExecute(this.s.tba, calls[0] as PolicyCall)
          : encodeExecuteBatch(this.s.tba, calls);
      return this.sendChecked(this.s.policy, data);
    });
  }
}
