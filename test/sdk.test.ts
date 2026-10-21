// The SDK against a scripted (possibly malicious) server: the buyer's limits must hold no
// matter what the server says.
import { decodePaymentSignatureHeader, encodePaymentRequiredHeader } from "@x402/core/http";
import type { PaymentRequired } from "@x402/core/types";
import { declarePaymentIdentifierExtension } from "@x402/extensions/payment-identifier";
import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { TollyX402Client, X402Error } from "../src/sdk.ts";

const BASE = "https://agent.example";
const PAY_TO = "0x00000000000000000000000000000000000000aa";
const OTHER = "0x00000000000000000000000000000000000000bb";
const account = privateKeyToAccount(`0x${"1".repeat(64)}`);
const SERVICE = {
  id: "s.v1",
  inputSchema: { type: "object", properties: { x: { type: "integer" } }, required: ["x"] },
};

function required(over: Partial<PaymentRequired["accepts"][number]> = {}): PaymentRequired {
  return {
    x402Version: 2,
    resource: {
      url: `${BASE}/v1/services/s.v1/invoke`,
      description: "s",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:5042002",
        asset: "0x3600000000000000000000000000000000000000",
        amount: "20000",
        payTo: PAY_TO,
        maxTimeoutSeconds: 300,
        extra: { name: "USDC", version: "2", quote: "q" },
        ...over,
      },
    ],
    // Like the real gateway: payment-identifier is declared, so the SDK attaches its id.
    extensions: { "payment-identifier": declarePaymentIdentifierExtension(false) },
  };
}

const r402 = (req: PaymentRequired, error?: string) =>
  new Response(JSON.stringify({ ...req, ...(error ? { error } : {}) }), {
    status: 402,
    headers: { "PAYMENT-REQUIRED": encodePaymentRequiredHeader(req) },
  });

/** A scripted server: `paid` decides the answer to each signed request; records signatures. */
function server(paid: (n: number) => Response, offer = required()) {
  const signatures: string[] = [];
  const fetcher = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const u = String(url);
    if (u.endsWith("/v1/services/s.v1")) return new Response(JSON.stringify(SERVICE));
    const sig = new Headers(init?.headers).get("PAYMENT-SIGNATURE");
    if (!sig) return r402(offer);
    signatures.push(sig);
    return paid(signatures.length);
  }) as typeof fetch;
  return { fetcher, signatures };
}

const client = (fetcher: typeof fetch, policy = {}) =>
  new TollyX402Client({
    baseUrl: BASE,
    signer: account,
    fetch: fetcher,
    policy: {
      network: "eip155:5042002",
      maxPerCallAtomic: 50_000n,
      budgetAtomic: 100_000n,
      timeoutMs: 5_000,
      ...policy,
    },
  });

const nonceOf = (header: string) =>
  (decodePaymentSignatureHeader(header).payload as { authorization: { nonce: string } })
    .authorization.nonce;

describe("spending policy against a malicious server", () => {
  it("REVIEW H1: a server claiming 'not charged' does not get the budget back", async () => {
    const s = server(
      () => new Response(JSON.stringify({ error: "job_failed", charged: false }), { status: 502 }),
    );
    const c = client(s.fetcher);
    for (let i = 0; i < 5; i++) await c.invoke("s.v1", { x: 1 }).catch(() => {});
    // Budget 0.1 at 0.02 per call: exactly five signatures, then the policy stops signing.
    expect(s.signatures).toHaveLength(5);
    expect(c.spentAtomic).toBe(100_000n);
    const err = await c.invoke("s.v1", { x: 1 }).catch((e) => e);
    expect((err as X402Error).code).toBe("policy_rejected");
    expect(s.signatures).toHaveLength(5);
  });

  it("REVIEW H2: every signature within one invoke uses the same nonce (the chain allows one)", async () => {
    const s = server(() => r402(required(), "quote_expired"));
    const c = client(s.fetcher, { maxAttempts: 3 });
    await c.invoke("s.v1", { x: 1 }).catch(() => {});
    expect(s.signatures.length).toBeGreaterThanOrEqual(2);
    expect(new Set(s.signatures.map(nonceOf)).size).toBe(1);
    expect(c.spentAtomic).toBe(20_000n);
  });

  it("REVIEW H2: a re-sign to a different payee is refused", async () => {
    const s = server(() => r402(required({ payTo: OTHER }), "quote_expired"));
    const err = await client(s.fetcher)
      .invoke("s.v1", { x: 1 })
      .catch((e) => e);
    expect((err as X402Error).code).toBe("policy_rejected");
    expect(s.signatures).toHaveLength(1);
  });

  it("REVIEW M3: refuses near-permanent authorizations and non-EIP-3009 methods", async () => {
    for (const over of [
      { maxTimeoutSeconds: 1_000_000_000 },
      { extra: { name: "USDC", version: "2", assetTransferMethod: "permit2" } },
    ]) {
      const s = server(() => new Response("{}"), required(over));
      const err = await client(s.fetcher)
        .invoke("s.v1", { x: 1 })
        .catch((e) => e);
      expect((err as X402Error).code).toBe("policy_rejected");
      expect(s.signatures).toHaveLength(0);
    }
  });

  it("signs exactly the offer: amount, payee, short validity, EIP-3009 only", async () => {
    const s = server(() => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    await client(s.fetcher).invoke("s.v1", { x: 1 });
    const p = decodePaymentSignatureHeader(s.signatures[0] ?? "");
    const inner = p.payload as { authorization: Record<string, string> };
    expect(Object.keys(p.payload).sort()).toEqual(["authorization", "signature"]);
    expect(inner.authorization).toMatchObject({ to: PAY_TO, value: "20000" });
    expect(Number(inner.authorization.validBefore) - Date.now() / 1000).toBeLessThanOrEqual(301);
    expect(p.extensions?.["payment-identifier"]).toBeTruthy();
  });

  it("REVIEW L1: refuses a baseUrl outside its own allowed origins", () => {
    expect(
      () =>
        new TollyX402Client({
          baseUrl: BASE,
          signer: account,
          policy: {
            network: "eip155:5042002",
            maxPerCallAtomic: 1n,
            budgetAtomic: 1n,
            allowedOrigins: ["https://other.example"],
          },
        }),
    ).toThrow(/allowedOrigins/);
  });

  it("REVIEW M1: with validateLocally=false no schema code is compiled (CSP-safe)", async () => {
    const s = server(() => new Response(JSON.stringify({ ok: true }), { status: 200 }));
    const c = new TollyX402Client({
      baseUrl: BASE,
      signer: account,
      fetch: s.fetcher,
      validateLocally: false,
      policy: { network: "eip155:5042002", maxPerCallAtomic: 50_000n, budgetAtomic: 100_000n },
    });
    await c.invoke("s.v1", { x: 1 });
    expect((c as unknown as { ajv: unknown }).ajv).toBeUndefined();
  });

  it("REVIEW M4: errors carry the payment reference to resume without paying twice", async () => {
    const s = server(() => new Response("{}", { status: 503 }));
    const err = (await client(s.fetcher, { maxAttempts: 1 })
      .invoke("s.v1", { x: 1 })
      .catch((e) => e)) as X402Error;
    expect(err.details.paymentId).toMatch(/^tolly_/);
    expect(err.charged).toBe("unknown");
  });
});

describe("routed purchases (invokeRouted)", () => {
  const ROUTE = "0123456789abcdef";
  /** A scripted routed endpoint: records method, URL and body of every request. */
  function routed(paid: () => Response, offer = required()) {
    const seen: { method: string; url: string; body: string | null; signed: boolean }[] = [];
    const fetcher = (async (url: RequestInfo | URL, init?: RequestInit) => {
      const sig = new Headers(init?.headers).get("PAYMENT-SIGNATURE");
      seen.push({
        method: init?.method ?? "GET",
        url: String(url),
        body: (init?.body as string | undefined) ?? null,
        signed: Boolean(sig),
      });
      return sig ? paid() : r402(offer);
    }) as typeof fetch;
    return { fetcher, seen };
  }

  it("forwards GET with the query string, never a body; POST with the JSON body", async () => {
    const s = routed(() => Response.json({ ok: 1 }));
    const c = client(s.fetcher);
    const p = await c.invokeRouted(ROUTE, { query: { a: "1 2", b: "x" } }, { payTo: PAY_TO });
    expect(p.result).toEqual({ ok: 1 });
    expect(s.seen.map((x) => [x.method, x.url, x.body])).toEqual([
      ["GET", `${BASE}/v1/routed/${ROUTE}/invoke?a=1+2&b=x`, null],
      ["GET", `${BASE}/v1/routed/${ROUTE}/invoke?a=1+2&b=x`, null],
    ]);
    await c.invokeRouted(ROUTE, { body: { q: 1 } });
    expect(s.seen.slice(2).map((x) => [x.method, x.body])).toEqual([
      ["POST", '{"q":1}'],
      ["POST", '{"q":1}'],
    ]);
    await expect(c.invokeRouted("../services/x", {})).rejects.toThrow(/route id/);
    await expect(c.invokeRouted(ROUTE, { method: "GET", body: {} })).rejects.toThrow(/no body/);
  });

  it("refuses another payee or a price above the ceiling before signing", async () => {
    const s = routed(() => new Response("{}", { status: 200 }));
    const c = client(s.fetcher);
    const other = (await c.invokeRouted(ROUTE, {}, { payTo: OTHER }).catch((e) => e)) as X402Error;
    expect(other.code).toBe("policy_rejected");
    const above = (await c
      .invokeRouted(ROUTE, {}, { maxAmountAtomic: 19_999n })
      .catch((e) => e)) as X402Error;
    expect(above.code).toBe("policy_rejected");
    expect(s.seen.filter((x) => x.signed)).toHaveLength(0);
    expect(c.spentAtomic).toBe(0n);
  });

  it("hands back a non-JSON seller answer as text; a refund (410) is an error with its body", async () => {
    const text = routed(
      () => new Response("a,b\n1,2", { status: 200, headers: { "content-type": "text/csv" } }),
    );
    const p = await client(text.fetcher).invokeRouted(ROUTE);
    expect(p.result).toEqual({ contentType: "text/csv", text: "a,b\n1,2" });
    const refunded = routed(
      () =>
        new Response(
          JSON.stringify({ error: "refunded", charged: true, refund: { state: "requested" } }),
          { status: 410, headers: { "X-Job-Id": "j1", "X-Job-Token": "t1" } },
        ),
    );
    const err = (await client(refunded.fetcher)
      .invokeRouted(ROUTE)
      .catch((e) => e)) as X402Error;
    expect(err.message).toBe("refunded");
    expect(err.details).toMatchObject({ jobId: "j1", jobToken: "t1", status: 410 });
    expect((err.details.body as { refund: unknown }).refund).toEqual({ state: "requested" });
  });

  it("a 429 marked charged:false (routing_blocked) is final, not retried", async () => {
    const s = routed(
      () =>
        new Response(JSON.stringify({ error: "routing_blocked", charged: false }), {
          status: 429,
          headers: { "Retry-After": "3600" },
        }),
    );
    const err = (await client(s.fetcher)
      .invokeRouted(ROUTE)
      .catch((e) => e)) as X402Error;
    expect(err.charged).toBe(false);
    expect(err.message).toBe("routing_blocked");
    expect(s.seen.filter((x) => x.signed)).toHaveLength(1);
  });
});

describe("job board (listJobs, deliver, unlock)", () => {
  const JOB = "jb_00000000000000000001";
  const DL = "dl_00000000000000000001";
  function board(paid: () => Response, offer = required()) {
    const seen: { method: string; url: string; body: string | null; auth: string | null }[] = [];
    const fetcher = (async (url: RequestInfo | URL, init?: RequestInit) => {
      const h = new Headers(init?.headers);
      seen.push({
        method: init?.method ?? "GET",
        url: String(url),
        body: (init?.body as string | undefined) ?? null,
        auth: h.get("authorization"),
      });
      if (String(url).includes("/unlock")) return h.get("PAYMENT-SIGNATURE") ? paid() : r402(offer);
      if (String(url).endsWith("/deliveries"))
        return Response.json({ id: DL, allInAtomic: "33000", payoutTo: OTHER }, { status: 201 });
      if (String(url).endsWith("/v1/jobs") && init?.method === "POST")
        return Response.json({ error: "invalid", reason: "title is required" }, { status: 400 });
      return Response.json({ jobs: [], next: null, maxBudgetAtomic: "1000000" });
    }) as typeof fetch;
    return { fetcher, seen };
  }

  it("lists with filters, delivers with the identity proof, and refuses bad ids locally", async () => {
    const s = board(() => Response.json({}));
    const c = client(s.fetcher);
    await c.listJobs({ q: "pools", tag: "arc", maxBudgetAtomic: 50_000n, limit: 5 });
    expect(s.seen[0]?.url).toBe(`${BASE}/v1/jobs?q=pools&tag=arc&maxBudget=50000&limit=5`);
    const proof = { signer: account.address, issuedAt: "2026-10-21T00:00:00Z", signature: "0x01" };
    const d = await c.deliver(
      JOB,
      { agent: { kind: "erc8004", id: "77" }, priceAtomic: "30000", preview: "p", result: "r" },
      { proof },
    );
    expect(d.id).toBe(DL);
    expect(JSON.parse(s.seen[1]?.body ?? "{}")).toMatchObject({ proof, priceAtomic: "30000" });
    await c.deliver(
      JOB,
      { agent: { kind: "registry", id: "a" }, priceAtomic: "1000", preview: "p", result: "r" },
      { operatorToken: "op" },
    );
    expect(s.seen[2]?.auth).toBe("Bearer op");
    const bad = (await c
      .postJob({ title: "", brief: "", budgetAtomic: "1" }, "acct")
      .catch((e) => e)) as X402Error;
    expect(bad).toMatchObject({ code: "invalid_input", charged: false });
    await expect(c.unlock("../x")).rejects.toThrow(/delivery id/);
    await expect(c.getJob("x")).rejects.toThrow(/job id/);
  });

  it("unlocks with a GET, within the ceiling and payee; a refusal before any charge is final", async () => {
    const s = board(
      () =>
        new Response("a,b", {
          status: 200,
          headers: { "content-type": "text/csv; charset=utf-8" },
        }),
    );
    const c = client(s.fetcher);
    const p = await c.unlock(DL, { maxAmountAtomic: 20_000n, payTo: PAY_TO });
    expect(p.result).toEqual({ contentType: "text/csv; charset=utf-8", text: "a,b" });
    expect(s.seen.map((x) => x.method)).toEqual(["GET", "GET"]);
    const above = (await c.unlock(DL, { maxAmountAtomic: 19_999n }).catch((e) => e)) as X402Error;
    expect(above.code).toBe("policy_rejected");
    const refused = board(
      () => new Response(JSON.stringify({ error: "not_poster", charged: false }), { status: 403 }),
    );
    const err = (await client(refused.fetcher)
      .unlock(DL)
      .catch((e) => e)) as X402Error;
    expect(err).toMatchObject({ charged: false, message: "not_poster" });
  });
});
