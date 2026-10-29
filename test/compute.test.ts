// The MCP server's Tolly Compute tools against a scripted gateway on localhost: what is signed, what
// is paid (only credit denominations, within the per-call cap and the daily budget), and what the
// chat tool sends with the configured compute key.
import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttp, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { computeMessage } from "../src/usage.ts";
import { encodePaymentRequiredHeader, encodePaymentResponseHeader } from "@x402/core/http";
import type { PaymentRequired } from "@x402/core/types";
import { recoverMessageAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createServer } from "../src/index.ts";

const NET = "eip155:5042";
const USDC = "0x3600000000000000000000000000000000000000";
const TOLLY = "0x00000000000000000000000000000000000000aa";
const key = generatePrivateKey();
const me = privateKeyToAccount(key);
const COMPUTE_KEY = `tck_${"A".repeat(43)}`;

const credit = (usd: number) => ({
  id: `compute.credit.${usd}usd.v1`,
  title: `Compute credit ($${usd})`,
  semantics: "credit",
  availability: "available",
  purchasable: true,
  unavailableReason: null,
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: ["network"],
    properties: { network: { type: "string", enum: [NET, "eip155:5042002"] } },
  },
  outputSchema: {},
  payment: {
    scheme: "exact",
    network: NET,
    asset: USDC,
    decimals: 6,
    amountAtomic: String(usd * 1_000_000),
  },
});

type Seen = { method: string; path: string; body: string; auth: string | null; paid: boolean };
let http: HttpServer;
let base = "";
let seen: Seen[] = [];
let credited = 0n;
let dir = "";
/** false: the mock gateway answers like one with compute off (503 compute_unavailable). */
let computeOn = true;

beforeAll(async () => {
  http = createHttp((req, res) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
    });
    req.on("end", async () => {
      const url = new URL(req.url ?? "/", base);
      const sig = (req.headers["payment-signature"] as string | undefined) ?? null;
      seen.push({
        method: req.method ?? "",
        path: url.pathname,
        body,
        auth: (req.headers.authorization as string | undefined) ?? null,
        paid: Boolean(sig),
      });
      const json = (status: number, v: unknown, headers: Record<string, string> = {}) => {
        res.writeHead(status, { "content-type": "application/json", ...headers });
        res.end(JSON.stringify(v));
      };
      if (!computeOn && url.pathname.startsWith("/v1/compute/"))
        return json(503, { error: "compute_unavailable", reason: "not enabled" });
      if (url.pathname === "/v1/compute/models")
        return json(200, { network: NET, models: [{ id: "claude-x", provider: "anthropic" }] });
      if (url.pathname === "/v1/services") return json(200, { services: [credit(1), credit(5)] });
      const one = /^\/v1\/services\/compute\.credit\.(\d+)usd\.v1$/.exec(url.pathname);
      if (one) return json(200, credit(Number(one[1])));
      if (url.pathname === "/v1/compute/session") {
        const b = JSON.parse(body) as {
          address: string;
          issued_at: string;
          signature: `0x${string}`;
        };
        const signer = await recoverMessageAddress({
          message: computeMessage(b.address, b.issued_at, base, NET),
          signature: b.signature,
        });
        if (signer.toLowerCase() !== me.address.toLowerCase())
          return json(401, { error: "unauthorized" });
        return json(200, { token: "compute-session", expires_at: "2099-01-01T00:00:00Z" });
      }
      if (url.pathname === "/v1/compute/balance") {
        if (req.headers.authorization !== "Bearer compute-session") return json(401, {});
        return json(200, {
          address: me.address.toLowerCase(),
          network: NET,
          balance_atomic: credited.toString(),
          reserved_atomic: "0",
          available_atomic: credited.toString(),
          ledger: [
            { kind: "topup", amount_atomic: "1000000", note: "settled‮ <b>", created_at: "x" },
          ],
        });
      }
      if (url.pathname === "/v1/compute/messages") {
        res.writeHead(200, {
          "content-type": "application/json",
          "x-compute-cost-atomic": "357",
          "x-compute-request-id": "11111111-1111-1111-1111-111111111111",
        });
        return res.end(
          JSON.stringify({
            model: "claude-haiku-5-5",
            stop_reason: "end_turn",
            content: [{ type: "text", text: "hi there" }],
            usage: { input_tokens: 3, output_tokens: 2 },
          }),
        );
      }
      const m = /^\/v1\/services\/(compute\.credit\.(\d+)usd\.v1)\/invoke$/.exec(url.pathname);
      if (!m) return json(404, { error: "not_found" });
      const amount = String(Number(m[2]) * 1_000_000);
      if (!sig) {
        const required: PaymentRequired = {
          x402Version: 2,
          resource: { url: `${base}${url.pathname}`, description: "credit", mimeType: "" },
          accepts: [
            {
              scheme: "exact",
              network: NET,
              asset: USDC,
              amount,
              payTo: TOLLY,
              maxTimeoutSeconds: 300,
              extra: { name: "USDC", version: "2", quote: "q" },
            },
          ],
        };
        return json(402, required, { "PAYMENT-REQUIRED": encodePaymentRequiredHeader(required) });
      }
      credited += BigInt(amount);
      res.writeHead(200, {
        "content-type": "application/json",
        "X-Job-Id": `00000000-0000-0000-0000-${String(seen.length).padStart(12, "0")}`,
        "X-Job-Token": "jobtoken",
        "PAYMENT-RESPONSE": encodePaymentResponseHeader({
          success: true,
          transaction: `0x${"cd".repeat(32)}`,
          network: NET,
        }),
      });
      res.end(JSON.stringify({ credited_to: me.address.toLowerCase(), network: NET }));
    });
  });
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(http.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => http.close(() => r())));
beforeEach(() => {
  seen = [];
  credited = 0n;
  dir = mkdtempSync(join(tmpdir(), "mcp-compute-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

async function connect(env: Record<string, string> = {}) {
  const server = await createServer({
    TOLLY_X402_URL: base,
    TOLLY_X402_NETWORK: NET,
    BUYER_PRIVATE_KEY: key,
    TOLLY_X402_LEDGER: join(dir, "spend.json"),
    TOLLY_X402_MAX_PER_CALL: "2.00",
    TOLLY_X402_BUDGET: "5.00",
    ...env,
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "1" });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = await client.callTool({ name, arguments: args });
    const t = (r.content as { text: string }[])[0]?.text ?? "";
    let json: Record<string, unknown> = {};
    try {
      json = JSON.parse(t);
    } catch {}
    return { isError: Boolean(r.isError), text: t, json };
  };
  return { client, call };
}

describe("Tolly Compute MCP tools", () => {
  it("offers balance/top-up only with a wallet, and chat only with a compute key", async () => {
    const without = await connect({ BUYER_PRIVATE_KEY: "" });
    const names = (await without.client.listTools()).tools.map((t) => t.name);
    expect(names).not.toContain("tolly_compute_balance");
    expect(names).not.toContain("tolly_compute_topup");
    expect(names).not.toContain("tolly_compute_chat");
    const withKey = await connect({ TOLLY_COMPUTE_API_KEY: COMPUTE_KEY });
    expect((await withKey.client.listTools()).tools.map((t) => t.name)).toEqual(
      expect.arrayContaining([
        "tolly_compute_balance",
        "tolly_compute_topup",
        "tolly_compute_chat",
      ]),
    );
    await expect(connect({ TOLLY_COMPUTE_API_KEY: "sk-not-a-compute-key" })).rejects.toThrow(
      /compute API key/,
    );
  });

  it("hides balance/top-up until TOLLY serves compute; a call anyway gets the gateway's error", async () => {
    computeOn = false;
    try {
      const off = await connect();
      const names = (await off.client.listTools()).tools.map((t) => t.name);
      expect(names).not.toContain("tolly_compute_balance");
      expect(names).not.toContain("tolly_compute_topup");
      const r = await off.call("tolly_compute_balance", {});
      expect(r.isError).toBe(true);
      expect(r.text).toMatch(/compute_unavailable|not enabled/);
      expect(seen.some((s) => s.paid)).toBe(false);
    } finally {
      computeOn = true;
    }
  });

  it("reads the balance with a compute sign-in signed by the wallet (never a payment)", async () => {
    const { call } = await connect();
    const r = await call("tolly_compute_balance", {});
    expect(r.isError).toBe(false);
    expect(r.json).toMatchObject({ available_usdc: "0.000000", network: NET });
    expect(String((r.json.recent as { note: string }[])[0]?.note)).not.toMatch(/[<>‮]/);
    expect(seen.every((s) => !s.paid)).toBe(true);
    expect(seen.find((s) => s.path === "/v1/compute/session")).toBeDefined();
  });

  it("tops up with denominations within the per-call cap, stopping at the daily budget", async () => {
    // $5 is above the $2 per-call cap: only $1 denominations are bought; the $1.50 budget allows one.
    const { call } = await connect({ TOLLY_X402_BUDGET: "1.50" });
    const r = await call("tolly_compute_topup", { topUpToUsd: 2.5 });
    expect(r.isError).toBe(false);
    expect(r.json.status).toBe("partly_topped_up");
    expect(r.json.purchases).toHaveLength(1);
    const paid = seen.filter((s) => s.paid);
    expect(paid.map((s) => s.path)).toEqual(["/v1/services/compute.credit.1usd.v1/invoke"]);
    expect(JSON.parse(paid[0]?.body ?? "{}")).toEqual({ network: NET });
    expect(r.json.available_usdc).toBe("1.000000");
    // Already above the floor: nothing bought.
    const again = await call("tolly_compute_topup", { minUsd: 0.5, topUpToUsd: 3 });
    expect(again.json).toMatchObject({ status: "enough_credit", charged: false });
    expect(seen.filter((s) => s.paid)).toHaveLength(1);
  });

  it("buys until the target with a roomy budget", async () => {
    const { call } = await connect();
    const r = await call("tolly_compute_topup", { topUpToUsd: 3 });
    expect(r.json.status).toBe("topped_up");
    expect(r.json.purchases).toHaveLength(3);
    expect(r.json.available_usdc).toBe("3.000000");
  });

  it("chats with the compute key and reports the charge", async () => {
    const { call } = await connect({ TOLLY_COMPUTE_API_KEY: COMPUTE_KEY });
    const r = await call("tolly_compute_chat", {
      model: "claude-haiku-5-5",
      maxTokens: 50,
      messages: [{ role: "user", content: "hello" }],
    });
    expect(r.isError).toBe(false);
    expect(r.json).toMatchObject({ text: "hi there", charged_usdc: "0.000357" });
    const sent = seen.find((s) => s.path === "/v1/compute/messages");
    expect(sent?.auth).toBe(`Bearer ${COMPUTE_KEY}`);
    expect(JSON.parse(sent?.body ?? "{}")).toEqual({
      model: "claude-haiku-5-5",
      max_tokens: 50,
      messages: [{ role: "user", content: "hello" }],
    });
    expect(seen.every((s) => !s.paid)).toBe(true);
  });
});
