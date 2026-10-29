// Agent wallet spending rules v1 (the allowance float): the pull plan, the float's checks with a
// scripted chain, and the settings. (The end-to-end run on a local anvil chain stays in TOLLY's
// private test suite.)
import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttp } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getAddress } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { floatFrom, Ledger } from "../src/index.ts";
import {
  AgentFloat,
  type FloatChain,
  FloatError,
  type FloatSettings,
  hotKeyProofMessage,
  planPull,
  rpcChain,
  SentUnknown,
} from "../src/wallet.ts";

const USDC = "0x3600000000000000000000000000000000000000";
const TBA = "0x1111111111111111111111111111111111111111";
const HOT = privateKeyToAccount(generatePrivateKey()).address;
const $ = (usd: number) => BigInt(Math.round(usd * 1_000_000));

let dir = "";
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "mcp-wallet-"));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe("planPull", () => {
  const base = {
    price: $(0.1),
    allowance: $(5),
    account: $(10),
    pullLeft: $(1),
    target: $(1),
    min: $(0.25),
    reserve: $(0.05),
  };
  it("does nothing while the hot key covers the price, the gas reserve and the minimum", () => {
    expect(planPull({ ...base, hot: $(0.3) })).toEqual({
      amount: 0n,
      needed: $(0.15),
      enough: true,
    });
  });
  it("pulls up to the target when below the minimum or the price plus reserve", () => {
    expect(planPull({ ...base, hot: $(0.2) }).amount).toBe($(0.8)); // below min
    // Above min, but the payment would eat into the gas reserve.
    expect(planPull({ ...base, hot: $(0.3), price: $(0.28) }).amount).toBe($(0.7));
    // A price above the target: pull what the price and reserve need.
    expect(planPull({ ...base, hot: 0n, price: $(2), pullLeft: $(5) })).toEqual({
      amount: $(2.05),
      needed: $(2.05),
      enough: true,
    });
  });
  it("is capped by the allowance, the account's balance and today's pull cap", () => {
    expect(planPull({ ...base, hot: 0n, allowance: $(0.4) }).amount).toBe($(0.4));
    expect(planPull({ ...base, hot: 0n, account: $(0.3) }).amount).toBe($(0.3));
    expect(planPull({ ...base, hot: 0n, pullLeft: $(0.2) })).toEqual({
      amount: $(0.2),
      needed: $(0.15),
      enough: true,
    });
    expect(planPull({ ...base, hot: 0n, pullLeft: $(0.1) }).enough).toBe(false);
    expect(planPull({ ...base, hot: 0n, allowance: 0n })).toMatchObject({
      amount: 0n,
      enough: false,
    });
  });
});

/** A scripted chain: one USDC balance per address, native gas, and a record of every send. */
function fakeChain(over: Partial<FloatChain> = {}, extra: Partial<FloatSettings> = {}) {
  const st = {
    chainId: 5042,
    decimals: 6,
    usdc: { [TBA.toLowerCase()]: $(10), [HOT.toLowerCase()]: 0n } as Record<string, bigint>,
    allowance: $(5),
    native: 10n ** 18n,
    codes: { [TBA.toLowerCase()]: "0x6001" } as Record<string, string>,
    sends: [] as string[],
    failPull: null as Error | null,
  };
  const chain: FloatChain = {
    chainId: async () => st.chainId,
    decimals: async () => st.decimals,
    balanceOf: async (a) => st.usdc[a.toLowerCase()] ?? 0n,
    allowance: async () => st.allowance,
    nativeBalance: async () => st.native,
    code: async (a) => st.codes[a.toLowerCase()] ?? "0x",
    transferFrom: async (from, amount) => {
      st.sends.push(`transferFrom ${from.toLowerCase()} ${amount}`);
      if (st.failPull) throw st.failPull;
      if (amount > st.allowance) throw new Error("allowance");
      st.allowance -= amount;
      st.usdc[from.toLowerCase()] = (st.usdc[from.toLowerCase()] ?? 0n) - amount;
      st.usdc[HOT.toLowerCase()] = (st.usdc[HOT.toLowerCase()] ?? 0n) + amount;
      return `0x${"aa".repeat(32)}`;
    },
    transfer: async (to, amount) => {
      st.sends.push(`transfer ${to.toLowerCase()} ${amount}`);
      st.usdc[HOT.toLowerCase()] = (st.usdc[HOT.toLowerCase()] ?? 0n) - amount;
      st.usdc[to.toLowerCase()] = (st.usdc[to.toLowerCase()] ?? 0n) + amount;
      return `0x${"bb".repeat(32)}`;
    },
    ...over,
  };
  const pulls = new Ledger(join(dir, "spend.json"), `pull:${HOT}`);
  const float = new AgentFloat(chain, {
    hot: HOT,
    wallet: TBA,
    chainId: 5042,
    target: $(1),
    min: $(0.25),
    reserve: $(0.05),
    pullBudget: $(1),
    pulls,
    ...extra,
  });
  return { st, float, pulls };
}

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return "ok";
  } catch (e) {
    return e instanceof FloatError ? e.code : `other: ${(e as Error).message}`;
  }
};

describe("AgentFloat", () => {
  it("checks the chain and the token before any send", async () => {
    const a = fakeChain();
    a.st.chainId = 1;
    expect(await code(a.float.ensure($(0.1)))).toBe("wrong_chain");
    const b = fakeChain();
    b.st.chainId = 5042002; // Arc testnet, but not the configured network
    expect(await code(b.float.ensure($(0.1)))).toBe("wrong_chain");
    const c = fakeChain();
    c.st.decimals = 18;
    expect(await code(c.float.ensure($(0.1)))).toBe("wrong_token");
    expect([...a.st.sends, ...b.st.sends, ...c.st.sends]).toEqual([]);
  });

  it("refuses an agent wallet with no contract code (a typo would swallow a return)", async () => {
    for (const c of ["0x", `0xef0100${"22".repeat(20)}`]) {
      const a = fakeChain();
      a.st.codes[TBA.toLowerCase()] = c;
      a.st.usdc[HOT.toLowerCase()] = $(3);
      expect(await code(a.float.giveBack(0n))).toBe("wrong_wallet");
      expect(await code(a.float.ensure($(0.1)))).toBe("wrong_wallet");
      expect(a.st.sends).toEqual([]);
    }
  });

  it("pulls from the agent's account to itself, exactly, then not again while covered", async () => {
    const { st, float } = fakeChain();
    expect(await float.ensure($(0.1))).toEqual({
      pulled: $(1),
      transaction: `0x${"aa".repeat(32)}`,
    });
    expect(st.sends).toEqual([`transferFrom ${TBA.toLowerCase()} ${$(1)}`]);
    expect(await float.ensure($(0.1))).toEqual({ pulled: 0n, transaction: null });
    expect(st.sends).toHaveLength(1);
  });

  it("caps pulls per day at the budget: repeated spending cannot drain the account", async () => {
    const { st, float, pulls } = fakeChain();
    let paid = 0n;
    for (let i = 0; i < 30; i++) {
      const r = await code(float.ensure($(0.2)));
      if (r !== "ok") {
        expect(r).toBe("float_too_small");
        break;
      }
      st.usdc[HOT.toLowerCase()] = (st.usdc[HOT.toLowerCase()] ?? 0n) - $(0.2); // the payment
      paid += $(0.2);
    }
    expect(pulls.today()).toBeLessThanOrEqual($(1));
    expect(st.usdc[TBA.toLowerCase()]).toBeGreaterThanOrEqual($(9));
    expect(paid).toBeLessThanOrEqual($(1));
  });

  it("refuses without sending: no allowance, empty account, no gas", async () => {
    const a = fakeChain();
    a.st.allowance = 0n;
    const err = await a.float.ensure($(0.1)).catch((e: FloatError) => e);
    expect(err).toBeInstanceOf(FloatError);
    expect((err as FloatError).message).toMatch(/allowance is 0/);
    const b = fakeChain();
    b.st.usdc[TBA.toLowerCase()] = 0n;
    expect(((await b.float.ensure($(0.1)).catch((e) => e)) as Error).message).toMatch(/empty/);
    const c = fakeChain();
    c.st.native = 10n ** 11n; // less than 0.001 USDC of gas
    expect(await code(c.float.ensure($(0.1)))).toBe("no_gas");
    expect([...a.st.sends, ...b.st.sends, ...c.st.sends]).toEqual([]);
  });

  it("a failed pull gives its share of the day's cap back; one of unknown outcome keeps it", async () => {
    const a = fakeChain();
    a.st.failPull = new Error("reverted");
    expect(await code(a.float.ensure($(0.1)))).toBe("pull_failed");
    expect(a.pulls.today()).toBe(0n);
    const b = fakeChain();
    b.st.failPull = new SentUnknown("no receipt");
    expect(await code(b.float.ensure($(0.1)))).toBe("pull_failed");
    expect(b.pulls.today()).toBe($(1));
  });

  it("two calls at once pull once", async () => {
    const { st, float } = fakeChain();
    await Promise.all([float.ensure($(0.1)), float.ensure($(0.1)), float.ensure($(0.1))]);
    expect(st.sends).toHaveLength(1);
  });

  it("returns what is above the gas reserve, only to the agent's account", async () => {
    const { st, float } = fakeChain();
    st.usdc[HOT.toLowerCase()] = $(0.75);
    expect(await float.giveBack(0n)).toMatchObject({
      status: "returned",
      returned_usdc: "0.700000",
      kept_usdc: "0.050000",
      to: getAddress(TBA),
    });
    expect(st.sends).toEqual([`transfer ${TBA.toLowerCase()} ${$(0.7)}`]);
    expect(await float.giveBack($(0.5))).toMatchObject({ status: "nothing_to_return" });
    st.usdc[HOT.toLowerCase()] = $(2);
    expect(await float.giveBack($(0.5))).toMatchObject({ returned_usdc: "1.500000" });
  });

  it("status: worst case is the hot key plus what it can still pull, never more than the account", async () => {
    const { st, float } = fakeChain();
    st.usdc[HOT.toLowerCase()] = $(0.4);
    st.usdc[TBA.toLowerCase()] = $(3);
    expect(await float.status()).toMatchObject({
      hot_key_usdc: "0.400000",
      agent_wallet_usdc: "3.000000",
      allowance_usdc: "5.000000",
      pullable_now_usdc: "3.000000",
      worst_case_if_key_leaks_usdc: "3.400000",
      worst_case_if_wallet_topped_up_usdc: "5.400000",
      gas_ok: true,
      decimals: 6,
    });
    expect(st.sends).toEqual([]);
  });
});

describe("hot key proof", () => {
  // One test vector shared with TOLLY's Spending panel and gateway tests.
  const VECTOR = {
    key: `0x${"11".repeat(32)}` as const,
    hot: "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A",
    wallet: "0x1234567890123456789012345678901234567890",
    signature:
      "0xf4db70a2a3eae3e5764c14233fbb79146e41530f2d99bf7d4f3a395d60c77e163cba79a172eb74eee4860c7a79395b14ea8145fe1330df4ac1c212c9ba8686081b",
  };
  it("is the exact text the Spending panel rebuilds, signed by the hot key", async () => {
    expect(hotKeyProofMessage(5042, VECTOR.wallet)).toBe(
      "TOLLY agent hot key v1\nChain: 5042\nAgent wallet: 0x1234567890123456789012345678901234567890\nThe key that signed this message is this agent wallet's hot key. Its owner may approve it for a USDC allowance.",
    );
    const acct = privateKeyToAccount(VECTOR.key);
    expect(acct.address).toBe(VECTOR.hot);
    expect(await acct.signMessage({ message: hotKeyProofMessage(5042, VECTOR.wallet) })).toBe(
      VECTOR.signature,
    );
  });
  it("status carries the proof when the float can sign", async () => {
    const signed: string[] = [];
    const { float } = fakeChain(
      {},
      {
        sign: async (m) => {
          signed.push(m);
          return "0xproof";
        },
      },
    );
    expect(await float.status()).toMatchObject({ hot_key_proof: "0xproof" });
    expect(signed).toEqual([hotKeyProofMessage(5042, TBA)]);
  });
});

describe("rpcChain sends", () => {
  /** A scripted JSON-RPC: answers what a send needs, and fails the raw send as told. */
  const fakeRpc = async (onSend: "http_502" | "revert_on_estimate") => {
    const methods: string[] = [];
    const srv = createHttp((req, res) => {
      let body = "";
      req.on("data", (d) => {
        body += d;
      });
      req.on("end", () => {
        const one = (m: { id: number; method: string }) => {
          methods.push(m.method);
          const ok = (result: unknown) => ({ jsonrpc: "2.0", id: m.id, result });
          switch (m.method) {
            case "eth_chainId":
              return ok("0x13b2");
            case "eth_getTransactionCount":
              return ok("0x0");
            case "eth_estimateGas":
              return onSend === "revert_on_estimate"
                ? { jsonrpc: "2.0", id: m.id, error: { code: 3, message: "execution reverted" } }
                : ok("0xc350");
            case "eth_gasPrice":
            case "eth_maxPriorityFeePerGas":
              return ok("0x1");
            case "eth_getBlockByNumber":
              return ok({
                number: "0x1",
                baseFeePerGas: "0x1",
                timestamp: "0x1",
                hash: `0x${"00".repeat(32)}`,
              });
            default:
              return null;
          }
        };
        const msg = JSON.parse(body) as { id: number; method: string };
        if (msg.method === "eth_sendRawTransaction") {
          methods.push(msg.method);
          res.writeHead(502);
          return res.end("bad gateway");
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(one(msg)));
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    return { url, methods, close: () => new Promise<void>((r) => srv.close(() => r())) };
  };

  it("a raw send that failed in transport is of unknown outcome (its pull stays counted)", async () => {
    const rpc = await fakeRpc("http_502");
    try {
      const chain = rpcChain(rpc.url, privateKeyToAccount(generatePrivateKey()), 5042);
      const err = await chain.transferFrom(TBA, 1n).catch((e) => e);
      expect(err).toBeInstanceOf(SentUnknown);
      expect(rpc.methods).toContain("eth_sendRawTransaction");
    } finally {
      await rpc.close();
    }
  });

  it("a revert before the send is a plain failure (nothing went out, the cap is given back)", async () => {
    const rpc = await fakeRpc("revert_on_estimate");
    try {
      const chain = rpcChain(rpc.url, privateKeyToAccount(generatePrivateKey()), 5042);
      const err = await chain.transferFrom(TBA, 1n).catch((e) => e);
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(SentUnknown);
      expect(rpc.methods).not.toContain("eth_sendRawTransaction");
    } finally {
      await rpc.close();
    }
  });
});

describe("float settings", () => {
  const key = generatePrivateKey();
  const acct = privateKeyToAccount(key);
  const env = (over: Record<string, string>) => ({
    TOLLY_AGENT_WALLET: getAddress(TBA),
    TOLLY_RPC_URL: "https://arc.example",
    ...over,
  });
  const make = (over: Record<string, string>, network = "eip155:5042") =>
    floatFrom(env(over), acct, network, $(1), join(dir, "s.json"));
  it("refuses bad settings at start", () => {
    expect(() => make({ TOLLY_AGENT_WALLET: "0x1234" })).toThrow(/not an address/);
    const mixed = "0xAbCdEf0123456789aBcDeF0123456789AbCdEf01";
    expect(() => make({ TOLLY_AGENT_WALLET: mixed })).toThrow(/checksum/);
    expect(() => make({ TOLLY_RPC_URL: "" })).toThrow(/TOLLY_RPC_URL/);
    expect(() => make({ TOLLY_RPC_URL: "http://rpc.example" })).toThrow(/https/);
    expect(() => make({}, "eip155:1")).toThrow(/Arc only/);
    expect(() => make({ TOLLY_AGENT_WALLET: acct.address })).toThrow(/own address/);
    expect(() => make({ TOLLY_AGENT_WALLET: USDC })).toThrow(/not zero or the USDC/);
    expect(() => make({ TOLLY_FLOAT_RESERVE_USD: "0" })).toThrow(/at least 0.01/);
    expect(() => make({ TOLLY_FLOAT_MIN_USD: "2" })).toThrow(/above/);
    expect(() => make({ TOLLY_FLOAT_TARGET_USD: "1.0000001" })).toThrow(/USDC amount/);
    expect(() => floatFrom(env({}), null, "eip155:5042", $(1), join(dir, "s.json"))).toThrow(
      /BUYER_PRIVATE_KEY/,
    );
    expect(make({})).toBeInstanceOf(AgentFloat);
  });
});
