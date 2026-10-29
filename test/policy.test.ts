// The MCP's AgentSpendPolicy mode against a scripted chain: settings fail closed, the chain /
// policy / account checks before any send, mode selection (account payer vs fallback), and the
// x402 signer's refusals (nothing sent for a tampered request). The real contract path runs in
// TOLLY's private end-to-end suite.
import {
  authorizationDigest,
  encodeCancelPreauthorization,
  x402PolicySignature,
} from "../src/spend-policy.ts";
import { encodeFunctionData, erc20Abi, type Hex, keccak256 } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";
import { type AcpToolContext, callAcpTool, type PolicyRoute } from "../src/acp.ts";
import { policyFrom } from "../src/index.ts";
import {
  AgentPolicy,
  type PolicyCallRecord,
  type PolicyChain,
  PolicyError,
} from "../src/policy.ts";

const POLICY = "0x5050505050505050505050505050505050505050";
const TBA = "0x6161616161616161616161616161616161616161";
const OWNER = "0x7171717171717171717171717171717171717171";
const PAYEE = "0x4CAF61991132b7a55d25B85583B203C807407E84";
const NFT = "0x8181818181818181818181818181818181818181";
const USDC = "0x3600000000000000000000000000000000000000";
const POLICY_CODE = "0x6080604052";
const TBA_CODE = `0x363d3d373d3d3d363d73${"00".repeat(163)}` as Hex;
const hot = privateKeyToAccount(generatePrivateKey());

const config = (o: Record<string, unknown> = {}) => ({
  owner: OWNER,
  expiresAt: 0,
  accepted: true,
  paused: false,
  allowNative: false,
  allowPreauth: true,
  day: Math.floor(Date.now() / 86_400_000),
  spentToday: 0n,
  perTxCap: 2_000_000n,
  dailyCap: 10_000_000n,
  ...o,
});

function fakeChain(
  o: {
    chainId?: number;
    cfg?: Record<string, unknown>;
    tbaCode?: Hex;
    derived?: string;
    digest?: (args: readonly unknown[]) => Hex;
  } = {},
) {
  const sent: { to: string; data: Hex }[] = [];
  const chain: PolicyChain = {
    pub: {
      getChainId: async () => o.chainId ?? 5042,
      getCode: async ({ address }: { address: string }) =>
        address.toLowerCase() === POLICY ? POLICY_CODE : (o.tbaCode ?? TBA_CODE),
      getBalance: async () => 10n ** 18n,
      call: async () => ({ data: "0x" }),
      waitForTransactionReceipt: async () => ({ status: "success", transactionHash: "0x01" }),
      readContract: async ({
        functionName,
        args,
      }: {
        functionName: string;
        args?: readonly unknown[];
      }) => {
        switch (functionName) {
          case "decimals":
            return 6;
          case "usdc":
            return USDC;
          case "tollyPayee":
            return PAYEE;
          case "defaultPerTxCap":
            return 2_000_000n;
          case "defaultDailyCap":
            return 10_000_000n;
          case "token":
            return [BigInt(o.chainId ?? 5042), NFT, 1n];
          case "account":
            return o.derived ?? TBA;
          case "getConfig":
            return o.cfg ?? config();
          case "generation":
            return 1n;
          case "owner":
            return OWNER;
          case "isLocked":
            return false;
          case "permissions":
            return true;
          case "isPayee":
            return true;
          case "balanceOf":
            return 0n;
          case "authorizationDigest": {
            const [from, to, value, validAfter, validBefore, nonce] = args as [
              Hex,
              Hex,
              bigint,
              bigint,
              bigint,
              Hex,
            ];
            return (
              o.digest?.(args ?? []) ??
              authorizationDigest(5042, { from, to, value, validAfter, validBefore, nonce })
            );
          }
        }
        throw new Error(`unexpected read ${functionName}`);
      },
    } as unknown as PolicyChain["pub"],
    send: async (tx) => {
      sent.push(tx);
      return `0x${"aa".repeat(32)}`;
    },
  };
  return { chain, sent };
}

const policy = (o: Parameters<typeof fakeChain>[0] = {}, codehash: Hex | null = null) => {
  const f = fakeChain(o);
  return {
    ...f,
    p: new AgentPolicy(f.chain, {
      policy: POLICY,
      tba: TBA,
      hot: hot.address,
      chainId: 5042,
      codehash,
    }),
  };
};

describe("settings", () => {
  const env = {
    TOLLY_SPEND_POLICY: "0x5050505050505050505050505050505050505050",
    TOLLY_AGENT_WALLET: TBA,
    TOLLY_RPC_URL: "https://arc.example",
  };
  it("is off without TOLLY_SPEND_POLICY and fails closed on a bad setting", () => {
    expect(policyFrom({}, hot, "eip155:5042")).toBeNull();
    expect(policyFrom(env, hot, "eip155:5042")).toBeInstanceOf(AgentPolicy);
    expect(() => policyFrom({ ...env, TOLLY_SPEND_POLICY: "0x12" }, hot, "eip155:5042")).toThrow();
    expect(() =>
      policyFrom({ ...env, TOLLY_SPEND_POLICY_CODEHASH: "0x1" }, hot, "eip155:5042"),
    ).toThrow(/CODEHASH/);
    expect(() => policyFrom({ ...env, TOLLY_AGENT_WALLET: "" }, hot, "eip155:5042")).toThrow(
      /TOLLY_AGENT_WALLET/,
    );
    expect(() => policyFrom(env, null, "eip155:5042")).toThrow(/BUYER_PRIVATE_KEY/);
    expect(() => policyFrom(env, hot, "eip155:1")).toThrow(/Arc only/);
    expect(() => policyFrom({ ...env, TOLLY_RPC_URL: "" }, hot, "eip155:5042")).toThrow(/RPC/);
    expect(() =>
      policyFrom({ ...env, TOLLY_RPC_URL: "http://arc.example" }, hot, "eip155:5042"),
    ).toThrow(/https/);
    expect(() =>
      policyFrom({ ...env, TOLLY_AGENT_WALLET: hot.address }, hot, "eip155:5042"),
    ).toThrow(/own address/);
  });
});

describe("checks before any send", () => {
  it("refuses another chain, a policy whose code is not the pinned one, and a fake account", async () => {
    const wrongChain = policy({ chainId: 1 });
    await expect(wrongChain.p.accept()).rejects.toMatchObject({ code: "wrong_chain" });
    const pinned = policy({}, `0x${"00".repeat(32)}`);
    await expect(pinned.p.accept()).rejects.toMatchObject({ code: "wrong_policy" });
    const notAccount = policy({ tbaCode: "0x6080" });
    await expect(notAccount.p.accept()).rejects.toMatchObject({ code: "wrong_wallet" });
    const lookAlike = policy({ derived: "0x9999999999999999999999999999999999999999" });
    await expect(lookAlike.p.accept()).rejects.toMatchObject({ code: "wrong_wallet" });
    for (const x of [wrongChain, pinned, notAccount, lookAlike]) expect(x.sent).toEqual([]);
    // The right code hash passes.
    const ok = policy({ cfg: config({ accepted: false }) }, keccak256(POLICY_CODE));
    expect(await ok.p.accept()).toMatchObject({ transaction: expect.any(String) });
    expect(ok.sent).toHaveLength(1);
  });
});

describe("mode", () => {
  it("pays from the account only when the rules are active and allow x402", async () => {
    expect((await policy().p.mode()).mode).toBe("account");
    // No rules for this key yet: the float or the hot key may pay.
    for (const [cfg, why] of [
      [config({ accepted: false }), /accept/],
      [config({ owner: "0x0000000000000000000000000000000000000000" }), /Not enabled/],
      [config({ owner: PAYEE }), /previous owner/],
    ] as const) {
      const m = await policy({ cfg }).p.mode();
      expect(m.mode).toBe("fallback");
      expect(m.mode === "fallback" ? m.why : "").toMatch(why);
    }
    // The owner's rules say stop: nothing pays around them (no float, no hot key).
    for (const [cfg, why] of [
      [config({ paused: true }), /Paused/],
      [config({ allowPreauth: false }), /allowPreauth/],
      [config({ expiresAt: 1 }), /Expired/],
    ] as const) {
      const m = await policy({ cfg }).p.mode();
      expect(m.mode).toBe("stopped");
      expect(m.mode === "stopped" ? m.why : "").toMatch(why);
    }
  });
});

describe("the x402 signer", () => {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const typed = (
    o: {
      domain?: Record<string, unknown>;
      message?: Record<string, unknown>;
      primaryType?: string;
    } = {},
  ) => ({
    domain: { name: "USDC", version: "2", chainId: 5042, verifyingContract: USDC, ...o.domain },
    types: {},
    primaryType: o.primaryType ?? "TransferWithAuthorization",
    message: {
      from: TBA,
      to: PAYEE,
      value: 20_000n,
      validAfter: 0n,
      validBefore: now + 300n,
      nonce: `0x${"11".repeat(32)}`,
      ...o.message,
    },
  });
  it("preauthorizes the exact payment, then returns the 97-byte policy signature", async () => {
    const { p, sent } = policy();
    const record: PolicyCallRecord = { ceiling: 20_000n, registered: [], unknown: false };
    const sig = await p.signerFor(record).signTypedData(typed());
    expect(sig).toBe(x402PolicySignature(POLICY));
    expect(sent).toHaveLength(1);
    expect(sent[0]?.to).toBe(POLICY);
    expect(record.registered).toHaveLength(1);
    // A re-sign for a new quote (a different, quote-bound nonce) withdraws the first one
    // before registering, so at most one of them can ever settle.
    await p
      .signerFor(record)
      .signTypedData(
        typed({ message: { validBefore: now + 400n, nonce: `0x${"22".repeat(32)}` } }),
      );
    expect(sent).toHaveLength(3);
    expect(sent[1]?.data.slice(0, 10)).toBe(
      encodeCancelPreauthorization({
        from: TBA,
        to: PAYEE,
        value: 1n,
        validAfter: 0n,
        validBefore: 1n,
        nonce: `0x${"11".repeat(32)}`,
      }).slice(0, 10),
    );
    expect(record.registered).toHaveLength(1);
    expect(record.registered[0]?.nonce).toBe(`0x${"22".repeat(32)}`);
  });
  it("never signs again after a preauthorize with an unknown outcome", async () => {
    const { p, chain, sent } = policy();
    chain.send = async (tx) => {
      sent.push(tx);
      throw Object.assign(new Error("timeout"), { hash: `0x${"bb".repeat(32)}` });
    };
    const record: PolicyCallRecord = { ceiling: 20_000n, registered: [], unknown: false };
    await expect(p.signerFor(record).signTypedData(typed())).rejects.toMatchObject({
      code: "send_unknown",
    });
    expect(record).toMatchObject({ unknown: true, uncertain: [expect.anything()] });
    await expect(
      p.signerFor(record).signTypedData(typed({ message: { nonce: `0x${"33".repeat(32)}` } })),
    ).rejects.toMatchObject({ code: "send_unknown" });
    expect(sent).toHaveLength(1);
  });
  it("refuses anything else unsigned, with nothing sent", async () => {
    for (const [t, code] of [
      [typed({ domain: { name: "USD Coin" } }), "not_usdc_authorization"],
      [typed({ domain: { version: "1" } }), "not_usdc_authorization"],
      [typed({ domain: { chainId: 1 } }), "not_usdc_authorization"],
      [typed({ domain: { verifyingContract: PAYEE } }), "not_usdc_authorization"],
      [typed({ primaryType: "Permit" }), "not_usdc_authorization"],
      [typed({ message: { from: OWNER } }), "wrong_payer"],
      // A 402 naming another allowlisted counterparty (e.g. the ACP escrow) is refused.
      [typed({ message: { to: OWNER } }), "wrong_payee"],
      [typed({ message: { value: 20_001n } }), "above_ceiling"],
      [typed({ message: { value: 0n } }), "above_ceiling"],
      [typed({ message: { validBefore: now + 7200n } }), "bad_window"],
      [typed({ message: { validAfter: now + 60n } }), "bad_window"],
      [typed({ message: { validBefore: now - 1n } }), "bad_window"],
    ] as const) {
      const { p, sent } = policy();
      const err = await p
        .signerFor({ ceiling: 20_000n, registered: [], unknown: false })
        .signTypedData(t)
        .catch((e) => e);
      expect(err).toBeInstanceOf(PolicyError);
      expect(err.code).toBe(code);
      expect(sent).toEqual([]);
    }
    // USDC's on-chain domain differs from the one signed: refused before any send.
    const { p, sent } = policy({ digest: () => `0x${"ee".repeat(32)}` });
    await expect(
      p.signerFor({ ceiling: 20_000n, registered: [], unknown: false }).signTypedData(typed()),
    ).rejects.toMatchObject({ code: "domain_mismatch" });
    expect(sent).toEqual([]);
  });
});

describe("ACP through the policy", () => {
  const ACP = "0xacacacacacacacacacacacacacacacacacacacac";
  const tba = TBA.toLowerCase() as `0x${string}`;
  const built: { action: string; body: Record<string, unknown> }[] = [];
  const executed: { target: string; data: Hex }[][] = [];
  const route: PolicyRoute = {
    tba: TBA,
    execute: async (calls) => {
      executed.push(calls);
      return { transactionHash: `0x${"bb".repeat(32)}`, status: "success", logs: [] };
    },
  };
  const ctx = (): AcpToolContext => ({
    base: "https://tolly.example",
    info: {
      address: ACP,
      chainId: 5042,
      network: "eip155:5042",
      token: USDC,
      platformBp: 1000,
      evaluatorBp: 0,
    },
    account: hot,
    pinned: true,
    network: "eip155:5042",
    rpcUrl: undefined,
    maxPerCall: 5_000_000n,
    getJson: async (url, init) => {
      const u = new URL(url);
      if (u.pathname.startsWith("/v1/acp/tx/")) {
        const action = u.pathname.split("/").pop() as string;
        const body = JSON.parse(String(init?.body ?? "{}"));
        built.push({ action, body });
        const id = BigInt(String(body.jobId ?? "0"));
        const data =
          action === "approve"
            ? encodeFunctionData({
                abi: erc20Abi,
                functionName: "approve",
                args: [ACP, 1_500_000n],
              })
            : action === "fund"
              ? (await import("../src/tolly-acp.ts")).encodeFund(id, 1_500_000n)
              : "0x";
        return {
          ok: true,
          status: 200,
          headers: new Headers(),
          body: JSON.stringify({
            to: action === "approve" ? USDC : ACP,
            data,
            value: "0",
            chainId: 5042,
          }),
        };
      }
      return {
        ok: true,
        status: 200,
        headers: new Headers(),
        body: JSON.stringify({
          job: { id: "4", client: tba, budgetAtomic: "1500000", status: "Open" },
        }),
      };
    },
    signIn: async () => "t",
    reserve: (atomic) => ({ key: "k", atomic }),
    release: () => {},
    overBudget: () => ({ content: [{ type: "text", text: "over" }], isError: true }),
    settle: () => ({}),
    text: (v, isError = false) => ({
      content: [{ type: "text", text: JSON.stringify(v) }],
      isError,
    }),
    clients: {
      pub: {
        getChainId: async () => 5042,
        getCode: async () => "0x6080",
        readContract: async () => USDC,
      } as never,
      send: async () => {
        throw new Error("the hot key must not send client actions of the agent wallet's jobs");
      },
    },
    policyRoute: async () => route,
  });
  const out = (r: { content: { text: string }[] }) => JSON.parse(r.content[0]?.text ?? "{}");

  it("needs a named evaluator and a 30-day expiry for the agent wallet's jobs", async () => {
    expect(out(await callAcpTool(ctx(), "tolly_acp_create", { description: "x" })).message).toMatch(
      /name an evaluator/,
    );
    expect(
      out(
        await callAcpTool(ctx(), "tolly_acp_create", {
          description: "x",
          evaluator: PAYEE,
          expiresInHours: 721,
        }),
      ).message,
    ).toMatch(/720/);
  });

  it("funds from the agent's wallet: approve + fund in one policy batch, built for the TBA", async () => {
    const r = await callAcpTool(ctx(), "tolly_acp_fund", { jobId: "4", expectBudgetUsd: 1.5 });
    expect(r.isError).toBe(false);
    expect(out(r)).toMatchObject({ status: "sent", funded_from: "agent_wallet", charged: true });
    expect(built.map((b) => [b.action, b.body.from])).toEqual([
      ["fund", tba],
      ["approve", tba],
    ]);
    const batch = executed.at(-1) ?? [];
    expect(batch.map((c) => c.target)).toEqual([USDC, ACP]);
    expect(batch[0]?.data).toBe(
      encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [ACP, 1_500_000n] }),
    );
  });
});
