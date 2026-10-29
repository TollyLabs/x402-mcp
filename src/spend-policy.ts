// Typed helpers for AgentSpendPolicy (TOLLY's contract): on-chain spending rules
// for an agent's hot key on its Tokenbound V3 account (TBA). Design and threat model:
// docs/os/AGENT_SPEND_POLICY.md. Everything here builds or reads data: calldata for a wallet to
// sign and send, typed data and digests, the x402 contract signature, readable errors and a
// status summary. Nothing here signs or sends a transaction.
//
// The policy is a singleton the NFT owner grants Tokenbound permission on the TBA. That grant
// makes it a full executor of the account, so every caller of this package must pin the policy
// address (and, where it can, its runtime code hash) and check it on chain before building
// setPermissions: see verifySpendPolicyDeployment.
import {
  type Address,
  BaseError,
  ContractFunctionRevertedError,
  concat,
  decodeErrorResult,
  decodeFunctionData,
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  type Hex,
  hashTypedData,
  isAddress,
  keccak256,
  type PublicClient,
  pad,
  parseAbi,
  toFunctionSelector,
  toHex,
} from "viem";
import { agentSpendPolicyAbi } from "./abi/spend-policy.js";

export { agentSpendPolicyAbi } from "./abi/spend-policy.js";

/** Arc USDC through its ERC-20 interface (6 decimals), the only token the policy budgets. */
export const ARC_USDC: Address = "0x3600000000000000000000000000000000000000";
/** The EIP-712 domain of Arc USDC (FiatToken v2.2): name "USDC", version "2". */
export const USDC_DOMAIN = { name: "USDC", version: "2" } as const;
/** The default preset (configureDefault) on TOLLY's deployment: 2 USDC per payment, 10 per day. */
export const DEFAULT_PER_TX_CAP = 2_000_000n;
export const DEFAULT_DAILY_CAP = 10_000_000n;
/** The policy refuses a preauthorization whose validBefore is more than this after now. */
export const MAX_AUTH_WINDOW_SECONDS = 3600;
/** The largest cap the site and tools build (USDC atomic units, 6 dp): 1,000 USDC. */
export const MAX_CAP = 1_000_000_000n;
/** List sizes the contract accepts per call. */
export const MAX_LIST_LENGTH = 32;
export const ERC1271_MAGIC: Hex = "0x1626ba7e";
/** The leak bound in plain words (the same text on the site, in the gateway and the MCP). */
export const LEAK_BOUND_TEXT =
  "A leaked hot key can spend up to 3 times the daily cap within 24 hours (around 00:00 UTC), and only to the allowed payees and contracts. If the key may be compromised, Revoke (not Pause). Caps of 0 are not a freeze.";

const ZERO: Address = "0x0000000000000000000000000000000000000000";
/** Uniswap's Permit2 (same address on every chain): an allowance to it bypasses the policy. */
export const PERMIT2: Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
/** The ERC-6551 registry and Tokenbound V3 account proxy TOLLY's agent wallets use. */
export const ERC6551_REGISTRY: Address = "0x000000006551c19487814612e58FE06813775758";
export const TOKENBOUND_ACCOUNT_PROXY: Address = "0x55266d75D1a14E4572138116aF39863Ed6596E7F";
export const registryAbi = parseAbi([
  "function account(address implementation, bytes32 salt, uint256 chainId, address tokenContract, uint256 tokenId) view returns (address)",
]);

/** The Tokenbound V3 functions the enable flow and the status read use. */
export const tokenboundAbi = parseAbi([
  "function setPermissions(address[] callers, bool[] permissions)",
  "function permissions(address owner, address caller) view returns (bool)",
  "function owner() view returns (address)",
  "function token() view returns (uint256 chainId, address tokenContract, uint256 tokenId)",
  "function isLocked() view returns (bool)",
  "function execute(address to, uint256 value, bytes data, uint8 operation) payable returns (bytes)",
]);
const erc20Abi = parseAbi([
  "function approve(address spender, uint256 amount) returns (bool)",
  "function transfer(address to, uint256 amount) returns (bool)",
]);

/** ERC-8183 / TollyACP client actions the default preset allows on the ACP address. */
export const ACP_PRESET_SELECTORS = {
  createJob: toFunctionSelector("createJob(address,address,uint256,string,address)"),
  setProvider: toFunctionSelector("setProvider(uint256,address,bytes)"),
  setBudget: toFunctionSelector("setBudget(uint256,uint256,bytes)"),
  fund: toFunctionSelector("fund(uint256,uint256,bytes)"),
  reject: toFunctionSelector("reject(uint256,bytes32,bytes)"),
  claimRefund: toFunctionSelector("claimRefund(uint256)"),
} as const;
export const USDC_PRESET_SELECTORS = {
  transfer: toFunctionSelector("transfer(address,uint256)"),
  approve: toFunctionSelector("approve(address,uint256)"),
} as const;

// ──────────────────── types ────────────────────

/** `AgentSpendPolicy.Config`, as getConfig returns it. */
export interface PolicyConfig {
  owner: Address;
  expiresAt: number;
  accepted: boolean;
  paused: boolean;
  allowNative: boolean;
  allowPreauth: boolean;
  day: number;
  spentToday: bigint;
  perTxCap: bigint;
  dailyCap: bigint;
}

export interface PolicySettings {
  perTxCap: bigint;
  dailyCap: bigint;
  /** Unix seconds; 0 = no expiry. */
  expiresAt?: number;
  allowNative?: boolean;
  allowPreauth?: boolean;
}

export interface TargetRule {
  target: Address;
  selectors: Hex[];
}

export interface PolicyCall {
  target: Address;
  value?: bigint;
  data: Hex;
}

/** One USDC EIP-3009 TransferWithAuthorization from the TBA (x402's exact scheme). */
export interface Authorization {
  from: Address;
  to: Address;
  value: bigint;
  validAfter: bigint;
  validBefore: bigint;
  nonce: Hex;
}

/** A transaction for a wallet to send: no native value, ever. */
export interface PolicyTx {
  to: Address;
  data: Hex;
}

// ──────────────────── checks ────────────────────

const addr = (a: string, what: string): Address => {
  if (!isAddress(a, { strict: false })) throw new Error(`${what}: not an address`);
  return getAddress(a);
};
const nonZero = (a: string, what: string): Address => {
  const x = addr(a, what);
  if (x === ZERO) throw new Error(`${what}: the zero address`);
  return x;
};

/** Why a pair of caps cannot be set, or null. Atomic USDC (6 dp). */
export function capsProblem(perTxCap: bigint, dailyCap: bigint): string | null {
  if (perTxCap <= 0n || dailyCap <= 0n)
    return "Both caps must be above 0. To stop the key, pause it.";
  if (perTxCap > dailyCap) return "The per-payment cap cannot be above the daily cap.";
  if (dailyCap > MAX_CAP) return "The daily cap is at most 1,000 USDC here.";
  return null;
}

// ──────────────────── owner: enable, edit, turn off ────────────────────

/** TBA.setPermissions([policy], [enabled]): sent by the NFT owner (Tokenbound checks it). */
export function encodeSetPermissions(policy: string, enabled: boolean): Hex {
  return encodeFunctionData({
    abi: tokenboundAbi,
    functionName: "setPermissions",
    args: [[nonZero(policy, "policy")], [enabled]],
  });
}

export function encodeConfigureDefault(tba: string, key: string, acp: string | null): Hex {
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "configureDefault",
    args: [nonZero(tba, "tba"), nonZero(key, "key"), acp ? nonZero(acp, "acp") : ZERO],
  });
}

export function encodeConfigure(
  tba: string,
  key: string,
  s: PolicySettings,
  targets: TargetRule[],
  payees: string[],
): Hex {
  const problem = capsProblem(s.perTxCap, s.dailyCap);
  if (problem) throw new Error(problem);
  if (targets.length > MAX_LIST_LENGTH || payees.length > MAX_LIST_LENGTH)
    throw new Error("at most 32 targets and 32 payees");
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "configure",
    args: [
      nonZero(tba, "tba"),
      nonZero(key, "key"),
      {
        perTxCap: s.perTxCap,
        dailyCap: s.dailyCap,
        expiresAt: s.expiresAt ?? 0,
        allowNative: s.allowNative ?? false,
        allowPreauth: s.allowPreauth ?? true,
      },
      targets.map((t) => ({ target: nonZero(t.target, "target"), selectors: t.selectors })),
      payees.map((p) => nonZero(p, "payee")),
    ],
  });
}

/**
 * The owner's call that sets the TBA's USDC allowance for `spender` to 0: TBA.execute(USDC, 0,
 * approve(spender, 0), 0), a plain CALL sent by the NFT owner.
 */
export function zeroAllowanceCall(tba: string, spender: string, usdc: string = ARC_USDC): PolicyTx {
  return {
    to: nonZero(tba, "tba"),
    data: encodeFunctionData({
      abi: tokenboundAbi,
      functionName: "execute",
      args: [
        nonZero(usdc, "usdc"),
        0n,
        encodeFunctionData({
          abi: erc20Abi,
          functionName: "approve",
          args: [nonZero(spender, "spender"), 0n],
        }),
        0,
      ],
    }),
  };
}

/**
 * The enable flow, in order: the TBA's live USDC allowances to the preset's payees (and to
 * Permit2) set to 0 (`zeroAllowancesOf`, the spenders whose allowance the caller read as
 * non-zero: an allowance would let a payee pull outside the budget, and the policy refuses a
 * payee that holds one), the permission, then the default preset for the hot key. One EIP-5792
 * batch from the owner's wallet when it supports one, else these transactions in this order (the
 * configuration is harmless until the key accepts; the permission is harmless until a
 * configuration exists).
 */
export function enableCalls(p: {
  policy: string;
  tba: string;
  key: string;
  acp: string | null;
  zeroAllowancesOf?: string[];
}): PolicyTx[] {
  const policy = nonZero(p.policy, "policy");
  const tba = nonZero(p.tba, "tba");
  const key = nonZero(p.key, "key");
  if (key === tba || key === policy) throw new Error("the hot key must be a separate wallet");
  const zero = [...new Set((p.zeroAllowancesOf ?? []).map((a) => nonZero(a, "spender")))];
  return [
    ...zero.map((spender) => zeroAllowanceCall(tba, spender)),
    { to: tba, data: encodeSetPermissions(policy, true) },
    { to: policy, data: encodeConfigureDefault(tba, key, p.acp) },
  ];
}

export function encodeSetCaps(tba: string, key: string, perTxCap: bigint, dailyCap: bigint): Hex {
  const problem = capsProblem(perTxCap, dailyCap);
  if (problem) throw new Error(problem);
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "setCaps",
    args: [nonZero(tba, "tba"), nonZero(key, "key"), perTxCap, dailyCap],
  });
}

export function encodeSetExpiry(tba: string, key: string, expiresAt: number): Hex {
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "setExpiry",
    args: [nonZero(tba, "tba"), nonZero(key, "key"), expiresAt],
  });
}

export function encodeSetFlags(
  tba: string,
  key: string,
  allowNative: boolean,
  allowPreauth: boolean,
): Hex {
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "setFlags",
    args: [nonZero(tba, "tba"), nonZero(key, "key"), allowNative, allowPreauth],
  });
}

export function encodeSetPayees(tba: string, key: string, payees: string[], allowed: boolean): Hex {
  if (payees.length === 0 || payees.length > MAX_LIST_LENGTH)
    throw new Error("between 1 and 32 payees");
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "setPayees",
    args: [
      nonZero(tba, "tba"),
      nonZero(key, "key"),
      payees.map((p) => nonZero(p, "payee")),
      allowed,
    ],
  });
}

export function encodeSetSelectors(
  tba: string,
  key: string,
  target: string,
  selectors: Hex[],
  allowed: boolean,
): Hex {
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "setSelectors",
    args: [nonZero(tba, "tba"), nonZero(key, "key"), nonZero(target, "target"), selectors, allowed],
  });
}

type OwnerAction = "pause" | "unpause" | "revoke" | "clearStale";
export function encodeOwnerAction(action: OwnerAction, tba: string, key: string): Hex {
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: action,
    args: [nonZero(tba, "tba"), nonZero(key, "key")],
  });
}

// ──────────────────── hot key: accept, spend ────────────────────

export function encodeAcceptKey(tba: string): Hex {
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "acceptKey",
    args: [nonZero(tba, "tba")],
  });
}

export function encodeExecute(tba: string, call: PolicyCall): Hex {
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "execute",
    args: [nonZero(tba, "tba"), nonZero(call.target, "target"), call.value ?? 0n, call.data],
  });
}

export function encodeExecuteBatch(tba: string, calls: PolicyCall[]): Hex {
  if (calls.length === 0 || calls.length > MAX_LIST_LENGTH)
    throw new Error("between 1 and 32 calls");
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "executeBatch",
    args: [
      nonZero(tba, "tba"),
      calls.map((c) => ({
        target: nonZero(c.target, "target"),
        value: c.value ?? 0n,
        data: c.data,
      })),
    ],
  });
}

const authArgs = (a: Authorization) =>
  [
    nonZero(a.from, "from"),
    nonZero(a.to, "to"),
    a.value,
    a.validAfter,
    a.validBefore,
    a.nonce,
  ] as const;

export function encodePreauthorize(a: Authorization): Hex {
  if (a.value <= 0n) throw new Error("the amount must be above 0");
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "preauthorize",
    args: authArgs(a),
  });
}

export function encodeCancelPreauthorization(a: Authorization): Hex {
  return encodeFunctionData({
    abi: agentSpendPolicyAbi,
    functionName: "cancelPreauthorization",
    args: authArgs(a),
  });
}

/** USDC.approve(spender, amount) and USDC.transfer(to, amount), as policy calls. */
export const usdcApproveCall = (spender: string, amount: bigint): PolicyCall => ({
  target: ARC_USDC,
  data: encodeFunctionData({
    abi: erc20Abi,
    functionName: "approve",
    args: [nonZero(spender, "spender"), amount],
  }),
});
export const usdcTransferCall = (to: string, amount: bigint): PolicyCall => ({
  target: ARC_USDC,
  data: encodeFunctionData({
    abi: erc20Abi,
    functionName: "transfer",
    args: [nonZero(to, "to"), amount],
  }),
});

/** Decodes a call to the policy (to check a transaction before signing it). */
export function decodePolicyCall(data: Hex) {
  return decodeFunctionData({ abi: agentSpendPolicyAbi, data });
}

/** Decodes a call to a Tokenbound account (setPermissions, execute). */
export function decodeTokenboundCall(data: Hex) {
  return decodeFunctionData({ abi: tokenboundAbi, data });
}

// ──────────────────── x402: the digest and the contract signature ────────────────────

/** The EIP-712 typed data of a USDC TransferWithAuthorization on Arc (or a test chain). */
export function transferWithAuthorizationTypedData(
  chainId: number,
  a: Authorization,
  usdc = ARC_USDC,
) {
  return {
    domain: {
      name: USDC_DOMAIN.name,
      version: USDC_DOMAIN.version,
      chainId,
      verifyingContract: getAddress(usdc),
    },
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" },
        { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "TransferWithAuthorization",
    message: {
      from: getAddress(a.from),
      to: getAddress(a.to),
      value: a.value,
      validAfter: a.validAfter,
      validBefore: a.validBefore,
      nonce: a.nonce,
    },
  } as const;
}

/** The digest USDC asks the TBA to validate (= policy.authorizationDigest on that chain). */
export function authorizationDigest(chainId: number, a: Authorization, usdc = ARC_USDC): Hex {
  return hashTypedData(transferWithAuthorizationTypedData(chainId, a, usdc));
}

/**
 * The Tokenbound V3 contract signature that names the policy as signer: r = policy, s = 65 (the
 * offset of the inner signature), v = 0, then one zero word as the inner signature. 97 bytes, so
 * @x402/evm sends it verbatim through USDC's `bytes` overload of transferWithAuthorization (a
 * 65-byte signature would go through (v, r, s) and depend on nobody normalising v = 0).
 */
export function x402PolicySignature(policy: string): Hex {
  return concat([
    pad(nonZero(policy, "policy"), { size: 32 }),
    toHex(65n, { size: 32 }),
    "0x00",
    pad("0x", { size: 32 }),
  ]);
}

/** True when `sig` is exactly the 97-byte policy signature for `policy`. */
export function isX402PolicySignature(sig: string, policy: string): boolean {
  return (
    /^0x[0-9a-fA-F]{194}$/.test(sig) &&
    sig.toLowerCase() === x402PolicySignature(policy).toLowerCase()
  );
}

/** A random EIP-3009 nonce (32 bytes). */
export function randomAuthorizationNonce(): Hex {
  const b = new Uint8Array(32);
  globalThis.crypto.getRandomValues(b);
  return toHex(b);
}

// ──────────────────── status ────────────────────

export type PolicyStatusName =
  | "not_configured"
  | "owner_changed"
  | "not_permitted"
  | "locked"
  | "awaiting_accept"
  | "paused"
  | "expired"
  | "active";

/**
 * One word for the state of (TBA, hot key), from what was read on chain. Ordered so the first
 * reason it cannot spend is the one shown.
 */
export function policyStatus(s: {
  config: PolicyConfig;
  currentOwner: Address | null;
  permitted: boolean;
  locked: boolean;
  now: number;
}): PolicyStatusName {
  const c = s.config;
  if (c.owner === ZERO) return "not_configured";
  if (!s.currentOwner || getAddress(c.owner) !== getAddress(s.currentOwner)) return "owner_changed";
  if (!s.permitted) return "not_permitted";
  if (s.locked) return "locked";
  if (!c.accepted) return "awaiting_accept";
  if (c.paused) return "paused";
  if (c.expiresAt !== 0 && s.now >= c.expiresAt) return "expired";
  return "active";
}

export const STATUS_TEXT: Record<PolicyStatusName, string> = {
  not_configured: "Not enabled for this hot key.",
  owner_changed:
    "Written by a previous owner of the agent NFT: it does nothing now. The new owner enables it again.",
  not_permitted:
    "Configured, but the agent's wallet does not let the policy act for it (setPermissions is off).",
  locked: "The agent's wallet is locked by its owner: nothing can be spent.",
  awaiting_accept: "Configured. The agent's hot key still has to accept it (tolly_policy_accept).",
  paused: "Paused by the owner: the hot key cannot spend.",
  expired: "Expired: the hot key cannot spend.",
  active: "Active: the hot key spends from the agent's wallet within these rules.",
};

/** USDC (6 dp) still spendable today under the daily cap (the contract's remainingToday). */
export function remainingToday(c: PolicyConfig, nowSec: number): bigint {
  const today = Math.floor(nowSec / 86_400);
  const spent = c.day === today ? c.spentToday : 0n;
  return spent >= c.dailyCap ? 0n : c.dailyCap - spent;
}

export interface PolicyState {
  policy: Address;
  tba: Address;
  key: Address;
  status: PolicyStatusName;
  config: PolicyConfig;
  /** Today's spend counted under the daily cap (0 after 00:00 UTC). */
  spentToday: bigint;
  remainingToday: bigint;
  currentOwner: Address | null;
  permitted: boolean;
  locked: boolean;
  /** Payees checked by isPayee: the ones the caller asked about. */
  payees: { address: Address; allowed: boolean }[];
  generation: bigint;
}

type Reader = Pick<PublicClient, "readContract">;

/**
 * Everything the status needs, read on chain in one go. `payees` are checked with isPayee (the
 * contract keeps no list of them). A TBA whose owner() cannot be read counts as ownerless.
 */
export async function readPolicyState(
  client: Reader,
  p: { policy: string; tba: string; key: string; payees?: string[]; now?: number },
): Promise<PolicyState> {
  const policy = nonZero(p.policy, "policy");
  const tba = nonZero(p.tba, "tba");
  const key = nonZero(p.key, "key");
  const now = p.now ?? Math.floor(Date.now() / 1000);
  const ownerOf = async (): Promise<Address | null> => {
    try {
      const o = (await client.readContract({
        address: tba,
        abi: tokenboundAbi,
        functionName: "owner",
      })) as Address;
      return o === ZERO ? null : getAddress(o);
    } catch {
      return null;
    }
  };
  const [raw, currentOwner, locked, generation] = await Promise.all([
    client.readContract({
      address: policy,
      abi: agentSpendPolicyAbi,
      functionName: "getConfig",
      args: [tba, key],
    }) as Promise<PolicyConfig>,
    ownerOf(),
    (
      client.readContract({
        address: tba,
        abi: tokenboundAbi,
        functionName: "isLocked",
      }) as Promise<boolean>
    ).catch(() => true),
    client.readContract({
      address: policy,
      abi: agentSpendPolicyAbi,
      functionName: "generation",
      args: [tba, key],
    }) as Promise<bigint>,
  ]);
  const config: PolicyConfig = {
    owner: getAddress(raw.owner),
    expiresAt: Number(raw.expiresAt),
    accepted: raw.accepted,
    paused: raw.paused,
    allowNative: raw.allowNative,
    allowPreauth: raw.allowPreauth,
    day: Number(raw.day),
    spentToday: BigInt(raw.spentToday),
    perTxCap: BigInt(raw.perTxCap),
    dailyCap: BigInt(raw.dailyCap),
  };
  const permitted = currentOwner
    ? ((await client.readContract({
        address: tba,
        abi: tokenboundAbi,
        functionName: "permissions",
        args: [currentOwner, policy],
      })) as boolean)
    : false;
  const payees = await Promise.all(
    [...new Set((p.payees ?? []).map((a) => nonZero(a, "payee")))].map(async (a) => ({
      address: a,
      allowed: (await client.readContract({
        address: policy,
        abi: agentSpendPolicyAbi,
        functionName: "isPayee",
        args: [tba, key, a],
      })) as boolean,
    })),
  );
  const left = remainingToday(config, now);
  return {
    policy,
    tba,
    key,
    status: policyStatus({ config, currentOwner, permitted, locked, now }),
    config,
    spentToday: config.day === Math.floor(now / 86_400) ? config.spentToday : 0n,
    remainingToday: left,
    currentOwner,
    permitted,
    locked,
    payees,
    generation,
  };
}

// ──────────────────── errors ────────────────────

const usd = (a: bigint) =>
  `${a / 1_000_000n}.${(a % 1_000_000n)
    .toString()
    .padStart(6, "0")
    .replace(/0{1,4}$/, "")}`;

/** A readable sentence for a policy custom error (name and args as viem decodes them). */
export function policyErrorText(name: string, args: readonly unknown[] = []): string {
  const a0 = args[0];
  const a1 = args[1];
  switch (name) {
    case "DailyCapExceeded":
      return `This would bring today's spend to ${usd(BigInt(a0 as bigint))} USDC, above the daily cap of ${usd(BigInt(a1 as bigint))} USDC. The cap resets at 00:00 UTC; the owner can raise it.`;
    case "PerTxCapExceeded":
      return `${usd(BigInt(a0 as bigint))} USDC is above the per-payment cap of ${usd(BigInt(a1 as bigint))} USDC. The owner can raise it.`;
    case "PayeeNotAllowed":
      return `${String(a0)} is not an allowed payee in the agent's spending rules. The owner adds it on the Spending rules panel.`;
    case "SelectorNotAllowed":
      return `The spending rules do not allow this call on ${String(a0)} (${String(a1)}).`;
    case "KeyNotAccepted":
      return "The hot key has not accepted the spending rules yet (tolly_policy_accept).";
    case "PolicyPaused":
      return "The owner paused the agent's spending rules.";
    case "PolicyExpired":
      return "The agent's spending rules expired.";
    case "OwnerChanged":
      return "The agent NFT changed hands: the rules written by the previous owner do nothing now.";
    case "NotConfigured":
      return "No spending rules are set for this hot key on this agent wallet.";
    case "AccountLocked":
      return "The agent's wallet is locked by its owner.";
    case "PreauthNotAllowed":
      return "The spending rules do not allow x402 payments.";
    case "InvalidAuthorizationWindow":
      return "The payment authorization must expire within an hour.";
    case "AuthorizationUsed":
      return "That payment authorization was already used.";
    case "AlreadyPreauthorized":
      return "That payment was already authorized.";
    case "UnknownPreauthorization":
      return "No such payment authorization.";
    case "Unauthorized":
      return "Only the agent NFT's owner (or the agent's wallet itself) can do this.";
    case "NoOwner":
      return "The agent's wallet has no readable owner.";
    case "NestedAccountUnsupported":
      return "The agent NFT is held by another token-bound account; the spending rules do not support that.";
    case "InvalidKey":
      return "That is not a valid hot key.";
    case "InvalidSettings":
      return "Those settings are not valid (an expiry must be in the future).";
    case "AlreadyAccepted":
      return "The hot key already accepted these rules.";
    case "ListTooLong":
      return "Too many entries in one call (at most 32).";
    case "ZeroAddress":
      return "The zero address is not allowed here.";
    case "ForbiddenPayee":
      return `${String(a0)} can never be a payee (USDC sent there is lost).`;
    case "ForbiddenTarget":
      return `${String(a0)} can never be called through the spending rules.`;
    case "UsdcSelectorForbidden":
      return "Only USDC transfer and approve are ever allowed.";
    case "NativeNotAllowed":
      return "The spending rules do not allow native value.";
    case "EmptyCall":
    case "MalformedCalldata":
      return "That call is malformed.";
    case "ZeroValue":
      return "The amount must be above 0.";
    case "AmountTooLarge":
      return "The amount is too large.";
    case "NotStale":
      return "The configuration still belongs to the current owner.";
    default:
      return `The spending policy refused: ${name}.`;
  }
}

/**
 * The policy's reason for a failed call or simulation, as a sentence, or null when the error is
 * not a policy revert (a network error, a revert in another contract without data we know).
 */
export function explainPolicyError(err: unknown): string | null {
  if (err instanceof BaseError) {
    const reverted = err.walk((e) => e instanceof ContractFunctionRevertedError);
    if (reverted instanceof ContractFunctionRevertedError) {
      if (reverted.data?.errorName && reverted.data.abiItem)
        return policyErrorText(reverted.data.errorName, reverted.data.args ?? []);
      if (reverted.raw) return explainRevertData(reverted.raw);
    }
    const withData = err.walk((e) => typeof (e as { data?: unknown }).data === "string") as
      | { data?: unknown }
      | undefined;
    if (typeof withData?.data === "string") return explainRevertData(withData.data as Hex);
  }
  return null;
}

/** Revert data (selector + args) of a policy error, as a sentence; null when unknown. */
export function explainRevertData(data: Hex): string | null {
  try {
    const d = decodeErrorResult({ abi: agentSpendPolicyAbi, data });
    return policyErrorText(d.errorName, (d.args ?? []) as readonly unknown[]);
  } catch {
    return null;
  }
}

// ──────────────────── deployment settings ────────────────────

export interface SpendPolicyDeployment {
  /** Checksummed address of the AgentSpendPolicy singleton. */
  address: Address;
  /** Pinned keccak256 of the runtime code (lower case), or null when not pinned. */
  codehash: Hex | null;
}

const HASH = /^0x[0-9a-fA-F]{64}$/;

/**
 * Reads SPEND_POLICY_ADDRESS (+ optional SPEND_POLICY_CODEHASH). Unset or empty: null, the
 * policy is off and nothing about it runs. Once set, a malformed value throws (fail closed).
 */
export function spendPolicySettingsFromEnv(
  env: Record<string, string | undefined>,
  names = { address: "SPEND_POLICY_ADDRESS", codehash: "SPEND_POLICY_CODEHASH" },
): SpendPolicyDeployment | null {
  const a = env[names.address]?.trim();
  if (!a) return null;
  if (!/^0x[0-9a-fA-F]{40}$/.test(a) || /^0x0{40}$/i.test(a))
    throw new Error(`${names.address} must be a non-zero 0x-prefixed 20-byte address`);
  if (!isAddress(a, { strict: true }))
    throw new Error(`${names.address}: the checksum (upper and lower case letters) does not match`);
  const h = env[names.codehash]?.trim();
  if (h && !HASH.test(h))
    throw new Error(
      `${names.codehash} must be 0x + 64 hex characters (keccak256 of the runtime code)`,
    );
  return { address: getAddress(a), codehash: h ? (h.toLowerCase() as Hex) : null };
}

export interface VerifiedSpendPolicy extends SpendPolicyDeployment {
  /** The observed runtime code hash. */
  observedCodehash: Hex;
  tollyPayee: Address;
  defaultPerTxCap: bigint;
  defaultDailyCap: bigint;
}

/**
 * Boot check, fail closed: code at the address, equal to the pinned hash when one is set, and a
 * policy that budgets the expected USDC. Returns what the policy's immutables say.
 */
export async function verifySpendPolicyDeployment(
  client: Pick<PublicClient, "getCode" | "readContract">,
  d: SpendPolicyDeployment,
  expectedUsdc: string = ARC_USDC,
): Promise<VerifiedSpendPolicy> {
  const code = await client.getCode({ address: d.address });
  if (!code || code === "0x") throw new Error(`no contract code at the spend policy ${d.address}`);
  const observedCodehash = keccak256(code).toLowerCase() as Hex;
  if (d.codehash && observedCodehash !== d.codehash)
    throw new Error(
      `spend policy codehash mismatch at ${d.address}: chain has ${observedCodehash}, pinned ${d.codehash}`,
    );
  const read = (functionName: "usdc" | "tollyPayee" | "defaultPerTxCap" | "defaultDailyCap") =>
    client.readContract({ address: d.address, abi: agentSpendPolicyAbi, functionName });
  const [usdc, tollyPayee, perTx, daily] = await Promise.all([
    read("usdc"),
    read("tollyPayee"),
    read("defaultPerTxCap"),
    read("defaultDailyCap"),
  ]);
  if (String(usdc).toLowerCase() !== expectedUsdc.toLowerCase())
    throw new Error(`the spend policy budgets ${String(usdc)}, not USDC ${expectedUsdc}`);
  return {
    ...d,
    observedCodehash,
    tollyPayee: getAddress(String(tollyPayee)),
    defaultPerTxCap: BigInt(perTx as bigint),
    defaultDailyCap: BigInt(daily as bigint),
  };
}

/** The ABI-encoded constructor arguments (for deploy scripts and tests). */
export function spendPolicyConstructorArgs(p: {
  usdc: string;
  tollyPayee: string;
  defaultDailyCap: bigint;
  defaultPerTxCap: bigint;
}): Hex {
  return encodeAbiParameters(
    [{ type: "address" }, { type: "address" }, { type: "uint128" }, { type: "uint128" }],
    [
      nonZero(p.usdc, "usdc"),
      nonZero(p.tollyPayee, "tollyPayee"),
      p.defaultDailyCap,
      p.defaultPerTxCap,
    ],
  );
}
