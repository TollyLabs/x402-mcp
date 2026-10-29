// Typed helpers for TollyACP, TOLLY's ERC-8183 job escrow contract.
// Everything here builds or reads data only: calldata for the caller to sign and send, and
// decoded events. Nothing signs or sends a transaction.
import {
  type Address,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  type Hex,
  type Log,
  parseEventLogs,
  toFunctionSelector,
} from "viem";
import { tollyAcpAbi } from "./abi/acp.js";

export { acpHookAbi, tollyAcpAbi } from "./abi/acp.js";

/** Mirrors `TollyACP.JobStatus` (uint8 on chain). */
export const JobStatus = {
  Open: 0,
  Funded: 1,
  Submitted: 2,
  Completed: 3,
  Rejected: 4,
  Expired: 5,
} as const;
export type JobStatusName = keyof typeof JobStatus;
export type JobStatusCode = (typeof JobStatus)[JobStatusName];

const STATUS_NAMES = Object.keys(JobStatus) as JobStatusName[];

export function jobStatusName(code: number): JobStatusName {
  const name = STATUS_NAMES[code];
  if (name === undefined) throw new Error(`unknown ACP job status ${code}`);
  return name;
}

export const ACP_LIMITS = {
  bpDenominator: 10_000n,
  maxPlatformFeeBp: 1_000n,
  maxEvaluatorFeeBp: 1_000n,
  minExpirySeconds: 5n * 60n,
  maxExpirySeconds: 365n * 24n * 60n * 60n,
  maxDescriptionBytes: 4_096,
  maxBudget: (1n << 128n) - 1n,
} as const;

/** Selectors the contract passes to hooks (ERC-8183 `beforeAction`/`afterAction`). */
export const ACP_SELECTORS = {
  setProvider: toFunctionSelector("setProvider(uint256,address,bytes)"),
  setBudget: toFunctionSelector("setBudget(uint256,uint256,bytes)"),
  fund: toFunctionSelector("fund(uint256,uint256,bytes)"),
  submit: toFunctionSelector("submit(uint256,bytes32,bytes)"),
  complete: toFunctionSelector("complete(uint256,bytes32,bytes)"),
  reject: toFunctionSelector("reject(uint256,bytes32,bytes)"),
} as const;
export type HookedAction = keyof typeof ACP_SELECTORS;

const ZERO: Address = "0x0000000000000000000000000000000000000000";
const ZERO32: Hex = `0x${"0".repeat(64)}`;

/** An unsigned call to TollyACP: the caller's wallet signs and sends it. */
export interface AcpCall {
  to: Address;
  data: Hex;
}

export interface CreateJobArgs {
  /** Omit to assign later with setProvider. */
  provider?: Address;
  evaluator: Address;
  /** Unix seconds; 5 minutes to 365 days from the block that includes the call. */
  expiredAt: bigint;
  description: string;
  /** Omit for no hook; otherwise an allowlisted ERC-8183 hook. */
  hook?: Address;
}

export function encodeCreateJob(a: CreateJobArgs): Hex {
  const bytes = new TextEncoder().encode(a.description).length;
  if (bytes > ACP_LIMITS.maxDescriptionBytes) {
    throw new Error(`description is ${bytes} bytes, at most ${ACP_LIMITS.maxDescriptionBytes}`);
  }
  return encodeFunctionData({
    abi: tollyAcpAbi,
    functionName: "createJob",
    args: [a.provider ?? ZERO, a.evaluator, a.expiredAt, a.description, a.hook ?? ZERO],
  });
}

export function encodeSetProvider(jobId: bigint, provider: Address, optParams: Hex = "0x"): Hex {
  return encodeFunctionData({
    abi: tollyAcpAbi,
    functionName: "setProvider",
    args: [jobId, provider, optParams],
  });
}

export function encodeSetBudget(jobId: bigint, amount: bigint, optParams: Hex = "0x"): Hex {
  if (amount < 0n || amount > ACP_LIMITS.maxBudget) throw new Error("budget out of range");
  return encodeFunctionData({
    abi: tollyAcpAbi,
    functionName: "setBudget",
    args: [jobId, amount, optParams],
  });
}

/**
 * `expectedBudget` must equal the job's budget as the client read it: the contract refuses the
 * call if the budget changed in between (front-running guard). The client must have approved
 * TollyACP for at least that amount of the payment token.
 */
export function encodeFund(jobId: bigint, expectedBudget: bigint, optParams: Hex = "0x"): Hex {
  return encodeFunctionData({
    abi: tollyAcpAbi,
    functionName: "fund",
    args: [jobId, expectedBudget, optParams],
  });
}

export function encodeSubmit(jobId: bigint, deliverable: Hex, optParams: Hex = "0x"): Hex {
  return encodeFunctionData({
    abi: tollyAcpAbi,
    functionName: "submit",
    args: [jobId, asBytes32(deliverable, "deliverable"), optParams],
  });
}

export function encodeComplete(jobId: bigint, reason: Hex = ZERO32, optParams: Hex = "0x"): Hex {
  return encodeFunctionData({
    abi: tollyAcpAbi,
    functionName: "complete",
    args: [jobId, asBytes32(reason, "reason"), optParams],
  });
}

export function encodeReject(jobId: bigint, reason: Hex = ZERO32, optParams: Hex = "0x"): Hex {
  return encodeFunctionData({
    abi: tollyAcpAbi,
    functionName: "reject",
    args: [jobId, asBytes32(reason, "reason"), optParams],
  });
}

export function encodeClaimRefund(jobId: bigint): Hex {
  return encodeFunctionData({ abi: tollyAcpAbi, functionName: "claimRefund", args: [jobId] });
}

/** Wraps calldata into an unsigned call to a TollyACP deployment. */
export function acpCall(acp: Address, data: Hex): AcpCall {
  return { to: acp, data };
}

function asBytes32(v: Hex, what: string): Hex {
  if (!/^0x[0-9a-fA-F]{64}$/.test(v)) throw new Error(`${what} must be 32 bytes (0x + 64 hex)`);
  return v;
}

// ──────────────────── fees ────────────────────

export interface CompletionSplit {
  platformFee: bigint;
  evaluatorFee: bigint;
  providerNet: bigint;
}

/** The contract's split on completion: fees round down, the provider gets the remainder. */
export function splitCompletion(
  budget: bigint,
  platformFeeBp: bigint,
  evaluatorFeeBp: bigint,
): CompletionSplit {
  if (platformFeeBp < 0n || platformFeeBp > ACP_LIMITS.maxPlatformFeeBp) {
    throw new Error("platform fee out of range");
  }
  if (evaluatorFeeBp < 0n || evaluatorFeeBp > ACP_LIMITS.maxEvaluatorFeeBp) {
    throw new Error("evaluator fee out of range");
  }
  const platformFee = (budget * platformFeeBp) / ACP_LIMITS.bpDenominator;
  const evaluatorFee = (budget * evaluatorFeeBp) / ACP_LIMITS.bpDenominator;
  return { platformFee, evaluatorFee, providerNet: budget - platformFee - evaluatorFee };
}

// ──────────────────── hook data (ERC-8183 encodings) ────────────────────

export type HookData =
  | { action: "setProvider"; provider: Address; optParams: Hex }
  | { action: "setBudget"; amount: bigint; optParams: Hex }
  | { action: "fund"; optParams: Hex }
  | { action: "submit"; deliverable: Hex; optParams: Hex }
  | { action: "complete"; reason: Hex; optParams: Hex }
  | { action: "reject"; reason: Hex; optParams: Hex };

/** Decodes the `data` a hook receives for `selector`; null for a selector TollyACP never hooks. */
export function decodeHookData(selector: Hex, data: Hex): HookData | null {
  const s = selector.toLowerCase();
  if (s === ACP_SELECTORS.fund) return { action: "fund", optParams: data };
  if (s === ACP_SELECTORS.setProvider) {
    const [provider, optParams] = decodeAbiParameters(
      [{ type: "address" }, { type: "bytes" }],
      data,
    );
    return { action: "setProvider", provider, optParams };
  }
  if (s === ACP_SELECTORS.setBudget) {
    const [amount, optParams] = decodeAbiParameters([{ type: "uint256" }, { type: "bytes" }], data);
    return { action: "setBudget", amount, optParams };
  }
  const withB32 = (): [Hex, Hex] => {
    const [b, o] = decodeAbiParameters([{ type: "bytes32" }, { type: "bytes" }], data);
    return [b, o];
  };
  if (s === ACP_SELECTORS.submit) {
    const [deliverable, optParams] = withB32();
    return { action: "submit", deliverable, optParams };
  }
  if (s === ACP_SELECTORS.complete) {
    const [reason, optParams] = withB32();
    return { action: "complete", reason, optParams };
  }
  if (s === ACP_SELECTORS.reject) {
    const [reason, optParams] = withB32();
    return { action: "reject", reason, optParams };
  }
  return null;
}

/** Encodes hook `data` the way TollyACP does (for hook tests and simulations). */
export function encodeHookData(d: HookData): Hex {
  switch (d.action) {
    case "fund":
      return d.optParams;
    case "setProvider":
      return encodeAbiParameters(
        [{ type: "address" }, { type: "bytes" }],
        [d.provider, d.optParams],
      );
    case "setBudget":
      return encodeAbiParameters([{ type: "uint256" }, { type: "bytes" }], [d.amount, d.optParams]);
    case "submit":
      return encodeAbiParameters(
        [{ type: "bytes32" }, { type: "bytes" }],
        [d.deliverable, d.optParams],
      );
    case "complete":
    case "reject":
      return encodeAbiParameters([{ type: "bytes32" }, { type: "bytes" }], [d.reason, d.optParams]);
  }
}

// ──────────────────── events ────────────────────

/** Decodes events emitted by the specified TollyACP deployment; other addresses are ignored. */
export function decodeAcpLogs(logs: readonly Log[], acp: Address) {
  const own = logs.filter((l) => l.address.toLowerCase() === acp.toLowerCase());
  return parseEventLogs({ abi: tollyAcpAbi, logs: own as Log[] });
}
export type AcpEvent = ReturnType<typeof decodeAcpLogs>[number];

/** Every job id a receipt created on that deployment, in log order (a batched or multicall
 *  transaction can create several). */
export function createdJobIds(logs: readonly Log[], acp: Address): bigint[] {
  return decodeAcpLogs(logs, acp).flatMap((e) =>
    e.eventName === "JobCreated" ? [e.args.jobId] : [],
  );
}

/** The job id a single createJob receipt produced, from that deployment only. Throws when the
 *  receipt created no job or more than one (use createdJobIds for batches). */
export function createdJobId(logs: readonly Log[], acp: Address): bigint {
  const ids = createdJobIds(logs, acp);
  if (ids.length === 0) throw new Error("no JobCreated event in these logs");
  if (ids.length > 1) throw new Error("several JobCreated events in these logs; use createdJobIds");
  return ids[0] as bigint;
}

// ──────────────────── ERC-8004 reputation mapping ────────────────────

export type ReputationSignal = "positive" | "negative" | "neutral";

export interface OutcomeSignal {
  jobId: bigint;
  provider: Address;
  client: Address;
  evaluator: Address;
  outcome: "completed" | "rejected" | "expired";
  /** The status the job left: "Submitted" means the provider delivered work. */
  prevStatus: JobStatusName;
  /** Signal for the provider's ERC-8004 identity. */
  providerSignal: ReputationSignal;
  /** True when the evaluator is the client (no third-party attestation). */
  selfEvaluated: boolean;
  /** The evaluator's attestation commitment (bytes32), zero when none. */
  reason: Hex;
  paidToProvider: bigint;
  refundedToClient: bigint;
}

/**
 * Maps a JobOutcome event to the trust signal TOLLY's indexer records against the provider
 * (docs/os/TOLLY_OS.md, "ERC-8004 reputation"): completed = positive; rejected after the provider
 * submitted work = negative; anything the provider never acted on (rejected while Open or
 * Funded, or expired) = neutral, because any client can name any provider and have a friendly
 * evaluator reject (final review M-1). Outcomes without a provider are skipped (null).
 * Self-evaluated jobs are flagged so reputation can weigh them lower.
 */
export function outcomeSignal(ev: AcpEvent): OutcomeSignal | null {
  if (ev.eventName !== "JobOutcome") return null;
  const a = ev.args;
  const name = jobStatusName(a.status);
  const outcome =
    name === "Completed"
      ? "completed"
      : name === "Rejected"
        ? "rejected"
        : name === "Expired"
          ? "expired"
          : null;
  if (!outcome) return null;
  if (/^0x0{40}$/i.test(a.provider)) return null;
  const prevStatus = jobStatusName(a.prevStatus);
  const providerSignal: ReputationSignal =
    outcome === "completed"
      ? "positive"
      : outcome === "rejected" && prevStatus === "Submitted"
        ? "negative"
        : "neutral";
  return {
    jobId: a.jobId,
    provider: a.provider,
    client: a.client,
    evaluator: a.evaluator,
    outcome,
    prevStatus,
    providerSignal,
    selfEvaluated: a.evaluator.toLowerCase() === a.client.toLowerCase(),
    reason: a.reason,
    paidToProvider: a.paidToProvider,
    refundedToClient: a.refundedToClient,
  };
}
