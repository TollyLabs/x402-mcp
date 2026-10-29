// Agent wallet spending rules, v1: the allowance float (docs/os/TOLLY_OS.md section 2.2).
//
// The agent's ERC-6551 account (its NFT's wallet, TOLLY_AGENT_WALLET) holds the money. Its owner
// approves this server's key (BUYER_PRIVATE_KEY, the "hot key") for a small USDC allowance on
// that account. When the hot key runs low it pulls a float with USDC.transferFrom(account, hot
// key, x) and keeps paying x402 from its own address, exactly as before. A leaked hot key can
// take at most what it holds plus what the allowance still lets it pull.
//
// Money rules here:
//   - one token only: Arc USDC at 0x3600..., 6 decimals (checked with decimals()), on the chain
//     TOLLY_X402_NETWORK names (checked with eth_chainId before any transaction);
//   - amounts are exact 6-decimal integers; the 18-decimal native balance is read only to tell
//     whether a transaction can pay its gas, and never mixed with the 6-decimal amounts;
//   - on Arc the native gas coin IS USDC: native and ERC-20 USDC are one balance at two
//     precisions. A float spent to zero leaves no gas for the next pull, so payments keep a
//     reserve (TOLLY_FLOAT_RESERVE_USD, default 0.05) and a return keeps it too;
//   - a pull is not spending, but pulls per UTC day are capped at the daily budget in the same
//     ledger file (their own key), so a stuck loop cannot drain the account faster than that;
//   - it only ever pulls to itself and only ever returns to the agent's account, which must be a
//     contract (an ERC-6551 account), so a mistyped TOLLY_AGENT_WALLET cannot swallow a return;
//   - tolly_wallet_status signs a hot key proof (hotKeyProofMessage): the owner pastes it into
//     the agent's Spending panel, which recovers the hot key from it locally and approves only
//     that address, so a lying server cannot swap the spender.
import {
  BaseError,
  createPublicClient,
  createWalletClient,
  encodeFunctionData,
  getAddress,
  HttpRequestError,
  http,
  keccak256,
  parseAbi,
  TimeoutError,
} from "viem";
import type { PrivateKeyAccount } from "viem/accounts";

export const ARC_USDC = "0x3600000000000000000000000000000000000000" as const;
/** Arc mainnet and testnet: the only chains a float is pulled on. */
export const ARC_CHAIN_IDS = new Set([5042, 5042002]);
/** 10^12: one 6-decimal USDC unit in the 18-decimal native balance. */
const NATIVE_PER_ATOMIC = 1_000_000_000_000n;
/** Below this much native USDC (0.001, in 6-decimal units) a pull or return cannot pay its gas. */
const MIN_GAS = 1_000n;
/** The native (18-decimal) balance in 6-decimal units, rounded down: only to compare with MIN_GAS. */
const nativeAsAtomic = (wei: bigint) => wei / NATIVE_PER_ATOMIC;

/**
 * What the hot key signs (EIP-191 personal_sign) to prove it is the hot key of one agent wallet
 * on one chain. TOLLY's Spending panel and gateway rebuild this exact text and recover the
 * signer, so it must not change (the tests pin one test vector shared with them).
 */
export function hotKeyProofMessage(chainId: number, agentWallet: string): string {
  return [
    "TOLLY agent hot key v1",
    `Chain: ${chainId}`,
    `Agent wallet: ${getAddress(agentWallet)}`,
    "The key that signed this message is this agent wallet's hot key. Its owner may approve it for a USDC allowance.",
  ].join("\n");
}

const ERC20 = parseAbi([
  "function decimals() view returns (uint8)",
  "function balanceOf(address) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function transferFrom(address from, address to, uint256 amount) returns (bool)",
]);

/** What the float needs from a chain: reads, and two sends that resolve once mined. */
export interface FloatChain {
  chainId(): Promise<number>;
  decimals(): Promise<number>;
  /** USDC through its ERC-20 interface, 6 decimals. */
  balanceOf(address: string): Promise<bigint>;
  allowance(owner: string, spender: string): Promise<bigint>;
  /** The native (gas) balance, 18 decimals. */
  nativeBalance(address: string): Promise<bigint>;
  /** The code at an address ("0x" or empty for a plain wallet). */
  code(address: string): Promise<string>;
  /** USDC.transferFrom(from, hot key, amount), sent by the hot key; resolves with the mined hash. */
  transferFrom(from: string, amount: bigint): Promise<string>;
  /** USDC.transfer(to, amount), sent by the hot key; resolves with the mined hash. */
  transfer(to: string, amount: bigint): Promise<string>;
}

/** Sent, but whether it was mined is unknown (keep the pull counted; never assume it failed). */
export class SentUnknown extends Error {}

/** A FloatChain over JSON-RPC, signing with the hot key. */
export function rpcChain(rpcUrl: string, account: PrivateKeyAccount, chainId: number): FloatChain {
  const chain = {
    id: chainId,
    name: "Arc",
    nativeCurrency: { name: "USDC", symbol: "USDC", decimals: 18 },
    rpcUrls: { default: { http: [rpcUrl] } },
  } as const;
  const pub = createPublicClient({ chain, transport: http(rpcUrl, { timeout: 15_000 }) });
  const wallet = createWalletClient({
    account,
    chain,
    transport: http(rpcUrl, { timeout: 15_000 }),
  });
  const mined = async (hash: `0x${string}`) => {
    let receipt: Awaited<ReturnType<typeof pub.waitForTransactionReceipt>>;
    try {
      receipt = await pub.waitForTransactionReceipt({ hash, timeout: 60_000 });
    } catch {
      throw new SentUnknown(`transaction ${hash} was sent; its receipt did not arrive in time`);
    }
    if (receipt.status !== "success") throw new Error(`transaction ${hash} reverted`);
    return hash;
  };
  /**
   * Builds, signs and sends a USDC call, then waits. Everything before the raw send (nonce, gas
   * estimate: a revert shows up there) fails plainly: nothing went out. A timeout or transport
   * error on the raw send itself may mean the transaction went out anyway: that is SentUnknown
   * (its pull stays counted), never a plain failure.
   */
  const sent = async (functionName: "transfer" | "transferFrom", args: readonly unknown[]) => {
    const request = await wallet.prepareTransactionRequest({
      account,
      chain,
      to: ARC_USDC,
      data: encodeFunctionData({ abi: ERC20, functionName, args: args as never }),
    });
    const raw = await wallet.signTransaction(request as never);
    const hash = keccak256(raw);
    try {
      await wallet.sendRawTransaction({ serializedTransaction: raw });
    } catch (err) {
      const unknown =
        err instanceof BaseError
          ? err.walk((e) => e instanceof TimeoutError || e instanceof HttpRequestError)
          : null;
      if (unknown)
        throw new SentUnknown(`transaction ${hash} may have gone out; its send timed out`);
      throw err;
    }
    return mined(hash);
  };
  const read = (functionName: "decimals" | "balanceOf" | "allowance", args: string[] = []) =>
    pub.readContract({
      address: ARC_USDC,
      abi: ERC20,
      functionName,
      args: args.map((a) => getAddress(a)) as never,
    });
  return {
    chainId: () => pub.getChainId(),
    decimals: async () => Number(await read("decimals")),
    balanceOf: async (a) => (await read("balanceOf", [a])) as bigint,
    allowance: async (o, s) => (await read("allowance", [o, s])) as bigint,
    nativeBalance: (a) => pub.getBalance({ address: getAddress(a) }),
    code: async (a) => (await pub.getCode({ address: getAddress(a) })) ?? "0x",
    transferFrom: (from, amount) =>
      sent("transferFrom", [getAddress(from), account.address, amount]),
    transfer: (to, amount) => sent("transfer", [getAddress(to), amount]),
  };
}

export interface FloatSettings {
  /** The hot key (this server's buyer wallet). */
  hot: string;
  /** The agent's account the float is pulled from and returned to. */
  wallet: string;
  /** The chain id TOLLY_X402_NETWORK names. */
  chainId: number;
  /** Pull up to this balance (6 decimals). */
  target: bigint;
  /** Pull when the balance is below this (6 decimals). */
  min: bigint;
  /** Never spend or return below this: gas for the next pull or return (6 decimals). */
  reserve: bigint;
  /** Most pulled per UTC day (6 decimals): the daily budget. */
  pullBudget: bigint;
  /** The pulls ledger: today's total pulled, and a reservation that fits the day's cap or null. */
  pulls: {
    today(): bigint;
    reserve(atomic: bigint, budget: bigint): { key: string; atomic: bigint } | null;
    release(r: { key: string; atomic: bigint }): void;
  };
  /** Signs a message with the hot key (EIP-191): the hot key proof for the Spending panel. */
  sign?: (message: string) => Promise<string>;
}

/** What to pull before paying `price`, from balances read just now. Pure, all 6 decimals. */
export function planPull(p: {
  hot: bigint;
  price: bigint;
  allowance: bigint;
  account: bigint;
  pullLeft: bigint;
  target: bigint;
  min: bigint;
  reserve: bigint;
}): { amount: bigint; needed: bigint; enough: boolean } {
  // A payment must leave the reserve behind: the float is also the gas.
  const needed = p.price + p.reserve;
  if (p.hot >= needed && p.hot >= p.min) return { amount: 0n, needed, enough: true };
  const goal = p.target > needed ? p.target : needed;
  let amount = goal - p.hot;
  for (const cap of [p.allowance, p.account, p.pullLeft]) if (cap < amount) amount = cap;
  if (amount < 0n) amount = 0n;
  return { amount, needed, enough: p.hot + amount >= needed };
}

const usd = (a: bigint) =>
  `${a < 0n ? "-" : ""}${(a < 0n ? -a : a) / 1_000_000n}.${((a < 0n ? -a : a) % 1_000_000n).toString().padStart(6, "0")}`;

export class FloatError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly details: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/** The float: status, a pull before a payment, and a return of what is above the reserve. */
export class AgentFloat {
  private verified: Promise<void> | null = null;
  /** One pull or return at a time in this process (two calls must not both pull). */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly chain: FloatChain,
    readonly s: FloatSettings,
  ) {
    if (getAddress(s.hot) === getAddress(s.wallet))
      throw new Error(
        "TOLLY_AGENT_WALLET is the buyer key's own address; name the agent's account",
      );
    if (s.min > s.target) throw new Error("TOLLY_FLOAT_MIN_USD is above TOLLY_FLOAT_TARGET_USD");
  }

  private serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  /** The RPC is the payment chain and 0x3600 is 6-decimal USDC; checked once, before any send. */
  verify(): Promise<void> {
    this.verified ??= (async () => {
      const id = await this.chain.chainId();
      if (id !== this.s.chainId || !ARC_CHAIN_IDS.has(id))
        throw new FloatError(
          "wrong_chain",
          `TOLLY_RPC_URL is chain ${id}; the float needs Arc chain ${this.s.chainId} (TOLLY_X402_NETWORK). Nothing sent.`,
        );
      const d = await this.chain.decimals();
      if (d !== 6)
        throw new FloatError(
          "wrong_token",
          `USDC at ${ARC_USDC} reports ${d} decimals, not 6. Nothing sent.`,
        );
      // The agent's wallet is an ERC-6551 account: code on chain. A plain address here is a
      // typo or a wrong setting, and a return would send the float where nobody can use it.
      const c = await this.chain.code(this.s.wallet);
      if (!c || c === "0x" || /^0xef0100[0-9a-f]{40}$/i.test(c))
        throw new FloatError(
          "wrong_wallet",
          `TOLLY_AGENT_WALLET ${getAddress(this.s.wallet)} has no contract code on chain ${id}: it is not an agent's ERC-6551 account. Nothing sent.`,
        );
    })();
    this.verified.catch(() => {
      this.verified = null; // a network error is retried next time; a wrong chain fails again
    });
    return this.verified;
  }

  async status() {
    await this.verify();
    const [hot, account, allowance, native] = await Promise.all([
      this.chain.balanceOf(this.s.hot),
      this.chain.balanceOf(this.s.wallet),
      this.chain.allowance(this.s.wallet, this.s.hot),
      this.chain.nativeBalance(this.s.hot),
    ]);
    const pullable = allowance < account ? allowance : account;
    const pulled = this.s.pulls.today();
    const left = this.s.pullBudget > pulled ? this.s.pullBudget - pulled : 0n;
    const proof = this.s.sign
      ? await this.s.sign(hotKeyProofMessage(this.s.chainId, this.s.wallet))
      : null;
    return {
      hot_key: getAddress(this.s.hot),
      agent_wallet: getAddress(this.s.wallet),
      token: ARC_USDC,
      decimals: 6,
      hot_key_usdc: usd(hot),
      agent_wallet_usdc: usd(account),
      allowance_usdc: usd(allowance),
      pullable_now_usdc: usd(pullable),
      worst_case_if_key_leaks_usdc: usd(hot + pullable),
      worst_case_if_wallet_topped_up_usdc: usd(hot + allowance),
      pulled_today_usdc: usd(pulled),
      pull_cap_left_today_usdc: usd(left),
      float: {
        target_usdc: usd(this.s.target),
        min_usdc: usd(this.s.min),
        gas_reserve_usdc: usd(this.s.reserve),
      },
      gas_ok: nativeAsAtomic(native) >= MIN_GAS,
      ...(proof
        ? {
            hot_key_proof: proof,
            hot_key_proof_note:
              "Give hot_key_proof to the agent's owner: they paste it on the agent's Spending panel, which checks locally that it was signed by this hot key for this agent wallet before approving anything. It is not a secret and authorizes nothing by itself.",
          }
        : {}),
      note: "On Arc the gas coin is USDC: the hot key's native balance (18 decimals) and its USDC balance (6 decimals) are the same money. The float keeps a gas reserve so it can always pull or return.",
    };
  }

  /**
   * Makes sure the hot key can pay `price` and keep its gas reserve, pulling from the agent's
   * account first if needed. Throws FloatError (nothing paid) when it cannot.
   */
  ensure(price: bigint): Promise<{ pulled: bigint; transaction: string | null }> {
    return this.serial(async () => {
      await this.verify();
      const [hot, account, allowance] = await Promise.all([
        this.chain.balanceOf(this.s.hot),
        this.chain.balanceOf(this.s.wallet),
        this.chain.allowance(this.s.wallet, this.s.hot),
      ]);
      const pulled = this.s.pulls.today();
      const pullLeft = this.s.pullBudget > pulled ? this.s.pullBudget - pulled : 0n;
      const { target, min, reserve } = this.s;
      const plan = planPull({ hot, price, allowance, account, pullLeft, target, min, reserve });
      const short = (why: string) =>
        new FloatError(
          "float_too_small",
          `The hot key holds ${usd(hot)} USDC and needs ${usd(plan.needed)} (price ${usd(price)} + gas reserve ${usd(this.s.reserve)}); ${why} Not paying.`,
          {
            hot_key_usdc: usd(hot),
            allowance_usdc: usd(allowance),
            agent_wallet_usdc: usd(account),
            pull_cap_left_today_usdc: usd(pullLeft),
          },
        );
      if (plan.amount === 0n && plan.enough) return { pulled: 0n, transaction: null };
      if (!plan.enough) {
        // A pull that cannot cover the payment is not sent: it would only use up the day's cap.
        throw short(
          allowance === 0n
            ? "the allowance is 0: the owner sets it on the agent's Spending panel."
            : account === 0n
              ? "the agent's wallet is empty: the owner tops it up."
              : pullLeft < plan.needed - hot
                ? "today's pull cap (TOLLY_X402_BUDGET) is too low for it."
                : "the allowance or the agent's wallet is too low for it.",
        );
      }
      if (nativeAsAtomic(await this.chain.nativeBalance(this.s.hot)) < MIN_GAS)
        throw new FloatError(
          "no_gas",
          `The hot key has no USDC for gas, so it cannot send the pull. Send it a little USDC once (0.10 is plenty); after that the float keeps a ${usd(this.s.reserve)} reserve. Not paying.`,
        );
      // Counted against today's pull cap before the transaction is sent (fail closed).
      const r = this.s.pulls.reserve(plan.amount, this.s.pullBudget);
      if (!r) throw short("today's pull cap (TOLLY_X402_BUDGET) is used up.");
      let tx: string;
      try {
        tx = await this.chain.transferFrom(this.s.wallet, plan.amount);
      } catch (err) {
        if (!(err instanceof SentUnknown)) this.s.pulls.release(r);
        throw new FloatError(
          "pull_failed",
          `Pulling ${usd(plan.amount)} USDC from the agent's wallet failed: ${String((err as Error).message).slice(0, 200)}. Not paying.`,
        );
      }
      return { pulled: plan.amount, transaction: tx };
    });
  }

  /** Sends what the hot key holds above `keep` (at least the gas reserve) back to the agent's account. */
  giveBack(keep: bigint) {
    return this.serial(async () => {
      await this.verify();
      const floor = keep > this.s.reserve ? keep : this.s.reserve;
      const hot = await this.chain.balanceOf(this.s.hot);
      if (hot <= floor)
        return {
          status: "nothing_to_return",
          hot_key_usdc: usd(hot),
          kept_usdc: usd(hot),
          returned_usdc: usd(0n),
          transaction: null,
        };
      if (nativeAsAtomic(await this.chain.nativeBalance(this.s.hot)) < MIN_GAS)
        throw new FloatError("no_gas", "The hot key has no USDC for gas. Nothing sent.");
      const amount = hot - floor;
      const tx = await this.chain.transfer(this.s.wallet, amount);
      return {
        status: "returned",
        returned_usdc: usd(amount),
        to: getAddress(this.s.wallet),
        kept_usdc: usd(floor),
        transaction: tx,
      };
    });
  }
}
