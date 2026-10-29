// Signed-message texts shared with TOLLY's gateway (it verifies the same text).
// The message a buyer signs to see their own usage (no account, no API key: the wallet that
// paid is the identity). Shared by the gateway, the portal and the MCP server.
export const USAGE_MAX_AGE_S = 300;

/** One spelling of a site on every side (scheme, host and port only). */
export const usageOrigin = (url: string) => new URL(url).origin;

export function usageMessage(
  address: string,
  issuedAt: string,
  origin: string,
  network: string,
): string {
  return [
    "tolly-x402: show my usage",
    `address: ${address.toLowerCase()}`,
    `network: ${network}`,
    `issued: ${issuedAt}`,
    `origin: ${usageOrigin(origin)}`,
    "Sign only on this site. For 5 minutes this signature lets the site list your purchases",
    "and receipts (prices, payments, refunds). It cannot move funds or open paid results.",
  ].join("\n");
}

/** The message an agent operator signs to manage its listings on the agent exchange. */
/** The account sign-in: follows, notifications and owned agent NFTs' profiles, for 30 days. */
export function accountMessage(
  address: string,
  issuedAt: string,
  origin: string,
  network: string,
): string {
  return [
    "tolly-x402: sign in to your agents account",
    `address: ${address.toLowerCase()}`,
    `network: ${network}`,
    `issued: ${issuedAt}`,
    `origin: ${usageOrigin(origin)}`,
    "Sign only on this site. For 30 days this signature lets the site keep the agents this",
    "wallet follows, its notifications, and the profiles of the agent NFTs it owns. It cannot",
    "move funds.",
  ].join("\n");
}

export function operatorMessage(
  address: string,
  issuedAt: string,
  origin: string,
  network: string,
): string {
  return [
    "tolly-x402: sign in as an agent operator",
    `address: ${address.toLowerCase()}`,
    `network: ${network}`,
    `issued: ${issuedAt}`,
    `origin: ${usageOrigin(origin)}`,
    "Sign only on this site. For 2 hours this signature lets the site create and edit the",
    "agent listings this wallet operates. It cannot move funds.",
  ].join("\n");
}

/**
 * What an ERC-8004 identity's owner (or its verified agentWallet) signs to deliver a job result
 * (docs/agents/JOBS.md): the job, the identity, the price and the exact result (sha256), so the
 * signature delivers this result only, once, within 5 minutes.
 */
export function jobDeliveryMessage(p: {
  jobId: string;
  agentId: string;
  signer: string;
  priceAtomic: string;
  resultSha256: string;
  contentType: string;
  issuedAt: string;
  origin: string;
  network: string;
}): string {
  return [
    "tolly-x402: deliver a job result",
    `job: ${p.jobId}`,
    `agent: erc8004:${p.agentId}`,
    `signer: ${p.signer.toLowerCase()}`,
    `price: ${p.priceAtomic}`,
    `result: ${p.resultSha256}`,
    `type: ${p.contentType}`,
    `network: ${p.network}`,
    `issued: ${p.issuedAt}`,
    `origin: ${usageOrigin(p.origin)}`,
    "Sign only to deliver this result. TOLLY pays the identity's wallet the price once the job's",
    "poster unlocks it. It cannot move funds.",
  ].join("\n");
}

/** What the same identity signs to withdraw one of its deliveries before it is unlocked. */
export function jobWithdrawMessage(p: {
  deliveryId: string;
  agentId: string;
  signer: string;
  issuedAt: string;
  origin: string;
  network: string;
}): string {
  return [
    "tolly-x402: withdraw a job delivery",
    `delivery: ${p.deliveryId}`,
    `agent: erc8004:${p.agentId}`,
    `signer: ${p.signer.toLowerCase()}`,
    `network: ${p.network}`,
    `issued: ${p.issuedAt}`,
    `origin: ${usageOrigin(p.origin)}`,
    "Sign only to withdraw this delivery. It cannot move funds.",
  ].join("\n");
}

/**
 * What a registry agent's operator or an ERC-8004 identity's owner/agentWallet signs to claim an
 * inbox for that identity (docs/os/INBOX.md): the address and the identity, valid 5 minutes,
 * single use. For a registry agent the operator's session is enough; an ERC-8004 identity signs.
 */
export function inboxClaimMessage(p: {
  address: string;
  agentId: string;
  signer: string;
  issuedAt: string;
  origin: string;
  network: string;
}): string {
  return [
    "tolly-x402: claim an agent inbox",
    `inbox: ${p.address.toLowerCase()}`,
    `agent: erc8004:${p.agentId}`,
    `signer: ${p.signer.toLowerCase()}`,
    `network: ${p.network}`,
    `issued: ${p.issuedAt}`,
    `origin: ${usageOrigin(p.origin)}`,
    "Sign only to give this agent identity this email address and the caller a 30-day token to",
    "read its mail (also readable by the identity's owner and agentWallet). It cannot move funds.",
  ].join("\n");
}

/**
 * What the same wallet signs to mint a read token for an inbox, to release the inbox, or to
 * manage it (delete one message, or revoke one read token: `target` names which).
 */
export function inboxAccessMessage(p: {
  action: "read-token" | "release" | "manage";
  handle: string;
  agentId: string;
  signer: string;
  days: number;
  issuedAt: string;
  origin: string;
  network: string;
  /** manage only: the message id (em_…) to delete or the token id (itk_…) to revoke. */
  target?: string;
}): string {
  const title = {
    "read-token": "tolly-x402: read an agent inbox",
    release: "tolly-x402: release an agent inbox",
    manage: "tolly-x402: manage an agent inbox",
  }[p.action];
  const tail = {
    "read-token":
      "Sign only to let the holder of the token read this inbox's mail. It cannot move funds.",
    release:
      "Sign only to give up this address for good: its mail is deleted and it is never reissued.",
    manage:
      "Sign only to delete this message from, or revoke this read token of, the inbox. It cannot move funds.",
  }[p.action];
  return [
    title,
    `inbox: ${p.handle.toLowerCase()}`,
    `agent: erc8004:${p.agentId}`,
    `signer: ${p.signer.toLowerCase()}`,
    ...(p.action === "read-token" ? [`days: ${p.days}`] : []),
    ...(p.action === "manage" ? [`target: ${p.target ?? ""}`] : []),
    `network: ${p.network}`,
    `issued: ${p.issuedAt}`,
    `origin: ${usageOrigin(p.origin)}`,
    tail,
  ].join("\n");
}

/**
 * What a wallet signs to manage its Tolly Compute API keys and read its compute credit
 * (docs/os/COMPUTE.md). Its own wording, so no other sign-in (usage, account, operator) can mint
 * a key that spends the wallet's credit.
 */
export function computeMessage(
  address: string,
  issuedAt: string,
  origin: string,
  network: string,
): string {
  return [
    "tolly-x402: manage my compute keys",
    `address: ${address.toLowerCase()}`,
    `network: ${network}`,
    `issued: ${issuedAt}`,
    `origin: ${usageOrigin(origin)}`,
    "Sign only on this site. For 1 hour this signature lets the site create and revoke API keys",
    "that spend this wallet's prepaid compute credit (within the limits you set per key), and",
    "show the credit. It cannot move funds from the wallet.",
  ].join("\n");
}
