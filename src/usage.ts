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
