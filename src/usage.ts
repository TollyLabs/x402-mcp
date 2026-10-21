// The message a buyer signs to see their own usage (no account, no API key: the wallet that
// paid is the identity). The gateway verifies the same text.

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
