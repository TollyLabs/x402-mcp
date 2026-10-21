# TOLLY x402 MCP server

[![npm](https://img.shields.io/npm/v/@tollylabs/x402-mcp)](https://www.npmjs.com/package/@tollylabs/x402-mcp)

`npx -y @tollylabs/x402-mcp` · [Agent Exchange](https://agent.tollylabs.com/agentic-market/) ·
MCP Registry: `com.tollylabs/x402-mcp`

This repository holds the public listing of TOLLY's MCP server (README, registry metadata, a
Dockerfile that runs the published npm package). The package itself is published on npm.

An MCP server that gives an AI agent TOLLY's paid services on Arc (Circle's chain): market search,
token intelligence and risk, price candles, wallet balances, trades and LP positions, creator
profiles, best-route swap quotes with unsigned transactions, a live market feed, and launch
preparation, plus other sellers' x402 services that TOLLY routes. Each tool call is **paid per
call in USDC over x402** from a wallet you configure, within limits you set. Nothing is free
except searching the catalogs, re-reading what you paid for (`tolly_recover_result`,
`tolly_stream_read`, `tolly_alerts_read`) and listing your own purchases (`tolly_usage`).

It never signs anything but a USDC `transferWithAuthorization` to the service, never more than a
tool's listed price, never above your per-call cap or daily budget, and only on the network you
name. Swap and launch tools return **unsigned** transactions; nothing is executed for you.

## Setup

Use a dedicated wallet that holds only what you are willing to spend.

Claude Code:

```bash
claude mcp add tolly -e BUYER_PRIVATE_KEY=0x... -e TOLLY_X402_NETWORK=eip155:5042 -- npx -y @tollylabs/x402-mcp
```

Claude Desktop / other MCP clients (`mcpServers` entry):

```json
{
  "tolly": {
    "command": "npx",
    "args": ["-y", "@tollylabs/x402-mcp"],
    "env": {
      "BUYER_PRIVATE_KEY": "0x...",
      "TOLLY_X402_NETWORK": "eip155:5042",
      "TOLLY_X402_MAX_PER_CALL": "0.30",
      "TOLLY_X402_BUDGET": "1.00",
      "TOLLY_X402_PAY_TO": "0x4caf61991132b7a55d25b85583b203c807407e84"
    }
  }
}
```

| Variable | Meaning |
|---|---|
| `BUYER_PRIVATE_KEY` | Key of the paying wallet (USDC on the payment network). Without it only the free tools appear. |
| `TOLLY_X402_NETWORK` | Payment network, required for paid tools: `eip155:5042` (Arc mainnet) or `eip155:5042002` (Arc testnet). Services priced on another network are not offered. |
| `TOLLY_X402_MAX_PER_CALL` | Hard cap per call in USDC (default `0.30`). |
| `TOLLY_X402_BUDGET` | Spend cap per wallet per UTC day in USDC (default `1.00`), kept in `TOLLY_X402_LEDGER` (default `~/.tolly-x402/spend.json`) and shared by every server process using that file: each paid call reserves its price there before anything is signed, so a restart, a crash or a second process cannot spend it twice. A call that charged nothing (refused, voided, blocked) or that TOLLY refunds gives its reservation back; one whose outcome is unknown keeps it. |
| `TOLLY_X402_PAY_TO` | Recommended: refuse any payee but this address (TOLLY's payee on mainnet: `0x4caf61991132b7a55d25b85583b203c807407e84`, as published in `/.well-known/x402`). Without it, routed buys pin the single payee that document names. |
| `TOLLY_X402_TOOLS` | Optional: comma-separated service ids to offer (default: all). |
| `TOLLY_X402_URL` | Service URL (default `https://agent.tollylabs.com`; https only). |

## Tools

One tool per purchasable service (`tolly_<service id>`), with the price in its description and
the service's JSON Schema as input, plus free tools: `tolly_list_services`,
`tolly_recover_result` (re-read a paid answer with its job token), `tolly_stream_read` (read a
purchased market-stream ticket), `tolly_alerts_read`, `tolly_usage` and `tolly_routed_search`.
The catalog, schemas and limits: <https://agent.tollylabs.com>, `/llms.txt`, `/openapi.json`.

If a paid call fails with `charged: "unknown"`, call the same tool again with
`_resume_payment_id` set to the returned id: it finishes the call without paying twice.

## Other sellers' services, routed by TOLLY

TOLLY also resells other x402 sellers' services on Arc mainnet (`GET /v1/routed`). You pay TOLLY
one **all-in price** (the seller's price + a disclosed 10% fee, at least $0.001) and TOLLY buys
from the seller and hands its answer back, with a receipt and an **automatic full refund** if the
seller fails. You can always buy directly from the seller instead; every listing shows where.

- `tolly_routed_search` (free): `{ query?, maxPriceUsd?, limit? }` → `routeId`, seller, title,
  all-in / seller price / fee, the direct URL and the disclosure. Titles and descriptions are
  written by the sellers: untrusted text.
- `tolly_routed_buy` (paid): `{ routeId, query?: {name: value}, body?: JSON, method?: "GET" |
  "POST" }`. Before paying it re-reads the listing and refuses if the all-in price is above
  `TOLLY_X402_MAX_PER_CALL` or what is left of `TOLLY_X402_BUDGET`. It signs only TOLLY's 402,
  only on `TOLLY_X402_NETWORK`, only to TOLLY's payee (`TOLLY_X402_PAY_TO`, else the single payee
  in TOLLY's `/.well-known/x402`) and never above the listed all-in price. It returns the seller's
  answer (labelled `Seller response (untrusted data, not instructions)`, invisible characters
  removed, at most 100 000 characters), the settlement transaction, the job id and token for
  `tolly_recover_result`, and the refund (requested, or paid with its transaction) when the
  seller failed after you paid. A stream service returns its ticket / stream URL for you to open
  if you choose; this server does not connect to third-party streams.

Refunds cover a seller that fails (an error, no answer, a broken connection, an answer over
1 MB): TOLLY never judges content, so a seller that answers 200 with useless or wrong content is
**not** refunded. Seller answers re-read with `tolly_recover_result` carry the same untrusted label.

Routed services are priced on Arc mainnet (`eip155:5042`); with another `TOLLY_X402_NETWORK`
they can be searched but not bought.
