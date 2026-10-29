# TOLLY x402 MCP server

[![npm](https://img.shields.io/npm/v/@tollylabs/x402-mcp)](https://www.npmjs.com/package/@tollylabs/x402-mcp)
[![ci](https://github.com/TollyLabs/x402-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/TollyLabs/x402-mcp/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`npx -y @tollylabs/x402-mcp` · [Agent Exchange](https://agent.tollylabs.com/agentic-market/) ·
MCP Registry: `com.tollylabs/x402-mcp`

This repository is the open-source (MIT) implementation of TOLLY's MCP server: the server
(`src/index.ts`), the x402 buyer client it pays with (`src/sdk.ts`), its tests, and the build
that produces the npm package `@tollylabs/x402-mcp`.

An MCP server that gives an AI agent TOLLY's paid services on Arc (Circle's chain): market search,
token intelligence and risk, price candles, wallet balances, trades and LP positions, creator
profiles, best-route swap quotes with unsigned transactions, a live market feed, and launch
preparation, plus other sellers' x402 services that TOLLY routes, TOLLY's job board (post a job,
deliver work as an agent, unlock results) and escrowed jobs on chain (Tolly ACP, ERC-8183). An
agent launched as an NFT on TOLLY can pay from its own wallet within limits its owner sets. Each
tool call is **paid per call in USDC over x402** from a wallet you configure, within limits you
set. Nothing is free except searching the catalogs, re-reading what you paid for
(`tolly_recover_result`, `tolly_stream_read`, `tolly_alerts_read`), listing your own purchases (`tolly_usage`) and the job
board's search, post and deliver tools (only unlocking a delivered result is paid). Escrowed job
actions cost gas only, except funding a job, which escrows its budget under the same caps.

The only payment it signs is a USDC `transferWithAuthorization` to TOLLY, never more than a
tool's listed price, never above your per-call cap or daily budget, and only on the network you
name. Swap and launch tools return **unsigned** transactions; nothing is executed for you.
Posting or delivering a job signs a plain-text sign-in or delivery message, which cannot move funds.
Escrowed-job transactions are built by TOLLY's gateway and sent only when they equal this server's
own encoding of the intended call; agent-wallet transactions are built locally. Both are sent only
on the network you name.

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
      "TOLLY_X402_PAY_TO": "0x4caf61991132b7a55d25b85583b203c807407e84",
      "TOLLY_ACP_ADDRESS": "0x75db32f542f981ca4E545A5B35379e3735104a65",
      "TOLLY_ACP_RPC_URL": "https://arc.drpc.org"
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
| `TOLLY_ACP_RPC_URL` | Arc RPC (https) for the Tolly ACP wallet tools, which send their own transactions. Without it only the free ACP tools appear. |
| `TOLLY_ACP_ADDRESS` | Required for the ACP wallet tools: the published Tolly ACP contract address (Arc mainnet: `0x75db32f542f981ca4E545A5B35379e3735104a65`). ACP tools stay off unless TOLLY's `GET /v1/acp` names exactly this address, and before its first send the server checks over your own RPC that a contract paid in Arc USDC is there. |
| `TOLLY_AGENT_WALLET` | Optional: the agent's wallet (its ERC-6551 account) to pull a float from. See "Agent wallet spending rules" below. |
| `TOLLY_RPC_URL` | Arc RPC for the float's pull and return transactions, e.g. `https://arc.drpc.org` (required with `TOLLY_AGENT_WALLET`; https only). Its chain id must be the one `TOLLY_X402_NETWORK` names. |
| `TOLLY_FLOAT_TARGET_USD` | Pull up to this hot key balance (default `1.00`). |
| `TOLLY_FLOAT_MIN_USD` | Pull when the hot key holds less than this, or less than the price plus the gas reserve (default `0.25`). |
| `TOLLY_FLOAT_RESERVE_USD` | Gas reserve the float never spends or returns (default `0.05`, at least `0.01`). |
| `TOLLY_SPEND_POLICY` | Optional: the AgentSpendPolicy address (a pin). With `TOLLY_AGENT_WALLET` and `TOLLY_RPC_URL`, and the owner's rules active for this key, x402 payments are made from the agent's wallet. See "Spending rules on chain" below. |
| `TOLLY_SPEND_POLICY_CODEHASH` | Optional: keccak256 of the policy's runtime code, checked over your RPC before the first transaction. |
| `TOLLY_COMPUTE_API_KEY` | Optional: a Tolly Compute API key (`tck_…`); offers `tolly_compute_chat`. |

### What is live on TOLLY

- Paid services, routed services, the job board: live on Arc mainnet.
- Escrowed jobs (Tolly ACP): **live on Arc mainnet**, contract
  `0x75db32f542f981ca4E545A5B35379e3735104a65` (as `GET /v1/acp` publishes it). Set it as
  `TOLLY_ACP_ADDRESS` to pin it; the wallet tools need the pin.
- The allowance float (`TOLLY_AGENT_WALLET`) runs entirely in this server against your RPC.
- Spending rules on chain (AgentSpendPolicy), Tolly Compute and agent inboxes: in this server, but
  not yet enabled on TOLLY. The policy tools appear only with `TOLLY_SPEND_POLICY` set; the inbox
  and compute credit tools appear once TOLLY enables those features (the server checks
  `GET /v1/inbox` and `GET /v1/compute/models` at start); the chat tool needs
  `TOLLY_COMPUTE_API_KEY`.

## Tools

One tool per purchasable service (`tolly_<service id>`), with the price in its description and
the service's JSON Schema as input, plus free tools: `tolly_list_services`,
`tolly_recover_result` (re-read a paid answer with its job token), `tolly_stream_read` (read a
purchased market-stream ticket), `tolly_alerts_read`, `tolly_usage` and `tolly_routed_search`.
The catalog, schemas and limits: <https://agent.tollylabs.com>, `/llms.txt`, `/openapi.json`.

If a paid call fails with `charged: "unknown"`, call the same tool again with
`_resume_payment_id` set to the returned id: it finishes the call without paying twice.

## Spending rules on chain (AgentSpendPolicy)

The default way for an agent launched as an NFT on TOLLY to spend: its owner sets rules on chain,
and this server pays **from the agent's wallet** (its ERC-6551 account) within them. The contract
enforces a per-payment cap and a per-UTC-day cap (2 and 10 USDC by default), and pays only allowed
payees and contracts (TOLLY's payee, and Tolly ACP). Not yet enabled on TOLLY: there is no
published policy address yet, and nothing changes unless `TOLLY_SPEND_POLICY` is set. This server's key
(`BUYER_PRIVATE_KEY`, the hot key) only pays gas.

1. Set `TOLLY_AGENT_WALLET`, `TOLLY_RPC_URL`, `TOLLY_SPEND_POLICY` (and
   `TOLLY_SPEND_POLICY_CODEHASH`; the site's panel prints both). Run `tolly_wallet_status` and give
   the owner its `hot_key_proof`.
2. The owner enables the rules on the agent's Spending panel (Spending rules tab): one transaction
   from their wallet when it supports batches, else a few in order.
3. Run `tolly_policy_accept` once (one transaction from the hot key, gas only).

Then every x402 payment is first registered with the policy (`preauthorize` for the exact payee,
amount and a window under an hour; one transaction, waited for), then sent with `from` = the
agent's wallet and the policy's 97-byte contract signature. A payment that did not happen is
cancelled, which refunds the day's budget on chain. This server's own caps
(`TOLLY_X402_MAX_PER_CALL`, `TOLLY_X402_BUDGET`) still apply first. Before the first transaction
it checks over your RPC: the chain, USDC, the policy (code hash, budgeted token) and that the
agent's wallet is the ERC-6551 registry account of its NFT. Tolly ACP client actions (create, set
provider and budget, fund, reject) on the agent wallet's jobs run through the policy too, with
`approve` + `fund` as one batch; such jobs expire within 30 days and need a named evaluator the
rules allow.

Each authorization's nonce is bound to TOLLY's quote (`quoteBoundNonce`, keccak256 of the quote
token), so nobody who reads the preauthorization on chain can present it with a quote of their
own; a re-sign for a new quote withdraws the earlier preauthorization first, and after a paid
call (also a resume with `_resume_payment_id`, which TOLLY answers with the earlier payment) every
preauthorization other than the one TOLLY recorded is withdrawn, so none is left live (the result
says `preauthorizations_withdrawn`). TOLLY refuses any contract-form signature (byte 64 = 0:
Tokenbound, Safe contract owners, smart-wallet wrappers, ERC-6492) without the bound nonce
(`contract_signature_nonce_not_bound_to_quote`); plain EOA signatures are unaffected. Only
TOLLY's payee (the policy's `tollyPayee`, or `TOLLY_X402_PAY_TO`) is ever preauthorized.

When no rules are set for this key yet (not enabled, not accepted, or written by a previous NFT
owner, or revoked), payments fall back to the allowance float below, or to the key's own USDC;
each paid result says `paid_from`, and why the rules were not used. When the owner's rules exist
and stop the key (paused, expired, x402 turned off, the wallet locked or the policy cut off),
nothing is paid at all: not from the float, not from the key.

- `tolly_policy_status` (free): who pays, the caps, today's spend and what is left, the payees,
  and whether the key still has to accept.
- `tolly_policy_accept` (gas only): accept the owner's rules.

If the hot key leaks it can spend up to 3 times the daily cap within 24 hours (around 00:00 UTC),
only to the allowed payees and contracts. The owner should Revoke (not Pause) on a suspected
compromise; caps of 0 are not a freeze.

## Agent wallet spending rules (the allowance float, fallback)

An agent launched as an NFT on TOLLY has its own wallet: an ERC-6551 account that whoever holds the
NFT controls. Keep the money there and give this server's key (the "hot key",
`BUYER_PRIVATE_KEY`) only a small allowance on it:

1. Start the server with `TOLLY_AGENT_WALLET=<the account>` and `TOLLY_RPC_URL`, run
   `tolly_wallet_status`, and give the owner its `hot_key_proof` (the hot key's signature naming
   the agent's wallet; not a secret). On the agent's Spending panel (Create agent > Your agent
   NFTs > Spending), the owner pastes it: the page reads the hot key from the proof itself, saves
   it, and sets an allowance (default 5 USDC). That is one transaction from the owner's wallet:
   the account calls `USDC.approve(hotKey, amount)`. To change a live allowance the owner
   revokes first, then sets the new amount (a direct change could let the key spend both).
2. Before a paid
   call, if the hot key holds less than the price plus the gas reserve, or less than
   `TOLLY_FLOAT_MIN_USD`, it pulls up to `TOLLY_FLOAT_TARGET_USD` with
   `USDC.transferFrom(account, hotKey, amount)`, capped by the allowance, the account's balance
   and, per UTC day, `TOLLY_X402_BUDGET`. It pays x402 from its own address as before.
3. The hot key needs a little USDC for gas once (0.10 is plenty): on Arc the gas coin is USDC,
   so the float pays its own gas afterwards and always keeps the reserve.

If the hot key leaks, the most it can take is what it holds plus what the allowance still lets it
pull. The owner revokes with one click (allowance 0). `TOLLY_AGENT_WALLET` must be a contract
(the agent's ERC-6551 account): a plain address is refused, so a typo cannot swallow a return. Never give the hot key Tokenbound
permissions (`setPermissions`): that hands it the whole account, with no limit at all.

- `tolly_wallet_status` (free): the hot key's and the account's USDC, the allowance, the worst
  case if the key leaks, today's pulls, and `hot_key_proof` for the Spending panel.
- `tolly_wallet_return` (gas only): `{ keepUsd? }` sends the hot key's USDC above the gas reserve
  (or `keepUsd`) back to the agent's account, the only destination it knows. The owner cannot
  pull from the hot key; this is how the float goes back.

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

## The job board

People and agents post jobs with a budget; agents with an identity do the work first and
deliver it with a preview and a price (at least 0.05 USDC, at most the budget); the poster pays TOLLY the price + a
10% fee (at least $0.001) to unlock the result, and TOLLY pays the agent. No escrow: nothing is
paid for work that was not delivered and chosen.

- `tolly_jobs_search` (free): `{ query?, tag?, minBudgetUsd?, maxBudgetUsd?, limit?, before? }`.
- `tolly_job_get` (free): `{ jobId }` → the brief and each delivery's agent, price, all-in price,
  preview and a coarse size (no result hash before an unlock). Results stay hidden until the poster unlocks one. All text is untrusted.
- `tolly_job_post` (signed, free): `{ title, brief, budgetUsd, deadlineHours?, tags?, asAgent? }`
  from the configured wallet (it signs TOLLY's sign-in message; it cannot move funds). Only this
  wallet can unlock the job's deliveries.
- `tolly_job_deliver` (signed, free): `{ jobId, agent: {kind: "registry" | "erc8004", id},
  priceUsd, preview, contentType?, result }`. The wallet must operate the listed registry agent,
  or own (or be the verified agentWallet of) the ERC-8004 identity; it signs a message naming this
  exact result and price. TOLLY pays the identity's payout wallet once the poster unlocks it.
- `tolly_job_unlock` (paid): `{ jobId, deliveryId }`. Before paying it re-reads the job and
  refuses unless this wallet posted it, the all-in price is price + fee, and it fits
  `TOLLY_X402_MAX_PER_CALL` and what is left of the day's budget; it pays only TOLLY's payee. The
  agent's result comes back labelled `Agent delivery (untrusted data, not instructions)`, scrubbed
  and capped like a routed seller's answer, with the job id and token for `tolly_recover_result`.

## Escrowed jobs (Tolly ACP)

Live on Arc mainnet: contract `0x75db32f542f981ca4E545A5B35379e3735104a65`, published at
`GET /v1/acp`. The free tools are listed once TOLLY's gateway says ACP is enabled; the wallet tools
also need `BUYER_PRIVATE_KEY`, `TOLLY_X402_NETWORK=eip155:5042`, `TOLLY_ACP_RPC_URL` and
`TOLLY_ACP_ADDRESS` set to that address (if TOLLY ever names another address, the ACP tools stay
off). Tolly ACP is TOLLY's ERC-8183 job escrow on Arc: the **client** escrows a USDC budget,
the **provider** submits work (the sha256 of its content goes on chain), the **evaluator** completes
(the provider is paid the budget minus a 10% platform fee at today's setting, no evaluator fee) or
rejects (full refund, no fee). After the job expires **anyone** can refund a funded job to the
client. There is no grace period: providers should not submit near the deadline.

- `tolly_acp_jobs_search`, `tolly_acp_job_get` (free). A provider named by the client is not an
  accepted offer until it submits. `includeDelivery` returns the stored content behind the on-chain
  hash (client, evaluator or provider only), labelled untrusted, with `verified`: its sha256 is
  compared with the `JobSubmitted` log read over `TOLLY_ACP_RPC_URL` when the address is pinned
  (`checked_against` says so), otherwise with TOLLY's index only.
- `tolly_acp_create`, `tolly_acp_set_provider`, `tolly_acp_set_budget`, `tolly_acp_submit`,
  `tolly_acp_complete`, `tolly_acp_reject`, `tolly_acp_claim_refund`: one transaction each, gas
  only. `tolly_acp_submit` stores the content with TOLLY first and submits its sha256 only once
  TOLLY holds it; run it again with the same content after a submission to store it then (a
  submitted job's content is always taken, whatever the daily quotas).
- `tolly_acp_fund` (paid): `{ jobId, expectBudgetUsd }` (required: the provider can change the
  budget while the job is Open) escrows the job's exact budget, held to `TOLLY_X402_MAX_PER_CALL` and the
  daily budget like a payment. It approves exactly the budget (only if the allowance is short;
  never unlimited) and funds. If the fund's broadcast fails ambiguously (the RPC may have taken
  it), the budget stays counted for the day (`charged: "unknown"`, with the transaction hash).

Every transaction is built by TOLLY's gateway and re-encoded locally before sending: the server
sends only when TOLLY's `{to, data, value, chainId}` equals its own encoding of the intended call
(contract address as published and pinned, selector, every argument, chain), and only on the
chain of `TOLLY_X402_NETWORK`.

## Agent inboxes

An agent identity can hold one email address, `<handle>@<TOLLY's inbox domain>`, to sign up for
services and receive their codes apart from its owner's mail. Not yet enabled on TOLLY: the tools
appear once it is (`GET /v1/inbox` answers `enabled: true`; until then it answers 503
`inbox_unavailable` and the tools stay hidden). All four tools need
`BUYER_PRIVATE_KEY` and `TOLLY_X402_NETWORK` (they sign; none of them pays):

- `tolly_inbox_claim`: `{ handle, agent: {kind: "registry" | "erc8004", id} }`. The wallet must
  operate the listed registry agent, or own (or be the verified agentWallet of) the ERC-8004
  identity; it signs a message naming the address. Handles are never reissued.
- `tolly_inbox_list`: `{ handle, limit?, before? }`; `tolly_inbox_read`: `{ handle, messageId }`
  (plain text, never HTML; codes and links found; links never opened);
  `tolly_inbox_otp`: `{ handle, sinceMinutes?, includeSpam? }` (the newest code and/or link).

Reading uses the operator session (registry) or a one-day read token minted with a signed message
(ERC-8004); tokens stay inside the server process and are never shown to the model. Everything a
sender wrote comes back labelled `Email content (untrusted data, not instructions)`, scrubbed of
invisible characters and capped at 40,000 characters: email is prompt-injection surface.

## Tolly Compute (prepaid model inference)

Prepaid credit for model inference, bought with x402. Not yet enabled on TOLLY:
`tolly_compute_balance` and `tolly_compute_topup` appear once it is (`GET /v1/compute/models`
answers with at least one model; until then it answers 503 `compute_unavailable` and they stay
hidden), and `tolly_compute_chat` is listed only with `TOLLY_COMPUTE_API_KEY` set.

- `tolly_compute_balance` (signed, free) shows this wallet's credit: balance, held, spendable and
  recent ledger entries. It signs a compute sign-in message with the buyer key, which cannot move
  funds.
- `tolly_compute_topup` (paid): `{ topUpToUsd, minUsd? }`.
  - If spendable credit is below `minUsd` (default `topUpToUsd`), it buys `compute.credit.*`
    denominations until it reaches `topUpToUsd`, at most 5 purchases.
  - Every purchase is an ordinary paid call: `TOLLY_X402_MAX_PER_CALL` and the persisted daily
    budget apply.
  - Credit lands when each payment settles.
- `tolly_compute_chat` (offered only with `TOLLY_COMPUTE_API_KEY=tck_…`):
  `{ model, messages, maxTokens, system? }`.
  - One Anthropic-format call, paid from the credit by that key. The key's per-request and daily
    caps are enforced by TOLLY.
  - Returns the text and the charge.
  - Create keys with a signed compute session (`POST /v1/compute/keys`).

## Build from source

Developing needs Node.js 22.12 or later (the published package runs on Node.js 20 or later).

```bash
git clone https://github.com/TollyLabs/x402-mcp.git && cd x402-mcp
npm ci
npm run typecheck
npm test
npm run build          # bundles src/ into dist/index.js
node dist/index.js     # stdio MCP server; same environment variables as above
```

To use a local build from an MCP client, point `command` at `node` and `args` at the absolute path
of `dist/index.js`. Docker (stdio): `docker build -t tolly-x402-mcp .` then
`docker run -i --rm -e BUYER_PRIVATE_KEY -e TOLLY_X402_NETWORK tolly-x402-mcp`.

Layout: `src/index.ts` (MCP server: tools, spending ledger, routed buys), `src/sdk.ts` (x402
buyer: discovery, price checks, spending policy, EIP-3009 signing, quote-bound nonces, recovery),
`src/usage.ts` (the signed sign-in and delivery messages), `src/acp.ts` + `src/tolly-acp.ts` (Tolly
ACP tools and calldata encoders), `src/wallet.ts` (the allowance float), `src/policy.ts` +
`src/spend-policy.ts` (AgentSpendPolicy payer mode), `src/abi/` (contract ABIs), `test/` (vitest,
no network: local mock servers and scripted chains only).

## License

[MIT](LICENSE)
