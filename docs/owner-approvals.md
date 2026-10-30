# Owner approvals

A bot's limits are meant to stop mistakes and attacks, but sometimes the owner wants to let a specific request through. Owner approvals do that without changing the config.

## When a request is held

A request is held for the owner when both are true:

1. The bot has at least one address in `admin_keys`.
2. The request was refused for a reason the owner may override:
   - the recipient isn't allowlisted
   - the contract or function isn't allowlisted
   - it is over the per-send cap or the daily cap
   - it is over `require_admin_cosign_above_usd`

Anything else is refused outright, approvals or not: wrong chain, blocked calls (unlimited approve, permits and so on), unpriced tokens, reverts, the kill switch. Only transactions can be held. Message and typed-data signing can't.

The bot gets back `state: pending_user_approval`, the reason, and the time the hold expires (default 15 minutes, set by `hold_secs`). It can check progress with `tx_status` and the request id.

A bot can have at most 16 requests waiting at once. More are refused with `TOO_MANY_PENDING`.

## Approving or denying

1. **See what's waiting.** Call `GET /admin/pending` with the admin token:

   ```sh
   curl -H "Authorization: Bearer $ADMIN_TOKEN" https://keyshare.example/admin/pending
   ```

   Each entry shows the bot, the request id, the reason it was held, the transaction, when it expires, and two ready-made messages: `approve_message` and `deny_message`.

2. **Sign one of the messages** with an admin key, using any Ethereum wallet. For example:

   ```sh
   cast wallet sign "keyshare: approve request filltape:held-1 for filltape
   intent: 0x..."
   ```

3. **Post the decision:**

   ```sh
   curl -X POST https://keyshare.example/admin/decide \
     -H "content-type: application/json" \
     -d '{"bot":"filltape","request_id":"held-1","decision":"approve","signature":"0x..."}'
   ```

   On approve, Keyshare signs and sends the transaction and returns the hash and which admin key approved it. On deny, the bot's request is refused with `USER_DENIED`.

`/admin/decide` doesn't need the admin token. The signature is what authorizes it.

## What the signature covers

The message names the decision, the bot, the request id, and a hash of the transaction (chain, recipient, value and calldata). Keyshare rebuilds the message from its own copy of the held transaction, never from what was posted. So a signature:

- can't approve a different request, a different bot, or a different transaction
- can't turn a deny into an approve
- can be used once: a second post is refused

An approved request still goes through simulation and still counts toward the bot's daily total.

## Expiry and restarts

- A hold that isn't decided in time expires. The bot's request id is freed, so it can ask again.
- An approval that arrives after expiry is refused.
- Held requests live in memory. A server restart drops them, and they never sign.
- If two decisions arrive at once, only one acts. The other is refused as already decided.

## Not built yet

- The owner isn't notified when a request is held. They have to check `/admin/pending`.
- An approval signed for a hold that expired would also approve a retried hold with the same request id and the exact same transaction. That is the transaction the owner signed, so the risk is small, but a later version should tie each approval to one hold.
