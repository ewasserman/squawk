# Relay protocol

Squawk v1 delivers messages only between services that can open a WebSocket
connection to each other, which in practice means the same local network.
The relay lets two services on different networks exchange messages. Each
service keeps one outbound WebSocket connection to a relay server. The relay
keeps a mailbox for each service and holds sealed messages there until the
recipient fetches them. The relay cannot read the messages: they are sealed
(signed, then encrypted to the recipient) exactly as on the local network.

This document describes the protocol between a service and the relay. The
threats it raises are in [security.md](security.md), threats 9–17.

Task numbers refer to the sub-issues of GitHub issue #28 (task *n* is issue
#*n+28*).

## Overview

1. A service connects to its relay and proves which key it holds by signing
   a challenge, the same way two services do on the local network
   (`network.py`).
2. It tells the relay which keys may leave messages in its mailbox: its
   paired, unblocked contacts (the **allow list**).
3. To send, it **deposits** a sealed message into the recipient's mailbox.
   The relay accepts the deposit only if the sender is on the recipient's
   allow list.
4. The recipient's service **fetches** what is waiting, opens and stores each
   message, then tells the relay to **delete** it.
5. The recipient sends an end-to-end **receipt** back to the sender, also as
   a sealed message through the relay, so the sender knows the message
   reached the recipient's service and not only the relay.
6. Messages not fetched within **7 days** are deleted by the relay.

Delivery on the local network stays the first route: a service tries LAN
direct first and uses the relay only when the recipient cannot be reached
directly (task 6).

Each contact record stores the relay URL the contact uses, learned during
pairing. In this epic a service connects only to its own relay, so both
people must use the same relay. A message is still tried through our relay
when the contact's saved URL differs (the saved URL can be out of date); the
relay refuses it with `not-allowed` if the contact has no mailbox there, and
the message stays queued. Depositing at a contact's different relay is a
later step.

When the service switches to another relay, or a contact shows up on the
local network, messages the relay was holding for them are queued again for
every route, in case the relay lost them; a recipient that receives a second
copy only acknowledges it again.

## Transport

- WebSocket. In production the relay runs behind something that terminates
  TLS, and clients use `wss://`. The relay process itself speaks plain
  WebSocket.
- A client refuses a plain `ws://` relay URL unless its person opted in when
  setting the relay (`squawk relay set ws://localhost:8765 --allow-plain`;
  the opt-in is stored with the URL). This is for local testing against the
  Docker relay. Messages are sealed either way; what plain `ws://` exposes
  is the metadata listed under threat 15 to anyone on the path.
- Every frame is a UTF-8 JSON text object with a string field `"t"` (its
  type), as on the local network. Binary frames are refused.
- Plain HTTP `GET /healthz` on the same port answers `200` with
  `{"status": "ok", "version": "<squawk version>"}`. It reveals nothing
  else.

Identifiers below:

- *key id*: a squawk key identifier (as in `encoding.py`), the ed25519
  public key in text form.
- *sealed*: a sealed message object exactly as in `envelope.py` (`v`, `from`,
  `to`, `epk`, `nonce`, `ct`).

## Proving a key to the relay

The relay has its own ed25519 key, made when it first starts and kept in its
data directory. Its key id is sent in `hello`; it is not secret and is not
checked against anything in this epic (see threat 16).

```
relay  -> client  {"t":"hello", "v":1, "key":<relay key id>, "challenge":<32 random bytes, base64url>, "access":"open"|"keys"|"github"}
client -> relay   {"t":"auth",  "v":1, "key":<client key id>, "sig":<base64url>}
relay  -> client  {"t":"ok", "waiting":<number of messages in the mailbox>}
```

`sig` is the v1 signature, `auth_message(challenge, client key, relay key)`
from `network.py`: ed25519 over

```
squawk ws auth v1\n<challenge>\n<client key id>\n<relay key id>
```

Because the relay's key is part of what is signed, a dishonest relay cannot
pass a challenge from another relay to a client and use the answer to log in
to that other relay as the client.

Only the client proves its key; the relay does not need to, because
everything that matters is sealed or signed by the people at either end.

If the signature does not verify, the relay closes the connection with code
`4001` and reason `bad signature`. A client that has not sent a valid `auth`
within 10 seconds is disconnected. Any frame other than `auth` before `ok`
closes the connection.

`access` says how the relay decides who may use it
([relay-access.md](relay-access.md)); a missing `access` means `open`. After
a valid signature the relay asks its access mode about the key. A key it does
not admit is disconnected with code `4003`, reason `not permitted`, and gets
no mailbox. In `github` mode, a key the relay has not seen before gets
`{"t":"login-required","provider":"github"}` instead of `ok`, and its owner
signs in with GitHub before the relay answers `ok` (see "Signing in with
GitHub" in [relay-access.md](relay-access.md)). A key the operator
removed while it was connected is closed with code `4004`, reason `removed
by the operator`; the client then connects again and the access mode
decides.

There is one connection per key. If a second connection authenticates with
the same key, the relay closes the older one with code `4002`, reason
`replaced`.

A mailbox is created the first time a key authenticates, and is identified
only by that key id. There are no accounts, names or passwords.

## Frames after `ok`

Every request from the client carries `"req"`, a string of at most 64
characters chosen by the client; the relay's answer carries the same `req`.
Any refusal is

```
relay -> client  {"t":"refused", "req":<req>, "reason":<code>}
```

with one of these reason codes:

| Reason | Meaning |
| --- | --- |
| `malformed` | The frame does not have the expected fields. |
| `not-allowed` | The sender is not on the recipient's allow list (or the mailbox does not exist). |
| `sender-mismatch` | The sealed message's `from` is not the connected key. |
| `too-large` | The frame or sealed message is over its size limit. |
| `mailbox-full` | The recipient's mailbox is at its limit. |
| `rate-limited` | Too many requests of this kind; `"retry_after"` gives seconds. |
| `offline` | (`forward` only) The recipient is not connected now. |
| `no-such-invite` | (`invite-join` only) The code is unknown, expired or already used. |
| `error` | Something went wrong at the relay; try again later. |

`not-allowed`, `sender-mismatch`, `too-large` and `malformed` are permanent
for that message; the others can clear up and are retried.

### Allow list

```
client -> relay  {"t":"allow", "req":..., "senders":[<key id>, ...]}
relay  -> client {"t":"allowed", "req":...}
```

Replaces the whole allow list for the connected key's mailbox. The service
sends it after every `ok` and again whenever a contact is added, removed,
blocked or unblocked. It lists the key ids of paired, unblocked contacts. A
key never on the list cannot deposit; a key removed from the list cannot
deposit from then on (messages already waiting stay, and the recipient's
service refuses them on opening if it blocked that contact).

### Deposit

```
client -> relay  {"t":"deposit", "req":..., "id":<message id>, "sealed":<sealed>}
relay  -> client {"t":"deposited", "req":..., "id":<message id>}
```

The relay checks, in order: the sealed message's shape; `sealed.from` is the
connected key; the connected key is on the allow list of `sealed.to`'s
mailbox; the size and rate limits; the mailbox limits. It then stores the
sealed message with the time it arrived and answers `deposited`.

`id` is the message id the sender chose (a random UUID). The relay keeps at
most one message per sender and id: depositing the same `(from, id)` again,
for example after the `deposited` answer was lost, answers `deposited`
without storing a second copy.

The relay does not open the sealed message and has no key to do so. It
stores the sender key id, the recipient key id, the id, the arrival time
and the sealed message, nothing else.

### Fetch and delete

```
client -> relay  {"t":"fetch", "req":...}
relay  -> client {"t":"deliver", "rid":<relay item id>, "sealed":<sealed>, "deposited_at":<ISO time>}  (repeated)
client -> relay  {"t":"delete", "rid":<relay item id>}
```

After `fetch`, the relay sends every waiting message, oldest first, and
from then on sends each new deposit as it arrives, for as long as the
connection is open. `rid` is the relay's own id for the stored message. At
most 32 deliveries are outstanding (sent but not yet deleted) at a time; the
relay sends the next as each `delete` arrives.

The client sends `delete` once it has opened the message and either stored
it or refused it for good (and sent a `nack` receipt, below). A message
never deleted is sent again on the next `fetch`, after a reconnection; the
recipient's replay check turns the repeat into a second receipt rather than
a second copy. `deposited_at` is shown to the recipient's person only as
information; what the recipient checks is the signed send time inside the
envelope.

### Forward (live requests)

```
client -> relay  {"t":"forward", "req":..., "sealed":<sealed>}
relay  -> client {"t":"forwarded", "req":...}                   (to the sender)
relay  -> client {"t":"live", "sealed":<sealed>}                (to the recipient)
```

For requests that are only useful while both sides are online, such as
`squawk sessions` (task 7). The relay applies the same sender and allow-list
checks as for a deposit, then passes the sealed message straight to the
recipient's connection without storing it. If the recipient is not
connected, it answers `refused` with `offline`, which `squawk sessions`
reports as "Bob is offline". The answer travels back the same way, as a
`forward` from the recipient.

### Invites (pairing through the relay)

People on different networks cannot find each other by mDNS, so pairing
through the relay starts from a one-time invite code (task 8).

```
A -> relay  {"t":"invite-create", "req":...}
relay -> A  {"t":"invite", "req":..., "code":"K7QM-4XRT", "expires_at":<ISO time>}

B -> relay  {"t":"invite-join", "req":..., "code":"K7QM-4XRT"}
relay -> B  {"t":"invite-joined", "req":..., "room":<room id>, "peer":<A's key id>}
relay -> A  {"t":"invite-joined", "req":<A's invite-create req>, "room":<room id>, "peer":<B's key id>}

either -> relay  {"t":"pair", "room":..., "frame":<a pairing frame>}
relay -> other   {"t":"pair", "room":..., "frame":<the same frame>}
either -> relay  {"t":"pair-end", "room":...}
```

- `squawk invite` creates the code; the person reads it to the other person,
  who runs `squawk pair --code K7QM-4XRT`. The code is 8 characters from
  Crockford's base32 alphabet (about 40 bits), shown with a hyphen in the
  middle; case and the hyphen are ignored when typed.
- A code is valid for 10 minutes and for one join. The relay keeps only a
  SHA-256 hash of it. Both sides must stay connected; if A disconnects, the
  invite is gone.
- After `invite-joined`, the two sides run the existing pairing exchange
  (`pairing.py`) with B as the initiator: `pair-commit`, `pair-nonce`,
  `pair-reveal`, the 6-digit codes, `pair-confirm` or `pair-abort`. Each
  pairing frame is carried unchanged inside a `pair` frame. `pair-commit`
  and `pair-nonce` gain one optional field, `"relay"`, the sender's relay
  URL, which the other side saves with the contact.
- Either side sends `pair-end` when pairing finishes, fails or is cancelled;
  the relay forgets the room. A room also ends when either side disconnects,
  and after 10 minutes in any case.
- When pairing succeeds each side adds the other to its allow list and sends
  a new `allow`.
- The prompts tell both people to compare the 6-digit codes over a phone or
  video call, not by sending them through squawk or any channel the relay
  could touch. On the local network the WebSocket handshake proves which key
  each side holds; through the relay, the relay itself tells each side the
  other's key and could lie. The code comparison is what catches that (see
  threat 13).

### Keeping the connection alive

Both sides use WebSocket ping frames every 30 seconds and close a
connection that has not answered for 60 seconds. The client reconnects with
backoff (1 second, doubling to at most 5 minutes, with random jitter) and,
after each `ok`, sends `allow` and then `fetch`.

## End-to-end receipts

A deposit answered with `deposited` only says the relay has the message.
To learn that the recipient's service received it, the recipient sends a
**receipt**: a sealed envelope addressed to the original sender and
deposited into the sender's mailbox like any message (task 2).

A receipt is an ordinary squawk envelope with:

- `kind`: `"ack"` (stored) or `"nack"` (refused for good),
- `in_reply_to`: the id of the message it answers,
- `thread_id`: that message's thread,
- `body`: empty for `ack`; for `nack`, the reason code (as in `network.py`'s
  nack reasons, for example `bad_signature` or `message id already in use`).

Because a receipt is sealed and signed by the recipient's key, the relay
cannot read, forge or alter one. A receipt is never itself acknowledged, is
never shown to anyone's Claude, and is accepted only if `in_reply_to` names
a message this service sent to that same contact.

The new kinds `ack` and `nack` travel only through the relay, between
services that both support it. A squawk 0.1 service never receives them.

Requests and answers carried by `forward` (for example the session list)
are sealed envelopes too, of kinds `"sessions-request"` and `"sessions"`,
with the request id in `in_reply_to` and the answer's JSON in `body`. They
are never stored or shown.

## What the recipient checks

A message that arrives through the relay is opened with `open_sealed` like
one from the local network. The differences:

- **Sender.** On the local network the signed sender must match the key that
  proved itself on the connection. Through the relay, the connection is to
  the relay, so the recipient instead checks that the signed sender is a
  paired, unblocked contact. The relay also checks that `sealed.from` is the
  depositor's key, but the recipient does not rely on that.
- **Freshness.** On the local network a message whose signed send time is
  more than 5 minutes from the local clock is refused, and a waiting message
  is signed again at each attempt. A message held by the relay cannot be
  signed again, so through the relay a send time up to **7 days and 10
  minutes** in the past (and at most 5 minutes in the future) is accepted.
  The 10 minutes allow for two clock differences: the relay's 7 days are
  counted by the relay's clock, the send time by the sender's and the age
  by the recipient's.
- **Replays.** Seen message ids are kept for 7 days and 15 minutes, for both
  routes, so an id accepted once is refused for the whole time any copy of
  it could still be accepted. After that, a copy is too old to pass the
  freshness check.

A message the recipient refuses for good is answered with a `nack` receipt
and deleted at the relay. A message it cannot handle right now (for example
its database is locked) is not deleted, and comes back on the next fetch.

## Sender's outbox

Task 6 adds a `relayed` state to the outbox: the relay answered `deposited`
and the sender is waiting for the receipt. An `ack` receipt marks the
message delivered; a `nack` marks it failed with the reason. A message
still `relayed` after 7 days, which the relay will have deleted by then, is
marked failed as undelivered.

## Limits

All limits are enforced by the relay; the client keeps within them.

| What | Limit |
| --- | --- |
| WebSocket frame | 1 MiB, the same as on the local network |
| Sealed message in a deposit or forward | 512 KiB of JSON text |
| `req`, `id` | 64 and 128 characters |
| Messages waiting in one mailbox | 1,000 |
| Total size waiting in one mailbox | 50 MiB |
| Time a message waits at the relay | 7 days from when it arrived, then deleted |
| Deposits from one key | 60 per minute (bursts of 20) |
| Forwards from one key | 30 per minute |
| Allow list | 1,000 keys; replaced at most 30 times per minute |
| Deliveries outstanding (sent, not deleted) | 32 per connection |
| Invites created by one key | 10 per hour; one open at a time |
| Invite joins | 10 attempts per minute per connection, 30 per hour per IP address |
| Invite code | 10 minutes, one use |
| Pairing room | 10 minutes; `pair` frames: 20 per room |
| New connections from one IP address | 30 per minute |
| Time to authenticate | 10 seconds |
| Idle connection | ping every 30 s, closed after 60 s without an answer |

Expired messages and invites are purged once a minute and when the relay
starts.

A client that stops reading while more than 8 MiB of frames wait to be
written to it is disconnected.

Limits "per IP address" use the address the connection comes from. Behind a
proxy that terminates TLS, every connection comes from the proxy, so the
relay is started with `--trust-forwarded-for` and uses the last address in
the `X-Forwarded-For` header the proxy adds instead. Without a proxy that
option must stay off, or a client could claim any address.

## What the relay stores

In SQLite, in its data directory (a Docker volume for the local relay):

- its own key;
- each mailbox: key id, when it was created, when it last connected;
- each allow list: owner key id and the allowed key ids;
- each waiting message: relay id, sender key id, recipient key id, message
  id, arrival time, the sealed message;
- each open invite: hash of the code, the creating key id, expiry time.

Rate limit counters live in memory only.

## Out of scope for this epic

- Public deployment with TLS, and a trial across real networks.
- Pinning or checking the relay's own key (threat 16).
- Depositing into a contact's relay when it differs from your own.
- Hiding from the relay who talks to whom.
- Peer-to-peer connections through NAT.
