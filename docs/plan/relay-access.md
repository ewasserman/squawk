# Who may use a relay

Today any key that signs the relay's challenge gets a mailbox
([relay.md](relay.md), "Proving a key to the relay"). Strangers cannot
message anyone, because deposits are checked against each mailbox's allow
list, but they can open mailboxes of their own, store up to 50 MiB in each
and create invites. That is acceptable for a relay on a local network or in
Docker for testing. It is not acceptable for a relay on the open internet
that is meant for a fixed group of people.

This plan adds an **access check** to the relay: after a client proves its
key, the relay decides whether that key may use it at all. The relay
operator chooses how, when starting the relay:

| Mode | Who is admitted | Meant for |
| --- | --- | --- |
| `open` | Any key (today's behaviour) | Local testing, a relay on a trusted network |
| `keys` | Keys listed in a file | Operators who want no outside service |
| `github` | Keys whose owner signed in with GitHub as a user listed in a file | A relay on the internet for a known group of people |

Google sign-in is a later addition, as another mode beside `github`.

## Principles

- **The relay can protect itself, and the operator decides whether it
  should.** In `keys` and `github` modes the access check is enough on its
  own to keep strangers out of a relay on the open internet; it does not
  depend on a VPN, a firewall or a particular proxy. An operator who already
  limits who can reach the relay at the network level (a VPN such as
  Tailscale or WireGuard, or a firewall) may instead choose `open` and let
  that decide. Either is a legitimate choice; the relay only insists that the
  choice is made explicitly (see "Choosing the mode"). How the relay is
  deployed is the operator's choice; the deployment guide describes some
  options without requiring any of them.
- **TLS stays outside the relay.** As now, the relay speaks plain WebSocket
  and runs behind something that terminates TLS (Caddy, nginx, a Cloudflare
  tunnel, `tailscale serve`, or anything else).
- **Nothing about messages changes.** Messages are still sealed end to end,
  and the relay is still treated as possibly dishonest (threats 9–17 in
  [security.md](security.md)). The access check protects the relay and its
  operator, not the content of messages.
- **What the relay says about a person is not proof.** A relay that has
  checked someone's GitHub account still only *says* so. Pairing still
  depends on comparing the 6-digit code over a call (threat 13).

## Choosing the mode

New options for `squawk relay serve`:

```
--access open|keys|github
--allowed-keys FILE          (keys mode)
--allowed-users FILE         (github mode)
--github-client-id ID        (github mode)
--max-keys-per-user N        (github mode; default 5)
```

`--access` defaults to `open` only when the relay listens on a loopback
address (`127.0.0.1`, `::1`) and `--trust-forwarded-for` is not given. In
every other case, including listening on `0.0.0.0` and running behind a
proxy, the relay refuses to start until `--access` is given explicitly. A
relay behind a proxy on the same machine listens on loopback but is reached
from the internet; `--trust-forwarded-for` is the sign that it is behind a
proxy. In `open` mode the relay prints at startup:

```
Access: open. Anyone who can reach this relay can open a mailbox on it.
```

The Dockerfile's default command passes `--access open` explicitly, since
it listens on `0.0.0.0` inside the container, and `compose.yaml` keeps
publishing the port on `127.0.0.1` only by default.

## Protocol changes

### `hello` says how the relay admits keys

```
relay -> client  {"t":"hello", "v":1, "key":..., "challenge":..., "access":"open"|"keys"|"github"}
```

`access` is informational: it lets the client explain what is happening.
The client does not rely on it, and a missing `access` means `open`. Clients
from before this change ignore the field.

### After `auth`

The signature check is unchanged. If the signature is valid, the relay looks
up the key:

- **Admitted:** the relay answers `ok` as now.
- **Refused** (`keys` mode and the key is not in the file, or `github` mode
  and the key belongs to a user no longer in the file): the relay closes the
  connection with the new code `4003`, reason `not permitted`.
- **Unknown** (`github` mode, a key the relay has not seen before):

  ```
  relay -> client  {"t":"login-required", "provider":"github"}
  ```

  The connection stays open for at most 30 seconds, waiting for
  `login-start`. Any other frame, or none, closes it with `4003`.

A client from before this change sees an unexpected frame or a close and
keeps retrying with its usual backoff. It cannot use a relay in `keys` or
`github` mode until it is updated, which is correct.

### Signing in with GitHub (device flow)

GitHub's device flow lets a program without a web server sign a person in:
the person opens a page on github.com, types a short code and approves.
The relay runs the whole flow, so the GitHub token never leaves the relay.

```
client -> relay  {"t":"login-start"}
relay  -> client {"t":"login", "verification_uri":"https://github.com/login/device",
                  "user_code":"ABCD-1234", "expires_at":<ISO time>}
                  ... the person approves on github.com ...
relay  -> client {"t":"ok", "waiting":0, "user":"<github login>"}
```

or, if it does not work out:

```
relay  -> client {"t":"login-failed", "reason":<code>}    then close with 4003
```

with reasons `not-permitted` (the GitHub user is not in the file, or
already has the most keys allowed), `denied` (the person declined on
GitHub), `expired` (not approved in time), `busy` (too many sign-ins in
progress; try later) and `error` (GitHub could not be reached).

On the relay:

1. `login-start` makes the relay request a device code from GitHub
   (`POST https://github.com/login/device/code` with the client id and **no
   scopes**). No scopes means the token can read only the user's public
   profile.
2. The relay sends `login` with the code and URL GitHub gave it. It polls
   GitHub for the token at the interval GitHub gives, slowing down when
   GitHub asks it to, until the code expires (GitHub's limit, currently 15
   minutes).
3. With the token, it reads the user (`GET https://api.github.com/user`):
   their login and their numeric id.
4. It checks the user against the allowed users file (below). If they are
   permitted, it records that the key belongs to that user, forgets the
   token, and answers `ok` with `user` set. The connection then carries on
   like any other.

The relay keeps the token in memory only, and only until step 3 is done.
It cannot revoke the token, because revoking needs the OAuth app's client
secret and the device flow does not use one; a token with no scopes can
only read public profile information.

The connection stays open while the person signs in; neither the 10-second
authentication timeout nor the 30-second wait for `login-start` applies after
`login-start`. The
usual pings keep it alive.

### The allowed users file

One GitHub user per line; blank lines and text after `#` are ignored:

```
# name           optional GitHub user id
alice
bob              12345678
```

- **Pinning the account.** GitHub usernames can be renamed, and a freed name
  can be taken by someone else. A line with an id admits only the account
  with that id. A line without an id admits the first account that signs in
  with that name, and the relay then remembers that account's id; a later
  sign-in with the same name but another id is refused and logged. The relay
  prints the id after each first sign-in, so the operator can copy it into
  the file.
- **Removing someone.** Delete their line. The relay rereads the file when it
  changes (checked at least once a minute) and on `SIGHUP`. Keys belonging to
  a user who is no longer listed are refused from then on, and their open
  connections are closed with `4003`. Their mailboxes are deleted along with
  any messages waiting in them.
- **A new computer.** The person signs in again from the new computer; that
  key is added to their account, up to `--max-keys-per-user`. The operator
  can remove old keys (see "Administration").

### The allowed keys file (`keys` mode)

One squawk key id per line, optionally followed by a name for the operator's
own reference; text after `#` is ignored. Reread on change and on `SIGHUP`,
as above. A key no longer listed is refused, its connection closed, and its
mailbox deleted.

## What the relay stores (additions)

- each GitHub user that has signed in: numeric id, current login, when they
  first and last signed in;
- each admitted key's owner: key id, GitHub user id, when it was added.

No tokens are stored.

## Limits (additions)

| What | Limit |
| --- | --- |
| Time to send `login-start` after `login-required` | 30 seconds |
| Sign-ins started from one IP address | 10 per hour |
| Sign-ins in progress at once, per IP address | 2 |
| Sign-ins in progress at once, whole relay | 20 |
| Keys per GitHub user | 5 (`--max-keys-per-user`) |

These keep a stranger from making the relay ask GitHub for device codes, or
poll GitHub, without end. A refused key gets nothing else from the relay: no
mailbox, no invites, no deposits.

## The client

- On `login-required`, the service stops reconnecting on its own and
  reports the state. `squawk relay status` says:

  ```
  Relay: wss://relay.example.net (needs sign-in: run `squawk relay login`)
  ```

  It tries again only when `squawk relay login` asks it to, or every 6
  hours, in case the operator added the key another way.
- On close code `4003`, it reports `not permitted by this relay; ask the
  person who runs it` and retries only every 6 hours.
- **`squawk relay login`** asks the service to connect and send
  `login-start`, then prints:

  ```
  Open https://github.com/login/device and enter ABCD-1234 (valid for 15 minutes).
  GitHub should ask only to read your public profile. If it asks for
  anything more, deny it: the relay should never need more.
  ```

  and waits for `ok` (printing `Signed in to the relay as alice`) or for
  `login-failed` (printing what went wrong).
- `squawk relay set` with a relay in `github` mode ends by saying that the
  person needs to run `squawk relay login`, instead of reporting the
  connection as failed.

## Administration

`squawk relay admin` works directly on the relay's data directory, on the
machine where the relay runs:

```
squawk relay admin users [--data DIR]            # GitHub users, their keys, last seen
squawk relay admin remove-key KEY [--data DIR]   # forget one key and delete its mailbox
```

The running relay notices a removed key within a minute and closes its
connection. Adding and removing users is done in the allowed users file.

## Deployment guide

A new section in `docs/setup-guide.md` (or its own `docs/running-a-relay.md`)
covers what every deployment needs:

- something in front of the relay that terminates TLS, so clients use
  `wss://`;
- the relay listening on `127.0.0.1` behind that proxy, started with
  `--trust-forwarded-for`, and with `--access` set (normally `github` or
  `keys`);
- registering a GitHub OAuth App with device flow turned on (no callback URL
  or client secret needed), and writing the allowed users file;
- keeping the data directory (it holds the relay's key and waiting
  messages) backed up and readable only by the relay's user.

Then two worked examples, neither required:

- **Public:** a free dynamic DNS name (for example DuckDNS), port 443
  forwarded to Caddy, Caddy getting a Let's Encrypt certificate and passing
  connections to the relay.
- **Private:** Tailscale, with `tailscale serve` giving a `*.ts.net` name and
  certificate, and the relay's machine shared only with the people who use
  it. No ports are opened on the router. Here `--access open` is a
  reasonable choice, because Tailscale already decides who can connect. The
  guide says what that means: everyone who can reach the machine through
  Tailscale (every device and user on the tailnet, and anyone it is shared
  with) can use the relay, so Tailscale's access rules are what limit it;
  turning on Tailscale Funnel for that port would make it an open public
  relay; and `--access github` can be used as well, for a second check. The
  guide also checks whether `tailscale serve` adds `X-Forwarded-For`, which
  `--trust-forwarded-for` needs so that the per-address limits see each
  person and not only `127.0.0.1`.

## New threats

To be added to [security.md](security.md) as the work lands, numbered after
17.

**18. Strangers using a relay meant for a group.** Someone not in the group
opens mailboxes, stores data or creates invites. *Mitigation:* `keys` and
`github` modes refuse every key that is not admitted, right after it proves
its key; a refused key can do nothing else. A relay that listens beyond
loopback or behind a proxy will not start without an explicit access mode.

**19. A GitHub username changing hands.** A listed user renames their account
and someone else takes the old name. *Mitigation:* the relay remembers the
numeric GitHub id of the first account to sign in with a name and refuses
other accounts with that name; the operator can pin the id in the file.
*What remains:* a name in the file that nobody has signed in with yet admits
whoever owns that name at the time of their first sign-in.

**20. A dishonest relay misusing the sign-in.** The device code the person
types comes from the relay, so a dishonest relay could show a code that
belongs to some other OAuth app, one that asks for access to the person's
repositories. *Mitigation:* GitHub's approval page shows the app's name and
what it asks for; `squawk relay login` tells the person that the page should
ask only for public profile information and to deny anything more. *What
remains:* this depends on the person reading GitHub's page.

**21. GitHub tokens at the relay.** Someone who controls the relay's machine
during a sign-in obtains the token. *Mitigation:* the relay asks for no
scopes, so the token can only read public profile information, and keeps
it in memory only until it has read the user. *What remains:* the token
cannot be revoked by the relay and stays valid at GitHub until the person
revokes it in their GitHub settings or it goes unused for a year.

**22. The relay knows who owns each key.** In `github` mode the relay links
each key, and so each mailbox and its traffic, to a GitHub account. This
adds to the metadata in threat 15. *Accepted:* the operator is the person
who chose to admit those users. `keys` mode links nothing to an outside
account.

**23. Flooding the sign-in.** Someone starts many sign-ins so the relay keeps
asking GitHub for codes and polling for tokens, possibly reaching GitHub's
rate limits and blocking real sign-ins. *Mitigation:* the limits on sign-ins
per IP address and for the whole relay, above. As with threat 17, keeping a
public relay up under a determined flood is out of scope.

## Out of scope

- Google and other sign-in providers (a later mode beside `github`).
- Showing the relay's statement of someone's GitHub user during pairing.
  That would be a hint only, like a name found on the local network, and
  needs its own look at threat 13.
- Checking or pinning the relay's own key (threat 16).
- Relays operated by more than one person, or with an admin web page.

## Tasks

The work is GitHub epic #50; its sub-issues are the tasks (task *n* is
issue #*n+50*). They are tracked in beads under `sq-lk6`.
