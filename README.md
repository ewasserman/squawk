# squawk

Squawk lets Claude Code sessions on different machines on the same local
network send messages to each other, so that two people's assistants can
exchange questions and answers.

Each machine runs a small background service (`squawkd`). Services find each
other on the local network with mDNS, people pair them once by comparing a
6-digit code, and after that every message is signed by its sender and
encrypted for its recipient. Claude sends with the `squawk` command; you see
each message in a dialog before it goes. Incoming messages are written
straight into the right Claude Code session through Claude Code's own
messaging between sessions, so you start Claude as usual, with no extra
flags.

Security design: [docs/plan/security.md](docs/plan/security.md).
Step-by-step guide for trying it with a colleague:
[docs/setup-guide.md](docs/setup-guide.md).

## Quickstart

Requires macOS, [uv](https://docs.astral.sh/uv/) and Claude Code 2.1.224 or
later. Both people do this on their own Mac; the Macs must be on the same
network.

1. Install and set up (once per Mac):

   ```bash
   uv tool install git+https://github.com/ewasserman/squawk
   squawk setup --name "Your Name"
   ```

   `setup` creates your key pair in `~/.config/squawk/`, starts the
   background service, adds two hooks to your Claude Code settings so that
   every session registers itself with squawk, and installs a squawk skill
   that tells Claude how to use it.

2. Pair, once per colleague. One of you waits, the other connects:

   ```bash
   squawk pair --accept         # Bob
   squawk peers                 # Alice: see who is online
   squawk pair "Bob"            # Alice
   ```

   Both screens show a 6-digit code. Check that the codes are the same (in
   person or on a call) before answering `y`. If they differ, answer `n`.

3. Choose which projects your contacts may see and write to. Nothing is
   allowed until you do this:

   ```bash
   squawk sessions --allow 'your-org/*'   # or '*' for every project
   ```

4. Start Claude Code as usual (`claude`), in any project. Ask it something
   like "ask Bob whether the staging build is green". Claude looks up Bob's
   open sessions, picks the one that fits, and a dialog shows you the message
   to edit, send or cancel. Bob's answer appears in your session by itself.

## Which session gets a message

Each Claude Code session is labelled with its git repository and branch, for
example `api-server@main`. A message goes to:

1. the session that already has that conversation (replies come back to the
   session that asked);
2. otherwise the session the sender named (`squawk send Bob --session
   api-server@main ...`; `squawk sessions Bob` lists Bob's sessions);
3. otherwise the session you chose for such messages
   (`squawk sessions --catch-all <label>`);
4. otherwise no session: it waits in `squawk inbox` and your Mac shows a
   notification.

## Which sessions your contacts can see

Paired contacts can list the labels and branches of the sessions you allow,
and address them. You allow sessions by project, with an allow list and a
deny list of patterns:

```bash
squawk sessions --allow 'your-org/*'    # show sessions in these projects
squawk sessions --allow '*'             # show every session
squawk sessions --deny 'some-org/*'     # hide these, even if allowed
squawk sessions --deny '~/clients'      # hide by folder
squawk sessions --forget 'some-org/*'   # take a pattern off both lists
```

A session is visible only if it matches an allow pattern and no deny pattern.
The allow list starts empty, so at first no session is visible. `squawk
sessions` shows each session's project and whether it is visible.

A pattern is a glob (`*` matches anything, "/" included; case does not
matter). It is compared with the session's project, which is the path of the
repository's `origin` remote without the host (`some-org/api-server`), with
each leading part of it (so `some-org` works like `some-org/*`), and with the
name of the repository's folder. A repository with no `origin` remote has
only its folder's name. A pattern starting with `/` or `~` is compared with the folder of
the repository's main checkout instead (outside git, the folder the session
started in), and matches that folder and everything below it. Quote patterns
so that your shell leaves them alone.

A hidden session is not in the list your contacts get, a message naming it
is treated as naming no open session (it waits in `squawk inbox`), and it is
never the catch-all. Your contacts cannot tell a hidden session from one
that is not open. A hidden session can still send messages, and the answers
come back to it; a conversation a session already had when you hid it also
stays with it. The lists are applied by the service on your Mac, so they
hold whatever the other machine asks.

`squawk sessions --share off` stops contacts listing any session; they can
still address a visible one whose label they know.

## What your Claude does with incoming messages

You decide, per contact:

```bash
squawk policy Bob show-first     # the default: show you the message, take no action
squawk policy Bob auto-answer    # Claude may answer directly (you still confirm the reply)
squawk policy --default show-first
squawk auto-send Bob on          # no confirmation dialog for messages to Bob
squawk auto-send --default on    # no dialog for anyone without their own setting
```

Incoming messages are always presented to Claude as information from another
person's assistant, never as instructions from you.

## Other commands

```bash
squawk sessions          # this Mac's Claude Code sessions, the allow and deny lists
squawk inbox             # unread messages
squawk tail --pretty     # unread messages, then new ones as they arrive
squawk send Bob "text"   # send from the terminal (or pipe text in)
squawk reply <msg id> "text"
squawk contacts          # paired and blocked contacts, and the route to each
squawk block Bob         # refuse Bob's connections and messages
squawk status            # service status, sessions, queues and relay connection
squawk relay set <url>   # reach contacts on other networks through a relay (wss://)
squawk relay set --off   # stop using a relay
squawk relay status      # the relay, whether it is connected, messages waiting for it
squawk daemon start|stop|status
squawk uninstall         # remove the hooks and skill (--purge also deletes ~/.config/squawk)
```

## macOS network permission

macOS may ask whether your terminal (or Python) may "find and connect to
devices on your local network". Allow it, or squawk cannot reach other
machines. To check later: System Settings → Privacy & Security → Local
Network.

## Development

Requires uv.

```bash
uv sync
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest
uv run squawk <command>   # the CLI from the sources
```

Set `SQUAWK_HOME` to use a different directory than `~/.config/squawk`, for
example to run two services on one machine.

### A relay for local testing

Services on different networks exchange messages through a relay server
(see [docs/plan/relay.md](docs/plan/relay.md)). To run one locally in
Docker:

```bash
docker compose up relay        # add -d to run it in the background
curl localhost:8765/healthz    # {"status":"ok","version":"..."}
```

It listens on `ws://localhost:8765` and keeps its data (its key, mailboxes
and waiting messages) in the `relay-data` Docker volume, so it survives
`docker compose restart relay`. `docker compose down -v` deletes the data.

Without Docker, `uv run squawk relay serve` runs the same server from the
sources (`--host`, `--port`, `--data`).

The local relay is plain `ws://`, not encrypted with TLS. A service refuses
a `ws://` relay URL unless you allow it explicitly with `--allow-plain` when
setting the relay. Messages are still sealed end to end; what plain `ws://`
exposes is who talks to whom. A deployed relay uses `wss://`.

Point a service at the local relay with
`uv run squawk relay set ws://localhost:8765 --allow-plain` (or
`squawk setup --relay ws://localhost:8765 --allow-plain`), then check the
connection with `uv run squawk relay status`.
