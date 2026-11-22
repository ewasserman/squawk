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

Requires macOS or Linux, [uv](https://docs.astral.sh/uv/) and Claude Code
2.1.224 or later. On Linux you also need zenity or kdialog for the
confirmation dialog (see [Linux](#linux)). Both people do this on their own
machine; the machines must be on the same network.

1. Install and set up (once per machine):

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

3. Start Claude Code as usual (`claude`), in any project. Ask it something
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
4. otherwise no session: it waits in `squawk inbox` and your computer shows a
   notification.

Paired contacts can list your sessions' labels and branches;
`squawk sessions --share off` stops that.

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
squawk sessions          # this machine's Claude Code sessions
squawk inbox             # unread messages
squawk tail --pretty     # unread messages, then new ones as they arrive
squawk send Bob "text"   # send from the terminal (or pipe text in)
squawk reply <msg id> "text"
squawk contacts          # paired and blocked contacts
squawk block Bob         # refuse Bob's connections and messages
squawk status            # service status, sessions and queues
squawk daemon start|stop|status
squawk uninstall         # remove the hooks and skill (--purge also deletes ~/.config/squawk)
```

## macOS network permission

macOS may ask whether your terminal (or Python) may "find and connect to
devices on your local network". Allow it, or squawk cannot reach other
machines. To check later: System Settings → Privacy & Security → Local
Network.

## Linux

Squawk works the same way on Linux, with these differences:

- **Confirmation dialog.** It is shown by zenity or by kdialog (kdialog first
  on KDE). Squawk looks for them in `/usr/bin`, `/bin`, `/usr/local/bin` and
  `/run/current-system/sw/bin`, never on PATH, so another program cannot
  stand in for the dialog. If `squawk setup` warns that it found neither,
  install one, for example `sudo apt install zenity`. kdialog's Send button
  is labelled OK.
- **Notifications** for messages no session takes use `notify-send`
  (`libnotify-bin` on Debian and Ubuntu, `libnotify` elsewhere). Without
  it there is no notification; check `squawk inbox`.
- **Firewall.** If a firewall blocks incoming connections (ufw, firewalld),
  allow squawk's TCP port from your local network, or other people cannot
  connect to you to pair or deliver messages. `squawk status` shows the
  port; the service uses the same one again after a restart unless it is
  taken. For example, with ufw (whose default rules already let mDNS
  discovery through):

  ```bash
  sudo ufw allow from 192.168.1.0/24 to any port <port> proto tcp
  ```

  With firewalld: `sudo firewall-cmd --permanent --add-service=mdns
  --add-port=<port>/tcp && sudo firewall-cmd --reload`.
- **uv**: some distributions package it (`sudo pacman -S uv` on Arch);
  otherwise use the installer in the [setup guide](docs/setup-guide.md).
  uv uses an installed Python 3.12 or later, or downloads one.

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
