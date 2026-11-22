# Setting up squawk

This guide is for someone who wants to run squawk on their own Mac, for
example to try it with a colleague. It takes about 10 minutes. You need a
colleague doing the same on another Mac on the same network; one Mac on its
own has nobody to talk to.

## What you need

- macOS, on the same local network as your colleague (same office Wi-Fi or
  wired network; guest networks often block devices from seeing each other).
- uv: `uv --version`. If missing:
  `curl -LsSf https://astral.sh/uv/install.sh | sh` (or `brew install uv`).
  uv downloads a suitable Python by itself; you do not need to install one.
- Claude Code 2.1.224 or later, signed in: `claude --version`.

## 1. Install the `squawk` command

```bash
uv tool install git+https://github.com/ewasserman/squawk
squawk --version     # prints 0.2.0
```

If the shell says `command not found: squawk`, uv's folder for commands is
not on your PATH. Run `uv tool update-shell`, open a new terminal, and try
again.

## 2. Set up squawk

```bash
squawk setup --name "Your Name"
```

Use the name your colleague will know you by; they will type it to reach you.
This command:

- creates your key pair in `~/.config/squawk/` (the private key never leaves
  your machine),
- starts the squawk background service,
- adds two hooks to your Claude Code settings (`~/.claude/settings.json`; the
  old file is kept as `settings.json.squawk-backup`). They let each Claude
  Code session tell squawk it is open, so messages can be delivered into it,
- installs a squawk skill (`~/.claude/skills/squawk/`) that tells Claude how
  to send, reply and treat incoming messages.

You only run `setup` once per Mac. If it prints warnings, read them: they
mean something in your settings would stop messages reaching your sessions.

**macOS network permission.** The first time the service looks for other
machines, macOS may ask whether your terminal (or Python) may "find and
connect to devices on your local network". Choose **Allow**. If you missed
the prompt, open System Settings → Privacy & Security → Local Network, turn
your terminal app on, then run `squawk daemon stop && squawk daemon start`.

## 3. Check you can see each other

Once both of you have done step 2:

```bash
squawk peers
```

You should see your colleague's name. If not, see "Troubleshooting" below.

## 4. Pair, once

Pairing makes each of you trust the other's key. Only paired contacts can send
you messages. Agree who goes first:

| Person A (waits) | Person B (connects) |
| --- | --- |
| `squawk pair --accept` | |
| | `squawk pair "A's name"` (within 2 minutes) |

Both screens then show a 6-digit code. **Compare the codes with each other** in
person or on a call, not over chat or email. If they match, both answer `y`. If
they differ, answer `n`: something between you is interfering.

Check it worked:

```bash
squawk contacts     # shows your colleague as "paired"
```

## 5. Use it from Claude Code

Start Claude Code as usual, in any project:

```bash
claude
```

Sessions that were already open before step 2 must be restarted once. Check
that squawk knows your sessions:

```bash
squawk sessions
```

Each session is labelled with its git repository and branch, for example
`api-server@main`. Your colleague's Claude can see these labels (not your
files or folders) to pick the right session; `squawk sessions --share off`
stops that.

Now try it:

- Ask Claude: *"ask <colleague's name> whether they are free for a call"*.
  Claude lists their sessions and picks one, or asks you which.
- A dialog shows you the message. You can edit the text, then choose
  **Send** or **Cancel**. Nothing is sent without this step unless you turn
  on auto-send (step 6).
- Your colleague's answer appears in the session that asked, by itself,
  marked as a message from another session.

A message that names none of your open sessions is not guessed at: it waits
in `squawk inbox` and your Mac shows a notification. To have one session take
all such messages: `squawk sessions --catch-all <label>`.

## 6. Decide what your Claude does with incoming messages

By default, Claude shows you an incoming message and does not act on it. You
can let it answer one contact directly (you still confirm every reply in the
dialog):

```bash
squawk policy "Their Name" auto-answer   # Claude may answer this contact
squawk policy "Their Name" show-first    # back to the default
squawk auto-send "Their Name" on         # no confirmation dialog for this contact
squawk auto-send --default on            # no dialog for anyone without their own setting
squawk contacts                          # shows each contact's settings
```

## Useful commands

```bash
squawk status                  # service status, sessions, queued messages
squawk inbox                   # unread messages
squawk tail --pretty           # unread messages, then watch for new ones
squawk send "Their Name" "hi"  # send from the terminal
squawk block "Their Name"      # refuse a contact
squawk daemon stop | start     # stop or start the background service
```

The service is not started when your Mac starts. The first Claude Code
session you open starts it, or run `squawk daemon start`.

## Updating

```bash
uv tool upgrade squawk
squawk daemon stop && squawk daemon start
```

Restart open Claude Code sessions so they pick up the new version.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| `squawk peers` shows nobody | Check both Macs are on the same network (not a guest network), the service is running on both (`squawk status`), and the Local Network permission is allowed (step 2). Then `squawk daemon stop && squawk daemon start` on both. |
| `pair` says the other person "is not waiting to pair" | They need to run `squawk pair --accept` first; it waits for 2 minutes. |
| `pair` cannot find the name | Use the exact name shown by `squawk peers`, in quotes if it has spaces. You can also give `host:port` from `squawk peers`. |
| `squawk sessions` lists no sessions | Restart Claude Code (sessions opened before `setup` are not registered). Check `claude --version` is 2.1.224 or later and that `/hooks` in Claude lists squawk's SessionStart hook. |
| A message says "queued, not yet delivered" | The other service did not answer. It keeps retrying for up to 7 days; check `squawk peers` on both sides. |
| No dialog appears when Claude sends | The dialog needs a logged-in screen session on the Mac. Check `squawk contacts`: with auto-send on, no dialog is shown. |
| Claude says it cannot find `squawk` | Run `uv tool update-shell`, open a new terminal, and restart Claude Code. |
| Messages never appear in a session | Check `squawk sessions` shows it as reachable. Sessions started with `--dangerously-skip-permissions` hold each message for your approval, and the setting `crossSessionInbound: "refuse"` blocks them; messages then wait in `squawk inbox`. |
| Anything else | The service log is `~/.config/squawk/run/squawkd.log`; the hooks log to `~/.config/squawk/run/hook.log`. |

## Removing squawk

```bash
squawk uninstall --purge     # removes the hooks and skill, stops the service,
                             # deletes ~/.config/squawk (your key pair, contacts and messages)
uv tool uninstall squawk
```
