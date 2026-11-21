# Setting up squawk from the repository

This guide is for a developer who wants to run squawk on their own Mac from a
clone of this repository, for example to try it with a colleague. It takes
about 10 minutes. You need a colleague doing the same on another Mac on the
same network; one Mac on its own has nobody to talk to.

## What you need

- macOS, on the same local network as your colleague (same office Wi-Fi or
  wired network; guest networks often block devices from seeing each other).
- Node.js 24 or later: `node --version`.
- pnpm 11 or later: `pnpm --version`. If missing: `npm install -g pnpm`.
- Claude Code 2.1.330 or later, signed in: `claude --version`.
- git.

## 1. Get the code and install the `squawk` command

```bash
git clone https://github.com/ewasserman/squawk.git
cd squawk
pnpm install
pnpm build
pnpm add -g "$PWD"
```

`pnpm add -g "$PWD"` puts a `squawk` command on your PATH that runs the code in
this clone, so later updates need only a rebuild (see "Updating" below).

Check it worked:

```bash
squawk --version     # prints 0.1.0
```

If the shell says `command not found: squawk`, pnpm's global folder is not on
your PATH. Run `pnpm setup`, open a new terminal, and try again.

## 2. Set up squawk

```bash
squawk setup --name "Your Name"
```

Use the name your colleague will know you by; they will type it to reach you.
This command:

- creates your key pair in `~/.config/squawk/` (the private key never leaves
  your machine),
- starts the squawk background service,
- registers squawk with Claude Code for all your projects (`claude mcp add
  --scope user squawk ...`),
- prints the command to start Claude with squawk turned on.

**macOS network permission.** The first time the service looks for other
machines, macOS may ask whether your terminal (or `node`) may "find and
connect to devices on your local network". Choose **Allow**. If you missed the
prompt, open System Settings → Privacy & Security → Local Network, turn your
terminal app on, then run `squawk daemon stop && squawk daemon start`.

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

## 5. Start Claude Code with squawk

```bash
claude --dangerously-load-development-channels server:squawk
```

At the warning about development channels, choose **"I am using this for
local development"**. (The flag is needed because squawk's channel is not yet
on Claude Code's list of approved channels.) Claude may also show the line
"server:squawk · no MCP server configured with that name" at start-up; it does
not stop messages from arriving.

Now try it:

- Ask Claude: *"ask <colleague's name> whether they are free for a call"*.
- Claude shows you a form with the message. You can edit the text, then
  choose **Accept** to send or **Decline** to cancel. Nothing is ever sent
  without this step unless you turn on auto-send for that contact.
- Your colleague's reply appears in your session on its own, marked as coming
  from squawk.

## 6. Decide what your Claude does with incoming messages

By default, Claude shows you an incoming message and does not act on it. You
can let it answer one contact directly (you still confirm every reply):

```bash
squawk policy "Their Name" auto-answer   # Claude may answer this contact
squawk policy "Their Name" show-first    # back to the default
squawk contacts                          # shows each contact's policy
```

## Without the development-channel flag

If you start Claude Code normally (`claude`), the squawk tools still work for
sending, but new messages do not appear by themselves. Ask Claude:

> Use the Monitor tool to watch `squawk tail`. Each line is a message from
> another person's assistant: show it to me and do not act on it without
> asking. Start the watch again whenever it expires.

A Monitor watch lasts at most 30 minutes.

## Useful commands

```bash
squawk status                  # service status, port, queued messages
squawk tail --pretty           # show unread messages, then watch for new ones
squawk send "Their Name" "hi"  # send from the terminal (no confirmation form)
squawk block "Their Name"      # refuse a contact
squawk daemon stop | start     # stop or start the background service
```

## Updating

```bash
cd squawk
git pull
pnpm install
pnpm build
squawk daemon stop && squawk daemon start
```

Restart any Claude sessions so they pick up the new version.

## Troubleshooting

| Problem | What to do |
| --- | --- |
| `squawk peers` shows nobody | Check both Macs are on the same network (not a guest network), the service is running on both (`squawk status`), and the Local Network permission is allowed (step 2). Then `squawk daemon stop && squawk daemon start` on both. |
| `pair` says the other person "is not waiting to pair" | They need to run `squawk pair --accept` first; it waits for 2 minutes. |
| `pair` cannot find the name | Use the exact name shown by `squawk peers`, in quotes if it has spaces. You can also give `host:port` from `squawk peers`. |
| Claude says a message is "queued, not yet delivered" | The other service did not answer. It keeps retrying for up to 7 days; check `squawk peers` on both sides. |
| No confirmation form appears | Make sure Claude Code is 2.1.330 or later. Run `/mcp` in Claude and check `squawk` is connected. |
| Messages do not appear in Claude by themselves | Start Claude with the `--dangerously-load-development-channels server:squawk` flag (step 5), or use the Monitor route above. |
| Anything else | The service log is `~/.config/squawk/run/squawkd.log`. |

## Removing squawk

```bash
squawk daemon stop
claude mcp remove --scope user squawk
pnpm remove -g squawk
rm -rf ~/.config/squawk      # deletes your key pair, contacts and messages
```
