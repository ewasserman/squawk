# Running a relay

A relay lets squawk services that cannot reach each other directly exchange
messages: two people on different networks, or anyone whose network does
not allow direct connections. This guide is for the person who runs one. If
you only want to use a relay someone else runs, see step 7 of the
[setup guide](setup-guide.md).

What the relay can and cannot do:

- It holds sealed messages until the recipient's service fetches them (for
  up to 7 days). It cannot read them: they are encrypted for the recipient
  and signed by the sender ([security.md](plan/security.md), threats 9–17).
- It passes pairing invitations along, but people still compare a 6-digit
  code on a call, so a relay cannot pair itself into a conversation.
- It sees who talks to whom and when, how much, and from which IP
  addresses. Run it somewhere you would be comfortable holding that.

The protocol and the relay's limits are in [plan/relay.md](plan/relay.md);
how it decides who may use it is in
[plan/relay-access.md](plan/relay-access.md).

## Choose who may use it

`squawk relay serve --access` takes one of three modes:

| Mode | Who is admitted | Use it when |
| --- | --- | --- |
| `github` | Keys whose owner signed in with GitHub as a user you list | The relay is on the internet, for a known group of people |
| `keys` | Keys you list in a file | You do not want to depend on GitHub, and can collect each person's key |
| `open` | Anyone who can reach the relay | Something in front of it already limits who can reach it (a VPN such as Tailscale, or a firewall), or for testing |

Every key still has to prove itself, and a key that is not admitted is
disconnected before it can do anything: it gets no mailbox, cannot leave
messages and cannot create invites.

`open` is the default only for a relay that listens on `127.0.0.1` without
`--trust-forwarded-for`, that is, one only this machine can reach. Any other
relay refuses to start until you give `--access`. In `open` mode it says so
when it starts:

```
Access: open. Anyone who can reach this relay can open a mailbox on it.
```

## What every deployment needs

1. **Something in front of the relay that handles TLS**, so that people
   connect with `wss://`. The relay itself speaks plain WebSocket. Caddy,
   nginx, a Cloudflare tunnel or `tailscale serve` all work; the examples
   below use Caddy and Tailscale.
2. **The relay listening on `127.0.0.1`** behind that proxy, started with
   `--trust-forwarded-for` (so that its limits per IP address use each
   person's address from the proxy's `X-Forwarded-For` header, rather than
   the proxy's own address) and with `--access`. Without a proxy, leave
   `--trust-forwarded-for` off, or a client could claim any address.
3. **The list of who may use it**: an allowed users file with a GitHub OAuth
   App (`github` mode), or an allowed keys file (`keys` mode). Both are
   described below.
4. **A data directory** that is kept, backed up and readable only by the
   relay's user (see "The data directory").

A typical command line, for `github` mode:

```bash
squawk relay serve --host 127.0.0.1 --port 8765 \
  --data /var/lib/squawk-relay \
  --trust-forwarded-for \
  --access github \
  --github-client-id Ov23li... \
  --allowed-users /etc/squawk-relay/allowed-users
```

`squawk relay serve --help` lists every option and its default.

**People using the relay need squawk 0.5.0 or later.** Older versions
cannot sign in: against a relay in `github` or `keys` mode they report only
"the relay did not accept our key", and `squawk relay login` does not
exist. They upgrade with `uv tool upgrade squawk`.

### GitHub mode: register an OAuth App

The relay signs people in with GitHub's device flow: `squawk relay login`
shows the person a short code, they enter it at github.com/login/device and
approve, and the relay learns their GitHub user name and numeric id. The
relay asks for no permissions (no scopes), so all it can read is their
public profile. Register the app once:

1. On github.com: **Settings → Developer settings → OAuth Apps → New OAuth
   App**.
2. **Application name**: something people will recognise on GitHub's
   approval page, such as "squawk-relay". **Homepage URL**: any page about
   your relay. **Redirect URI** (or "Authorization callback URL"): any URL;
   the device flow never uses it.
3. Tick **Enable Device Flow**.
4. Tick **Expire user access tokens** if it is offered. The relay uses each
   token once, right away, and then forgets it; with expiry, a token that
   someone captured at the relay stops working after 8 hours
   ([security.md](plan/security.md), threat 21).
5. Register it, and copy the **Client ID** for `--github-client-id`. It is
   not secret. **Do not generate a client secret**: the relay does not use
   one, and without it a refresh token cannot be used.

The **allowed users file** lists one GitHub user name per line, optionally
followed by the account's numeric id; text after `#` and blank lines are
ignored:

```
# name           optional GitHub id
alice
bob              12345678
```

GitHub names can change hands: someone renames their account and a
stranger takes the old name. The relay protects against that by remembering
the numeric id of the first account that signs in with each name, and
refusing another account with that name later. It prints the id after a
first sign-in:

```
squawk relay: GitHub user alice signed in for the first time; their GitHub id is 583231. To pin it, write alice 583231 on their line in /etc/squawk-relay/allowed-users
```

Copying the id into the file ("pinning" it) is worth doing: a pinned id
admits that account under whatever name the line uses, so when someone
renames their account you only change the name on their line.

Each person can sign in from up to 5 computers (`--max-keys-per-user`).

### Keys mode: list the keys

Each person runs `squawk whoami` and sends you the line that starts with
`Key:`. The **allowed keys file** has one key per line, optionally followed
by a name for your own reference:

```
# key                                         who
RLrY24-5jgOPl-x8QtuWAoveKoubDMXJJ5oM5HbmkeE   Alice's laptop
X8PUANVUiYbMLzNpsFTh1U9SmNCO7QrYWz5Y7OjmS3k   Bob's desktop
```

A key is not secret, but get it from the person over a channel you trust,
so that nobody can slip their own key into your list.

### Changing who may use it

Edit the file. The relay rereads it every 20 seconds, and at once when it
gets `SIGHUP` (`systemctl reload squawk-relay` with the unit below).

- People you add can connect straight away.
- People you take out are disconnected, and their mailboxes, with any
  messages waiting in them, are deleted. So that an editor caught half-way
  through saving the file cannot lock everyone out, a removal takes effect
  only when two readings of the file 20 seconds apart agree, or at once on
  `SIGHUP`.
- A file that cannot be read or has a line the relay does not understand
  changes nothing: the relay keeps the list it had and logs why. Check the
  log after editing.
- A file that lists nobody stops the relay from starting.

`squawk relay admin` works on the relay's data directory, on the relay's
machine, while the relay runs. Only the relay's user can read that
directory, so run it as that user (with the service below, `squawk-relay`):

```bash
sudo -u squawk-relay /home/squawk-relay/.local/bin/squawk relay admin users \
  --data /var/lib/squawk-relay                      # GitHub users and their keys
sudo -u squawk-relay /home/squawk-relay/.local/bin/squawk relay admin remove-key KEY \
  --data /var/lib/squawk-relay
```

`remove-key` forgets one key and deletes its mailbox, for example a
computer someone no longer uses, which frees one of their 5 places. In
`github` mode that computer must sign in again to use the relay; in `keys`
mode, also take the key out of the allowed keys file.

### The data directory

The relay keeps everything in one SQLite database in its data directory:
its own key (people's services see it as the relay's identity), mailboxes,
allow lists, waiting messages, and in `github` mode which GitHub account
owns each key. It never stores GitHub tokens. The relay creates the
directory readable only by its own user (mode 0700, files 0600); keep it
that way.

Back it up, for example nightly, to somewhere off the relay's machine. If
it is lost, the relay makes a new key and starts empty: messages waiting in
it are lost (their senders see them fail after 7 days), and in `github`
mode everyone signs in again.

The database (`relay.db`) is in use while the relay runs, so copying its
files then can give a broken copy. Make a consistent copy with SQLite
instead, as the relay's user, and copy that:

```bash
sudo -u squawk-relay sqlite3 /var/lib/squawk-relay/relay.db \
  "VACUUM INTO '/var/lib/squawk-relay/backup.db'"
```

A backup holds the relay's private key and who talks to whom, so keep it as
private as the data directory. To check one, run `squawk relay admin users
--data <a directory holding the copy as relay.db>`.

### Installing squawk

squawk needs Python 3.12 or later, which [uv](https://docs.astral.sh/uv/)
downloads by itself if the system's Python is older. On Linux, give the
relay a user of its own that cannot log in, and install uv and squawk for
that user:

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin squawk-relay
sudo -u squawk-relay -H sh -c 'curl -LsSf https://astral.sh/uv/install.sh | sh'
sudo -u squawk-relay -H /home/squawk-relay/.local/bin/uv tool install \
  git+https://github.com/ewasserman/squawk@v0.5.0
sudo -u squawk-relay /home/squawk-relay/.local/bin/squawk --version
```

The `@v0.5.0` picks a release ([the list of releases](https://github.com/ewasserman/squawk/releases));
`@main` installs the latest code instead. The program is then at
`/home/squawk-relay/.local/bin/squawk`. The relay needs no other packages;
Caddy, if you use it, is installed from your distribution or
[caddyserver.com](https://caddyserver.com/docs/install).

The allowed users or keys file is read by the relay's user, so make it
readable by that user and writable only by you:

```bash
sudo mkdir -p /etc/squawk-relay
sudoedit /etc/squawk-relay/allowed-users
sudo chown root:squawk-relay /etc/squawk-relay/allowed-users
sudo chmod 640 /etc/squawk-relay/allowed-users
```

### Running it as a service

On Linux with systemd, create `/etc/systemd/system/squawk-relay.service`:

```ini
[Unit]
Description=squawk relay
After=network-online.target
Wants=network-online.target

[Service]
User=squawk-relay
StateDirectory=squawk-relay
StateDirectoryMode=0700
ExecStart=/home/squawk-relay/.local/bin/squawk relay serve \
  --host 127.0.0.1 --port 8765 --data /var/lib/squawk-relay \
  --trust-forwarded-for --access github \
  --github-client-id Ov23li... \
  --allowed-users /etc/squawk-relay/allowed-users
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

and run `systemctl enable --now squawk-relay`. `StateDirectory` makes
systemd create `/var/lib/squawk-relay` for the relay's user, readable only
by it. The last four lines take away privileges the relay does not need
and make the rest of the file system read-only to it. The relay logs to standard
error, so `journalctl -u squawk-relay` shows sign-ins, refusals and file
rereads. `GET /healthz` on its port answers
`{"status":"ok","version":"..."}`.

## Example: a relay at home, reachable from the internet

This is one way to do it, not a requirement. It suits a relay on a computer
at home for a small group, with nothing to pay for. It was tried on a Mac
with a UniFi router ([the trial](plan/relay-access-trial.md)); other routers
call the same things by other names.

**Run it in a virtual machine, not on your own computer's operating
system, and on a network of its own.** A relay is software that strangers
on the internet can connect to. If it, or Caddy in front of it, ever had a
flaw that let someone run code, a virtual machine keeps them away from your
personal files, and a separate network keeps them away from your other
devices. A separate user account on your Mac is a much weaker boundary: it
shares the operating system, the network and often more files than you
expect. On a Mac, [Tart](https://tart.run) runs Linux virtual machines; on
Linux, any virtual machine or a separate small computer does the same job.

Do the steps in this order: the router's forward has to work before Caddy
asks Let's Encrypt for a certificate.

1. **A separate network for the relay.** Putting the virtual machine
   directly on your home network does not isolate it: devices on one
   network talk to each other through the switch, never through the
   router, so no router rule can stop the virtual machine reaching the Mac
   it runs on or anything else at home. Instead, create a separate network
   in the router (a VLAN, for example with id 20) and let the Mac carry it
   without taking part in it:

   ```bash
   sudo networksetup -createVLAN relay en0 20     # makes the interface vlan0
   sudo networksetup -setv4off "relay Configuration"
   sudo networksetup -setv6off "relay Configuration"
   ```

   The Mac then has no address on that network, and the virtual machine
   (step 2) joins it through `vlan0`. Tagged traffic passed through
   ordinary unmanaged switches without trouble in the trial. A spare
   Ethernet port on the router, set to that network, does the same job.

2. **The virtual machine.** Create a small Linux one (Debian or Ubuntu),
   for example `tart clone ghcr.io/cirruslabs/ubuntu:latest squawk-relay`,
   and run it without a window, bridged onto the relay's network, with no
   shared folders: `tart run --no-graphics --net-bridged=vlan0
   squawk-relay`. Give it a fixed address in the router (a DHCP
   reservation).

   **That image comes with logins anyone can guess:** user `admin` with
   password `admin`, a second user `ubuntu`, sudo without a password, and
   SSH accepting passwords. Before the virtual machine is reachable from
   anywhere, lock both passwords and turn SSH off. `tart exec` runs
   commands in it without the network, so you do not need SSH:

   ```bash
   tart exec squawk-relay sudo passwd -l admin
   tart exec squawk-relay sudo passwd -l ubuntu
   tart exec squawk-relay sudo systemctl mask --now ssh.socket ssh.service
   ```

   To start it when the Mac starts, use a LaunchDaemon in
   `/Library/LaunchDaemons` (a LaunchAgent starts only when you log in),
   run as the user who owns the virtual machine:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
     <key>Label</key><string>local.squawk-relay-vm</string>
     <key>UserName</key><string>YOUR-MAC-USER</string>
     <key>ProgramArguments</key>
     <array>
       <string>/opt/homebrew/bin/tart</string>
       <string>run</string>
       <string>--no-graphics</string>
       <string>--net-bridged=vlan0</string>
       <string>squawk-relay</string>
     </array>
     <key>RunAtLoad</key><true/>
     <key>KeepAlive</key><true/>
   </dict>
   </plist>
   ```

   Restart the Mac once to check that the virtual machine comes up.

3. **Updates inside the virtual machine.** Turn on automatic security
   updates (`unattended-upgrades` on Debian and Ubuntu). They cover only
   the distribution's own packages, so also:
   - Install Caddy from [its own repository](https://caddyserver.com/docs/install)
     (Ubuntu 24.04's packaged Caddy is an old 2.6), and add that repository
     to the automatic updates, or the one program facing the internet
     never updates. In `/etc/apt/apt.conf.d/51unattended-upgrades-caddy`:

     ```
     Unattended-Upgrade::Origins-Pattern {
         "origin=cloudsmith/caddy/stable,codename=any-version";
     };
     Unattended-Upgrade::Automatic-Reboot "true";
     Unattended-Upgrade::Automatic-Reboot-Time "04:00";
     ```

     The last two lines restart the virtual machine when an update needs
     it (a new kernel); services reconnect by themselves.
   - squawk, and the Python packages it uses, update only when you install
     a new release (see "Upgrading" below).

4. **The router's firewall.** For traffic coming from the relay's network,
   in this order:
   1. Accept traffic that is part of a connection already set up (the
      *established* and *related* states). Without this, the virtual
      machine's replies to devices at home are dropped, and the relay
      cannot be reached by its public name from home.
   2. Drop everything to private addresses (`10.0.0.0/8`, `172.16.0.0/12`,
      `192.168.0.0/16`, and `fc00::/7` for IPv6) and to the router itself,
      except DHCP. Give the relay's network a public DNS server, since the
      router's is now out of reach.
   3. For IPv6, also drop traffic to the router's link-local addresses
      (`fe80::/10`). Even with IPv6 turned off for that network, the router
      had a link-local address on it in the trial, and its SSH, web admin
      and DNS answered over IPv6, past the IPv4 rules.

   Turn off UPnP for the relay's network, or the virtual machine could
   open ports on the router itself (blocking it from the router, rule 2,
   also does this).

   Then test from inside the virtual machine, over both IPv4 and IPv6:

   ```bash
   nc -vz -w 5 <the Mac's home address> 22             # should time out
   nc -vz -w 5 <the router's home address> 443         # should time out
   ip -6 route | grep default                          # "via fe80::... dev <if>"
   nc -6 -vz -w 5 fe80::...%<if> 22                    # should time out
   curl -sI https://github.com | head -1               # should work
   ```

5. **A name.** A free dynamic DNS service such as [DuckDNS](https://www.duckdns.org)
   gives you a name like `myrelay.duckdns.org` that follows your home
   connection's IP address. Run its updater in the virtual machine (for
   DuckDNS, a cron job that calls its update URL every 5 minutes).

6. **The port forward.** Forward TCP port 443 to the virtual machine, and
   nothing else. Before starting Caddy, check it from another network (a
   phone's hotspot): `nc -vz -w 5 myrelay.duckdns.org 443` should say the
   connection was *refused*, which means it reached the virtual machine
   and nothing is listening yet. A *timeout* means the forward is not
   working yet. Checking from home tells you nothing: there the public
   address is the router itself.

7. **Caddy** terminates TLS and gets a Let's Encrypt certificate by itself.
   Its whole configuration (`/etc/caddy/Caddyfile`) is:

   ```
   myrelay.duckdns.org {
       reverse_proxy 127.0.0.1:8765
   }
   ```

   Caddy passes WebSocket connections through and adds `X-Forwarded-For`.
   With only port 443 forwarded, Caddy proves to Let's Encrypt that it owns
   the name over port 443 itself (the TLS-ALPN challenge). Start it only
   once step 6 works: if it asks too early, the attempts fail, and Let's
   Encrypt allows only 5 failed attempts per name per hour.

8. **The relay**, installed and run as a systemd service as above, with
   `--access github` (or `keys`).

9. **Back up** the relay's database every night to somewhere off the Mac
   (see "The data directory" for why a plain copy is not enough). From the
   Mac, `tart exec` reaches the virtual machine without the network:

   ```bash
   tart exec squawk-relay sudo -u squawk-relay sqlite3 /var/lib/squawk-relay/relay.db \
     "VACUUM INTO '/var/lib/squawk-relay/backup.db'"
   tart exec squawk-relay sudo sh -c \
     'cat /var/lib/squawk-relay/backup.db && rm /var/lib/squawk-relay/backup.db' \
     > relay-$(date +%F).db
   ```

   (`sqlite3` is in the `sqlite3` package.) Then copy the file off the Mac,
   kept as private as the data directory itself.

Then check from a network other than your home one:

```bash
curl https://myrelay.duckdns.org/healthz
squawk relay set wss://myrelay.duckdns.org
squawk relay status            # "needs sign-in: run `squawk relay login`"
squawk relay login             # enter the code at github.com/login/device
squawk relay status            # "Connected: yes"
```

From home, the same name works too, thanks to the first firewall rule.

## Example: a private relay over Tailscale

If everyone who will use the relay is already on your
[Tailscale](https://tailscale.com) network, or you can share the relay's
machine with them, Tailscale can provide both the TLS and the decision about
who can connect. No ports are opened on your router.

```bash
squawk relay serve --host 127.0.0.1 --port 8765 --data ~/squawk-relay \
  --trust-forwarded-for --access open
tailscale serve --bg 8765
```

`tailscale serve` gives the machine an address such as
`https://relay-box.your-tailnet.ts.net` with a certificate, and passes
connections to the relay. People use
`squawk relay set wss://relay-box.your-tailnet.ts.net`.

Here `--access open` is a reasonable choice, because Tailscale already
decides who can connect. Be clear about what that admits:

- Everyone who can reach that machine through Tailscale can use the relay:
  every device and user on your tailnet, and anyone you share the machine
  with. Tailscale's access rules are what limit it, so tighten them if your
  tailnet is larger than the group.
- **Do not turn on Tailscale Funnel for this port.** Funnel makes it
  reachable from the whole internet, which would make this an open public
  relay.
- If you want a second check, use `--access github` (or `keys`) here as
  well; it works the same behind Tailscale.

`--trust-forwarded-for` lets the relay's limits per address see each
person's Tailscale address. Reports from people using `tailscale serve`
show it setting `X-Forwarded-For` to the client's Tailscale address
(`100.x.y.z`); we have not confirmed this ourselves yet. If it does not,
every connection appears to come from `127.0.0.1` and the limits per
address apply to everyone together.

## Upgrading

Back up the database (see "The data directory"), install the new release over the old one,
and restart the relay:

```bash
sudo -u squawk-relay -H /home/squawk-relay/.local/bin/uv tool install --force \
  git+https://github.com/ewasserman/squawk@vX.Y.Z
sudo systemctl restart squawk-relay
```

 Services reconnect by themselves within a few seconds to a few
minutes. The database is upgraded in place when the new version starts,
which is why the backup comes first.
