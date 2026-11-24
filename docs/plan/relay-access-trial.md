# Trial: a relay in github mode over the internet

The last check for relay access control (GitHub #60, epic #50): a relay
on the internet, set up by following [the guide to running a
relay](../running-a-relay.md), used by two people on different networks.
Problems found become tasks in the epic.

## The deployment

Install squawk v0.5.0 (the first release with access control) as the
guide's "Installing squawk" says, and follow its example of a relay at
home: a Tart Linux virtual
machine on a Mac, bridged networking, no shared folders, only TCP
443 forwarded from the router, Caddy, a DuckDNS name, and the relay as a
systemd service with `--access github`. The allowed users file lists the
two people who take part, **A** and **B**. **C** is a third GitHub account
that is not in the file (a second account of either person will do).

Note anything in the guide that was wrong, missing or unclear.

**As run:** the virtual machine was *not* bridged onto the home network, as
the guide says, but onto a VLAN of its own (a DMZ) behind the home router,
with the Mac holding no address on that VLAN. See correction 1 below for
why.

## Steps

Run steps 1 and 2 from a network other than the home one (a phone's
hotspot will do).

1. **Only the relay is reachable.** `curl https://<name>/healthz`, then
   `nc -vz -w 5 <home IP> 22` and the same for 80 and 8765.
   - Expected: `/healthz` answers `{"status":"ok",...}` with a valid
     certificate; the other three ports do not connect.
2. **The virtual machine cannot reach the home network.** Inside the
   virtual machine, `nc -vz -w 5 <the Mac's LAN address> 22` and the
   same for the router's admin page (443 or 80).
   - Expected: neither connects. `curl https://github.com` works.
3. **A signs in.** On A's Mac: `squawk relay set wss://<name>`, then
   `squawk relay status`, `squawk relay login`, approve on github.com,
   `squawk relay status` again.
   - Expected: the first status says it needs sign-in; the last says
     "Connected: yes".
4. **B signs in**, the same way, on a different network from A.
   - Expected: the same.
5. **A and B pair by invite** (setup guide step 7), then each asks Claude
   to send the other a message.
   - Expected: both messages arrive.
6. **C is refused.** On a third Mac or a third squawk service, signed in
   to GitHub as C: `squawk relay login`.
   - Expected: "the relay does not permit this GitHub account", and
     `squawk relay status` shows that it is not permitted.
7. **Removing B cuts B off.** Take B's line out of the allowed users file
   and save it. Wait 60 seconds without reloading.
   - Expected: B's `squawk relay status` no longer says connected, and
     the relay's log (`journalctl -u squawk-relay`) says B's mailbox was
     deleted. Note how many seconds it took.
8. **Adding B back.** Put B's line back, then `systemctl reload
   squawk-relay`. B runs `squawk relay login` again.
   - Expected: B is connected again at once, and A can message B (after
     pairing again if needed).
9. **The admin command.** On the virtual machine:
   `sudo -u squawk-relay /home/squawk-relay/.local/bin/squawk relay admin
   users --data /var/lib/squawk-relay`.
   - Expected: lists A and B with their keys and last sign-in times.
10. **A restart keeps everyone.** `systemctl restart squawk-relay`, then
    A messages B.
    - Expected: both reconnect by themselves within a minute and the
      message arrives.
11. **The backup restores.** Copy the newest nightly backup somewhere
    else and run `squawk relay admin users --data <that copy>` there.
    - Expected: the same list as step 9.

## Results

| Step | Worked? | Notes |
| --- | --- | --- |
| 1 | Yes | From a phone's hotspot: `/healthz` answered with a valid certificate (issued over TLS-ALPN, after correction 5); 22 and 8765 timed out, 80 gave "host is down". From the home network the results mean nothing: the public address is the router itself there (its SSH answered on 22), and the relay is unreachable (correction 6). |
| 2 | Yes | Tested from inside the VM: github.com, Let's Encrypt and DuckDNS reachable; the Mac, other LAN hosts and the router's admin ports not, over IPv4 and, after correction 2, IPv6. |
| 3 | Yes | After updating A's client from 0.3.1 to 0.5.0 (correction 7). The relay logged the first sign-in with the pinned id. |
| 4 | Yes | B (on 0.5.0, on another network) signed in; the relay logged the first sign-in with B's pinned id, and `admin users` lists B with one key. |
| 5 | Yes | A and B were already paired from before, so no new invite was needed: the clients send their contact lists when they connect, and the relay let the two exchange messages. Messages flowed both ways, including Claude sessions on each side talking to each other; the relay's message counter rose with each one and nothing was left waiting. Pairing by invite through the relay was not tested here. See corrections 10 and 11. |
| 6 | Not run | No third GitHub account was at hand. |
| 7 | Yes | With no reload, the relay reread the file 36 seconds after it was saved, logged "1 removed" and deleted B's mailbox; B's `squawk relay status` then said not connected and not permitted. |
| 8 | Yes | B's line put back (pinned id checked against GitHub) and the relay reloaded; B ran `squawk relay login`, was connected at once, and messages worked both ways without pairing again. |
| 9 | Yes | Lists A with one key, first and last sign-in times. |
| 10 | Yes | After `systemctl restart squawk-relay`, both A's and B's services reconnected by themselves within about a second (the relay recorded both connections 1 second after the restart), and A's next message to B arrived. |
| 11 | Yes | Nightly backup out of the VM through `tart exec` (no network path needed), using SQLite's `VACUUM INTO` for a consistent copy; restored into a scratch directory, `admin users` matched the live relay exactly. |

Corrections to the guide:

1. **Bridging onto the home network does not isolate the VM.** The guide
   bridges the VM onto the home LAN and suggests router rules so it "cannot
   start connections to anything else on your home network". Hosts on one
   subnet talk through the switch, never the router, so no router rule can
   do that: the VM could reach the Mac it runs on and every other home
   device. The guide should put the VM on its own segment (a VLAN, or a
   separate Ethernet port) and firewall that segment at the router: drop
   from it to all private ranges and to the router itself, except DHCP.
   With macOS, `networksetup -createVLAN <name> en0 <id>` makes `vlan0`;
   turning IPv4 and IPv6 off on its service (named "<name> Configuration")
   leaves the Mac with no address on it, and `tart run --net-bridged=vlan0`
   works. Tagged frames passed through unmanaged switches without trouble.
2. **IPv6 link-local gets past IPv4-only rules.** With IPv6 set to none on
   the DMZ network, the router still had a link-local (fe80::) address on
   it, and from the VM its SSH, web admin and DNS answered over IPv6. The
   IPv4 rules do not apply. A rule dropping TCP/UDP from `fe80::/10` to the
   router (a local-input IPv6 rule) closed it. The guide should tell
   operators to test from inside the VM, over both IPv4 and IPv6.
3. **The cirruslabs Ubuntu image has default logins.** User `admin` with
   password `admin`, a second user `ubuntu`, passwordless sudo, and SSH
   with password login listening on all addresses. The guide should say to
   lock the passwords and turn SSH off (`systemctl mask ssh.socket
   ssh.service`) before the VM is reachable; `tart exec` manages the VM
   through the guest agent without the network.
4. **"Automatic security updates" do not cover Caddy, squawk or uv.**
   Ubuntu's unattended-upgrades takes only Ubuntu's archive. Caddy from its
   own repository (Ubuntu 24.04's packaged Caddy is an old 2.6) needs its
   origin added (`origin=cloudsmith/caddy/stable,codename=any-version`), or
   the one internet-facing program never updates. Kernel updates also need
   `Unattended-Upgrade::Automatic-Reboot`. Nothing updates squawk's Python
   dependencies between releases.
5. **Starting Caddy before the port forward is live fails, and the failures
   count.** Caddy asked for a certificate seconds after the forward was
   saved, before the router had applied it; TLS-ALPN timed out and the
   HTTP-01 fallback failed on the unforwarded port 80. Let's Encrypt allows
   5 failed validations per hostname per hour. The guide should say to
   check the forward from outside first (or with Caddy stopped and a packet
   capture in the VM), then start Caddy with the real name.
6. **The relay is not reachable from its own home network.** From the home
   LAN, the public name times out: the router does not hairpin the forward,
   and the DMZ rules drop the VM's replies to private addresses. The guide's
   "check from another network" is necessary, not just advice, and people
   at the relay's home need split DNS plus a rule letting the DMZ reply to
   the LAN.
7. **Old clients fail confusingly.** A 0.3.1 client against a `github`
   relay reports only "the relay did not accept our key", and `squawk relay
   login` prints usage. The guide (and the setup guide's step 7) should say
   that clients need 0.5.0 or later first.
8. **Smaller gaps.** The guide does not mention UPnP (if the router allows
   it, the VM could open ports itself; blocking the DMZ from the router
   covers it); gives no example launchd job for starting the VM (and a
   LaunchAgent starts only at login, not boot); and `squawk relay serve
   --help` is not supported, so its options had to be read from the source.
   The guide's systemd unit could also add standard sandboxing
   (`ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`,
   `CapabilityBoundingSet=` and similar); the relay ran fine under it.
9. **"Back it up" needs a method.** The data directory is a live SQLite
   database in WAL mode, so copying the files while the relay runs can
   give an inconsistent copy. The guide should give a command, such as
   `VACUUM INTO` (or `sqlite3 relay.db ".backup ..."`) run as the relay's
   user, and say that the backup holds the relay's private key, so it
   must be kept as private as the data directory.
10. **A client that moves networks can wait up to 5 minutes to reconnect.**
    After failed attempts (here, on the relay's home network), the client
    backs off to a 5-minute retry and does not notice a network change, so
    `squawk relay status` said not connected after the move to a working
    network. `squawk daemon stop && squawk daemon start` fixed it. Either
    the client should retry when the network changes, or `relay status`
    should say when it will try next and the guide should mention the
    restart.
11. **`squawk contacts` shows a stale route.** A contact paired before
    either side used a relay shows `route=local network` even when all
    traffic goes through the relay. The field is the relay the contact
    reported at pairing time and is never updated; sending ignores it.
    It should be updated (or dropped), or say what it means.

Problems filed:
