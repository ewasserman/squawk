# Trial: a relay in github mode over the internet

The last check for relay access control (GitHub #60, epic #50): a relay
on the internet, set up by following [the guide to running a
relay](../running-a-relay.md), used by two people on different networks.
Problems found become tasks in the epic.

## The deployment

Follow the guide's example of a relay at home: a Tart Linux virtual
machine on the Mac Studio, bridged networking, no shared folders, only TCP
443 forwarded from the router, Caddy, a DuckDNS name, and the relay as a
systemd service with `--access github`. The allowed users file lists the
two people who take part, **A** and **B**. **C** is a third GitHub account
that is not in the file (a second account of either person will do).

Note anything in the guide that was wrong, missing or unclear.

## Steps

Run steps 1 and 2 from a network other than the home one (a phone's
hotspot will do).

1. **Only the relay is reachable.** `curl https://<name>/healthz`, then
   `nc -vz -w 5 <home IP> 22` and the same for 80 and 8765.
   - Expected: `/healthz` answers `{"status":"ok",...}` with a valid
     certificate; the other three ports do not connect.
2. **The virtual machine cannot reach the home network.** Inside the
   virtual machine, `nc -vz -w 5 <Mac Studio's LAN address> 22` and the
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
   `squawk relay admin users --data /var/lib/squawk-relay`.
   - Expected: lists A and B with their keys and last sign-in times.
10. **A restart keeps everyone.** `systemctl restart squawk-relay`, then
    A messages B.
    - Expected: both reconnect by themselves within a minute and the
      message arrives.
11. **The backup restores.** Copy the newest nightly backup somewhere
    else and run `squawk relay admin users --data <that copy>`.
    - Expected: the same list as step 9.

## Results

| Step | Worked? | Notes |
| --- | --- | --- |
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |
| 7 | | |
| 8 | | |
| 9 | | |
| 10 | | |
| 11 | | |

Corrections to the guide:

Problems filed:
