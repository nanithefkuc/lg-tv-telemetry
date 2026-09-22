# TV Relay Blocklist Document

**Device:** Orange Pi 5 Pro relay (`192.168.2.1`) → LG TV (`192.168.2.77`)
**Last updated:** 2026-09-15
**Goal:** contain vendor telemetry (LG and friends), keep TV functionality (streaming, apps, browser, firmware) intact.

---

## Where the rules live

| Layer | File / mechanism | Apply changes |
|---|---|---|
| DNS sinkholes | `/etc/dnsmasq.d/tv-blocklist.conf` | edit → `sudo systemctl restart dnsmasq` |
| IP blackholes | `blocked_v4` set in `/etc/nftables.conf` | edit + `sudo nft -f /etc/nftables.conf` |
| Port / behavior rules | `forward` + `prerouting` chains, `/etc/nftables.conf` | same |
| Observation | `tvendpoints` CLI + `/var/lib/tvsniff/flows.jsonl` | read-only |

## How to add / remove entries

### Add a blocked domain

```sh
ssh orange-pi
echo 'address=/example-telemetry.com/0.0.0.0' | sudo tee -a /etc/dnsmasq.d/tv-blocklist.conf
sudo systemctl restart dnsmasq
dig +short @192.168.2.1 example-telemetry.com A     # must answer 0.0.0.0
```
One line per domain; it covers **all subdomains** automatically. Only add
the shortest name you're sure about (`lgtviot.com`, not `kic.lgtviot.com`).
Because of the forced-DNS rule this is authoritative for every plain-DNS
lookup the TV makes, no matter which resolver it tries.

### Remove a blocked domain

```sh
sudo sed -i '\|^address=/example-telemetry.com/|d' /etc/dnsmasq.d/tv-blocklist.conf
sudo systemctl restart dnsmasq
```

### Add a blocked IP

There are TWO steps — runtime (immediate) and persistent (survives reboot).

```sh
# 1. runtime (takes effect immediately)
sudo nft add element inet tvrelay blocked_v4 { 203.0.113.7 }

# 2. persistent — add the IP to the elements block in:
sudo nano /etc/nftables.conf        # keep the trailing comma placement intact
sudo nft -c -f /etc/nftables.conf   # syntax check
sudo nft -f /etc/nftables.conf      # reload (resets all counters)
```
Skipping the second silently re-allows the IP after the next reboot.

### Remove a blocked IP

Same two places:

```sh
sudo nft delete element inet tvrelay blocked_v4 { 203.0.113.7 }
# then delete the IP from /etc/nftables.conf and reload as above
```

### Verify either change

```sh
dig +short @192.168.2.1 <domain> A                     # domain block
sudo nft list set inet tvrelay blocked_v4              # IP block
sudo nft list chain inet tvrelay forward | grep drop   # counters climbing = TV still trying
tvendpoints --since 10m                                # what's still getting through
```


Revert a single DNS block: delete its `address=` line, restart dnsmasq.
Revert a single IP block: `sudo nft delete element inet tvrelay blocked_v4 { IP }`
**and** delete the line from `/etc/nftables.conf` (else it returns at reboot).

Evidence column: `SNI` = hostname observed on the wire by tvsniff (fact).
"Likely service" = attribution, marked with confidence.

---

## DNS sinkholes (`0.0.0.0`, subdomains included)

| Domain | Likely service | Evidence | Confidence | If something breaks, remove when… |
|---|---|---|---|---|
| `lgsmartad.com` | LG ad network (`sg.ad.*`, `sg.info.*`) | SNI both subdomains | high | — no legit function known |
| `wiselg.com` | LG analytics ("Wise", `kic.tv.*`) | SNI | high | — |
| `nextlgsdp.com` | LG SDP = data collection platform (`sg.rdx2.*`) | SNI | high | — |
| `lgtviot.com` | LG TV IoT cloud (`kic.*`) | SNI | high | TV↔smart-home features wanted (unlikely use) |
| `lgthinq.com` | LG ThinQ appliance cloud | SNI `kic-connect-client.*`, `common.*` | high | same as above |
| `ngfts.lge.com` | LG webOS platform service (not firmware — that's `snu.lge.com`, untouched) | SNI, netify listing | medium | some LG app misbehaves |
| `its-newid.net` | **LG Channels** backend + ad manifests (`cdn88-accio.*`) | SNI + m3u/logo URLs public | high | you watch LG Channels free TV |
| `customerevents.netflix.com` | Netflix telemetry beacon | user-sourced | high | — |
| `beacon.netflix.com` | Netflix telemetry beacon (alias family) | user-sourced | high | — |
| `logs.netflix.com` | Netflix client logs (covers `nrdp.logs.*`) | SNI | high | — never load-bearing for playback |
| `unagi-fe.amazon.com` | Amazon analytics FE (Prime Video telemetry) | SNI; blocklist docs | medium-high | Prime Video playback issues |
| `unagi-na.amazon.com` | same, NA region | sibling of above | medium-high | same |
| `meethue.com` | Philips Hue cloud — TV probed `discovery.*`; **no Hue devices in this house** | SNI `discovery.meethue.com` | high (unused) | you ever buy Hue |
| `alphonso.tv` | **Alphonso ACR** — content-recognition collector (`tkacr425`), beacon (`bl-server`), LG provisioning (`prov-lg`) | SNI ×11 | high | never |
| `lgacfde.com` | LG ACR / LivePlus consent domain | canonical in LG guides | preemptive | never |
| `lgtvcommon.com` | LG **Customer Data Platform** beacons (`kic.cdpbeacon2/cdpsvc/cdplauncher`) | SNI ×20 | high | never |
| `lgtvsdp.com` | **older** LG SDP endpoint (predecessor of `nextlgsdp.com`; both operational) | community list | high | — |
| `lgtvdp.com` | LG TV data platform | community list | high | — |
| `lgecloudapm.com` | LG APM/RUM telemetry | community list | high | — |
| `lgthinqhome.com` | ThinQ home cloud | community list | high | smart-home wanted |
| see ACR section below | partner ad/tracking batch (`castoola.tv`, `cjpowercast.com`, `thetake.com`, `smartclip.*`, `yumenetworks.com`, `lgsmartweb.com`, `lggalleryplus.com`, `ad.lgappstv.com`, `lgrecommends.lgappstv.com`, `tvsdp.lgeapi.com`, `nevoai-*`) | community LG blocklist | medium | per-domain |
| `sibbo.net` | consent-management sync | community list | unsure — REVIEW | repeated privacy prompts |
| `nuancemobility.net` | Nuance voice input stack | community list | unsure — REVIEW | you use voice search |
| `eligibility-panelresearch.googlevideo.com` | Google audience-measurement panel | SNI | high | — targeted subdomain, streaming unaffected |

## IP blackholes (`blocked_v4`)

### LG fleet — AWS Korea/Singapore (ad/SDP/IoT/MQTT)
| IPs | Observed SNI / role |
|---|---|
| `3.39.34.70`, `15.165.157.0` | `sg.nextlgsdp.com`, `kic.tv.wiselg.com` (the "Korea data farm" pair) |
| `13.125.1.66`, `54.116.132.89` | `sg.rdx2.nextlgsdp.com` |
| `3.39.65.189`, `3.36.243.207`, `54.117.15.181` | `sg.nextlgsdp.com` |
| `3.34.120.24` | `sg.info.lgsmartad.com` |
| `43.200.132.56`, `43.202.98.98` | `sg.ad.lgsmartad.com` |
| `13.125.151.32` | `kic.tv.wiselg.com` |
| `13.125.147.86` | `kic-connect-client.lgthinq.com` |
| `54.116.99.53` | `kic.lgtviot.com` |
| `13.124.167.186` | nameless, same ranges |
| `3.34.206.243`, `13.125.181.130`, `13.209.123.235`, `3.37.151.244`, `54.116.134.133` | MQTT :8883 fleet (ThinQ/IoT transport — also port-blocked) |

### Amazon — hash-SNI anonymous collectors (us-east-2)
| IPs | Role |
|---|---|
| `44.207.185.112`, `52.205.51.211`, `35.173.7.10`, `44.208.157.219` | SNI was a raw SHA-hash + UUID (`e2092e47aa…`) — classic unnamed telemetry collector |

### Netflix telemetry (sealed against cached-IP skirt)
| IPs | Role |
|---|---|
| `34.212.185.237`, `44.242.131.93`, `44.228.67.58`, `52.33.247.19`, `44.226.179.188` | `logs.netflix.com` / `nrdp.logs.*` hosts — TV kept hitting them by cached IP after DNS block |
| `52.37.176.140`, `44.239.254.161`, `50.112.122.241` | nameless `nrdp`-cloud (us-west-2) — blocked on suspicion, weakest entries in the list |

### One-offs
| IP | Role |
|---|---|
| `173.233.81.175` | hardcoded collector on :4433 — **CONFIRMED Alphonso**: `tkacr425.alphonso.tv` CNAME→`krishnaw374.alphonso.tv` A→this IP; live TLS cert `O=Alphonso Inc., CN=*.alphonso.tv`; Turnkey Internet AS420244, Albany NY |
| `67.231.244.222` | `prov-lb` / `prov-geo-aws.alphonso.tv` — live Alphonso provisioning LB (found during attribution verification) |
| `34.117.13.189` | `discovery.meethue.com` (Google Cloud LB) — Hue probe, blocked |
| `95.216.195.133` | Hetzner, HTTP-only, first-boot era, never seen again |

### Alphonso ACR — wire-confirmed 2026-09-15

tvsniff caught the TV actively using the ACR (automatic content recognition)
stack. This is the "TV watches what you watch" pipeline:

| Hostname | Role |
|---|---|
| `tkacr425.alphonso.tv` | ACR collector (tokenized audio/content fingerprint upload) |
| `bl-server.alphonso.tv` | beacon/log server |
| `prov-lg.alphonso.tv` | LG-specific ACR provisioning |
| `kic.cdpbeacon2.lgtvcommon.com` | LG Customer Data Platform beacon |
| `kic.cdpsvc.lgtvcommon.com` | CDP service |
| `kic.cdplauncher.lgtvcommon.com` | CDP launcher |
| `kic.lgchhomeapp.lgtvcommon.com` | LG Channels home-app integration |

All parent domains are now sinkholed (`alphonso.tv`, `lgtvcommon.com`,
`lgtvdp.com`, `lgtvsdp.com`, `lgecloudapm.com`, `lgthinqhome.com`,
`lgacfde.com` preemptively). Partner ad/tracking domains from the community
LG blocklist added as well: `castoola.tv`, `cjpowercast.com`, `thetake.com`,
`smartclip.net/.com`, `yumenetworks.com`, `lgsmartweb.com`,
`lggalleryplus.com`, `ad.lgappstv.com`, `lgrecommends.lgappstv.com`,
`tvsdp.lgeapi.com`, `nevoai-iothub-53-prod.azure-devices.net`.

**`173.233.81.175:4433` attribution (updated):** DNS history reportedly ties
it to an Alphonso domain via a US AS; the IP now reverse-looks-up to a
Japanese Linode host (`hershestory.com`), suggesting infrastructure
rotation/reassignment. The 161+ persistent reconnect attempts fit a hardcoded
beacon collector. Verdict: probable former/current Alphonso collector —
**stays blocked**; identity shift (Linode front) is not a reason to trust it.

Two flagged-for-review entries in this batch: `sibbo.net` (consent-sync —
may cause repeated privacy-dialog prompts if blocked) and
`nuancemobility.net` (voice input — remove if you use voice search).

## Port / behavioral rules

| Rule | Purpose | Break-risk |
|---|---|---|
| `tcp dport 8883` drop (TV) | kills AWS-IoT MQTT regardless of destination IP | any TV smart-home/IoT feature |
| ICMP echo → `192.168.0.0/16` drop | TV cannot ping-scan the LAN | none known (webOS uses HTTP checks) |
| all `:53` → DNAT to relay dnsmasq | forced DNS: closes hardcoded-8.8.8.8 side channel (verified intercepting) | if a device needs a specific external resolver |
| masquerade `oifname wlan0` | NAT — load-bearing, do not touch | everything |

## Deliberately NOT blocked (breakage would land here first)

| Host / range | Why kept |
|---|---|
| `googlevideo.com` (excl. panelresearch subdomain), `i.ytimg.com`, `*.gstatic.com`, `clientsN.google.com` | YouTube playback, thumbnails, connectivity checks |
| `netflix.com`, `nflxvideo.net` CDN, `nrdp.prod.ftl.netflix.com` | **Netflix streaming runs on nrdp/FTL** — never block `nrdp.*` wholesale |
| `nrdp.push.prod.netflix.com` | app push channel (borderline, left open) |
| `keho.api.amazonvideo.com`, `api.amazon.co.jp`, `images-fe.ssl-images-amazon.com` | Prime Video API + artwork |
| `snu.lge.com`, `su-ssl.lge.com` | **firmware OTA** — blocking = no more updates |
| CloudFront / Akamai / Cloudflare shared IPs (`65.8.x`, `3.160.x`, `13.35.x`, `104.69.x`, `108.156.x`, `172.66.x`, `65.9.x`…) | shared by half the internet incl. the TV browser; blocking breaks unrelated sites |

## Known gaps

- **QUIC / DoH (UDP 443):** observed in use (Google). A DNS-hiding DoH channel could exist. Escalation lever: drop `udp dport 443` — forces TCP/TLS where SNI is visible, costs QUIC streaming perf.
- **Cached IPs:** apps can use previously-resolved IPs after a DNS block (happened with `logs.netflix.com`); seal with an `blocked_v4` entry when seen.
- **Shared-CDN telemetry:** LG/analytics hosted on CloudFront/Akamai can't be IP-blocked without collateral; domain-block only.
- **Counters reset on every `nft -f` reload** — don't compare across reloads.

## Monitoring cheat sheet

```sh
tvendpoints                      # who is the TV talking to (add --since 1h --limit 100)
tvendpoints --all                # include private/multicast rows
sudo tvblocked                    # cumulative telemetry-blocked scoreboard
sudo nft list chain inet tvrelay forward    # drop counters (blackholed dst / mqtt / lan probe)
sudo nft list chain inet tvrelay prerouting # forced-DNS interception counter
grep dns_q /var/lib/tvsniff/flows.jsonl | tail   # what the TV is resolving
cat /var/lib/tvsniff/daily-blocked.log   # daily 23:59 evidence snapshots (auto)
```

## Changelog

- **2026-09-15** — initial: `lgsmartad.com`, `customerevents/beacon.netflix.com`, `wiselg.com`, IPs `173.233.81.175` + `34.117.13.189`, MQTT :8883, LAN ICMP guard, forced DNS.
- **2026-09-15 (evening)** — +LG fleet (`nextlgsdp`, `lgtviot`, `lgthinq`, `ngfts.lge.com`, `its-newid.net`), +`logs.netflix.com` (+5 host-IPs), +`unagi-fe/na`, +`meethue.com`, +panelresearch subdomain, +hash-SNI & nameless EC2 clusters, +Hetzner beacon, +3 nameless `nrdp`-cloud IPs.

- **2026-09-15 (night)** — Alphonso ACR confirmed on the wire (`tkacr425`/`bl-server`/`prov-lg.alphonso.tv` + LG CDP beacons on `lgtvcommon.com`). Blocked: `alphonso.tv`, `lgacfde.com`, `lgtvcommon.com`, `lgtvsdp.com`, `lgtvdp.com`, `lgecloudapm.com`, `lgthinqhome.com`, partner ad batch (`castoola.tv`, `cjpowercast.com`, `thetake.com`, `smartclip.net/.com`, `yumenetworks.com`, `lgsmartweb.com`, `lggalleryplus.com`, `ad.lgappstv.com`, `lgrecommends.lgappstv.com`, `tvsdp.lgeapi.com`, `nevoai-iothub-53-prod.azure-devices.net`), review-flagged `sibbo.net` + `nuancemobility.net`. `173.233.81.175` re-attributed: probable Alphonso collector (DNS history), now fronted by Linode JP / `hershestory.com`.

- **2026-09-22** — daily evidence pipeline: `tvblocked-daily.timer` appends a full `tvblocked` snapshot to `/var/lib/tvsniff/daily-blocked.log` at 23:59 daily (`Persistent=true`, catches up if the Pi was off). Since `flows.jsonl` logrotates daily, each snapshot covers exactly that day — day-over-day deltas are per-day totals. Week-one observation: `nextlgsdp.com` alone reaches 13k–27k lookups/day.

- **2026-09-22 (night 2)** — `173.233.81.175` **confirmed as Alphonso**: forward
  DNS (`krishnaw374.alphonso.tv` A record), CNAME chain from the TV's own
  `tkacr425.alphonso.tv` collector, and a live TLS certificate
  `O=Alphonso Inc., CN=*.alphonso.tv`. Added `67.231.244.222`
  (`prov-lb`/`prov-geo-aws.alphonso.tv`). Generic hoster rDNS
  (`static.as420244.net`) explains why most RDNS tools showed no Alphonso link.
