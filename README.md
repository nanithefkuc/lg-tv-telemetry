# What Your LG TV Reaches For: A Wire-Level Census

> [!WARNING]
> **AI-assisted research — read with skepticism.** The tooling, analysis, and
> attribution in this writeup were produced with AI assistance and may contain
> errors or overconfident conclusions. "Wire-verified" entries are observed
> facts (SNI/DNS seen on the wire); everything else is assessment. The full
> methodology (`tvsniff` and friends) is included in this repo so every claim
> can be independently re-derived and checked.

> [!WARNING]
> **Region-specific data.** Captured from a Singapore-provisioned device:
> region-scoped hostnames appear as `sg.*` (`sg.nextlgsdp.com`,
> `sg.ad.lgsmartad.com`, …). LG deploys the same platforms under other
> regional prefixes (`us.`, `eu.`, `de.`, …). The blocking method used here
> sinks entire parent domains, which covers every regional variant.

An LG smart TV was placed behind a small Linux relay that routes, resolves,
sniffs, and firewalls all of its traffic. Everything below was observed on
the wire — not inferred from app permissions or privacy policies.

## Topology

```
[LG TV] ──eth──> [Orange Pi 5 Pro] ──wifi──> [home router] ──> internet
                    192.168.2.1/24
                    DHCP + DNS + NAT + sniffer + firewall
```

The TV knows nothing about the relay. It receives normal DHCP (gateway and
DNS = the Pi) and ordinary NAT'd internet. Every packet it sends crosses the
Pi's ethernet port, where three things happen:

1. **Sniffing** — an AF_PACKET sniffer (`tvsniff`) logs every connection
   attempt (src/dst IP, port, protocol), every TLS ClientHello server name
   (SNI), and every DNS question and answer. Metadata only; payloads are
   never stored.
2. **Forced DNS** — any UDP/TCP port-53 packet from the TV, regardless of
   destination resolver, is DNAT'd to the relay's dnsmasq. The TV queries
   its DHCP resolver and a hardcoded `8.8.8.8` in parallel; both paths are
   captured.
3. **Firewall** — nftables with per-rule counters: a DNS sinkhole
   (`0.0.0.0` answers), an IP blackhole set, port rules, and a LAN probe
   guard (ICMP echo to `192.168.0.0/16` is dropped).

## How ownership is attributed

Evidence strength, strongest first:

| Method | Nature |
|---|---|
| SNI hostname on the wire | fact |
| DNS answer → IP mapping | fact |
| RDAP/ASN + reverse DNS of raw IPs | strong |
| Domain appearing in community LG blocklists | corroboration |
| Traffic pattern (reconnect loops, MQTT :8883, query volume) | indicative |

## Confirmed LG-owned infrastructure (wire-verified)

| Domain | Observed hostnames | Role |
|---|---|---|
| `nextlgsdp.com` | `sg.nextlgsdp.com`, `sg.rdx2.nextlgsdp.com` | LG SDP data platform — **13k–27k lookups/day** |
| `lgtvcommon.com` | `kic.cdpbeacon2/cdpsvc/cdplauncher.*` | LG Customer Data Platform beacons |
| `lgsmartad.com` | `sg.ad.*`, `sg.info.*` | LG ad network |
| `wiselg.com` | `kic.tv.wiselg.com` | LG "Wise" analytics |
| `lgtvsdp.com` | `rdx2.*` | **older** LG SDP endpoint; `nextlgsdp.com` is the successor — both fully operational |
| `lgtvdp.com` | — | LG TV data platform |
| `lgtviot.com` | `kic.lgtviot.com`, `kic.api.*`, `kic-ocp.*` | TV IoT cloud |
| `lgthinq.com` | `kic-connect-client.*`, `common.*` | ThinQ appliance cloud |
| `lgthinqhome.com` | `kr-op-v2.*` | ThinQ home |
| `lgecloudapm.com` | `eic-rum.elsa.*` | application perf monitoring (RUM) |
| `ngfts.lge.com` | `kic-ngfts.*` | webOS platform service |
| `lgacfde.com` | — | ACR / LivePlus consent domain (blocked preemptively) |

Supporting raw-IP fleet (no DNS name, AWS `ap-northeast-2` / `ap-southeast-1`,
attributed by hosting the above hostnames at capture time):
`3.39.34.70`, `3.39.65.189`, `3.36.243.207`, `3.34.120.24`, `3.34.206.243`,
`13.124.167.186`, `13.125.1.66`, `13.125.147.86`, `13.125.151.32`,
`13.125.181.130`, `13.209.123.235`, `3.37.151.244`, `43.200.132.56`,
`43.202.98.98`, `54.116.99.53`, `54.116.132.89`, `54.116.134.133`,
`54.117.15.181`, `15.165.157.0`.

A five-IP subset of that fleet is contacted exclusively on **tcp/8883
(AWS IoT MQTT)** — the ThinQ/IoT message transport. Blocking the port
kills it regardless of which IP rotates in.

## Confirmed partner: Alphonso (automatic content recognition)

The TV actively maintained connections to the vendor that measures *what is
being watched*:

| Hostname | Role |
|---|---|
| `tkacr425.alphonso.tv` | ACR collector (content fingerprint upload) |
| `bl-server.alphonso.tv` | beacon/log server |
| `prov-lg.alphonso.tv` | LG-specific provisioning |

`tkacr425.alphonso.tv` is a CNAME to `krishnaw374.alphonso.tv`, which holds
the A record `173.233.81.175` — the hardcoded IP the TV hammered on port
4433. That IP's TLS service presents a valid certificate
`CN=*.alphonso.tv, O=Alphonso Inc.` (verified live), closing the attribution:
**the hardcoded collector is Alphonso's**, hosted at Turnkey Internet
(AS420244, Albany, NY, US). Other live Alphonso infrastructure found during
verification: `prov-lb` / `prov-geo-aws.alphonso.tv` → `67.231.244.222`.
Certificate Transparency also shows an active `*.alphonso.tv` wildcard plus
endpoints such as `flog.alphonso.tv` (logging) and
`tvos-voice-gateway.alphonso.tv` (voice).

LG's own CDP beacons (`lgtvcommon.com`) run alongside it. In the TV's own
settings, turning off Live Plus and withdrawing the "Viewing Information"
agreement are the in-device controls; network blocking enforces them.

## Ad/tracking partners (community-blocklist corroborated)

`its-newid.net` (LG Channels backend + ad manifests), `castoola.tv`,
`cjpowercast.com`, `thetake.com` (shoppable-TV tracking), `smartclip.net/.com`,
`yumenetworks.com`, `lgsmartweb.com`, `lggalleryplus.com`,
`ad.lgappstv.com`, `lgrecommends.lgappstv.com`, `tvsdp.lgeapi.com`,
`nevoai-iothub-53-prod.azure-devices.net`, `sibbo.net` (consent sync),
`nuancemobility.net` (voice input stack).

## Suspicious, but not provable

| Indicator | Observation | Assessment |
|---|---|---|
| ~~`173.233.81.175:4433`~~ | **since confirmed — see the ACR section above**: `tkacr425.alphonso.tv` CNAMEs to `krishnaw374.alphonso.tv` which holds this A record; its TLS service presents `O=Alphonso Inc., CN=*.alphonso.tv` (verified live) | **confirmed Alphonso collector** (Turnkey Internet, AS420244, Albany NY) |
| `44.207.185.112`, `52.205.51.211`, `35.173.7.10`, `44.208.157.219` (AWS us-east-2) | TLS SNI is a raw SHA-hash + UUID, nothing else | anonymous telemetry collectors; owner unknown |
| 10× nameless AWS us-west-2 EC2 (`35.165.63.51`, `54.189.185.191`, `35.163.192.149`, `54.213.101.195`, `52.24.26.117`, `52.10.248.239`, `35.82.23.172`, `52.10.208.126`, `35.82.63.100`, `54.189.176.25`) | no SNI, one-shot bursts | unattributed; blocked on pattern (bare EC2 = rented data pipeline) |
| `95.216.195.133` (Hetzner) | plain HTTP, first-boot window only, never again | provisioning/config beacon |
| `discovery.meethue.com` → `34.117.13.189` | TV probed Philips Hue discovery **with zero Hue devices present** | benign-looking service, unexplained probing; blocked |

Unexplained behavior worth stating plainly: a TV with no smart-home devices
queries Hue discovery, and maintains MQTT sessions to AWS IoT — neither has
a user-facing function here.

## How to block it

```
# DNS sinkhole (dnsmasq) — covers all subdomains, answers 0.0.0.0
address=/nextlgsdp.com/0.0.0.0

# Forced DNS (nftables) — TV cannot bypass via hardcoded resolvers
ip saddr @tvlan udp dport 53 counter dnat to 192.168.2.1

# IP blackhole + IoT MQTT + LAN probe guard (nftables)
ip daddr @blocked_v4 counter drop
ip saddr @tvlan tcp dport 8883 counter drop
ip saddr @tvlan ip daddr 192.168.0.0/16 icmp type echo-request counter drop
```

Keeping the TV functional: firmware OTA (`snu.lge.com`, `su-ssl.lge.com`),
the app store (`ibs.lgappstv.com`), streaming CDNs, and shared
CloudFront/Akamai/Cloudflare IPs are deliberately left open.

## Results

- ~23 telemetry attempts **per minute** intercepted at steady state.
- `nextlgsdp.com` alone: **13,000–27,000 DNS lookups per day** — a query
  every few seconds, around the clock, independent of TV usage.
- Cumulative scoreboard (`tvblocked`) and daily 23:59 snapshots
  (`/var/lib/tvsniff/daily-blocked.log`) provide per-day evidence.

## Known gaps

- QUIC/DoH (UDP 443) remains open; blocking it forces TCP/TLS where SNI is
  visible, at some streaming-performance cost.
- Telemetry on shared CDN IPs cannot be blocked without collateral.
- Apps can use cached IPs after a DNS sinkhole; seal with IP entries when
  observed.

## Tools & methodology (in this repo)

The full toolchain is included so the methodology is reproducible and every
claim above can be re-derived from raw packets:

- `tvsniff` — AF_PACKET endpoint logger (flows, SNI, DNS Q/A), JSONL output;
  the primary evidence source
- `selftest.py` — parser self-test (crafted frames: flow tracking, split-segment
  SNI reassembly, DNS Q/A with compression pointers, teardown, byte accounting)
- `config/` — deployment artifacts: `nftables.conf` (firewall + forced DNS +
  blackhole set), `dnsmasq-tv-blocklist.conf` (the sinkhole list),
  `dnsmasq-tv-relay.conf` (DHCP/DNS for the TV segment), `tvsniff.service`,
  `tvblocked-daily.{service,timer}` (23:59 evidence snapshots), sysctl +
  logrotate bits. Interface names and subnets are device-specific — adapt
  to your relay.
- `tvendpoints` — per-endpoint summary view of the log
- `tvblocked` — cumulative blocked-telemetry scoreboard
- `Blocklist-Document.md` — annotated blocklist with attribution and revert
  procedures for every entry
