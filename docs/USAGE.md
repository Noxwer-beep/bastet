# Bastet — usage

Every command, what it does with the data, and the three workflows it was built around.
If something here disagrees with the tool, the tool is right and this file is a bug.

```
bastet                     the dashboard
bastet cat                 the cat
bastet ioc <value...>      indicator triage
bastet extract <file|->    pull indicators out of text
bastet logs <file|->       log triage
bastet cve <id>            NVD lookup
bastet attack <id|word>    ATT&CK technique
bastet port <n|word>       port reference
bastet ip <cidr>           subnet maths
bastet decode <text>       peel encodings
bastet encode <text>       apply one
bastet hash                digests / identify
bastet case ...            incident notes
bastet triage <playbook>   checklists
bastet doctor               environment check
```

Exit codes: `0` ok · `1` error · `2` not found or bad usage · `3` network unavailable
· `4` findings at or above `--fail-on` (or an address outside the range).

Most commands take `--json`. When they do, that is the only thing on stdout, so
`| jq` works without a filter.

---

## ioc

```
bastet ioc 45.155.205.233 evil-login.top d41d8cd98f00b204e9800998ecf8427e
```

Classifies (ipv4, ipv6, domain, url, email, md5/sha1/sha256/sha512, cve), then reads it:

| Reading | When |
|---|---|
| loopback / RFC1918 / TEST-NET / link-local | the value cannot be a remote attacker |
| public address | reputation lookup is worth the paste; VT, AbuseIPDB, Shodan links attached |
| punycode (`xn--`) | high — the displayed name is not the real one |
| throwaway TLD (`.top`, `.zip`, `.click`, …) | high |
| credentials in the URL (`user:pw@host`) | high — the part before @ is not the host |
| IP literal as URL host | medium — no domain, no certificate story |
| known hash (empty file, EICAR) | named, because you will meet it in a test |

No network calls, no API keys, same answer offline.

## extract

```
bastet extract alert.txt
pbpaste | bastet extract -
bastet extract report.txt --only ipv4,domain --json
```

Regex finds candidates; `ioc` explains them. Two deliberate filters keep the output
usable: an IPv6-shaped timestamp (`2026:10:00:11`) is validated and dropped, and a
filename ending (`report.png`, `notes.log`) is never treated as a TLD.

## logs

```
bastet logs /var/log/auth.log
bastet logs access.log --ip 45.155.205.233
bastet logs auth.log --since 02:00 --until 05:00
zcat auth.log.1.gz | bastet logs -
```

Reads sshd/syslog auth lines and nginx/apache combined access lines, in one streaming
pass. It never loads the file into memory, reads `.gz` directly, and refuses anything
that looks binary instead of printing garbage.

Detections and their thresholds (`bastet/logs.py`, `THRESHOLDS`):

| Finding | Rule | Severity |
|---|---|---|
| success-after-failure | one address has ≥1 failure and ≥1 accepted login | **critical** |
| brute-force | ≥5 failures from one address (≥20 → high) | medium/high |
| user-enumeration | ≥3 distinct usernames from one address | medium |
| scanner-paths | request for a path in `SCAN_PATHS` (`.env`, `.git/config`, `wp-login.php`, …) | high |
| 404 flood | ≥20 404s from one address | low |
| tool user agent | UA matches sqlmap, nuclei, curl, … | medium |

Everything else is counting: top sources, top accounts, top paths, status histogram,
events per hour. `--json` gives all of it.

## cve

```
bastet cve CVE-2021-44228
bastet cve 2021-44228 --refresh
```

NVD first, then a disk cache in `~/.local/share/bastet/cache/cve/`. A cached record
prints `source: cache`; if the network is down and nothing is cached, exit code 3.
`NVD_API_KEY` is optional and only raises the rate limit.

## attack / port

```
bastet attack                     browse by tactic
bastet attack T1110               exact
bastet attack powershell          free text
bastet attack --tactic exfiltration
bastet port 445
bastet port --risk critical
```

36 techniques and 46 ports are bundled in `src/bastet/data/`. Adding one is a JSON
entry — no code change.

## ip / decode / encode / hash

```
bastet ip 10.10.10.0/24
bastet ip 10.10.10.0/24 --contains 10.10.10.55     # exit 4 when it is not inside
bastet decode aGVsbG8gd29ybGQ=
bastet encode "hello" --as base64
bastet hash "hello"                                 # md5, sha1, sha256, sha512
bastet hash --file malware.bin
bastet hash --identify 5d41402abc4b2a76b9719d911017c592
```

`decode` peels in order — url, html, base64, hex — up to five layers, and prints each
step so you can see where it ends. Short base64 only counts if it carries padding;
otherwise every eight-letter word in a log would "decode".

## case

```
bastet case new --title "SSH brute force on web01" --severity high
bastet case list --status open
bastet case add IR-2026-0001 "18 failures then a login from 45.155.205.233" --kind finding
bastet case playbook IR-2026-0001 host
bastet case show IR-2026-0001
bastet case status IR-2026-0001 closed --resolution "blocked at the firewall"
bastet case export IR-2026-0001 -o case.md
```

Cases live in `~/.local/share/bastet/cases.db`. Event kinds: note, ioc, log, action,
finding, decision, comms — the last two matter when someone asks later why you did it.

## triage

```
bastet triage --list
bastet triage phishing
bastet triage host --case IR-2026-0001 -o checklist.md
```

Playbooks: phishing, host, bec, malware, exposure. Attaching one to a case records the
fact in the timeline.

---

## Three workflows

**Start of shift**

```bash
bastet                                   # open cases, cache, the time
bastet case list --status open
```

**A phishing report lands**

```bash
# save the raw message to mail.txt first
bastet extract mail.txt                  # addresses, links, hashes, CVEs
bastet ioc <the interesting ones>
bastet case new --title "Phishing: invoice lure" --severity medium
bastet case playbook IR-2026-0002 phishing
bastet case add IR-2026-0002 "3 recipients, 1 clicked" --kind finding
```

**Something is brute-forcing a host**

```bash
bastet logs /var/log/auth.log --fail-on critical   # exit 4 means get up
bastet logs /var/log/auth.log --ip 45.155.205.233 --json | jq .findings
bastet case new --title "SSH brute force on web01" --severity high
```

---

## Where it stores things

```
~/.local/share/bastet/
├── cases.db            cases and their timelines (SQLite)
├── cache/cve/          one JSON file per CVE looked up
└── exports/            if you point an export here
```

`BASTET_DATA_DIR` overrides the whole thing — point it at a case directory when you are
working an incident and want the notes next to the evidence.
