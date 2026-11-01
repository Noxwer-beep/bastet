"""Playbooks: what to do, in order, when the alert lands.

These are the checklists an analyst already has in their head at 02:00 and forgets
at 02:10. Each one is a markdown document you can attach to a case and tick off.
"""

from __future__ import annotations

PLAYBOOKS: dict[str, dict] = {
    "phishing": {
        "title": "Suspicious email / phishing",
        "goal": "Decide whether the mail is malicious, who opened it, and whether anything ran.",
        "phases": [
            ("Triage", [
                "Get the raw message (headers included). Do not trust the displayed sender.",
                "Check SPF, DKIM and DMARC results in the headers, and the real Return-Path.",
                "Extract every URL and attachment hash; defang before pasting them anywhere.",
                "Compare the display name against the envelope sender — lookalike domain?",
            ]),
            ("Scope", [
                "Search the mail gateway for the same subject, sender and message-id.",
                "List every recipient, and every one who clicked (proxy or mail-trace).",
                "Check whether anyone replied, forwarded, or entered credentials.",
            ]),
            ("Contain", [
                "Purge the message from all mailboxes; block the sender and the URL at the proxy.",
                "If credentials were entered: force a password reset and revoke sessions.",
                "If a file ran: isolate the endpoint before doing anything else.",
            ]),
            ("Investigate", [
                "Detonate the attachment in a sandbox, not on a workstation.",
                "Check authentication logs for the affected accounts from unusual locations.",
                "Look for new MFA devices, mailbox rules, or forwarding rules (classic BEC follow-up).",
            ]),
            ("Close", [
                "Write what happened, what was clicked, and what was blocked.",
                "Add the indicators to the blocklist and the case export.",
                "If it got through the gateway, note why — that is the actual finding.",
            ]),
        ],
    },
    "host": {
        "title": "Suspected endpoint compromise",
        "goal": "Establish whether the host is running someone else's code, and how far it spread.",
        "phases": [
            ("Triage", [
                "Do not reboot. Memory may be the only evidence left.",
                "Record who is logged in, and what the user says they did.",
                "Check the alert source: EDR, antivirus, a user report, or a network signature?",
            ]),
            ("Scope", [
                "Process tree around the alert: parent, command line, user, start time.",
                "Persistence: run keys, services, scheduled tasks, cron, systemd units.",
                "Network: outbound connections, beacons, and DNS lookups in the last 24h.",
                "Ask the same question of every host with the same image or the same user.",
            ]),
            ("Contain", [
                "Isolate from the network (keep the agent channel if your EDR allows it).",
                "Disable the account if it was used for the intrusion, not just the user's.",
            ]),
            ("Eradicate", [
                "Remove persistence before removing the payload, or it comes back.",
                "Rebuild rather than clean if the intruder had admin — you cannot prove absence.",
            ]),
            ("Close", [
                "Timeline: first execution, persistence, lateral attempts, containment.",
                "Map to ATT&CK; note which detections fired and which should have.",
            ]),
        ],
    },
    "bec": {
        "title": "Business email compromise",
        "goal": "Stop the money, not just the mail.",
        "phases": [
            ("Triage", [
                "Check for new inbox rules (forwarding, mark-as-read, move-to-RSS) — this is the fingerprint.",
                "Check for successful logins from new locations or new devices.",
                "Ask finance whether any payment instruction changed in the last 72 hours.",
            ]),
            ("Contain", [
                "Reset the password, revoke all sessions and refresh tokens.",
                "Remove mailbox rules and forwarding; check the Sent Items for replies.",
                "Tell finance and the bank before telling anyone else, if money moved.",
            ]),
            ("Investigate", [
                "How was the account accessed: password spray, phishing, token theft, MFA fatigue?",
                "Which other accounts received the same mail?",
                "Did the attacker enroll their own MFA method?",
            ]),
            ("Close", [
                "Count the exposure: mails read, mails sent, invoices touched.",
                "Fix the root cause — conditional access, MFA number matching, or mail rules alerting.",
            ]),
        ],
    },
    "malware": {
        "title": "Malware detection",
        "goal": "Identify the family, the stage, and whether this is one host or a campaign.",
        "phases": [
            ("Triage", [
                "Hash the file; look it up before you run anything.",
                "Where did it come from: browser download, mail attachment, USB, or a script?",
                "Is the detection on write, on execute, or on network?",
            ]),
            ("Investigate", [
                "Strings and imports: does it talk to a domain, a raw IP, or a named pipe?",
                "Is it packed? Check entropy and section names before spending time on strings.",
                "Any signed parent process (rundll32, regsvr32, mshta) is worth a look.",
            ]),
            ("Contain", [
                "Isolate; block the C2 domain at DNS and the proxy.",
                "Check peer hosts for the same hash and the same DNS queries.",
            ]),
            ("Close", [
                "Record the family, the hash, the C2, and the ATT&CK techniques.",
                "Push the indicators into the blocklist and note the detection gap.",
            ]),
        ],
    },
    "exposure": {
        "title": "Exposed service found by a scan",
        "goal": "Decide whether it is meant to be reachable, and by whom.",
        "phases": [
            ("Triage", [
                "Identify the owner from the asset inventory, not from the banner.",
                "Is it internet-facing, or only reachable from a segment that should not see it?",
                "Check the port against what the service actually is — 8080 is not a finding on its own.",
            ]),
            ("Assess", [
                "Version known? Cross-check the CVE list rather than the banner alone.",
                "Is there authentication at all, and is it default?",
                "Does the exposure come from a firewall rule, a misplaced container port, or a host firewall that is off?",
            ]),
            ("Fix", [
                "Close the port or restrict the source range; prefer the rule over the app.",
                "Patch if the version is out of support — check the vendor's EOL date, not a blog.",
                "Re-scan after the change and keep both results.",
            ]),
            ("Close", [
                "Note the owner, the decision, and the date it was re-scanned.",
            ]),
        ],
    },
}


def names() -> list[str]:
    return sorted(PLAYBOOKS)


def get(name: str) -> dict:
    key = name.strip().lower()
    if key not in PLAYBOOKS:
        raise KeyError(name)
    return PLAYBOOKS[key]


def render_markdown(name: str, case_id: str = "") -> str:
    playbook = get(name)
    lines = [f"# Playbook — {playbook['title']}", ""]
    if case_id:
        lines.append(f"Case: **{case_id}**")
        lines.append("")
    lines.append(f"_{playbook['goal']}_")
    lines.append("")
    for phase, items in playbook["phases"]:
        lines.append(f"## {phase}")
        lines.append("")
        for item in items:
            lines.append(f"- [ ] {item}")
        lines.append("")
    return "\n".join(lines)
