"""A small SOAR-style response playbook.

Detection rules answer "what happened?". This module answers "what do we do
about it?", following the same steps a SOAR platform (Splunk SOAR, Cortex
XSOAR, Tines, Sentinel playbooks) runs after an alert:

    1. ENRICH   look up context about the source IP in threat intelligence
    2. DECIDE   apply response rules: block, escalate to a human, or monitor
    3. ACT      carry out the decision (simulated: files, not a real firewall)
    4. NOTIFY   summarise what was done for the analyst
    5. RECORD   write every decision to an audit log

The guiding principle is human-in-the-loop: automate only what we are
confident about, and send anything risky or uncertain to a person.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .models import Alert, Decision, EnrichedAlert


# ---------------------------------------------------------------- 1. ENRICH

def load_intel(path: Path) -> Dict:
    """Read a threat-intel file with "allowlist" and "ips" sections."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {"allowlist": data.get("allowlist", {}), "ips": data.get("ips", {})}


def enrich(alert: Alert, intel: Dict) -> EnrichedAlert:
    """Attach what threat intel knows about the alert's source IP."""
    ip = alert.source_ip
    if ip in intel["allowlist"]:
        return EnrichedAlert(alert, "allowlisted", "??", (), intel["allowlist"][ip])

    entry = intel["ips"].get(ip)
    if entry is None:
        return EnrichedAlert(alert, "unknown", "??", ())

    return EnrichedAlert(
        alert=alert,
        reputation=entry.get("reputation", "unknown"),
        country=entry.get("country", "??"),
        tags=tuple(entry.get("tags", [])),
    )


# ---------------------------------------------------------------- 2. DECIDE

def decide(enriched: EnrichedAlert) -> Decision:
    """Turn an enriched alert into a verdict. Rules are checked in order.

    The order matters: safety rules come first, so no later rule can ever
    auto-block an allowlisted IP or skip a human on a possible compromise.
    """
    alert, reputation = enriched.alert, enriched.reputation

    if reputation == "allowlisted":
        return Decision("monitor", f"IP is allowlisted ({enriched.note}); never auto-blocked")

    if alert.severity == "critical":
        return Decision(
            "escalate",
            "Possible account compromise: blocking the IP is not enough, "
            "a human must reset credentials and investigate",
        )

    if reputation == "malicious":
        return Decision("block", "Attack from an IP that threat intel lists as malicious")

    if alert.severity == "high":
        return Decision(
            "escalate",
            f"High-severity attack but IP reputation is {reputation}; "
            "not confident enough to auto-block",
        )

    return Decision("monitor", f"Low-risk activity from a {reputation} IP; logged only")


# ---------------------------------------------------------------- 3. ACT

@dataclass
class PlaybookResult:
    """Everything the playbook did in one run, for reporting and tests."""

    dry_run: bool
    steps: List[tuple] = field(default_factory=list)   # (EnrichedAlert, Decision)
    blocked: List[str] = field(default_factory=list)   # IPs newly added to the blocklist
    incidents: List[dict] = field(default_factory=list)


def run_playbook(alerts: List[Alert], intel: Dict, out_dir: Path,
                 dry_run: bool = False) -> PlaybookResult:
    """Run every alert through enrich -> decide -> act -> record.

    With dry_run=True nothing is written: you see what WOULD happen. Real SOC
    teams test new playbooks this way before letting them take action.
    """
    out_dir = Path(out_dir)
    result = PlaybookResult(dry_run=dry_run)
    blocklist = out_dir / "blocklist.txt"
    already_blocked = set(blocklist.read_text().split()) if blocklist.exists() else set()
    audit_lines = []

    for alert in alerts:
        enriched = enrich(alert, intel)
        decision = decide(enriched)
        result.steps.append((enriched, decision))

        if decision.verdict == "block" and alert.source_ip not in already_blocked:
            already_blocked.add(alert.source_ip)
            result.blocked.append(alert.source_ip)
        elif decision.verdict == "escalate":
            result.incidents.append(_incident(len(result.incidents) + 1, enriched, decision))

        audit_lines.append(
            f"{datetime.now():%Y-%m-%d %H:%M:%S} | {alert.rule} | {alert.source_ip} | "
            f"{enriched.reputation} | {decision.verdict} | {decision.reason}"
        )

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        if result.blocked:
            with blocklist.open("a", encoding="utf-8") as f:
                f.writelines(ip + "\n" for ip in result.blocked)
        if result.incidents:
            (out_dir / "incidents.json").write_text(
                json.dumps(result.incidents, indent=2), encoding="utf-8")
        with (out_dir / "audit.log").open("a", encoding="utf-8") as f:
            f.writelines(line + "\n" for line in audit_lines)

    return result


# What an analyst should do next, per detection rule. In a real SOAR platform
# these are the manual tasks attached to a case. {ip} and {user} are filled in.
RECOMMENDED_STEPS = {
    "ssh_success_after_failures": [
        "Disable or reset the password of the account that logged in{user}",
        "Review what that account did after the successful login (commands, files, new keys)",
        "Check ~/.ssh/authorized_keys and cron jobs for persistence added by the attacker",
        "Block {ip} once the compromise is confirmed",
        "Search other servers' logs for activity from {ip}",
    ],
    "ssh_brute_force": [
        "Check whether {ip} belongs to a known user, partner or internal system",
        "Confirm no login from {ip} succeeded",
        "Block {ip} if it is not a known source",
        "Make sure the targeted account{user} uses key-based login or MFA",
    ],
    "ssh_password_spraying": [
        "Confirm no login from {ip} succeeded on any of the targeted accounts",
        "Block {ip} if it is not a known source",
        "Review the targeted accounts for weak or default passwords",
        "Consider disabling password login for SSH",
    ],
    "web_sql_injection": [
        "Check the web server response codes for the requests from {ip} (a 200 may mean success)",
        "Review database logs for unusual queries around the same time",
        "Block {ip} at the WAF or firewall if the activity is not an authorised test",
        "Make sure the affected endpoint uses parameterised queries",
    ],
    "web_path_traversal": [
        "Check whether any request from {ip} returned 200 with file contents",
        "Confirm sensitive files (e.g. /etc/passwd, config files) were not exposed",
        "Block {ip} at the WAF or firewall if the activity is not an authorised test",
        "Fix input validation on the affected path",
    ],
    "web_scanner": [
        "Check whether {ip} is an authorised scanner; if so, add it to the allowlist",
        "Watch {ip} for follow-up exploitation attempts",
    ],
}
DEFAULT_STEPS = ["Investigate activity from {ip}", "Decide whether to block {ip}"]


def recommended_steps(alert: Alert) -> List[str]:
    """The analyst checklist for an escalated alert, with the IP and user filled in."""
    user = _username(alert.description)
    return [step.format(ip=alert.source_ip, user=f" ('{user}')" if user else "")
            for step in RECOMMENDED_STEPS.get(alert.rule, DEFAULT_STEPS)]


def _username(description: str) -> str:
    """Pull an account name out of descriptions like "... as 'deploy' ..."."""
    parts = description.split("'")
    return parts[1] if len(parts) >= 3 else ""


def _incident(number: int, enriched: EnrichedAlert, decision: Decision) -> dict:
    """An incident ticket, the shape a Jira or ServiceNow integration would send."""
    alert = enriched.alert
    return {
        "id": f"INC-{number:04d}",
        "severity": alert.severity,
        "title": f"{alert.rule} from {alert.source_ip}",
        "description": alert.description,
        "mitre": f"{alert.mitre_id} {alert.mitre_name}",
        "source_ip": alert.source_ip,
        "ip_reputation": enriched.reputation,
        "ip_country": enriched.country,
        "reason_escalated": decision.reason,
        "recommended_steps": recommended_steps(alert),
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
    }


# ---------------------------------------------------------------- 4. NOTIFY

ICONS = {"block": "BLOCK   ", "escalate": "ESCALATE", "monitor": "MONITOR "}


def format_playbook(result: PlaybookResult, out_dir: Path) -> str:
    """A summary of the response for the analyst, printed after the alerts."""
    mode = " (DRY RUN - nothing was written)" if result.dry_run else ""
    lines = [f"Response playbook{mode}", ""]
    for enriched, decision in result.steps:
        a = enriched.alert
        lines.append(f"[{ICONS[decision.verdict]}] {a.source_ip:<15} {a.rule:<28} "
                     f"intel: {enriched.reputation}")
        lines.append(f"             why: {decision.reason}")
        if decision.verdict == "escalate":
            lines.append("             next steps for the analyst:")
            lines += [f"               - {step}" for step in recommended_steps(a)]
    lines += [
        "",
        f"Blocked {_count(len(result.blocked), 'new IP')}, opened "
        f"{_count(len(result.incidents), 'incident')} for a human, monitored the rest.",
    ]
    if not result.dry_run:
        lines.append(f"Files written to {out_dir}/ (blocklist.txt, incidents.json, audit.log)")
    return "\n".join(lines)


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" + ("" if n == 1 else "s")
