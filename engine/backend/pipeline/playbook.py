"""
Layer 7: Dynamic Playbook Generation
Context-aware response playbooks based on incident type, severity, and context
MITRE ATT&CK aligned
"""

from typing import Dict, List


PLAYBOOK_TEMPLATES = {
    "C2 Beaconing": {
        "title": "C2 Beaconing Response Playbook",
        "mitre_tags": ["T1071", "T1059", "TA0011"],
        "steps": [
            {
                "step": 1,
                "action": "Isolate {src_ip} from network segment immediately",
                "priority": "IMMEDIATE",
                "owner": "Network Team",
                "sla_minutes": 1,
            },
            {
                "step": 2,
                "action": "Block egress to {dst_ip} at perimeter firewall",
                "priority": "IMMEDIATE",
                "owner": "Network Team",
                "sla_minutes": 2,
            },
            {
                "step": 3,
                "action": "Capture full PCAP for forensic analysis (60s window around event)",
                "priority": "HIGH",
                "owner": "SOC Analyst",
                "sla_minutes": 5,
            },
            {
                "step": 4,
                "action": "Scan host {src_ip} for C2 malware — IOC list auto-attached",
                "priority": "HIGH",
                "owner": "IR Team",
                "sla_minutes": 10,
            },
            {
                "step": 5,
                "action": "Escalate to P1 — notify IR team, open ticket",
                "priority": "HIGH",
                "owner": "SOC Lead",
                "sla_minutes": 5,
            },
            {
                "step": 6,
                "action": "Threat-hunt lateral movement from this host (check SMB, RDP logs)",
                "priority": "MEDIUM",
                "owner": "Threat Hunter",
                "sla_minutes": 30,
            },
            {
                "step": 7,
                "action": "Document findings and update threat intel feeds with IOCs",
                "priority": "LOW",
                "owner": "SOC Analyst",
                "sla_minutes": 60,
            },
        ]
    },
    "Data Exfiltration": {
        "title": "Data Exfiltration Response Playbook",
        "mitre_tags": ["T1041", "T1048", "TA0010"],
        "steps": [
            {
                "step": 1,
                "action": "Immediately block outbound connections from {src_ip}",
                "priority": "IMMEDIATE",
                "owner": "Network Team",
                "sla_minutes": 1,
            },
            {
                "step": 2,
                "action": "Identify what data was transferred — check DLP logs for classification",
                "priority": "IMMEDIATE",
                "owner": "DLP Team",
                "sla_minutes": 5,
            },
            {
                "step": 3,
                "action": "Revoke credentials for user {user} — potential account compromise",
                "priority": "HIGH",
                "owner": "IAM Team",
                "sla_minutes": 5,
            },
            {
                "step": 4,
                "action": "Preserve forensic image of {src_ip} before remediation",
                "priority": "HIGH",
                "owner": "IR Team",
                "sla_minutes": 15,
            },
            {
                "step": 5,
                "action": "Notify DPO/Legal if PII or regulated data involved (GDPR/DPDP)",
                "priority": "HIGH",
                "owner": "Legal/Compliance",
                "sla_minutes": 30,
            },
            {
                "step": 6,
                "action": "Review access logs for the past 30 days for {user}",
                "priority": "MEDIUM",
                "owner": "SOC Analyst",
                "sla_minutes": 60,
            },
        ]
    },
    "Brute Force": {
        "title": "Brute Force / Credential Stuffing Response Playbook",
        "mitre_tags": ["T1110", "T1110.001", "TA0006"],
        "steps": [
            {
                "step": 1,
                "action": "Rate-limit or block {src_ip} at WAF/firewall — threshold exceeded",
                "priority": "IMMEDIATE",
                "owner": "Network Team",
                "sla_minutes": 2,
            },
            {
                "step": 2,
                "action": "Force MFA re-enrollment for targeted accounts",
                "priority": "HIGH",
                "owner": "IAM Team",
                "sla_minutes": 10,
            },
            {
                "step": 3,
                "action": "Check for successful logins from {src_ip} in the attack window",
                "priority": "HIGH",
                "owner": "SOC Analyst",
                "sla_minutes": 10,
            },
            {
                "step": 4,
                "action": "Check HaveIBeenPwned / dark web for credential leaks",
                "priority": "MEDIUM",
                "owner": "Threat Intel",
                "sla_minutes": 30,
            },
            {
                "step": 5,
                "action": "Update SIEM rule to alert on similar patterns from /24 subnet",
                "priority": "LOW",
                "owner": "SOC Engineer",
                "sla_minutes": 60,
            },
        ]
    },
    "Lateral Movement": {
        "title": "Lateral Movement Response Playbook",
        "mitre_tags": ["T1021", "T1021.002", "TA0008"],
        "steps": [
            {
                "step": 1,
                "action": "Isolate compromised host {src_ip} — quarantine from internal network",
                "priority": "IMMEDIATE",
                "owner": "Network Team",
                "sla_minutes": 2,
            },
            {
                "step": 2,
                "action": "Map all systems {src_ip} connected to in past 24h (SMB/RDP/WMI)",
                "priority": "IMMEDIATE",
                "owner": "SOC Analyst",
                "sla_minutes": 10,
            },
            {
                "step": 3,
                "action": "Reset all credentials on {src_ip} and connected hosts",
                "priority": "HIGH",
                "owner": "IAM Team",
                "sla_minutes": 15,
            },
            {
                "step": 4,
                "action": "Scan all reached hosts for persistence mechanisms (startup, cron, registry)",
                "priority": "HIGH",
                "owner": "IR Team",
                "sla_minutes": 30,
            },
            {
                "step": 5,
                "action": "Check for privilege escalation indicators on target hosts",
                "priority": "MEDIUM",
                "owner": "IR Team",
                "sla_minutes": 30,
            },
            {
                "step": 6,
                "action": "Review initial access vector — trace back to patient zero",
                "priority": "MEDIUM",
                "owner": "Threat Hunter",
                "sla_minutes": 60,
            },
        ]
    }
}


class PlaybookGenerator:
    def generate(self, incident: Dict) -> Dict:
        threat_type = incident.get("threat_type", "")
        template = PLAYBOOK_TEMPLATES.get(threat_type)

        if not template:
            return {
                "title": f"Generic Response — {threat_type}",
                "mitre_tags": [],
                "steps": [
                    {"step": 1, "action": "Investigate and document the anomalous activity", "priority": "HIGH"},
                    {"step": 2, "action": "Escalate to SOC lead for manual review", "priority": "MEDIUM"},
                ]
            }

        # Fill in context-specific values
        src_ip  = incident.get("src_ip", "UNKNOWN_IP")
        dst_ip  = incident.get("dst_ip", "UNKNOWN_IP")
        user    = incident.get("user") or "unknown_user"

        filled_steps = []
        for step in template["steps"]:
            filled = dict(step)
            filled["action"] = step["action"].format(
                src_ip=src_ip,
                dst_ip=dst_ip,
                user=user,
            )
            filled_steps.append(filled)

        return {
            "title": template["title"],
            "mitre_tags": template["mitre_tags"],
            "steps": filled_steps,
            "severity": incident.get("severity", "MEDIUM"),
            "incident_id": incident.get("id", ""),
            "generated_at": __import__("datetime").datetime.now().isoformat(),
            "rule_1_10_60": {
                "detect_target": "< 1 min",
                "investigate_target": "< 10 min",
                "remediate_target": "< 60 min",
            }
        }
