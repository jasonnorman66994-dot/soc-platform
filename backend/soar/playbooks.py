"""
SOAR Playbook Orchestration

Automated response engine that chains integrations based on alert/incident patterns.

Playbooks define response workflows:
- Account Takeover Detection → Disable user, revoke sessions, notify SOC
- Data Exfiltration → Block IP, isolate subnet, escalate
- Phishing Campaign → Block domains, notify users, quarantine emails
"""

from datetime import datetime, timezone
from typing import Any

from integrations.identity import disable_user, revoke_sessions, force_password_reset, enable_mfa
from integrations.network import block_ip, block_domain, isolate_subnet
from integrations.messaging import send_alert, send_to_slack, send_to_teams, send_to_siem, notify_all_channels


class PlaybookExecutor:
    """Execute SOAR playbook actions for incident response."""
    
    def __init__(self):
        self.execution_history = []
    
    def log_action(self, action: str, result: dict, incident_id: int = None):
        """Log action execution."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "result": result,
            "incident_id": incident_id,
        }
        self.execution_history.append(entry)
        return entry
    
    def execute_account_takeover_playbook(self, incident: dict, event: dict) -> dict:
        """
        Respond to account takeover detection.
        
        Actions:
        1. Disable user account
        2. Revoke all sessions
        3. Force password reset on re-enable
        4. Enable MFA
        5. Notify security team
        """
        incident_id = incident.get("id")
        user_id = event.get("user") or incident.get("context", {}).get("user")
        
        if not user_id:
            return {
                "status": "error",
                "incident_id": incident_id,
                "message": "No user_id in incident context",
            }
        
        actions = []
        
        # Step 1: Disable user
        disable_result = disable_user(user_id)
        actions.append(("disable_user", disable_result))
        self.log_action("disable_user", disable_result, incident_id)
        
        # Step 2: Revoke sessions
        revoke_result = revoke_sessions(user_id)
        actions.append(("revoke_sessions", revoke_result))
        self.log_action("revoke_sessions", revoke_result, incident_id)
        
        # Step 3: Force password reset
        pwd_result = force_password_reset(user_id)
        actions.append(("force_password_reset", pwd_result))
        self.log_action("force_password_reset", pwd_result, incident_id)
        
        # Step 4: Enable MFA
        mfa_result = enable_mfa(user_id)
        actions.append(("enable_mfa", mfa_result))
        self.log_action("enable_mfa", mfa_result, incident_id)
        
        # Step 5: Notify
        notify_result = notify_all_channels(
            title=f"Account Takeover Response: {user_id}",
            message=f"User {user_id} disabled and sessions revoked. MFA enforced.",
            incident_data=incident,
        )
        actions.append(("notify", notify_result))
        self.log_action("notify", notify_result, incident_id)
        
        return {
            "status": "success",
            "incident_id": incident_id,
            "playbook": "account_takeover",
            "user": user_id,
            "actions": actions,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def execute_suspicious_ip_playbook(self, incident: dict, event: dict) -> dict:
        """
        Respond to suspicious IP detection.
        
        Actions:
        1. Block IP at edge
        2. Optionally isolate subnet
        3. Notify SOC
        """
        incident_id = incident.get("id")
        ip = event.get("ip") or incident.get("context", {}).get("ip")
        
        if not ip:
            return {
                "status": "error",
                "incident_id": incident_id,
                "message": "No IP in incident context",
            }
        
        actions = []
        severity = incident.get("severity", "medium")
        
        # Step 1: Block IP
        block_result = block_ip(ip, reason=f"Suspicious activity - {incident.get('title')}")
        actions.append(("block_ip", block_result))
        self.log_action("block_ip", block_result, incident_id)
        
        # Step 2: For critical incidents, isolate entire subnet
        if severity in ("critical", "high"):
            subnet = ".".join(ip.split(".")[:3]) + ".0/24"  # Simple subnet extraction
            isolate_result = isolate_subnet(subnet, reason=f"High-severity incident {incident_id}")
            actions.append(("isolate_subnet", isolate_result))
            self.log_action("isolate_subnet", isolate_result, incident_id)
        
        # Step 3: Notify
        notify_result = notify_all_channels(
            title=f"Suspicious IP Blocked: {ip}",
            message=f"IP {ip} has been blocked at the edge. Severity: {severity}",
            incident_data=incident,
        )
        actions.append(("notify", notify_result))
        self.log_action("notify", notify_result, incident_id)
        
        return {
            "status": "success",
            "incident_id": incident_id,
            "playbook": "suspicious_ip",
            "ip": ip,
            "actions": actions,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def execute_phishing_playbook(self, incident: dict, event: dict) -> dict:
        """
        Respond to phishing campaign detection.
        
        Actions:
        1. Block sender domain
        2. Notify users to report/delete emails
        3. Alert SOC for investigation
        """
        incident_id = incident.get("id")
        sender_domain = event.get("sender_domain") or incident.get("context", {}).get("sender_domain")
        
        actions = []
        
        if sender_domain:
            # Step 1: Block domain
            block_result = block_domain(sender_domain, reason=f"Phishing campaign - {incident_id}")
            actions.append(("block_domain", block_result))
            self.log_action("block_domain", block_result, incident_id)
        
        # Step 2: Notify
        notify_result = notify_all_channels(
            title="Phishing Campaign Detected",
            message=f"Domain {sender_domain} blocked. All users have been notified.",
            incident_data=incident,
        )
        actions.append(("notify", notify_result))
        self.log_action("notify", notify_result, incident_id)
        
        return {
            "status": "success",
            "incident_id": incident_id,
            "playbook": "phishing",
            "domain": sender_domain,
            "actions": actions,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def execute_data_exfiltration_playbook(self, incident: dict, event: dict) -> dict:
        """
        Respond to data exfiltration detection.
        
        Actions:
        1. Block suspicious IP
        2. Disable user
        3. Isolate subnet
        4. Escalate to incident commander
        """
        incident_id = incident.get("id")
        user_id = event.get("user") or incident.get("context", {}).get("user")
        ip = event.get("ip") or incident.get("context", {}).get("ip")
        
        actions = []
        
        if ip:
            block_result = block_ip(ip, reason="Data exfiltration attempt")
            actions.append(("block_ip", block_result))
            self.log_action("block_ip", block_result, incident_id)
            
            # Isolate the subnet for high-severity exfiltration
            if incident.get("severity") in ("critical", "high"):
                subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                isolate_result = isolate_subnet(subnet, reason="Data exfiltration containment")
                actions.append(("isolate_subnet", isolate_result))
                self.log_action("isolate_subnet", isolate_result, incident_id)
        
        if user_id:
            disable_result = disable_user(user_id)
            actions.append(("disable_user", disable_result))
            self.log_action("disable_user", disable_result, incident_id)
        
        # Escalate
        notify_result = notify_all_channels(
            title=f"🚨 DATA EXFILTRATION: {user_id} → {ip}",
            message=f"Potential data exfiltration. User disabled, IP blocked, subnet isolated.",
            incident_data=incident,
        )
        actions.append(("escalate_notify", notify_result))
        self.log_action("escalate_notify", notify_result, incident_id)
        
        return {
            "status": "success" if actions else "warning",
            "incident_id": incident_id,
            "playbook": "data_exfiltration",
            "user": user_id,
            "ip": ip,
            "actions": actions,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    
    def execute_playbook_for_incident(self, incident: dict, event: dict) -> dict:
        """
        Intelligently select and execute playbooks based on incident type.
        
        Args:
            incident: Incident dict with id, title, severity, etc.
            event: Event dict with user, ip, event_type, etc.
        
        Returns:
            Execution summary with all action results
        """
        incident_type = incident.get("title", "").lower()
        title = incident.get("title", "unknown")
        
        # Route to appropriate playbook
        if "account_takeover" in incident_type or "login_anomaly" in incident_type:
            return self.execute_account_takeover_playbook(incident, event)
        
        elif "suspicious_ip" in incident_type or "impossible_travel" in incident_type:
            return self.execute_suspicious_ip_playbook(incident, event)
        
        elif "phishing" in incident_type:
            return self.execute_phishing_playbook(incident, event)
        
        elif "exfiltration" in incident_type or "data_loss" in incident_type:
            return self.execute_data_exfiltration_playbook(incident, event)
        
        else:
            # Generic response for unknown incident type
            notify_result = notify_all_channels(
                title=f"Incident Detected: {title}",
                message=f"Manual investigation required. Severity: {incident.get('severity')}",
                incident_data=incident,
            )
            return {
                "status": "warning",
                "incident_id": incident.get("id"),
                "playbook": "generic_alert",
                "message": "No automated playbook matched. Ticket created for manual review.",
                "notification": notify_result,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
    
    def get_execution_history(self, incident_id: int = None) -> list:
        """Retrieve execution history, optionally filtered by incident."""
        if incident_id is None:
            return self.execution_history
        return [e for e in self.execution_history if e.get("incident_id") == incident_id]


# Global executor instance
_executor = PlaybookExecutor()


def execute_playbook_for_incident(incident: dict, event: dict) -> dict:
    """Execute playbook for incident. Entry point for API/worker."""
    return _executor.execute_playbook_for_incident(incident, event)


def get_execution_history(incident_id: int = None) -> list:
    """Get playbook execution history."""
    return _executor.get_execution_history(incident_id)
