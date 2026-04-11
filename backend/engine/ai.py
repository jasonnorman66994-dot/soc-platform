"""
AI Analyst Engine

Provides intelligent analysis of security incidents:
- Attack summary generation
- Impact assessment
- Root cause analysis
- Risk scoring
- Automated recommendations
"""

from datetime import datetime, timezone
from enum import Enum


class RiskLevel(Enum):
    """Risk assessment levels."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


class AIAnalyzer:
    """Intelligent incident analysis engine."""
    
    MITRE_ATTACK_MAP = {
        "phishing": ["T1598", "T1199"],  # Phishing for information, Trusted relationship
        "account_takeover": ["T1078", "T1110"],  # Valid accounts, Brute force
        "data_exfiltration": ["T1041", "T1020"],  # Exfiltration over C2, Automated exfil
        "privilege_escalation": ["T1134", "T1548"],  # Access token manipulation, Abuse elevation
        "lateral_movement": ["T1570", "T1570"],  # Lateral tool transfer
    }
    
    @staticmethod
    def analyze_incident(incident: dict) -> dict:
        """
        Comprehensive incident analysis.
        
        Returns:
        - summary: Human-readable attack narrative
        - impact: Business/operational impact assessment
        - risk_score: Numerical risk assessment (0-100)
        - timeline: Event sequence
        - root_cause: Likely entry point/vulnerability
        - affected_assets: Systems/users/data impacted
        - mitre_techniques: ATT&CK framework techniques
        - recommendations: Prioritized response actions
        - next_steps: Immediate next actions for analyst
        """
        incident_id = incident.get("id", "unknown")
        title = incident.get("title", "Unknown incident")
        severity = incident.get("severity", "medium")
        description = incident.get("description", "")
        context = incident.get("context", {})
        
        # Extract key information
        user = context.get("user") or "unknown"
        ip = context.get("ip") or "unknown"
        event_type = context.get("event_type") or "unknown"
        location = context.get("location") or "unknown"
        
        # Analyze severity
        is_critical = severity in ("critical", "high")
        
        # Generate attack summary
        summary = AIAnalyzer._generate_summary(title, user, ip, event_type, description)
        
        # Assess impact
        impact = AIAnalyzer._assess_impact(incident)
        
        # Calculate risk score
        risk_score = AIAnalyzer._calculate_risk_score(incident)
        
        # Determine root cause
        root_cause = AIAnalyzer._analyze_root_cause(title, event_type)
        
        # Get affected assets
        affected_assets = AIAnalyzer._identify_affected_assets(incident, context)
        
        # Map ATT&CK techniques
        mitre_techniques = AIAnalyzer._get_mitre_techniques(title)
        
        # Generate recommendations
        recommendations = AIAnalyzer._generate_recommendations(incident, severity)
        
        # Next steps
        next_steps = AIAnalyzer._prioritize_next_steps(is_critical, severity)
        
        return {
            "incident_id": incident_id,
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            "confidence": 0.85,  # In production, derive from model confidence
            "summary": summary,
            "impact": impact,
            "risk_score": risk_score,
            "risk_level": AIAnalyzer._score_to_level(risk_score),
            "timeline": incident.get("story", {}).get("stages", []),
            "root_cause": root_cause,
            "affected_assets": affected_assets,
            "mitre_techniques": mitre_techniques,
            "recommendations": recommendations,
            "next_steps": next_steps,
            "estimated_mttc": AIAnalyzer._estimate_containment_time(severity),
        }
    
    @staticmethod
    def _generate_summary(title: str, user: str, ip: str, event_type: str, desc: str) -> str:
        """Generate narrative summary of attack."""
        if "account_takeover" in title.lower():
            return f"Suspicious login activity detected for user {user} from unexpected location ({ip}). Pattern suggests credential compromise or account takeover attempt."
        
        elif "phishing" in title.lower():
            return f"Phishing email detected targeting {user}. Email contains malicious link or attachment. Click-through or download may compromise system."
        
        elif "data_exfiltration" in title.lower():
            return f"Large data transfer detected from {user} to external IP {ip}. Potential unauthorized data exfiltration or lateral movement."
        
        elif "privilege_escalation" in title.lower():
            return f"Privilege escalation attempt detected by {user}. Successful elevation may grant admin/system access."
        
        else:
            return f"Security incident detected: {event_type} activity by {user}. {desc}"
    
    @staticmethod
    def _assess_impact(incident: dict) -> dict:
        """Assess business impact of incident."""
        severity = incident.get("severity", "medium")
        context = incident.get("context", {})
        
        impact_map = {
            "critical": {
                "scope": "enterprise-wide",
                "affected_users": "multiple_departments",
                "data_risk": "sensitive_pii_phi_financial",
                "business_impact": "revenue_loss_regulatory_breach",
                "recovery_time": "24-48_hours",
            },
            "high": {
                "scope": "department",
                "affected_users": "team_or_department",
                "data_risk": "internal_confidential",
                "business_impact": "operational_disruption",
                "recovery_time": "4-12_hours",
            },
            "medium": {
                "scope": "single_user",
                "affected_users": "one_or_few",
                "data_risk": "low_sensitivity",
                "business_impact": "minor_disruption",
                "recovery_time": "1-4_hours",
            },
            "low": {
                "scope": "isolated",
                "affected_users": "user_only",
                "data_risk": "none",
                "business_impact": "none_or_minor",
                "recovery_time": "less_than_1_hour",
            },
        }
        
        return impact_map.get(severity, impact_map["low"])
    
    @staticmethod
    def _calculate_risk_score(incident: dict) -> int:
        """Calculate numerical risk score (0-100)."""
        severity_scores = {"critical": 95, "high": 75, "medium": 50, "low": 25}
        severity = incident.get("severity", "medium")
        
        base_score = severity_scores.get(severity, 50)
        
        # Adjust for additional factors
        context = incident.get("context", {})
        alert_count = incident.get("alert_count", 1)
        
        # More alerts = higher risk
        if alert_count > 5:
            base_score = min(100, base_score + 10)
        
        return base_score
    
    @staticmethod
    def _score_to_level(score: int) -> str:
        """Convert score to risk level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    @staticmethod
    def _analyze_root_cause(title: str, event_type: str) -> dict:
        """Analyze likely root cause."""
        root_causes = {
            "account_takeover": {
                "likely_cause": "Compromised credentials",
                "entry_points": ["Phishing", "Credential stuffing", "Password spray", "Keylogger"],
                "required_evidence": ["Login from new IP", "Unusual login time", "Failed login attempts"],
            },
            "phishing": {
                "likely_cause": "Social engineering",
                "entry_points": ["Email", "Messaging", "Phone call"],
                "required_evidence": ["Malicious link", "Attachment", "Spoofed sender"],
            },
            "data_exfiltration": {
                "likely_cause": "Insider threat or compromised account",
                "entry_points": ["Compromised user", "Insider", "Application vulnerability"],
                "required_evidence": ["Large file transfer", "Unusual destination", "Off-hours activity"],
            },
        }
        
        for key, cause_info in root_causes.items():
            if key in title.lower() or key in event_type.lower():
                return cause_info
        
        return {
            "likely_cause": "Unknown, requires investigation",
            "entry_points": ["Investigation needed"],
            "required_evidence": ["Collect logs and alerts"],
        }
    
    @staticmethod
    def _identify_affected_assets(incident: dict, context: dict) -> dict:
        """Identify systems and users affected."""
        return {
            "users": [context.get("user", "unknown")],
            "ips": [context.get("ip", "unknown")],
            "systems": context.get("systems", []),
            "applications": context.get("applications", []),
            "data_classifications": ["requires_investigation"],
        }
    
    @staticmethod
    def _get_mitre_techniques(title: str) -> list:
        """Map incident to MITRE ATT&CK techniques."""
        title_lower = title.lower()
        techniques = set()
        
        for incident_type, technique_ids in AIAnalyzer.MITRE_ATTACK_MAP.items():
            if incident_type in title_lower:
                techniques.update(technique_ids)
        
        return list(techniques) if techniques else ["T1005"]  # Data from local system (generic)
    
    @staticmethod
    def _generate_recommendations(incident: dict, severity: str) -> list:
        """Generate prioritized response recommendations."""
        recommendations = []
        title = incident.get("title", "").lower()
        
        # Always include immediate actions for high-severity incidents
        if severity in ("critical", "high"):
            recommendations.append({
                "priority": "immediate",
                "action": "Isolate affected systems from network",
                "rationale": "Prevent further damage or lateral movement",
                "estimated_time": "5-15 minutes",
            })
            recommendations.append({
                "priority": "immediate",
                "action": "Alert incident response team",
                "rationale": "Coordinate rapid response",
                "estimated_time": "2 minutes",
            })
        
        # Attack-specific recommendations
        if "account_takeover" in title:
            recommendations.extend([
                {
                    "priority": "high",
                    "action": "Disable compromised user account",
                    "rationale": "Prevent attacker from using account",
                    "estimated_time": "2 minutes",
                },
                {
                    "priority": "high",
                    "action": "Revoke all active sessions",
                    "rationale": "Force re-authentication",
                    "estimated_time": "2 minutes",
                },
                {
                    "priority": "high",
                    "action": "Force password reset (with MFA)",
                    "rationale": "Reclaim account",
                    "estimated_time": "30 seconds",
                },
            ])
        
        elif "phishing" in title:
            recommendations.extend([
                {
                    "priority": "high",
                    "action": "Block sender domain/email",
                    "rationale": "Prevent further phishing attempts",
                    "estimated_time": "2 minutes",
                },
                {
                    "priority": "high",
                    "action": "Quarantine emails from this sender",
                    "rationale": "Recall attacks",
                    "estimated_time": "5 minutes",
                },
                {
                    "priority": "medium",
                    "action": "User awareness notification",
                    "rationale": "Alert organization to threat",
                    "estimated_time": "10 minutes",
                },
            ])
        
        elif "data_exfiltration" in title:
            recommendations.extend([
                {
                    "priority": "immediate",
                    "action": "Block IP at edge firewall",
                    "rationale": "Prevent ongoing exfiltration",
                    "estimated_time": "1 minute",
                },
                {
                    "priority": "high",
                    "action": "Disable user account",
                    "rationale": "Stop attacker activity",
                    "estimated_time": "2 minutes",
                },
                {
                    "priority": "high",
                    "action": "Forensic analysis of data accessed",
                    "rationale": "Understand scope of breach",
                    "estimated_time": "2-4 hours",
                },
            ])
        
        return recommendations
    
    @staticmethod
    def _prioritize_next_steps(is_critical: bool, severity: str) -> list:
        """Get prioritized next steps for analyst."""
        next_steps = []
        
        if is_critical:
            next_steps = [
                "1. Confirm incident with data owner",
                "2. Execute incident response playbook",
                "3. Notify compliance/legal if breach suspected",
                "4. Begin forensic evidence collection",
                "5. Document incident timeline",
            ]
        else:
            next_steps = [
                "1. Review incident details",
                "2. Query for related incidents (same user/IP)",
                "3. Check if playbook automation has executed",
                "4. Assess need for manual containment",
                "5. Plan investigation if needed",
            ]
        
        return next_steps
    
    @staticmethod
    def _estimate_containment_time(severity: str) -> str:
        """Estimate time to contain incident."""
        estimates = {
            "critical": "5-15 minutes",
            "high": "15-60 minutes",
            "medium": "1-4 hours",
            "low": "4-24 hours",
        }
        return estimates.get(severity, "4-24 hours")


def analyze_incident(incident):
    """Entry point for incident analysis."""
    return AIAnalyzer.analyze_incident(incident)

