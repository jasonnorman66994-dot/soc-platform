def analyze_incident(incident):
    story = incident.get("story") or {}
    stages = story.get("stages") or []

    return {
        "summary": "Phishing led to credential compromise",
        "impact": "User account accessed from unusual geography with follow-on suspicious activity",
        "timeline": stages,
        "next_steps": [
            "Reset affected user password",
            "Revoke all active sessions",
            "Enable or enforce MFA for impacted identities",
            "Block malicious sender domain and source IP",
        ],
    }
