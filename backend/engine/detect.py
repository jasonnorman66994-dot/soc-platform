TRUSTED_DOMAINS = {"company.com", "microsoft.com", "github.com", "google.com"}


def _get_nested_value(data: dict, path: str):
    current = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _matches_field(actual, expected) -> bool:
    if isinstance(expected, list):
        return actual in expected
    if isinstance(expected, str) and isinstance(actual, str):
        return actual.lower() == expected.lower()
    return actual == expected


def _matches_match_block(event: dict, match: dict) -> bool:
    event_type = event.get("event_type") or event.get("type")
    raw = event.get("raw") or {}

    match_event_types = set(match.get("event_types", []))
    if match_event_types and event_type not in match_event_types:
        return False

    if match.get("geo_mismatch") and not raw.get("geo_mismatch"):
        return False

    required_fields = match.get("fields", {})
    for field_path, expected in required_fields.items():
        actual = _get_nested_value(event, field_path)
        if not _matches_field(actual, expected):
            return False

    return True


def _matches_sigma_detection(event: dict, detection: dict) -> bool:
    if not detection:
        return False

    # Supports a minimal Sigma-like form:
    # detection:
    #   selection:
    #     event_type: login_anomaly
    #     raw.geo_mismatch: true
    #   condition: selection
    selection = detection.get("selection")
    condition = str(detection.get("condition") or "selection").strip()
    if condition != "selection" or not isinstance(selection, dict):
        return False

    for field_path, expected in selection.items():
        actual = _get_nested_value(event, field_path)
        if not _matches_field(actual, expected):
            return False

    return True


def _append_custom_rule_alerts(event: dict, rules: list[dict], alerts: list[dict]) -> None:
    for rule in rules:
        matched = False
        if isinstance(rule.get("match"), dict):
            matched = _matches_match_block(event, rule.get("match") or {})
        elif isinstance(rule.get("detection"), dict):
            matched = _matches_sigma_detection(event, rule.get("detection") or {})

        if not matched:
            continue

        alerts.append(
            {
                "rule_id": rule.get("id", "custom-rule"),
                "title": rule.get("title", "Custom Detection Match"),
                "severity": rule.get("severity", "medium"),
                "confidence": int(rule.get("confidence", 75)),
                "mitre": rule.get("mitre", "N/A"),
                "summary": rule.get("summary", f"Matched rule {rule.get('id', 'custom-rule')}"),
            }
        )


def detect(event: dict, rules: list[dict] | None = None) -> list[dict]:
    alerts = []
    subject = (event.get("subject") or "").lower()
    sender_domain = (event.get("sender_domain") or "").lower()
    event_type = event.get("event_type") or event.get("type")
    raw = event.get("raw") or {}

    if event_type == "email" and "urgent" in subject and sender_domain and sender_domain not in TRUSTED_DOMAINS:
        alerts.append(
            {
                "rule_id": "SIGMA-001",
                "title": "Phishing Suspected",
                "severity": "high",
                "confidence": 87,
                "mitre": "T1566.001",
                "summary": f"Urgent email from untrusted domain {sender_domain}",
            }
        )

    if event_type == "login_anomaly":
        alerts.append(
            {
                "rule_id": "SIGMA-002",
                "title": "Login Anomaly",
                "severity": "critical",
                "confidence": 92,
                "mitre": "T1078",
                "summary": "Potential account takeover behavior detected",
            }
        )

    if event_type == "email_click":
        alerts.append(
            {
                "rule_id": "SIGMA-004",
                "title": "Suspicious Link Click",
                "severity": "medium",
                "confidence": 74,
                "mitre": "T1204.001",
                "summary": "User clicked link from suspicious email",
            }
        )

    if event_type == "data_exfil":
        alerts.append(
            {
                "rule_id": "SIGMA-003",
                "title": "Data Exfiltration Suspected",
                "severity": "high",
                "confidence": 90,
                "mitre": "T1048",
                "summary": "Suspicious outbound transfer pattern",
            }
        )

    if event_type == "file_download" and raw.get("sensitive"):
        alerts.append(
            {
                "rule_id": "SIGMA-005",
                "title": "Sensitive File Access",
                "severity": "high",
                "confidence": 81,
                "mitre": "T1530",
                "summary": "Sensitive file download detected",
            }
        )

    if event_type == "oauth_grant" and raw.get("untrusted_app"):
        alerts.append(
            {
                "rule_id": "SIGMA-006",
                "title": "Suspicious OAuth Application Consent",
                "severity": "high",
                "confidence": 86,
                "mitre": "T1528",
                "summary": "Untrusted OAuth app granted tenant-wide scope",
            }
        )

    if event_type == "powershell_exec" and raw.get("encoded_command"):
        alerts.append(
            {
                "rule_id": "SIGMA-007",
                "title": "Encoded PowerShell Execution",
                "severity": "critical",
                "confidence": 93,
                "mitre": "T1059.001",
                "summary": "Potential post-exploitation PowerShell execution chain",
            }
        )

    if rules:
        _append_custom_rule_alerts(event, rules, alerts)

    return alerts
