def calculate_risk(events):
    score = 0

    for e in events:
        event_type = e.get("type") or e.get("event_type")
        if event_type == "phishing":
            score += 40
        if event_type == "login_anomaly":
            score += 30
        if event_type == "data_exfil":
            score += 35

    return min(score, 100)
