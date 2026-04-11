import urllib.request, json

API = "http://localhost/api"

# 1. Bootstrap demo
r = urllib.request.urlopen(f"{API}/demo/bootstrap")
d = json.loads(r.read())
tid = d["tenant_id"]
ak = d["api_key"]
email = d["analyst"]["email"]
pw = d["analyst"]["password"]
print(f"1. Bootstrap OK: tenant={tid}")

# 2. Login
body = json.dumps({"email": email, "password": pw}).encode()
req = urllib.request.Request(f"{API}/auth/login", data=body, headers={"Content-Type": "application/json", "X-Tenant-ID": tid})
r = urllib.request.urlopen(req)
d = json.loads(r.read())
token = d["access_token"]
print("2. Login OK")

h = {"Content-Type": "application/json", "Authorization": f"Bearer {token}", "X-Tenant-ID": tid}
ih = {"Content-Type": "application/json", "X-API-Key": ak, "X-Tenant-ID": tid}

# 3. Ingest (with enriched_data)
body = json.dumps({"user_id": "demo.user", "event_type": "email", "subject": "URGENT verify", "sender_domain": "evil.com", "ip": "203.0.113.42", "raw": {}}).encode()
req = urllib.request.Request(f"{API}/ingest", data=body, headers=ih, method="POST")
r = urllib.request.urlopen(req)
d = json.loads(r.read())
enriched = d.get("enriched_data", {})
geo_country = (enriched.get("geo_ip") or {}).get("country")
id_name = (enriched.get("identity") or {}).get("full_name")
print(f"3. Ingest OK: enriched_data={bool(enriched)}, geo={geo_country}, identity={id_name}")
inc_id = (d.get("incident") or {}).get("id")

# 4. Get SOAR policies (should include ml_risk_threshold)
req = urllib.request.Request(f"{API}/soar/policies", headers=h)
r = urllib.request.urlopen(req)
d = json.loads(r.read())
policy = d.get("policy", {})
ml_thresh = policy.get("ml_risk_threshold")
print(f"4. SOAR Policy OK: ml_risk_threshold={ml_thresh}")

# 5. SOAR stats
req = urllib.request.Request(f"{API}/soar/stats?window_days=30", headers=h)
r = urllib.request.urlopen(req)
d = json.loads(r.read())
print(f"5. SOAR Stats OK: deflected={d.get('total_deflected_threats')}, rate={d.get('success_rate')}, users={d.get('active_monitored_users')}")

# 6. Timeline with enriched_data
if inc_id:
    req = urllib.request.Request(f"{API}/incidents/{inc_id}/timeline", headers=h)
    r = urllib.request.urlopen(req)
    d = json.loads(r.read())
    enriched_tl = d.get("enriched_data", {})
    print(f"6. Timeline OK: enriched_data={bool(enriched_tl)}, events={d.get('event_count')}")
else:
    print("6. Timeline SKIP (no incident)")

print("ALL SMOKE TESTS PASSED")
