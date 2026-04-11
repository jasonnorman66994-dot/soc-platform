from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import timedelta, timezone
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import app as backend_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Seed a 7-day synthetic baseline of activity.")
    parser.add_argument("--tenant-id", default="demo-corp")
    parser.add_argument("--current-user", default="demo.user")
    parser.add_argument("--team-users", default="owner.user,analyst.user,viewer.user")
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def build_user_set(current_user: str, team_users_csv: str) -> list[str]:
    team_users = [item.strip() for item in team_users_csv.split(",") if item.strip()]
    ordered = [current_user, *team_users]
    unique: list[str] = []
    for user_id in ordered:
        if user_id not in unique:
            unique.append(user_id)
    return unique


def synthetic_events(tenant_id: str, user_id: str, day_offset: int, rng: random.Random) -> list[tuple[str, str, str, str]]:
    base_day = backend_app.now_utc().astimezone(timezone.utc).replace(hour=8, minute=0, second=0, microsecond=0) - timedelta(days=day_offset)
    remote_ip = f"198.51.100.{20 + day_offset}"
    records: list[tuple[str, str, str, str]] = []

    login_count = 2 + (day_offset % 2)
    for login_index in range(login_count):
        timestamp = base_day + timedelta(minutes=login_index * 35 + rng.randint(0, 10))
        payload = {
            "ip": remote_ip,
            "location": "UK",
            "synthetic_baseline": True,
            "category": "login_times",
            "team_scope": "current_user_and_team",
        }
        records.append((tenant_id, user_id, "login_success", json.dumps(payload), timestamp.isoformat()))

    network_count = 4 + (day_offset % 3)
    for network_index in range(network_count):
        timestamp = base_day.replace(hour=13, minute=15) + timedelta(minutes=network_index * 22 + rng.randint(0, 8))
        payload = {
            "ip": remote_ip,
            "bytes": 150000 + (network_index * 18000) + rng.randint(0, 25000),
            "port": 443,
            "synthetic_baseline": True,
            "category": "network_volume",
            "team_scope": "current_user_and_team",
        }
        records.append((tenant_id, user_id, "network_connection", json.dumps(payload), timestamp.isoformat()))

    return records


def seed_baseline(tenant_id: str, current_user: str, team_users_csv: str, days: int, seed: int) -> dict:
    rng = random.Random(seed)
    users = build_user_set(current_user, team_users_csv)
    inserted_count = 0

    with backend_app.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM events
                WHERE tenant_id=%s
                  AND timestamp >= NOW() - (%s * INTERVAL '1 day')
                  AND raw->>'synthetic_baseline'='true'
                """,
                (tenant_id, max(days + 1, 8)),
            )

            for day_offset in range(days):
                for user_id in users:
                    for record in synthetic_events(tenant_id, user_id, day_offset, rng):
                        cur.execute(
                            """
                            INSERT INTO events (tenant_id, user_id, type, raw, timestamp)
                            VALUES (%s, %s, %s, %s::jsonb, %s)
                            """,
                            record,
                        )
                        inserted_count += 1

            cur.execute(
                """
                INSERT INTO audit_logs (tenant_id, user_id, action, resource, meta, timestamp)
                VALUES (%s, %s, %s, %s, %s::jsonb, NOW())
                """,
                (
                    tenant_id,
                    None,
                    "sentinel.synthetic_baseline_seeded",
                    f"tenants/{tenant_id}",
                    json.dumps(
                        {
                            "current_user": current_user,
                            "team_users": users[1:],
                            "days": days,
                            "inserted_events": inserted_count,
                        }
                    ),
                ),
            )
        conn.commit()

    return {
        "tenant_id": tenant_id,
        "current_user": current_user,
        "team_users": users[1:],
        "days": days,
        "inserted_events": inserted_count,
    }


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    result = seed_baseline(
        tenant_id=args.tenant_id,
        current_user=args.current_user,
        team_users_csv=args.team_users,
        days=max(1, args.days),
        seed=args.seed,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())