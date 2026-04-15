"""Email Spamming Drive — high-velocity email event simulator for Z-score stress testing."""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from datetime import timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend import app as backend_app


SPAM_TLDS = ["evil-spam.xyz", "promo-blast.biz", "phish-net.info", "bulk-mailer.click", "offer-now.top"]

SENDER_NAMES = [
    "noreply", "deals", "support", "invoice", "alert",
    "update", "verify", "security", "billing", "admin",
]


def _random_sender(rng: random.Random, tld: str) -> str:
    return f"{rng.choice(SENDER_NAMES)}@{tld}"


def _sender_reputation(rng: random.Random, burst: bool) -> int:
    if burst:
        return rng.randint(0, 25)
    return rng.randint(30, 100)


def _link_density(rng: random.Random, burst: bool) -> int:
    if burst:
        return rng.randint(6, 25)
    return rng.randint(0, 3)


def generate_email_events(
    tenant_id: str,
    target_user: str,
    tld: str,
    count: int,
    rng: random.Random,
    burst: bool = True,
    total_events: int | None = None,
    time_spread_secs: int = 3600,
) -> list[tuple[str, str, str, str, str]]:
    """Generate email_received events with spam drive metadata."""
    now = backend_app.now_utc().astimezone(timezone.utc)
    records: list[tuple[str, str, str, str, str]] = []
    burst_freq = total_events if total_events is not None else count
    for i in range(count):
        sender = _random_sender(rng, tld)
        reputation = _sender_reputation(rng, burst)
        link_count = _link_density(rng, burst)
        ts = now - timedelta(seconds=rng.randint(0, time_spread_secs))
        payload = {
            "sender": sender,
            "tld": tld,
            "sender_reputation": reputation,
            "link_density": link_count,
            "burst_frequency": burst_freq,
            "subject": f"{'URGENT: ' if burst else ''}Message {i + 1}",
            "spam_drive_sim": True,
        }
        records.append((tenant_id, target_user, "email_received", json.dumps(payload), ts.isoformat()))
    return records


def run_spam_drive(
    tenant_id: str,
    target_user: str,
    tld: str = "evil-spam.xyz",
    total_events: int = 500,
    batch_size: int = 100,
    seed: int = 99,
    dry_run: bool = False,
    time_spread_secs: int = 3600,
    confirm: bool = False,
) -> dict:
    """Execute the spamming drive: insert high-velocity email events in batches."""
    rng = random.Random(seed)
    inserted = 0
    batches = 0
    start = time.monotonic()

    if dry_run:
        events = generate_email_events(
            tenant_id, target_user, tld, min(batch_size, total_events), rng,
            burst=True, total_events=total_events, time_spread_secs=time_spread_secs,
        )
        return {
            "mode": "dry_run",
            "tenant_id": tenant_id,
            "target_user": target_user,
            "tld": tld,
            "sample_count": len(events),
            "sample": [json.loads(e[3]) for e in events[:3]],
        }

    if not confirm:
        raise SystemExit(
            "Live mode requires --confirm flag to prevent accidental bulk inserts. "
            "Use --dry-run to preview first."
        )

    remaining = total_events
    with backend_app.get_conn() as conn:
        with conn.cursor() as cur:
            while remaining > 0:
                chunk = min(batch_size, remaining)
                events = generate_email_events(
                    tenant_id, target_user, tld, chunk, rng,
                    burst=True, total_events=total_events,
                    time_spread_secs=time_spread_secs,
                )
                cur.executemany(
                    """
                    INSERT INTO events (tenant_id, user_id, type, raw, timestamp)
                    VALUES (%s, %s, %s, %s::jsonb, %s)
                    """,
                    events,
                )
                conn.commit()
                inserted += chunk
                remaining -= chunk
                batches += 1

    elapsed = round(time.monotonic() - start, 2)
    eps = round(inserted / elapsed, 1) if elapsed > 0 else 0
    return {
        "mode": "live",
        "tenant_id": tenant_id,
        "target_user": target_user,
        "tld": tld,
        "total_inserted": inserted,
        "batches": batches,
        "elapsed_seconds": elapsed,
        "events_per_second": eps,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Email Spamming Drive — stress-test Z-score anomaly detection")
    parser.add_argument("--tenant-id", default="demo-corp")
    parser.add_argument("--target-user", default="cyber.lead")
    parser.add_argument("--tld", default=None, help="Sender TLD for the spam drive (random from SPAM_TLDS if omitted)")
    parser.add_argument("--total", type=int, default=500, help="Total email events to generate")
    parser.add_argument("--batch-size", type=int, default=100, help="Events per insert batch")
    parser.add_argument("--seed", type=int, default=99)
    parser.add_argument("--dry-run", action="store_true", help="Preview events without inserting")
    parser.add_argument("--time-spread", type=int, default=3600, help="Seconds of back-spread for event timestamps (default: 3600)")
    parser.add_argument("--confirm", action="store_true", help="Required for live mode to prevent accidental bulk inserts")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    tld = args.tld or random.Random(args.seed).choice(SPAM_TLDS)
    result = run_spam_drive(
        tenant_id=args.tenant_id,
        target_user=args.target_user,
        tld=tld,
        total_events=args.total,
        batch_size=args.batch_size,
        seed=args.seed,
        dry_run=args.dry_run,
        time_spread_secs=args.time_spread,
        confirm=args.confirm,
    )
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
