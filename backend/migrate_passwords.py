import os

import psycopg

from app import hash_password, is_password_hash


def main() -> None:
    db_url = os.environ.get("DATABASE_URL", "postgresql://soc:socpass@db:5432/socdb")
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password FROM users")
            rows = cur.fetchall()
            updated = 0
            for user_id, password in rows:
                if password and not is_password_hash(password):
                    cur.execute(
                        "UPDATE users SET password = %s WHERE id = %s",
                        (hash_password(password), user_id),
                    )
                    updated += 1
        conn.commit()
    print(f"migrated={updated}")


if __name__ == "__main__":
    main()
