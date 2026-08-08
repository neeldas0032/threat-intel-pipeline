"""Postgres storage for pipeline results."""
import logging
from datetime import datetime, timezone

import psycopg2

from threatintel.config import settings

logger = logging.getLogger(__name__)

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS threat_scores (
    id              SERIAL PRIMARY KEY,
    run_ts          TIMESTAMPTZ NOT NULL,
    cve_id          TEXT NOT NULL,
    priority        REAL NOT NULL,
    on_kev          BOOLEAN NOT NULL,
    epss            REAL NOT NULL,
    cvss            REAL NOT NULL
);
"""

INSERT_ROW = """
INSERT INTO threat_scores (run_ts, cve_id, priority, on_kev, epss, cvss)
VALUES (%s, %s, %s, %s, %s, %s);
"""


def get_connection():
    """Return a new Postgres connection using settings."""
    return psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )


def save_results(results: list[tuple]) -> None:
    """Write scored results to the threat_scores table."""
    run_ts = datetime.now(timezone.utc)
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(CREATE_TABLE)
            for priority, cve_id, on_kev, epss, cvss in results:
                cur.execute(INSERT_ROW, (run_ts, cve_id, priority, on_kev, epss, cvss))
        conn.commit()
        logger.info("Saved %d rows to threat_scores (run_ts=%s)", len(results), run_ts)
    except Exception:
        conn.rollback()
        logger.exception("Failed to save results to Postgres")
        raise
    finally:
        conn.close()