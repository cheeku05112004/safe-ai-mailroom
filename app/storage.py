import json
import os
import re
import sqlite3
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DB_PATH = Path(__file__).resolve().parent.parent / "mailroom.db"


class DBConnection:
    def __init__(self, connection, postgres=False):
        self.connection = connection
        self.postgres = postgres

    @property
    def in_transaction(self):
        return self.connection.info.transaction_status != 0 if self.postgres else self.connection.in_transaction

    def execute(self, sql, params=()):
        if self.postgres:
            sql = sql.replace("BEGIN IMMEDIATE", "BEGIN")
            sql = sql.replace("?", "%s")
            sql = sql.replace("ORDER BY rowid", "ORDER BY ctid")

            if "INSERT OR IGNORE INTO" in sql:
                sql = sql.replace("INSERT OR IGNORE INTO", "INSERT INTO")
                sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"

        return self.connection.execute(sql, params)

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self.connection.__exit__(exc_type, exc, tb)


def get_connection():
    if DATABASE_URL:
        connection = psycopg.connect(
            DATABASE_URL,
            row_factory=dict_row,
            autocommit=True,
            connect_timeout=10,
        )
        return DBConnection(connection, postgres=True)

    connection = sqlite3.connect(
        DB_PATH,
        timeout=10,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    return DBConnection(connection)


def initialize_database():
    with get_connection() as conn:
        if not DATABASE_URL:
            conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                input_digest TEXT NOT NULL,
                verifier_json TEXT NOT NULL,
                propose_response TEXT,
                commit_response TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS proposals (
                evaluation_id TEXT NOT NULL,
                dossier_id TEXT NOT NULL,
                content_fingerprint TEXT NOT NULL,
                proposal_json TEXT NOT NULL,
                PRIMARY KEY (evaluation_id, dossier_id),
                FOREIGN KEY (evaluation_id)
                    REFERENCES evaluations(evaluation_id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS decision_cache (
                content_fingerprint TEXT PRIMARY KEY,
                proposal_json TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                evaluation_id TEXT NOT NULL,
                dossier_id TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                verified INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (evaluation_id, dossier_id),
                FOREIGN KEY (evaluation_id)
                    REFERENCES evaluations(evaluation_id)
            )
        """)


def get_evaluation(evaluation_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM evaluations WHERE evaluation_id = ?",
            (evaluation_id,),
        ).fetchone()
        return dict(row) if row else None


def get_cached_decision(content_fingerprint):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT proposal_json FROM decision_cache WHERE content_fingerprint = ?",
            (content_fingerprint,),
        ).fetchone()
        return json.loads(row["proposal_json"]) if row else None


def save_propose_result(
    evaluation_id, input_digest, verifier_json, response, proposals
):
    response_json = json.dumps(
        response, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            existing = conn.execute(
                "SELECT input_digest, propose_response FROM evaluations "
                "WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()

            if existing:
                if existing["input_digest"] != input_digest:
                    raise ValueError(
                        "Evaluation ID already used with different input."
                    )
                if existing["propose_response"]:
                    conn.execute("COMMIT")
                    return json.loads(existing["propose_response"])
                raise ValueError("Evaluation is already being processed.")

            conn.execute(
                """
                INSERT INTO evaluations (
                    evaluation_id, input_digest, verifier_json, propose_response
                ) VALUES (?, ?, ?, ?)
                """,
                (evaluation_id, input_digest, verifier_json, response_json),
            )

            for item in proposals:
                proposal_json = json.dumps(
                    item["proposal"],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )

                conn.execute(
                    """
                    INSERT INTO proposals (
                        evaluation_id, dossier_id, content_fingerprint, proposal_json
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        evaluation_id,
                        item["dossierId"],
                        item["contentFingerprint"],
                        proposal_json,
                    ),
                )

                conn.execute(
                    """
                    INSERT OR IGNORE INTO decision_cache (
                        content_fingerprint, proposal_json
                    ) VALUES (?, ?)
                    """,
                    (item["contentFingerprint"], proposal_json),
                )

            conn.execute("COMMIT")
            return response
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise


def get_proposals(evaluation_id):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT dossier_id, content_fingerprint, proposal_json "
            "FROM proposals WHERE evaluation_id = ? ORDER BY rowid",
            (evaluation_id,),
        ).fetchall()

        return [
            {
                "dossierId": row["dossier_id"],
                "contentFingerprint": row["content_fingerprint"],
                "proposal": json.loads(row["proposal_json"]),
            }
            for row in rows
        ]


def save_receipts(evaluation_id, receipts):
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for receipt in receipts:
                conn.execute(
                    """
                    INSERT INTO receipts (
                        evaluation_id, dossier_id, receipt_json, verified
                    ) VALUES (?, ?, ?, 1)
                    """,
                    (
                        evaluation_id,
                        receipt["dossierId"],
                        json.dumps(
                            receipt,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ),
                    ),
                )
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise


def save_commit_response(evaluation_id, response):
    response_json = json.dumps(
        response, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    with get_connection() as conn:
        conn.execute(
            "UPDATE evaluations SET commit_response = ? WHERE evaluation_id = ?",
            (response_json, evaluation_id),
        )


def save_commit_result(evaluation_id, receipts, response):
    """Save verified receipts atomically and protect exact commit replay."""
    response_json = json.dumps(
        response, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if conn.postgres:
                row = conn.execute(
                    "SELECT commit_response FROM evaluations "
                    "WHERE evaluation_id = ? FOR UPDATE",
                    (evaluation_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT commit_response FROM evaluations WHERE evaluation_id = ?",
                    (evaluation_id,),
                ).fetchone()

            if row is None:
                raise ValueError("Unknown evaluation.")

            incoming = {
                item["dossierId"]: json.dumps(
                    item, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
                for item in receipts
            }

            if row["commit_response"]:
                saved_rows = conn.execute(
                    "SELECT dossier_id, receipt_json FROM receipts "
                    "WHERE evaluation_id = ?",
                    (evaluation_id,),
                ).fetchall()

                saved = {
                    item["dossier_id"]: json.dumps(
                        json.loads(item["receipt_json"]),
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    )
                    for item in saved_rows
                }

                if saved != incoming:
                    raise ValueError(
                        "Evaluation was already committed with different receipts."
                    )

                conn.execute("COMMIT")
                return json.loads(row["commit_response"])

            for receipt in receipts:
                conn.execute(
                    """
                    INSERT INTO receipts (
                        evaluation_id, dossier_id, receipt_json, verified
                    ) VALUES (?, ?, ?, 1)
                    """,
                    (
                        evaluation_id,
                        receipt["dossierId"],
                        json.dumps(
                            receipt,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ),
                    ),
                )

            conn.execute(
                "UPDATE evaluations SET commit_response = ? WHERE evaluation_id = ?",
                (response_json, evaluation_id),
            )

            conn.execute("COMMIT")
            return response

        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully!")
    print("Database:", "PostgreSQL" if DATABASE_URL else str(DB_PATH))
