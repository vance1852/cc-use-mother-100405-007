"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
-- 研究参与者权益与样本使用协作域
CREATE TABLE IF NOT EXISTS service_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS participants (
    participant_id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'merged')),
    merged_into TEXT REFERENCES participants(participant_id),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subject_links (
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    code_hash TEXT NOT NULL,
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(site_id, code_hash)
);
CREATE TABLE IF NOT EXISTS participant_merges (
    merge_id TEXT PRIMARY KEY,
    canonical_participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    duplicate_participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(duplicate_participant_id)
);
CREATE TABLE IF NOT EXISTS consents (
    consent_id TEXT PRIMARY KEY,
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    version_tag TEXT NOT NULL,
    purposes_json TEXT NOT NULL,
    signed_at TEXT NOT NULL,
    document_hash TEXT NOT NULL,
    superseded_at TEXT,
    recorded_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(participant_id, version_tag)
);
CREATE TABLE IF NOT EXISTS protocols (
    protocol_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    owner_organization_id TEXT NOT NULL,
    purposes_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'closed')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS irb_approvals (
    approval_id TEXT PRIMARY KEY,
    protocol_id TEXT NOT NULL REFERENCES protocols(protocol_id),
    site_id TEXT REFERENCES sites(site_id),
    purposes_json TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    conditions_json TEXT NOT NULL DEFAULT '[]',
    recorded_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    parent_sample_id TEXT REFERENCES samples(sample_id),
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    material_type TEXT NOT NULL,
    unit TEXT NOT NULL,
    quantity_total REAL NOT NULL CHECK(quantity_total >= 0),
    quantity_reserved REAL NOT NULL DEFAULT 0 CHECK(quantity_reserved >= 0),
    quantity_consumed REAL NOT NULL DEFAULT 0 CHECK(quantity_consumed >= 0),
    status TEXT NOT NULL DEFAULT 'available' CHECK(status IN ('available', 'depleted')),
    collected_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sample_ledger (
    ledger_id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL REFERENCES samples(sample_id),
    delta_total REAL NOT NULL,
    delta_reserved REAL NOT NULL,
    delta_consumed REAL NOT NULL,
    reason TEXT NOT NULL,
    ref_type TEXT,
    ref_id TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS datasets (
    dataset_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dataset_participants (
    dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id),
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    PRIMARY KEY(dataset_id, participant_id)
);
CREATE TABLE IF NOT EXISTS access_applications (
    application_id TEXT PRIMARY KEY,
    request_id TEXT,
    researcher_actor_id TEXT NOT NULL,
    protocol_id TEXT NOT NULL REFERENCES protocols(protocol_id),
    purpose TEXT NOT NULL,
    dataset_id TEXT REFERENCES datasets(dataset_id),
    items_json TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'denied', 'blocked', 'closed')),
    decision_reason_json TEXT,
    decided_by TEXT,
    decided_at TEXT,
    released_at TEXT,
    expires_at TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_open_fingerprint
    ON access_applications(fingerprint) WHERE status IN ('pending', 'approved');
CREATE TABLE IF NOT EXISTS authorization_basis (
    application_id TEXT NOT NULL REFERENCES access_applications(application_id),
    basis_version INTEGER NOT NULL DEFAULT 1,
    basis_json TEXT NOT NULL,
    basis_hash TEXT NOT NULL,
    decided_at TEXT NOT NULL,
    PRIMARY KEY(application_id, basis_version)
);
CREATE TABLE IF NOT EXISTS reservations (
    reservation_id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES access_applications(application_id),
    sample_id TEXT NOT NULL REFERENCES samples(sample_id),
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    quantity REAL NOT NULL CHECK(quantity > 0),
    consumed_qty REAL NOT NULL DEFAULT 0 CHECK(consumed_qty >= 0),
    state TEXT NOT NULL CHECK(state IN ('held', 'consumed', 'released')),
    created_at TEXT NOT NULL,
    consumed_at TEXT,
    released_at TEXT,
    UNIQUE(application_id, sample_id)
);
CREATE TABLE IF NOT EXISTS dataset_releases (
    release_id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL UNIQUE REFERENCES access_applications(application_id),
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS withdrawals (
    withdrawal_id TEXT PRIMARY KEY,
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    scope_json TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    applied_at TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS obligations (
    obligation_id TEXT PRIMARY KEY,
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    application_id TEXT REFERENCES access_applications(application_id),
    kind TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'discharged')),
    created_at TEXT NOT NULL,
    discharged_at TEXT
);
CREATE TABLE IF NOT EXISTS research_outputs (
    output_id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES access_applications(application_id),
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    citation TEXT NOT NULL,
    published_at TEXT NOT NULL,
    basis_hash TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS trg_samples_nonnegative_update
BEFORE UPDATE OF quantity_total, quantity_reserved, quantity_consumed ON samples
FOR EACH ROW
WHEN NEW.quantity_total < 0 OR NEW.quantity_reserved < 0 OR NEW.quantity_consumed < 0
     OR NEW.quantity_reserved + NEW.quantity_consumed > NEW.quantity_total + 1e-9
BEGIN
    SELECT RAISE(ABORT, 'sample quantities must stay non-negative and reserved+consumed cannot exceed total');
END;
CREATE TRIGGER IF NOT EXISTS trg_samples_nonnegative_insert
BEFORE INSERT ON samples
FOR EACH ROW
WHEN NEW.quantity_total < 0 OR NEW.quantity_reserved < 0 OR NEW.quantity_consumed < 0
     OR NEW.quantity_reserved + NEW.quantity_consumed > NEW.quantity_total + 1e-9
BEGIN
    SELECT RAISE(ABORT, 'sample quantities must stay non-negative and reserved+consumed cannot exceed total');
END;
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield self.connection
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
