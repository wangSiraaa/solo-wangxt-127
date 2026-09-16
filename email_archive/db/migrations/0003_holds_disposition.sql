-- 0003_holds_disposition.sql
-- 证据保全 + 到期处置。所有新对象均为追加式；不改动既有版本模型数据。
BEGIN;

CREATE TABLE IF NOT EXISTS hold_policies (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            TEXT NOT NULL,
    hold_type       TEXT NOT NULL CHECK (hold_type IN ('single','query')),
    query_filter    JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN
                        ('draft','active','suspended','expired','purging','completed')),
    activated_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    idempotency_key TEXT UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_hold_disposition_run
    ON hold_policies(id) WHERE status IN ('purging');
CREATE INDEX IF NOT EXISTS idx_holds_status ON hold_policies(status);

CREATE TABLE IF NOT EXISTS hold_policy_targets (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id       BIGINT NOT NULL REFERENCES hold_policies(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    state           TEXT NOT NULL DEFAULT 'held'
                    CHECK (state IN ('held','released')),
    UNIQUE (policy_id, eml_sha256)
);
CREATE INDEX IF NOT EXISTS idx_hold_targets_eml ON hold_policy_targets(eml_sha256);

CREATE TABLE IF NOT EXISTS hold_policy_events (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id       BIGINT NOT NULL REFERENCES hold_policies(id) ON DELETE CASCADE,
    action          TEXT NOT NULL CHECK (action IN
                        ('created','updated','activated','suspended','resumed',
                         'expired','disposition_started','disposition_completed')),
    actor           TEXT NOT NULL,
    detail          TEXT,
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_hold_events_policy ON hold_policy_events(policy_id, at);

CREATE OR REPLACE FUNCTION eml_is_held(p_sha TEXT, p_at TIMESTAMPTZ DEFAULT now())
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1
          FROM hold_policy_targets t
          JOIN hold_policies p ON p.id = t.policy_id
         WHERE t.eml_sha256 = p_sha
           AND t.state = 'held'
           AND p.status = 'active'
           AND (p.expires_at IS NULL OR p.expires_at > p_at))
$$;

CREATE TABLE IF NOT EXISTS disposition_runs (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('hold_expiry','manual_retention')),
    hold_policy_id  BIGINT NULL REFERENCES hold_policies(id) ON DELETE CASCADE,
    reason          TEXT NOT NULL,
    actor           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running' CHECK (status IN
                        ('running','aborted','completed','failed')),
    last_note       TEXT,
    total_targets   INT NOT NULL DEFAULT 0,
    purged_count    INT NOT NULL DEFAULT 0,
    skipped_count   INT NOT NULL DEFAULT 0,
    idempotency_key TEXT UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_dispo_status ON disposition_runs(status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_dispo_active_per_hold
    ON disposition_runs(hold_policy_id)
    WHERE hold_policy_id IS NOT NULL AND status = 'running';

CREATE TABLE IF NOT EXISTS disposition_run_targets (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES disposition_runs(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN
                        ('pending','purged','skipped_held','skipped_active_job',
                         'skipped_missing','failed')),
    deleted_summary JSONB,
    attempts        INT NOT NULL DEFAULT 0,
    last_error      TEXT,
    processed_at    TIMESTAMPTZ,
    UNIQUE (run_id, eml_sha256)
);
CREATE INDEX IF NOT EXISTS idx_dispo_targets_pending
    ON disposition_run_targets(run_id, id) WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS disposition_audit (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES disposition_runs(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    object_type     TEXT NOT NULL CHECK (object_type IN
                        ('raw_eml','parse_version','attachment_file','spill_file',
                         'reparse_job')),
    object_ref      TEXT,
    summary         JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT NOT NULL,
    actor           TEXT NOT NULL,
    at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (run_id, object_type, object_ref)
);
CREATE INDEX IF NOT EXISTS idx_dispo_audit_eml ON disposition_audit(eml_sha256, at);

CREATE OR REPLACE FUNCTION disposition_audit_appendonly() RETURNS trigger AS $$
BEGIN
    IF current_setting('app.archive_purge', true) = 'on' AND TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'disposition_audit is append-only (op=%)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_dispo_audit_appendonly ON disposition_audit;
CREATE TRIGGER trg_dispo_audit_appendonly
BEFORE UPDATE OR DELETE ON disposition_audit
FOR EACH ROW EXECUTE FUNCTION disposition_audit_appendonly();

CREATE TABLE IF NOT EXISTS file_graveyard (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES disposition_runs(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    relpath         TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('attachment','spill')),
    size_bytes      BIGINT,
    state           TEXT NOT NULL DEFAULT 'pending' CHECK (state IN
                        ('pending','deleted','missing','failed')),
    attempts        INT NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE (run_id, relpath)
);
CREATE INDEX IF NOT EXISTS idx_graveyard_pending ON file_graveyard(id)
    WHERE state IN ('pending','failed');

-- 处置审计必须在对象（raw_emls）被删除后存活：审计表不建立指向 raw_emls 的级联 FK。
-- 同时确保 schema_migrations 记录本迁移。
INSERT INTO schema_migrations(name) VALUES ('0003_holds_disposition.sql')
ON CONFLICT DO NOTHING;

COMMIT;
