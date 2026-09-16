-- Enterprise EML archive: normalized, versioned mail facts.
-- PostgreSQL 13+.
--
-- 版本化模型：
--   raw_emls            原始 EML 字节（与版本无关，永不重写）
--   parse_versions      不可变的解析版本（成功/结构失败均生成；触发器禁止改删）
--   current_versions    每封 EML 当前展示版本指针（原子切换/回退）
--   messages/mime_parts/parse_issues/message_addresses/message_links/
--   version_conflicts   均按 version_id 归属
--   reparse_jobs        重解析任务（queued/running/succeeded/failed/cancelled）
--   reparse_attempts    每次尝试历史（含重启中断记录）
--   current_switches    current 指针切换审计（initial/reparse/rollback）
--   identity_conflicts  全局图冲突（悬空/重用/环，只基于当前版本重算）

BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 1. 原始 EML
CREATE TABLE IF NOT EXISTS raw_emls (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL UNIQUE,
    eml_filename    TEXT,
    eml_size        BIGINT NOT NULL CHECK (eml_size >= 0),
    eml_bytes       BYTEA NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. 不可变解析版本
CREATE TABLE IF NOT EXISTS parse_versions (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    version_no      INT NOT NULL CHECK (version_no >= 1),
    parser_version  TEXT NOT NULL,
    policy_version  TEXT NOT NULL,             -- 解析策略版本
    parse_status    TEXT NOT NULL CHECK (parse_status IN ('ok','ok_with_issues','failed')),
    part_count      INT NOT NULL DEFAULT 0,
    attachment_count INT NOT NULL DEFAULT 0,
    source          TEXT NOT NULL CHECK (source IN ('ingest','reparse','legacy_backfill')),
    reason          TEXT,
    requested_by    TEXT,
    job_id          BIGINT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (eml_sha256, version_no)
);
CREATE INDEX IF NOT EXISTS idx_versions_eml ON parse_versions(eml_sha256, created_at DESC);

-- 版本不可修改：除受控清除（SET app.archive_purge='on'）外禁止 UPDATE/DELETE
CREATE OR REPLACE FUNCTION parse_versions_immutable() RETURNS trigger AS $$
BEGIN
    IF current_setting('app.archive_purge', true) = 'on' THEN
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'parse_versions are immutable (op=%)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_versions_immutable ON parse_versions;
CREATE TRIGGER trg_versions_immutable
BEFORE UPDATE OR DELETE ON parse_versions
FOR EACH ROW EXECUTE FUNCTION parse_versions_immutable();

-- 当前展示版本指针（一行/EML；切换在事务内更新，随新版本一起原子可见）
CREATE TABLE IF NOT EXISTS current_versions (
    eml_sha256      TEXT PRIMARY KEY REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    version_id      BIGINT NOT NULL REFERENCES parse_versions(id),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS current_switches (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL,
    version_id      BIGINT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('initial','reparse','rollback')),
    job_id          BIGINT NULL,
    actor           TEXT,
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_switches_eml ON current_switches(eml_sha256, at);

-- 3. 重解析任务
CREATE TABLE IF NOT EXISTS reparse_jobs (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    policy_version  TEXT NOT NULL CHECK (policy_version ~ '^[A-Za-z0-9._-]{1,64}$'),
    reason          TEXT,
    requested_by    TEXT,
    status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN
                        ('queued','running','succeeded','failed','cancelled')),
    attempts        INT NOT NULL DEFAULT 0,
    max_attempts    INT NOT NULL DEFAULT 3,
    run_after       TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_by       TEXT,
    lease_until     TIMESTAMPTZ,
    last_error      TEXT,
    result_version_id BIGINT NULL REFERENCES parse_versions(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);
-- 同 EML + 同策略只允许一个未终态任务（并发/重复请求据此合并）
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_job_eml_policy
    ON reparse_jobs(eml_sha256, policy_version)
    WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS idx_jobs_due
    ON reparse_jobs(status, run_after);
CREATE INDEX IF NOT EXISTS idx_jobs_eml ON reparse_jobs(eml_sha256, created_at DESC);

CREATE TABLE IF NOT EXISTS reparse_attempts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id          BIGINT NOT NULL REFERENCES reparse_jobs(id) ON DELETE CASCADE,
    attempt_no      INT NOT NULL,
    phase           TEXT NOT NULL CHECK (phase IN
                        ('started','succeeded','failed','interrupted','cancelled')),
    detail          TEXT,
    at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_attempts_job ON reparse_attempts(job_id, attempt_no);

-- 4. 可定位的解析问题（按版本）
CREATE TABLE IF NOT EXISTS parse_issues (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id      BIGINT NOT NULL REFERENCES parse_versions(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    issue_no        INT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('error','warning','info')),
    kind            TEXT NOT NULL,
    location        TEXT,
    detail          TEXT NOT NULL,
    UNIQUE (version_id, issue_no)
);
CREATE INDEX IF NOT EXISTS idx_parse_issues_ver ON parse_issues(version_id);

-- 5. 信头事实（每版本一行）
CREATE TABLE IF NOT EXISTS messages (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id      BIGINT NOT NULL UNIQUE REFERENCES parse_versions(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    message_id      TEXT,
    message_id_raw  TEXT,
    message_id_count INT NOT NULL DEFAULT 1,
    subject         TEXT,
    subject_raw     TEXT,
    date_raw        TEXT,
    sent_at         TIMESTAMPTZ,
    from_raw        TEXT,
    sender_raw      TEXT,
    reply_to_raw    TEXT,
    to_raw          TEXT,
    cc_raw          TEXT,
    bcc_raw         TEXT,
    in_reply_to     TEXT,
    in_reply_to_raw TEXT,
    references_list TEXT[] NOT NULL DEFAULT '{}',
    references_raw  TEXT,
    raw_headers     JSONB NOT NULL DEFAULT '[]'::jsonb,
    body_text       TEXT,
    body_text_path  TEXT,
    body_html       TEXT,
    body_html_escaped TEXT,
    body_html_path  TEXT,
    body_html_escaped_path TEXT,
    body_charset    TEXT,
    html_external_refs TEXT[] NOT NULL DEFAULT '{}',
    has_attachments BOOLEAN NOT NULL DEFAULT false,
    search_tsv      TSVECTOR
);
CREATE INDEX IF NOT EXISTS idx_messages_ver ON messages(version_id);
CREATE INDEX IF NOT EXISTS idx_messages_mid ON messages(message_id);
CREATE INDEX IF NOT EXISTS idx_messages_subject_trgm ON messages USING gin (subject gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_body_trgm ON messages USING gin (body_text gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_rawheaders ON messages USING gin (raw_headers jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_messages_search ON messages USING gin (search_tsv);

-- search_tsv 由主题/正文/信头派生（simple 配置；CJK 走 trigram ILIKE 回退）
CREATE OR REPLACE FUNCTION messages_tsv_trigger() RETURNS trigger AS $$
BEGIN
    NEW.search_tsv :=
        setweight(to_tsvector('simple', coalesce(NEW.subject,'')), 'A') ||
        setweight(to_tsvector('simple', coalesce(NEW.body_text,'')), 'B') ||
        setweight(to_tsvector('simple', coalesce(NEW.from_raw,'') || ' ' ||
              coalesce(NEW.to_raw,'') || ' ' || coalesce(NEW.message_id,'')), 'C');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_messages_tsv ON messages;
CREATE TRIGGER trg_messages_tsv BEFORE INSERT OR UPDATE ON messages
FOR EACH ROW EXECUTE FUNCTION messages_tsv_trigger();

-- 6. 参与方
CREATE TABLE IF NOT EXISTS addresses (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email_norm      TEXT NOT NULL UNIQUE,
    email_raw       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS message_addresses (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id      BIGINT NOT NULL REFERENCES parse_versions(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    address_id      BIGINT NOT NULL REFERENCES addresses(id),
    role            TEXT NOT NULL CHECK (role IN
                        ('from','sender','reply_to','to','cc','bcc')),
    position        INT NOT NULL DEFAULT 0,
    display_name    TEXT
);
CREATE INDEX IF NOT EXISTS idx_msg_addr_ver ON message_addresses(version_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_msg_addr
    ON message_addresses(version_id, address_id, role, position);

-- 7. MIME 部件（按版本；stored_relpath 指向受控目录中内容寻址文件，跨版本共享）
CREATE TABLE IF NOT EXISTS mime_parts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id      BIGINT NOT NULL REFERENCES parse_versions(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    part_no         INT NOT NULL,
    mime_path       TEXT NOT NULL,
    depth           INT NOT NULL,
    content_type    TEXT NOT NULL,
    content_type_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    disposition     TEXT,
    filename_raw    TEXT,
    filename_safe   TEXT,
    charset         TEXT,
    content_id      TEXT,
    cid_norm        TEXT,
    transfer_encoding TEXT,
    size_bytes      BIGINT,
    is_container    BOOLEAN NOT NULL DEFAULT false,
    is_attachment   BOOLEAN NOT NULL DEFAULT false,
    is_inline       BOOLEAN NOT NULL DEFAULT false,
    is_body         BOOLEAN NOT NULL DEFAULT false,
    stored_relpath  TEXT,
    sha256          TEXT,
    nested_message_id TEXT,
    nested_subject  TEXT,
    UNIQUE (version_id, mime_path)
);
CREATE INDEX IF NOT EXISTS idx_mime_parts_ver ON mime_parts(version_id);
CREATE INDEX IF NOT EXISTS idx_mime_parts_sha ON mime_parts(sha256);

-- 8. 会话边（版本快照）与引用解析
CREATE TABLE IF NOT EXISTS message_links (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id      BIGINT NOT NULL REFERENCES parse_versions(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    link_type       TEXT NOT NULL CHECK (link_type IN ('in_reply_to','references')),
    position        INT NOT NULL DEFAULT 0,
    target_message_id TEXT NOT NULL,
    target_raw      TEXT
);
CREATE INDEX IF NOT EXISTS idx_links_ver ON message_links(version_id);
CREATE INDEX IF NOT EXISTS idx_links_target ON message_links(target_message_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_links
    ON message_links(version_id, link_type, position, target_message_id);

CREATE TABLE IF NOT EXISTS link_resolutions (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_link_id BIGINT NOT NULL UNIQUE REFERENCES message_links(id) ON DELETE CASCADE,
    resolved        BOOLEAN NOT NULL,
    target_eml_sha256 TEXT REFERENCES raw_emls(eml_sha256) ON DELETE SET NULL
);

-- 9. 版本内标识冲突（随版本不可变快照）
CREATE TABLE IF NOT EXISTS version_conflicts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id      BIGINT NOT NULL REFERENCES parse_versions(id) ON DELETE CASCADE,
    conflict_type   TEXT NOT NULL CHECK (conflict_type IN
                        ('duplicate_message_id_in_header',
                         'missing_message_id',
                         'self_reference')),
    message_id      TEXT,
    detail          TEXT NOT NULL,
    UNIQUE (version_id, conflict_type, message_id, detail)
);
CREATE INDEX IF NOT EXISTS idx_version_conflicts_ver ON version_conflicts(version_id);

-- 10. 全局图冲突（基于 current 版本重算：ID 重用/悬空/环）
CREATE TABLE IF NOT EXISTS identity_conflicts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    conflict_type   TEXT NOT NULL CHECK (conflict_type IN
                        ('reassigned_message_id',
                         'dangling_reference',
                         'reference_cycle')),
    message_id      TEXT,
    eml_sha256      TEXT NOT NULL,
    detail          TEXT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (conflict_type, message_id, eml_sha256, detail)
);
CREATE INDEX IF NOT EXISTS idx_conflicts_eml ON identity_conflicts(eml_sha256);

COMMIT;
