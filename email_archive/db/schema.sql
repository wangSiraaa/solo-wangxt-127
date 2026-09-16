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

-- 11. 证据保全（Legal Hold）策略
CREATE TABLE IF NOT EXISTS hold_policies (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            TEXT NOT NULL,
    hold_type       TEXT NOT NULL CHECK (hold_type IN ('single','query')),
    -- single: 目标在 targets 中；query: 激活时把匹配结果快照到 targets（冻结证据范围）
    query_filter    JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft' CHECK (status IN
                        ('draft','active','suspended','expired','purging','completed')),
    activated_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    -- 同一策略重复提交（创建/到期处置触发）的幂等键
    idempotency_key TEXT UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 每个策略只有一个由其到期触发的活动/最近处置运行
CREATE UNIQUE INDEX IF NOT EXISTS uq_hold_disposition_run
    ON hold_policies(id) WHERE status IN ('purging');
CREATE INDEX IF NOT EXISTS idx_holds_status ON hold_policies(status);

-- 保全目标（单封 EML）。eml_sha256 不用 FK 级联：策略审计须在邮件被处置后仍然存在。
CREATE TABLE IF NOT EXISTS hold_policy_targets (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id       BIGINT NOT NULL REFERENCES hold_policies(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 目标在处置期间被确认仍受保全/被释放，便于审计核对
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

-- 邮件是否仍受任一 active 策略保全（目标在激活时快照，suspended 不提供保护）。
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

-- 12. 到期处置运行（游标即 disposition_run_targets，崩溃安全、可恢复、幂等）
CREATE TABLE IF NOT EXISTS disposition_runs (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('hold_expiry','manual_retention')),
    hold_policy_id  BIGINT NULL REFERENCES hold_policies(id) ON DELETE CASCADE,
    reason          TEXT NOT NULL,
    actor           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'running' CHECK (status IN
                        ('running','aborted','completed','failed')),
    -- abort 原因：如处置过程中目标恢复保全
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
-- 同一保全策略不得并发两个进行中的处置运行
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
    -- purged: 被删版本摘要（版本号/解析状态/部件数），审计快照
    deleted_summary JSONB,
    attempts        INT NOT NULL DEFAULT 0,
    last_error      TEXT,
    processed_at    TIMESTAMPTZ,
    UNIQUE (run_id, eml_sha256)
);
-- 恢复游标：只取 pending（部分唯一索引）
CREATE INDEX IF NOT EXISTS idx_dispo_targets_pending
    ON disposition_run_targets(run_id, id)
    WHERE state = 'pending';

-- 处置审计：每个被删对象一行，只追加（触发器禁止 UPDATE/DELETE）。
-- 不用指向 raw_emls 的 FK：审计必须在对象删除后存活。
CREATE TABLE IF NOT EXISTS disposition_audit (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id          BIGINT NOT NULL REFERENCES disposition_runs(id) ON DELETE CASCADE,
    eml_sha256      TEXT NOT NULL,
    object_type     TEXT NOT NULL CHECK (object_type IN
                        ('raw_eml','parse_version','attachment_file','spill_file',
                         'reparse_job')),
    object_ref      TEXT,             -- 版本号 / 存储相对路径 / job id
    summary         JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT NOT NULL,
    actor           TEXT NOT NULL,
    at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 同一运行内同一对象只能审计一次（重启恢复不重复审计）
    UNIQUE (run_id, object_type, object_ref)
);
CREATE INDEX IF NOT EXISTS idx_dispo_audit_eml ON disposition_audit(eml_sha256, at);

CREATE OR REPLACE FUNCTION disposition_audit_appendonly() RETURNS trigger AS $$
BEGIN
    IF current_setting('app.archive_purge', true) = 'on' AND TG_OP = 'DELETE' THEN
        RETURN OLD;  -- 仅受控清除（如管理员清除整个 run）允许
    END IF;
    RAISE EXCEPTION 'disposition_audit is append-only (op=%)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS trg_dispo_audit_appendonly ON disposition_audit;
CREATE TRIGGER trg_dispo_audit_appendonly
BEFORE UPDATE OR DELETE ON disposition_audit
FOR EACH ROW EXECUTE FUNCTION disposition_audit_appendonly();

-- 文件墓场台账：删除分两阶段，杜绝“库已删附件仍可访问/反向孤儿”。
-- pending：DB 事务已提交（引用已消失），等待物理删除；done：文件已删除。
-- idempotency：(run_id, relpath) 唯一；文件被引用计数为 0 才允许物理删除。
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

COMMIT;
