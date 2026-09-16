-- 0002_versions.sql
-- 从“非版本化”模型升级到“不可变解析版本 + 可追溯重解析任务”模型。
-- 可重复执行前半段的建表（IF NOT EXISTS）；结构变更用 DO/异常忽略以适配旧库。
BEGIN;

-- ============ 新表 ============
CREATE TABLE IF NOT EXISTS parse_versions (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    version_no      INT NOT NULL CHECK (version_no >= 1),
    parser_version  TEXT NOT NULL,
    policy_version  TEXT NOT NULL,
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
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_job_eml_policy
    ON reparse_jobs(eml_sha256, policy_version)
    WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS idx_jobs_due ON reparse_jobs(status, run_after);
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

-- identity_conflicts 在旧库可能含 6 种冲突类型；迁移只保留图级 3 种，
-- 其余转入 version_conflicts。先放宽约束以便删除版本内类型行前的过渡（无操作）。

-- ============ 旧结构改造 ============

-- messages: 增加 version_id、转义正文溢出列；旧 eml_sha256 唯一约束移除
ALTER TABLE messages ADD COLUMN IF NOT EXISTS version_id BIGINT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS body_html_escaped_path TEXT;

DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
         WHERE conrelid = 'messages'::regclass
           AND contype = 'u' AND conname LIKE '%eml_sha256%'
    LOOP
        EXECUTE 'ALTER TABLE messages DROP CONSTRAINT ' || quote_ident(c.conname);
    END LOOP;
    -- 旧外键 eml_sha256 -> raw_emls 不再需要（版本级 FK 才是权威）
    FOR c IN
        SELECT conname FROM pg_constraint
         WHERE conrelid = 'messages'::regclass AND contype = 'f'
           AND conname = 'messages_eml_sha256_fkey'
    LOOP
        EXECUTE 'ALTER TABLE messages DROP CONSTRAINT ' || quote_ident(c.conname);
    END LOOP;
END $$;

-- parse_issues: version_id
ALTER TABLE parse_issues ADD COLUMN IF NOT EXISTS version_id BIGINT;
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
         WHERE conrelid = 'parse_issues'::regclass AND contype IN ('u','p')
           AND conname = 'parse_issues_eml_sha256_issue_no_key'
    LOOP
        EXECUTE 'ALTER TABLE parse_issues DROP CONSTRAINT ' || quote_ident(c.conname);
    END LOOP;
END $$;

-- message_addresses
ALTER TABLE message_addresses ADD COLUMN IF NOT EXISTS version_id BIGINT;
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
         WHERE conrelid = 'message_addresses'::regclass AND contype = 'u'
    LOOP
        EXECUTE 'ALTER TABLE message_addresses DROP CONSTRAINT ' || quote_ident(c.conname);
    END LOOP;
END $$;

-- mime_parts
ALTER TABLE mime_parts ADD COLUMN IF NOT EXISTS version_id BIGINT;
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
         WHERE conrelid = 'mime_parts'::regclass AND contype = 'u'
           AND conname = 'mime_parts_eml_sha256_mime_path_key'
    LOOP
        EXECUTE 'ALTER TABLE mime_parts DROP CONSTRAINT ' || quote_ident(c.conname);
    END LOOP;
END $$;

-- message_links
ALTER TABLE message_links ADD COLUMN IF NOT EXISTS version_id BIGINT;
DO $$
DECLARE c RECORD;
BEGIN
    FOR c IN
        SELECT conname FROM pg_constraint
         WHERE conrelid = 'message_links'::regclass AND contype = 'u'
           AND conname = 'uq_links'
    LOOP
        EXECUTE 'ALTER TABLE message_links DROP CONSTRAINT ' || quote_ident(c.conname);
    END LOOP;
END $$;

-- ============ 回填：每封已有邮件生成 legacy_backfill 版本 1 ============
INSERT INTO parse_versions(
        eml_sha256, version_no, parser_version, policy_version, parse_status,
        part_count, attachment_count, source, reason, requested_by)
SELECT m.eml_sha256, 1,
       COALESCE((SELECT parser_version FROM parse_runs p WHERE p.eml_sha256 = m.eml_sha256),
                '1.0.0'),
       'legacy-v1',
       COALESCE((SELECT parse_status FROM parse_runs p WHERE p.eml_sha256 = m.eml_sha256),
                'ok'),
       COALESCE((SELECT count(*) FROM mime_parts mp WHERE mp.eml_sha256 = m.eml_sha256), 0),
       COALESCE((SELECT count(*) FROM mime_parts mp
                  WHERE mp.eml_sha256 = m.eml_sha256 AND mp.is_attachment), 0),
       'legacy_backfill', 'backfilled from unversioned schema', 'migration'
  FROM messages m
 WHERE NOT EXISTS (
        SELECT 1 FROM parse_versions v
         WHERE v.eml_sha256 = m.eml_sha256 AND v.version_no = 1);

UPDATE messages m SET version_id = v.id
  FROM parse_versions v
 WHERE m.version_id IS NULL AND v.eml_sha256 = m.eml_sha256 AND v.version_no = 1;

UPDATE parse_issues pi SET version_id = v.id
  FROM parse_versions v
 WHERE pi.version_id IS NULL AND v.eml_sha256 = pi.eml_sha256 AND v.version_no = 1;

UPDATE message_addresses ma SET version_id = v.id
  FROM parse_versions v
 WHERE ma.version_id IS NULL AND v.eml_sha256 = ma.eml_sha256 AND v.version_no = 1;

UPDATE mime_parts mp SET version_id = v.id
  FROM parse_versions v
 WHERE mp.version_id IS NULL AND v.eml_sha256 = mp.eml_sha256 AND v.version_no = 1;

UPDATE message_links ml SET version_id = v.id
  FROM parse_versions v
 WHERE ml.version_id IS NULL AND v.eml_sha256 = ml.eml_sha256 AND v.version_no = 1;

-- 当前指针 + 初始切换审计
INSERT INTO current_versions(eml_sha256, version_id)
SELECT eml_sha256, (SELECT id FROM parse_versions v
                     WHERE v.eml_sha256 = raw_emls.eml_sha256 ORDER BY version_no LIMIT 1)
  FROM raw_emls
 WHERE EXISTS (SELECT 1 FROM parse_versions v WHERE v.eml_sha256 = raw_emls.eml_sha256)
ON CONFLICT (eml_sha256) DO NOTHING;

INSERT INTO current_switches(eml_sha256, version_id, action, actor)
SELECT eml_sha256, version_id, 'initial', 'migration'
  FROM current_versions
 WHERE NOT EXISTS (SELECT 1 FROM current_switches s
                    WHERE s.eml_sha256 = current_versions.eml_sha256);

-- 版本内冲突迁移
INSERT INTO version_conflicts(version_id, conflict_type, message_id, detail)
SELECT cv.version_id, ic.conflict_type, ic.message_id, ic.detail
  FROM identity_conflicts ic
  JOIN current_versions cv ON cv.eml_sha256 = ic.eml_sha256
 WHERE ic.conflict_type IN
       ('duplicate_message_id_in_header','missing_message_id','self_reference')
ON CONFLICT DO NOTHING;

DELETE FROM identity_conflicts
 WHERE conflict_type IN
       ('duplicate_message_id_in_header','missing_message_id','self_reference');

-- ============ 收尾：非空 + 新约束/索引/FK ============
ALTER TABLE messages ALTER COLUMN version_id SET NOT NULL;
ALTER TABLE parse_issues ALTER COLUMN version_id SET NOT NULL;
ALTER TABLE message_addresses ALTER COLUMN version_id SET NOT NULL;
ALTER TABLE mime_parts ALTER COLUMN version_id SET NOT NULL;
ALTER TABLE message_links ALTER COLUMN version_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE messages ADD CONSTRAINT messages_version_id_key UNIQUE (version_id);
EXCEPTION WHEN duplicate_object OR duplicate_table THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE messages ADD CONSTRAINT messages_version_id_fkey
        FOREIGN KEY (version_id) REFERENCES parse_versions(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE parse_issues ADD CONSTRAINT parse_issues_version_id_fkey
        FOREIGN KEY (version_id) REFERENCES parse_versions(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE message_addresses ADD CONSTRAINT message_addresses_version_id_fkey
        FOREIGN KEY (version_id) REFERENCES parse_versions(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE mime_parts ADD CONSTRAINT mime_parts_version_id_fkey
        FOREIGN KEY (version_id) REFERENCES parse_versions(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
    ALTER TABLE message_links ADD CONSTRAINT message_links_version_id_fkey
        FOREIGN KEY (version_id) REFERENCES parse_versions(id) ON DELETE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_parse_issues_version
    ON parse_issues(version_id, issue_no);
CREATE UNIQUE INDEX IF NOT EXISTS uq_msg_addr_version
    ON message_addresses(version_id, address_id, role, position);
CREATE UNIQUE INDEX IF NOT EXISTS uq_mime_parts_version
    ON mime_parts(version_id, mime_path);
CREATE UNIQUE INDEX IF NOT EXISTS uq_links_version
    ON message_links(version_id, link_type, position, target_message_id);
CREATE INDEX IF NOT EXISTS idx_messages_ver ON messages(version_id);
CREATE INDEX IF NOT EXISTS idx_parse_issues_ver ON parse_issues(version_id);
CREATE INDEX IF NOT EXISTS idx_msg_addr_ver ON message_addresses(version_id);
CREATE INDEX IF NOT EXISTS idx_mime_parts_ver ON mime_parts(version_id);
CREATE INDEX IF NOT EXISTS idx_links_ver ON message_links(version_id);
CREATE INDEX IF NOT EXISTS idx_mime_parts_sha ON mime_parts(sha256);
CREATE INDEX IF NOT EXISTS idx_conflicts_eml ON identity_conflicts(eml_sha256);
-- 新唯一约束要求下，旧的同名列索引已无存在意义，保留无副作用。

COMMIT;
