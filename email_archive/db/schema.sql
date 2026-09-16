-- Enterprise EML archive: normalized mail facts.
-- PostgreSQL 13+.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- 1. 原始 EML 与解析批次（原文件摘要与解析结果关联）
CREATE TABLE IF NOT EXISTS raw_emls (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL UNIQUE,          -- 原始 EML 字节摘要（幂等键）
    eml_filename    TEXT,                          -- 上传时提供的文件名（仅元数据）
    eml_size        BIGINT NOT NULL CHECK (eml_size >= 0),
    eml_bytes       BYTEA NOT NULL,                -- 原始字节，支持原文回读/复核
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS parse_runs (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL UNIQUE REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    parsed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    parser_version  TEXT NOT NULL,
    parse_status    TEXT NOT NULL CHECK (parse_status IN ('ok','ok_with_issues','failed')),
    part_count      INT NOT NULL DEFAULT 0,
    attachment_count INT NOT NULL DEFAULT 0
);

-- 可定位的解析问题（结构缺陷/解码失败/安全处置记录）。绝不包含附件内容。
CREATE TABLE IF NOT EXISTS parse_issues (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    issue_no        INT NOT NULL,                  -- 在该 EML 内的序号，便于定位
    severity        TEXT NOT NULL CHECK (severity IN ('error','warning','info')),
    kind            TEXT NOT NULL,                 -- defect 类名 / 错误类别
    location        TEXT,                          -- 如 mime_path '1.2'、header 名
    detail          TEXT NOT NULL,
    UNIQUE (eml_sha256, issue_no)
);
CREATE INDEX IF NOT EXISTS idx_parse_issues_eml ON parse_issues(eml_sha256);

-- 2. 信头事实
CREATE TABLE IF NOT EXISTS messages (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL UNIQUE REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    message_id      TEXT,                          -- 规范化后的 Message-ID；缺失为 NULL
    message_id_raw  TEXT,                          -- 信头原始值，冲突可审计
    message_id_count INT NOT NULL DEFAULT 1,       -- Message-ID 信头出现次数（>1 为重复标识）
    subject         TEXT,
    subject_raw     TEXT,                          -- 解码前的编码主题
    date_raw        TEXT,
    sent_at         TIMESTAMPTZ,                   -- 解析失败/无时区时的处置见 parse_issues
    from_raw        TEXT,
    sender_raw      TEXT,
    reply_to_raw    TEXT,
    to_raw          TEXT,
    cc_raw          TEXT,
    bcc_raw         TEXT,
    in_reply_to     TEXT,                          -- 规范化的单值父引用
    in_reply_to_raw TEXT,
    references_list TEXT[] NOT NULL DEFAULT '{}',  -- 规范化、去重、保序（references 为保留字）
    references_raw  TEXT,
    raw_headers     JSONB NOT NULL DEFAULT '[]'::jsonb, -- 保序多值信头 [{name,value}]
    -- 正文：HTML 原样存储（不执行、不取远程资源），另存安全转义版本
    body_text       TEXT,
    body_text_path  TEXT,
    body_html       TEXT,
    body_html_escaped TEXT,
    body_html_path  TEXT,
    body_html_escaped_path TEXT,
    body_charset    TEXT,
    html_external_refs TEXT[] NOT NULL DEFAULT '{}', -- 仅登记，不抓取
    has_attachments BOOLEAN NOT NULL DEFAULT false,
    search_tsv      TSVECTOR
);
CREATE INDEX IF NOT EXISTS idx_messages_mid ON messages(message_id);
-- trigram 索引：主题模糊检索 + CJK 正文子串（ILIKE）回退
CREATE INDEX IF NOT EXISTS idx_messages_subject_trgm ON messages USING gin (subject gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_body_trgm ON messages USING gin (body_text gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_rawheaders ON messages USING gin (raw_headers jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_messages_search ON messages USING gin (search_tsv);

-- search_tsv 由主题/正文/信头派生（simple 配置：不做语言词干，编号/标识精确）。
-- 注意：PG15 内置 default 解析器把连续 CJK 当作一个词，中文检索走 trigram ILIKE 回退
-- （见 repository.search_messages 与下方 trigram 索引）。
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

-- 3. 参与方关系（邮箱归一化，显示名逐次保留）
CREATE TABLE IF NOT EXISTS addresses (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email_norm      TEXT NOT NULL UNIQUE,          -- 小写、去括号注释
    email_raw       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS message_addresses (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    address_id      BIGINT NOT NULL REFERENCES addresses(id),
    role            TEXT NOT NULL CHECK (role IN
                        ('from','sender','reply_to','to','cc','bcc')),
    position        INT NOT NULL DEFAULT 0,
    display_name    TEXT
);
CREATE INDEX IF NOT EXISTS idx_msg_addr_eml ON message_addresses(eml_sha256);
CREATE INDEX IF NOT EXISTS idx_msg_addr_addr ON message_addresses(address_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_msg_addr ON message_addresses(eml_sha256, address_id, role, position);

-- 4. 多层 MIME 结构与附件
CREATE TABLE IF NOT EXISTS mime_parts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    part_no         INT NOT NULL,                  -- 前序遍历序号
    mime_path       TEXT NOT NULL,                 -- 如 '1.2.1'
    depth           INT NOT NULL,
    content_type    TEXT NOT NULL,
    content_type_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    disposition     TEXT,                          -- attachment / inline / NULL
    filename_raw    TEXT,                          -- 原始（可能编码/含路径）附件名
    filename_safe   TEXT,                          -- 去路径、解码后的安全名
    charset         TEXT,
    content_id      TEXT,
    cid_norm        TEXT,
    transfer_encoding TEXT,
    size_bytes      BIGINT,
    is_container    BOOLEAN NOT NULL DEFAULT false,
    is_attachment   BOOLEAN NOT NULL DEFAULT false,
    is_inline       BOOLEAN NOT NULL DEFAULT false,
    is_body         BOOLEAN NOT NULL DEFAULT false,
    -- 受控目录内的存储相对路径；由服务端按摘要生成，不接受用户路径
    stored_relpath  TEXT,
    sha256          TEXT,
    nested_message_id TEXT,                        -- message/rfc822 内部信的 Message-ID
    nested_subject  TEXT,
    UNIQUE (eml_sha256, mime_path)
);
CREATE INDEX IF NOT EXISTS idx_mime_parts_eml ON mime_parts(eml_sha256);
CREATE INDEX IF NOT EXISTS idx_mime_parts_cid ON mime_parts(eml_sha256, cid_norm);
CREATE INDEX IF NOT EXISTS idx_mime_parts_sha ON mime_parts(sha256);

-- 5. 会话边（Message-ID / References / In-Reply-To；主题不入边）
CREATE TABLE IF NOT EXISTS message_links (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    eml_sha256      TEXT NOT NULL REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    link_type       TEXT NOT NULL CHECK (link_type IN ('in_reply_to','references')),
    position        INT NOT NULL DEFAULT 0,
    target_message_id TEXT NOT NULL,              -- 规范化的被引用 ID（可能悬空）
    target_raw      TEXT
);
CREATE INDEX IF NOT EXISTS idx_links_source ON message_links(eml_sha256);
CREATE INDEX IF NOT EXISTS idx_links_target ON message_links(target_message_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_links ON message_links(eml_sha256, link_type, position, target_message_id);

-- 引用解析结果：区分强链与悬空引用
CREATE TABLE IF NOT EXISTS link_resolutions (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_link_id BIGINT NOT NULL UNIQUE REFERENCES message_links(id) ON DELETE CASCADE,
    resolved        BOOLEAN NOT NULL,
    target_eml_sha256 TEXT REFERENCES raw_emls(eml_sha256) ON DELETE SET NULL
);

-- 6. 标识冲突与异常会话结构：保留冲突，不强行合并
CREATE TABLE IF NOT EXISTS identity_conflicts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    conflict_type   TEXT NOT NULL CHECK (conflict_type IN
                        ('duplicate_message_id_in_header',   -- 同一信内 Message-ID 重复/多值
                         'missing_message_id',               -- 无可用标识
                         'reassigned_message_id',            -- 同一 ID 被不同 EML 重用
                         'dangling_reference',               -- 引用了库中不存在的 ID
                         'reference_cycle',                  -- References/IRO 形成有向环
                         'self_reference')),                 -- 引用了自己
    message_id      TEXT,
    eml_sha256      TEXT NOT NULL REFERENCES raw_emls(eml_sha256) ON DELETE CASCADE,
    detail          TEXT NOT NULL,
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (conflict_type, message_id, eml_sha256, detail)
);
CREATE INDEX IF NOT EXISTS idx_conflicts_type ON identity_conflicts(conflict_type);
CREATE INDEX IF NOT EXISTS idx_conflicts_mid ON identity_conflicts(message_id);

COMMIT;
