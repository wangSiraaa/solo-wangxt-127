# 企业 EML 档案 API（FastAPI + Python email 标准库）

把 EML 原始字节解析为可检索的**邮件事实**：信头、参与方关系、多层 MIME 结构、
附件/内嵌资源、Message-ID 引用会话图。无前端；HTML 只存储/安全转义；附件写入
受控本地目录；不发起任何远程请求、不执行脚本。

## 设计原则

| 要求 | 实现 |
|---|---|
| 仅用 Python 标准库解析邮件 | `app/parser.py` 只用 `email`/`email.policy.default`；不引入邮件第三方库 |
| 多层 MIME 按结构解析 | 前序遍历 MIME 树，`mime_path`（如 `1.1.2.1`）+ `depth`，容器与叶子全部入库 |
| 多字符集 | 信头 RFC2047；正文按声明 charset → content_charset → utf-8 → latin-1 回退，回退/失败入 `parse_issues` |
| 内嵌资源 | `Content-ID` 规范化，与 HTML `cid:` 引用交叉校验；缺失/未用均登记 |
| 附件名 | RFC2231/RFC2047 解码，原始名（`filename_raw`）与净化名（`filename_safe`）并存；**文件名只做元数据，从不参与落盘路径** |
| 路径不越界 | 磁盘路径由服务端按摘要生成 `aa/bb/<sha256>`；`safe_resolve()` 严格白名单校验，读取再 resolve 一次 |
| HTML 安全 | 原文存 `body_html`（默认不下发），全文本转义存 `body_html_escaped`；`src/href/url()` 远程地址仅登记 `html_external_refs`，从不抓取 |
| 会话依赖标识 | 强关系只来自 `Message-ID`/`References`/`In-Reply-To`（`message_links`）；主题相同只进 `weak_subject_candidates`，**永不合并** |
| 重复/缺失标识 | 多 Message-ID、缺失 ID、ID 被不同 EML 重用、悬空引用、自引用、引用环 → `identity_conflicts` 全保留，不强行合并 |
| 原文↔结果关联 | `raw_emls`（字节+sha256）↔ `messages/mime_parts/parse_issues/parse_runs` 全部以 `eml_sha256` 关联，幂等入库（重传=重解析） |
| 解析失败可定位 | 即使致命结构错误也入库；`parse_issues(location=mime_path/header, severity, kind, detail)` + `/failures` |
| 附件不进普通日志 | 业务日志只记 sha/路径/类型/大小；`PayloadRedactionFilter` 兜底拦截 payload 标记 |

## 结构

```
app/
  config.py        环境配置（DATABASE_URL/ATTACHMENT_DIR/大小上限）
  parser.py        纯解析：bytes -> MailFact（不触网、不写盘）
  normalizers.py   Message-ID/地址/日期规范化（纯函数，有单测）
  security.py      受控存储、文件名净化、HTML 转义、外部资源识别
  threads.py       引用图：Tarjan SCC 找环、祖先/后代遍历（环安全）
  repository.py    PostgreSQL 持久化、附件落盘、冲突/悬空/环检测
  api.py           FastAPI 路由
db/schema.sql      全部表/索引/触发器
tests/
  sample_gen_*.py  多编码 / 循环引用 / 损坏边界样例生成器（输出 samples/*.eml）
  test_*.py        30 个测试（纯函数 + 真实 PostgreSQL 端到端）
scripts/           本地 PG 与 API 启动脚本
```

## 快速开始

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

# 1) PostgreSQL（示例使用 unix socket），建库后：
psql -f db/schema.sql          # 应用启动时也会自动幂等执行

# 2) 受控附件目录与 API
export DATABASE_URL='postgresql://user@/emailarchive?host=/var/run/postgresql'
export ATTACHMENT_DIR=/srv/eml-archive/attachments   # 服务账号独占 0700
./scripts/run_api.sh
```

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/emls` | 上传 EML（`message/rfc822` 原始体或 `multipart/form-data`），返回 sha/状态/部件数/问题数 |
| GET | `/emls` | 邮件列表 |
| GET | `/emls/{sha}` | 邮件事实详情（默认只给转义 HTML；`?include_raw_html=1` 显式取原文） |
| GET | `/emls/{sha}/raw` | 原始 EML 回读（attachment + nosniff + CSP none） |
| GET | `/emls/{sha}/parts/{1.2...}` | 受控下载部件（HTML/SVG 强制 octet-stream；路径白名单） |
| GET | `/emls/{sha}/thread` | 强线程（引用边）+ `weak_subject_candidates`（仅主题，不合并） |
| GET | `/search?q=` | 全文检索（simple FTS + trigram CJK/子串回退） |
| GET | `/failures` | 所有非 ok 解析及其可定位 issues |
| GET | `/health` | 健康检查 |

```bash
curl --data-binary @mail.eml -H 'Content-Type: message/rfc822' \
  http://localhost:8000/emls
```

## 样例（多编码 / 循环引用 / 损坏边界）

```bash
python tests/sample_gen_multicharset.py   # GB2312 正文、RFC2047 信头、三层 MIME、
                                          # 内联 GIF、2231/2047 中文附件名、rfc822 转发、
                                          # <script> 与远程资源
python tests/sample_gen_cycle.py          # a→b→c→a 引用环、重复 Message-ID、缺失 ID
python tests/sample_gen_corrupt.py        # boundary 不匹配(failed)、base64 截断、无 boundary
```

解析状态语义：
- `ok`：无错误级问题；
- `ok_with_issues`：邮件可用但有 error（如 base64 截断，附件保留原始字节并标注）；
- `failed`：结构致命（如起始 boundary 不存在 / multipart 无 boundary），raw 仍存档、
  问题定位到部件路径。

## 测试

```bash
pytest -q
# test_parser/test_security/test_threads 不依赖数据库；
# test_integration 需要真实 PostgreSQL（不可达自动 skip）。
```

## 运维注意

- 附件目录应放在独立卷、服务账号独占权限；本服务不提供删除/覆盖附件的接口。
- 同一载荷（sha256）在单封邮件目录下内容寻址去重；跨邮件保留独立目录以便整封删除。
- 全库引用图环检测为 O(边) 全量扫描，适合中小规模；超大库应改为“仅受影响 Message-ID
  子图”增量检测（`repository._detect_graph_conflicts` 注释处）。
- `MAX_UPLOAD_BYTES` 同时按 Content-Length 与流式累计双保险拦截。
