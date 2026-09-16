# 企业 EML 档案 API（FastAPI + Python email 标准库）

把 EML 原始字节解析为**不可变、可版本化、可检索、可保全、可审计处置**的邮件事实：
信头、参与方关系、多层 MIME 结构、附件/内嵌资源、Message-ID 引用会话图。无前端；
HTML 只存储/安全转义；附件写入受控本地目录；不发起远程请求、不执行脚本。

## 证据保全与到期处置（Legal Hold & Disposition）

- 保全策略 `hold_policies` 状态机：`draft → active → (suspended ⇄ active/resumed)
  → expired → purging → completed`；支持**单封 EML** 或**按查询条件**（白名单 DSL：
  主题/正文/收发件人包含、Message-ID、有无附件、时间范围）；query 策略在**激活时
  快照目标集合**，之后范围不再漂移。
- 保护期内禁止删除：raw EML、所有解析版本（不可变触发器）、附件、重解析任务历史。
  直删路径 `purge_eml` 也检查 `eml_is_held()`。
- 到期由异步处置任务**分批**清除“不再受保全且无 queued/running 重解析任务”的邮件：
  游标表 `disposition_run_targets(pending/purged/skipped_held/skipped_active_job/
  skipped_missing/failed)`，每封邮件独立事务；重启后从同一游标继续。
- 每个被删对象在 `disposition_audit`（只追加，触发器拒绝改删）留痕：原因、操作者、
  被删除版本摘要（版本号/策略/部件数/附件数/内部标识等）。
- 两阶段文件删除：DB 事务先写 `file_graveyard(pending)` 与审计再提交，**提交后**才
  物理删附件；worker 周期对账，崩溃恢复不产生“库已删文件仍在”或反向孤儿，引用计数
  复核保护跨版本共享文件。
- 并发协调：
  - 同 EML + 同策略/同 idempotency key 的并发请求由唯一索引合并为同一活动运行；
  - 每-EML 咨询事务锁让**处置删除、重解析执行、版本回退**三者互斥；
  - 处置游标中的 EML 拒绝新建重解析（HTTP 409，明确等待态），回退同样被拒；
  - 有活动任务的目标跳过为 `skipped_active_job`，任务结束后游标自动 reopen；
  - 处置中策略被重新激活 -> 整单安全 `aborted`（已删不回滚，未删保持完整可读）；
    单个目标被新策略重新保全 -> `skipped_held`。
- 进程重启：worker 启动先恢复过期租约的 running 重解析任务；处置无内存状态，直接
  从 `disposition_run_targets` 游标和 `file_graveyard` 墓场继续，重复运行不重复删除、
  不重复审计（唯一约束）。

## 版本化重解析（合规可追溯）

- `parse_versions`：每次成功（含结构失败）解析生成一个**不可修改**的版本
  （数据库触发器拒绝 UPDATE/DELETE，受控清除除外），带解析器版本、策略版本、
  原因、申请人与任务号。
- 所有派生事实（信头、部件、问题、地址关系、会话边、版本内冲突）都归属
  `version_id`；旧版本及其附件引用始终可读。
- `current_versions` 是每封 EML 的当前展示指针；重解析只有在新版本全部事实写入
  成功后，才在**同一事务内**原子切换指针。失败时旧 current 与附件不受影响。
- `reparse_jobs` 任务状态机：`queued → running → succeeded | failed | cancelled`。
  - 同 EML + 同策略的并发/重复请求由部分唯一索引合并为同一个未终态任务
    （响应 `created=false`）；
  - 不同策略可各自排队，但按 EML 咨询锁串行执行，**不会并发覆盖** current；
  - 失败按指数退避重试至 `max_attempts`，全程保留旧版本；
  - worker 用心跳续约；进程重启时把租约超时的 running 任务安全转回 queued 并记录
    `interrupted` 尝试历史；
  - queued 任务可取消，取消不产生任何派生数据；
  - 附件按内容寻址（`aa/bb/<payload-sha256>`），跨版本/重试天然去重，不重复落盘。
- `current_switches` 审计每次 `initial/reparse/rollback` 指针变更及操作者。

## 设计原则

| 要求 | 实现 |
|---|---|
| 仅用 Python 标准库解析邮件 | `app/parser.py` 只用 `email`；不引入邮件第三方库 |
| 多层 MIME 按结构解析 | 前序遍历 MIME 树，`mime_path`（如 `1.1.2.1`）+ `depth`，容器与叶子全部入库 |
| 多字符集 | 信头 RFC2047；正文按声明 charset → content_charset → utf-8 → latin-1 回退 |
| 内嵌资源 | `Content-ID` 规范化，与 HTML `cid:` 交叉校验 |
| 附件名 | RFC2231/2047 解码，原名与净化名并存；**文件名只做元数据，从不参与落盘路径** |
| 路径不越界 | 落盘路径由服务端摘要生成；`safe_resolve()` 严格白名单 + 二次 resolve |
| HTML 安全 | 原文默认不下发；全文本转义版随详情给出；远程 `src/href/url()` 仅登记不抓取 |
| 会话依赖标识 | 强关系只来自 `Message-ID/References/In-Reply-To`；同主题仅作弱候选，永不合并 |
| 重复/缺失/重用标识 | 信头级冲突随版本快照（`version_conflicts`）；ID 重用/悬空/引用环基于当前版本图重算（`identity_conflicts`） |
| 原文↔结果关联 | `raw_emls`（字节+sha256）↔ 版本与事实全部以 `eml_sha256` 关联 |
| 解析失败可定位 | 致命结构错误也入库；`parse_issues(location)` 与 `/failures`、任务尝试历史 |
| 附件不进普通日志 | 业务日志只记 sha/路径/类型/大小；`PayloadRedactionFilter` 兜底 |

## 结构

```
app/
  parser.py        纯解析：bytes -> MailFact（不触网、不写盘）
  normalizers.py   Message-ID/地址/日期规范化
  security.py      受控存储、文件名净化、HTML 转义、外部资源识别
  threads.py       引用图：Tarjan SCC 找环、环安全遍历
  repository.py    版本化持久化、重解析任务编排、租约/恢复、原子切换、冲突重算
  holds.py         保全策略、到期处置游标、两阶段文件删除、审计、并发协调
  worker.py        后台 worker（重解析领取 + 到期扫描 + 处置批次 + 墓场对账）
  api.py / main.py FastAPI 路由与生命周期（启动自动迁移 + worker）
db/
  schema.sql       全新部署全量模型
  migrations/0002_versions.sql     旧非版本化库 -> 版本化（旧邮件回填 legacy_backfill v1）
  migrations/0003_holds_disposition.sql  保全/处置模型
tests/test_holds.py  保全与处置端到端（并发/崩溃恢复/中止/legacy 兼容）
tests/
  sample_gen_*.py  多编码 / 循环引用 / 损坏边界样例
  test_*.py        38 个测试（纯函数 + 真实 PostgreSQL 端到端）
```

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/emls` | 上传 EML（幂等；同 sha 重传不创建新版本） |
| GET | `/emls` `/search` | 列表 / 全文+CJK trigram 检索（仅当前版本） |
| GET | `/emls/{sha}` | 当前版本事实；`?version=N` 看历史版本；`?include_raw_html=1` 取原始 HTML |
| GET | `/emls/{sha}/versions` | 版本列表（标记 is_current、策略、原因、任务） |
| POST | `/emls/{sha}/versions/{n}/activate` | 回退/切换当前展示版本（不重新解析，留 rollback 审计） |
| POST | `/emls/{sha}/reparse` | 创建重解析任务（body：`policy_version/reason/requested_by`），同策略并发自动合并 |
| GET | `/jobs?eml_sha256=` `/jobs/{id}` | 任务列表/详情（含尝试历史与产出版本） |
| POST | `/jobs/{id}/cancel` `/jobs/{id}/retry` | 取消排队任务 / 重试 failed|cancelled |
| POST | `/holds` | 创建保全策略（single/query；`expires_at` 到期；幂等 `idempotency_key`；默认激活） |
| GET | `/holds` `/holds/{id}` | 策略列表/详情（目标快照、事件、处置运行） |
| POST | `/holds/{id}/activate` `/suspend` `/resume` `/dispose` | 激活/暂停/恢复/对已到期策略发起处置 |
| POST | `/dispositions` | 手动到期处置（默认全库无保全无活动任务邮件；可传 sha 列表；幂等键） |
| GET | `/dispositions` `/dispositions/{id}` | 处置运行列表/详情（游标状态、被删版本摘要） |
| GET | `/audit?eml_sha256=` | 只追加处置审计（对象/原因/操作者/摘要） |
| GET | `/emls/{sha}/thread` | 强线程（引用边）+ 同主题弱候选（不合并） |
| GET | `/emls/{sha}/raw` | 原始 EML 回读 |
| GET | `/emls/{sha}/parts/{path}` | 受控下载；`?version=N` 下载历史版本附件 |
| GET | `/failures` | 当前版本解析失败 + failed 任务 |

```bash
# 创建到期保全（也可按 query_filter 批量；不设 expires_at 为无限期保全）
curl -XPOST http://localhost:8000/holds -H 'Content-Type: application/json' -d '{
  "name":"case-2026-09", "reason":"litigation", "created_by":"legal",
  "hold_type":"query",
  "query_filter":{"sent_before":"2026-01-01T00:00:00Z","from_contains":"acme.com"},
  "expires_at":"2027-09-16T00:00:00Z"}'
# 暂停/恢复
curl -XPOST http://localhost:8000/holds/7/suspend
curl -XPOST http://localhost:8000/holds/7/resume
# 到期后显式发起处置（worker 也会自动扫描到期策略）
curl -XPOST http://localhost:8000/holds/7/dispose
curl http://localhost:8000/dispositions/3          # 游标/审计摘要
curl 'http://localhost:8000/audit?eml_sha256=...' # 每个被删对象的不可篡改记录

# 创建带原因的重解析任务
curl -XPOST http://localhost:8000/emls/$SHA/reparse \
  -H 'Content-Type: application/json' \
  -d '{"policy_version":"policy.v2.1","reason":"charset rules update","requested_by":"compliance"}'
# 轮询
curl http://localhost:8000/jobs/12
# 比较并回退
curl http://localhost:8000/emls/$SHA/versions
curl -XPOST http://localhost:8000/emls/$SHA/versions/1/activate
```

## 部署

```bash
pip install -r requirements.txt
# 全新库：启动时自动建表；旧库：启动时自动按 db/migrations 顺序迁移并回填。
export DATABASE_URL='postgresql://user@/emailarchive?host=/var/run/postgresql'
export ATTACHMENT_DIR=/srv/eml-archive/attachments   # 服务账号独占
./scripts/run_api.sh      # API + 内置 worker
# 多副本时只在一个进程开 worker：其余设置 DISABLE_WORKER=1
WORKER_LEASE_SECONDS=300 WORKER_POLL_INTERVAL=1.0
```

## 样例

```bash
python tests/sample_gen_multicharset.py   # 多编码/三层 MIME/内联资源/rfc822/脚本与远程资源
python tests/sample_gen_cycle.py          # 引用环、重复/缺失 Message-ID
python tests/sample_gen_corrupt.py        # boundary 不匹配(failed)、base64 截断、无 boundary
```

## 测试

```bash
pytest -q   # 44 个：纯函数 + 真实 PostgreSQL 端到端
# test_integration：新版本+旧版本可读、8 并发同请求合并 1 任务 1 切换、失败保旧 current、
#                   取消无派生数据、崩溃恢复重试、附件去重、不同策略串行不并发覆盖；
# test_holds：到期仅清除无保全无活动任务邮件、审计不可篡改、并发策略/运行合并、
#             处置中重解析/回退 409、批次中恢复保全跳过/策略重激活中止、
#             崩溃游标与墓场对账无孤儿、legacy-v1 邮件查询下载重解析保持可用。
```

## 运维注意

- 不可变版本与处置审计均为只追加；受控清除须 `SET LOCAL app.archive_purge='on'`
  （即 `purge_eml` / 处置运行）。磁盘文件由 file_graveyard 两阶段删除，外部可再做
  按引用计数的 GC 复核。
- 处置与重解析共用每-EML 咨询锁；同一时刻同封邮件至多一个写入者。多副本部署时
  只在一个进程开 worker（`DISABLE_WORKER=1`）。
- 全量图冲突重算/到期处置为批量游标，适合中小规模；超大库可按目标分片串行运行多个
  manual_retention run。
- `MAX_UPLOAD_BYTES` 同时按 Content-Length 与流式累计拦截。
