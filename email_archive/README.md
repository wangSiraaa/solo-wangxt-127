# 企业 EML 档案 API（FastAPI + Python email 标准库）

把 EML 原始字节解析为**不可变、可版本化、可检索**的邮件事实：信头、参与方关系、
多层 MIME 结构、附件/内嵌资源、Message-ID 引用会话图。无前端；HTML 只存储/安全
转义；附件写入受控本地目录；不发起远程请求、不执行脚本。

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
  repository.py    版本化持久化、任务编排、租约/恢复、原子切换、冲突重算
  worker.py        后台重解析 worker（轮询领取/心跳/启动恢复）
  api.py / main.py FastAPI 路由与生命周期（启动自动迁移 + worker）
db/
  schema.sql       全新部署全量模型
  migrations/0002_versions.sql  旧非版本化库 -> 版本化（旧邮件回填 legacy_backfill v1）
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
| GET | `/emls/{sha}/thread` | 强线程（引用边）+ 同主题弱候选（不合并） |
| GET | `/emls/{sha}/raw` | 原始 EML 回读 |
| GET | `/emls/{sha}/parts/{path}` | 受控下载；`?version=N` 下载历史版本附件 |
| GET | `/failures` | 当前版本解析失败 + failed 任务 |

```bash
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
pytest -q
# 纯函数测试不依赖数据库；test_integration 需要真实 PostgreSQL（不可达自动 skip），
# 覆盖：新版本+旧版本可读、8 并发同请求合并为 1 任务 1 次切换、失败保旧 current、
# 取消无派生数据、崩溃恢复重试、附件去重、不同策略串行不并发覆盖、迁移旧邮件可查可下。
```

## 运维注意

- 不可变版本只能通过受控清除（`SET LOCAL app.archive_purge='on'`，即 `purge_eml`）
  随原始 EML 级联删除；磁盘文件不自动 GC，应由外部按引用计数定期清理。
- 全库引用图冲突重算在切换事务内全量执行，适合中小规模；超大库应改为受影响
  Message-ID 子图增量重算（`repository._recompute_global_conflicts`）。
- `MAX_UPLOAD_BYTES` 同时按 Content-Length 与流式累计拦截。
