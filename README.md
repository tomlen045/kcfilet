# kcfilet — Keycloak realm 档案差异解剖刀

> kcxport 负责把 realm 备份成档案，kcfilet 负责回答：**两份档案之间，realm 被谁动了什么。**

`v1.0.0` · 零依赖 · Python 3.6+ · 单文件 CLI · MIT

## 它解决什么问题

Keycloak 运维里最常缺席的不是备份，是**验收**：

- 迁移/升级前后，realm 到底搬干净了没有？——没人说得清
- 交接一台上生产过的 KC，谁加过 client、谁关过防爆破？——没有记录
- 加固基线推下去一周，有没有人改回去？——没人发现

kcfilet 吃两份 realm 档案 JSON（用 [kcxport](https://gitee.com/tomlen/kcxport) 从真机导出，或任意 partial-export 产物），产出一份分好高危/中危/低危的差异解剖报告。**一份报告，三种用法**：迁移前后对比、漂移检测、加固验收。

## 快速开始

```bash
# 差异解剖：对比两份档案（高危发现时退出码 1，可直接进 CI）
python3 kcfilet.py diff realm-周一.json realm-周五.json --report diff.json

# 单份档案体检：里面有几个 client、几个 IdP、多少处机密字段
python3 kcfilet.py inventory realm-周五.json

# 清点一个档案目录
python3 kcfilet.py list ./backups/

# 自测（18 项不变量）
python3 kcfilet.py selftest
```

## 输出长什么样

```
== 变更摘要 ==
  + 33 added   - 6 removed   ~ 3 changed   ⇄ 0 renamed
  高危 33 / 中危 0 / 低危 9

== 高危 (必须逐条签收) ==
  [ADD] $.clients<clientId=xh-migrator>.clientId
  [ADD] $.clients<clientId=xh-migrator>.directAccessGrantsEnabled   (密码直连授权(ROPC))
  [DEL] $.roles.realm<name=uma_authorization>.name
  [CHG] $.sslRequired: external → none   (HTTPS 强制策略)
  [CHG] $.accessTokenLifespan: 60 → 300   (访问令牌有效期)

verdict: ALERT (rc=1)
```

## 三条设计原则

1. **报告本身就是安全物**：机密类字段（secret/password/credential/privateKey…）在控制台和报告里只出现 `len + sha256 前 8 位` 指纹，永不出现原值——diff 报告可以直接贴进工单和群。
2. **重命名不冤枉人**：同集合内「ID 变了、内容一致」的实体判为 rename（⇄），不输出吓人的删+增；配对不唯一时宁可不判。
3. **证据文件按档案级权限管理**：报告新文件强制 0600，已存在默认拒绝覆盖（--force 才放行）；台账只记 sha8 和计数，零字段值。

## 判级口径

| 级别 | 触发 | 退出码贡献 |
|---|---|---|
| 高危 | 新增 client / 新增身份源 / 删除角色 / 生命周期字段变化（sslRequired、bruteForceProtected、directAccessGrantsEnabled、implicitFlowEnabled、accessTokenLifespan…） | verdict=ALERT, rc=1 |
| 中危 | 删除 client、删除用户、IdP 变化、协议映射变化 | NOTICE, rc=0 |
| 低危 | 用户属性、外观、描述类 | NOTICE, rc=0 |
| 无差异 | 两份档案一致 | CLEAN, rc=0 |

`rc=1` 是特意设计的：diff 挂进 crontab，白天动过的 realm 晚上自动对账，ALERT 直接进告警管道。

## 退役的法（通用铁律里先放一句）

kcfilet 只读两份 JSON，不连 KC、不改任何东西。想回滚一个 diff？用 kcxport 把 A 档案 import 回实例即可（`kc.sh import --file`）。

## 不变量体系（selftest 逐条验证，18/18）

I1 机密指纹化（控制台+报告双口径） · I2 档案零改动（diff 前后 sha/mtime 一致） · I3 报告安全落盘（拒绝覆盖/0600） · I4 生命周期必报（ALERT+rc=1） · I5 重命名识别（不误报删+增） · I6 空差异零发现 · I7 截断档案拒判（rc=2） · I8 匿名集合宁报不漏（口径声明） · I9 台账零字段值+append-only

## 与 kcxport 的咬合

```bash
# 周一备份
kcxport guard --url http://kc:8080 --realm prod --admin admin --output ./backups
# 周五对账（自动拉该目录最新两份）
python3 kcfilet.py diff backups/prod-realm-周一.json backups/prod-realm-周五.json --report diff.json --ledger ledger.csv
# rc=1 ? → 有人动了 realm，打开 diff.json 逐条签收
```

工具链全景：`kcxport`（备份+权限收口）→ `kcfilet`（差异验收）→ `oidcprobe`（对外暴露面巡检）。

## License

MIT
