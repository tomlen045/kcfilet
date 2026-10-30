# Changelog

## 1.0.0 (2026-10-30)

首发。

- `diff`：两份 realm 档案差异解剖，高危/中危/低危三档 + verdict + 退出码 0/1/2
- 实体级 rename 识别：同集合内 ID 变了、内容一致 → ⇄ rename，不误报删+增
- 机密指纹化：secret/password/credential/privateKey 类字段只出 len+sha8，报告可直接进工单
- lifespan/timeout 类数值字段白名单：含 token 字样但实为配置数值的不指纹化，保持可读
- `inventory` / `list`：单档案体检、目录清点
- `--report`（0600、拒绝覆盖）与 `--ledger`（CSV append-only、零字段值）
- 不变量 selftest 18 项全绿
- 真机偏态实测：KC 26.3.0 master realm（30+ 内置 client/8 条内置 flow），5 处计划内变更全中、零误伤
