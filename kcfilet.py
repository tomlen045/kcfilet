#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kcfilet — Keycloak realm 档案差异解剖刀（零依赖单文件 CLI）。

定位：kcxport 负责把 realm 备份成档案，kcfilet 负责回答
「两份档案之间，realm 被谁动了什么」——
迁移前后对比、漂移检测、加固验收，一份差异报告说清。

设计不变量（selftest 逐条验证）：
  I1  指纹化输出：机密类字段在控制台与报告里只出现 len+sha8 指纹，永不出现原值
  I2  档案零改动：diff 全程只读，两份输入档案 mtime/字节数/sha256 前后一致
  I3  报告安全落盘：--report 目标已存在默认拒绝；新报告文件权限 0600
  I4  生命周期必报：enabled/sslRequired/grants 类变化、clients 增项、roles 删项
      → verdict=ALERT 且退出码 1
  I5  重命名识别：同集合内 removed+added 内容哈希互配 → 判 rename，不误报删+增
  I6  空差异零发现：相同档案 → CLEAN、rc=0、changed 为空
  I7  截断档案拒判：任一侧 JSON 解析失败 → rc=2，不产出半截报告
  I8  匿名形态宁报不漏：无法命名的内容按索引对比，并在 caveats 声明
  I9  台账只写元数据：ledger 行只有 sha8/verdict/计数，不含任何字段值

用法：
  kcfilet diff A.json B.json [--report out.json] [--ledger FILE] [--force]
  kcfilet inventory ARCHIVE.json
  kcfilet list DIR
  kcfilet selftest

退出码：0=无高危  1=ALERT（存在高危变化）  2=用法/环境错误
"""
import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time

VERSION = "1.0.0"

# ---------------------------------------------------------------- 常量

SECRET_KEY_RE = re.compile(
    r"(secret|password|credential|privatekey|token|clientauthenticator)", re.I)

# 含敏感词但实为配置数值/开关的字段（如 accessTokenLifespan 含 "token"）不按机密处理
NON_SECRET_KEY_RE = re.compile(
    r"(lifespan|timeout|idle|max|expiration|notbefore|revocation)", re.I)

LIFECYCLE_RE = re.compile(
    r"\.(enabled|sslRequired|bruteForceProtected|directAccessGrantsEnabled"
    r"|standardFlowEnabled|implicitFlowEnabled|serviceAccountsEnabled"
    r"|publicClient|bearerOnly|frontchannelLogout|accessTokenLifespan"
    r"|revokeRefreshToken|refreshTokenMaxReuse|ssoSessionIdleTimeout"
    r"|ssoSessionMaxLifespan|accessCodeLifespan|notBefore"
    r"|defaultSignatureAlgorithm)$", re.I)

# 常见字段的人话解释（解释缺失字段时不硬编）
EXPLAIN = {
    "sslRequired": "HTTPS 强制策略",
    "enabled": "启用开关",
    "bruteForceProtected": "防爆破锁定",
    "directAccessGrantsEnabled": "密码直连授权(ROPC)",
    "standardFlowEnabled": "授权码登录流程",
    "implicitFlowEnabled": "隐式流程(高危遗留)",
    "serviceAccountsEnabled": "服务账号(M2M)",
    "publicClient": "公开客户端(无密钥)",
    "bearerOnly": "仅承载校验",
    "frontchannelLogout": "前端通道登出",
    "accessTokenLifespan": "访问令牌有效期",
    "ssoSessionIdleTimeout": "SSO 空闲超时",
    "ssoSessionMaxLifespan": "SSO 最长会话",
    "revokeRefreshToken": "刷新令牌吊销开关",
    "notBefore": "令牌吊销时间线",
    "defaultSignatureAlgorithm": "默认签名算法",
    "consentRequired": "授权确认页",
    "fullScopeAllowed": "全 scope 放行",
}

# 各命名集合的实体 ID 键优先级
ID_KEY_PRIORITY = ["clientId", "username", "alias", "path", "name", "type",
                   "internalId", "id"]
# 组成实体身份时要剔除的键（参与内容哈希前剔除，避免「名字变了内容必变」）
ID_STRIP_KEYS = set(ID_KEY_PRIORITY) | {"id"}

C = {
    "g": "\033[32m", "r": "\033[31m", "y": "\033[33m",
    "b": "\033[36m", "0": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
}


def cprint(color, text):
    if sys.stdout.isatty():
        print(C.get(color, "") + text + C["0"])
    else:
        print(text)


# ---------------------------------------------------------------- 指纹与脱敏

def _canon(v):
    if isinstance(v, str):
        return v
    return json.dumps(v, sort_keys=True, ensure_ascii=False)


def fingerprint(v):
    """机密字段的展示形态：<redacted len=N sha8=xxxxxxxx>。永不回原文。"""
    s = _canon(v)
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]
    return "<redacted len=%d sha8=%s>" % (len(s), h)


def smart_value(v):
    """非机密字段：截断长值（如 PEM 公钥），保留可读性。"""
    s = _canon(v)
    if len(s) > 70:
        return s[:67] + "…(len=%d)" % len(s)
    return s


def render_pair(key, old, new):
    if SECRET_KEY_RE.search(key) and not NON_SECRET_KEY_RE.search(key):
        return fingerprint(old) + " → " + fingerprint(new)
    return smart_value(old) + " → " + smart_value(new)


# ---------------------------------------------------------------- 档案读取

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_archive(path):
    """读档案 JSON；返回 (data, err)。err 非 None 即拒判。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except FileNotFoundError:
        return None, "档案不存在: %s" % path
    except PermissionError:
        return None, "档案无读取权限: %s" % path
    except json.JSONDecodeError as e:
        return None, "JSON 解析失败(疑似截断): %s: %s" % (path, e)
    except UnicodeDecodeError as e:
        return None, "编码异常(疑似损坏): %s: %s" % (path, e)


def realm_body(data):
    """partial-export 顶层就是 realm 对象；兼容 {'realm': {...}} 包装。"""
    if isinstance(data, dict) and isinstance(data.get("realm"), dict) and "realmName" not in data:
        return data["realm"]
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------- 扁平化

def _entity_key(items):
    """为 list-of-dicts 选一个在全部条目上都唯一可用的 ID 键；返回 (key, ok)。"""
    for k in ID_KEY_PRIORITY:
        if all(isinstance(it, dict) and isinstance(it.get(k), (str, int)) for it in items):
            vals = [str(it[k]) for it in items]
            if len(set(vals)) == len(vals):
                return k, True
    return None, False


def _content_hash(node):
    if not isinstance(node, (dict, list)):
        return hashlib.sha256(_canon(node).encode("utf-8")).hexdigest()[:8]
    scrubbed = _strip_ids(node)
    s = json.dumps(scrubbed, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]


def _strip_ids(node):
    if isinstance(node, dict):
        return {k: _strip_ids(v) for k, v in node.items() if k not in ID_STRIP_KEYS}
    if isinstance(node, list):
        return [_strip_ids(x) for x in node]
    return node


def flatten(node, path, out, caveats):
    """把 realm 树摊平成 {path: leaf}。命名集合用 <id=name>，匿名集合用 [i]。"""
    if isinstance(node, dict):
        for k in sorted(node.keys()):
            flatten(node[k], "%s.%s" % (path, k), out, caveats)
        return
    if isinstance(node, list):
        if not node:
            out[path] = []          # 空列表本身是叶子
            return
        if all(isinstance(x, dict) for x in node):
            key, ok = _entity_key(node)
            if ok:
                for it in node:
                    ident = str(it[key])
                    flatten(it, "%s<%s=%s>" % (path, key, ident), out, caveats)
            else:
                caveats.append("匿名集合按索引对比(重命名会判为改+增): " + path)
                for i, it in enumerate(node):
                    flatten(it, "%s[%d]" % (path, i), out, caveats)
            return
        if all(not isinstance(x, (dict, list)) for x in node):
            out[path] = sorted(_canon(x) for x in node)   # 标量列表按多重集比
            return
        caveats.append("混合类型列表按索引对比: " + path)
        for i, it in enumerate(node):
            flatten(it, "%s[%d]" % (path, i), out, caveats)
        return
    out[path] = node


# ---------------------------------------------------------------- 差异引擎

def diff_flat(fa, fb):
    added, removed, changed = [], [], []
    for p in sorted(set(fb) - set(fa)):
        added.append(p)
    for p in sorted(set(fa) - set(fb)):
        removed.append(p)
    for p in sorted(set(fa) & set(fb)):
        if fa[p] != fb[p]:
            changed.append((p, fa[p], fb[p]))
    return added, removed, changed


def collect_entities(node, path, out):
    """收集全部命名集合的 {集合路径: (id键, {实体ID: 内容哈希})}。

    内容哈希剔除全部 id 键——alias/clientId 改名不改变内容哈希，
    这是 rename 识别的依据。
    """
    if isinstance(node, dict):
        for k in sorted(node.keys()):
            collect_entities(node[k], "%s.%s" % (path, k), out)
        return
    if isinstance(node, list) and node and all(isinstance(x, dict) for x in node):
        key, ok = _entity_key(node)
        if ok:
            out[path] = (key, {str(it[key]): _content_hash(it) for it in node})
        return


def detect_renames(ents_a, ents_b):
    """实体级 rename 识别：同集合内「ID 变了、剔除 ID 后内容哈希不变」，
    且新旧两侧该哈希都唯一 → 判 rename。宁缺毋滥：配对不唯一就不判。"""
    renames = []
    for coll in sorted(set(ents_a) & set(ents_b)):
        ka, ha = ents_a[coll]
        _kb, hb = ents_b[coll]
        gone = [i for i in ha if i not in hb]
        new = [i for i in hb if i not in ha]
        if not gone or not new:
            continue
        for gi in gone:
            if not new:
                break
            h = ha[gi]
            if sum(1 for g2 in gone if ha[g2] == h) != 1:
                continue          # 旧侧同内容不唯一，不敢配
            matches = [nj for nj in new if hb[nj] == h]
            if len(matches) != 1:
                continue          # 新侧不唯一，不敢配
            nj = matches[0]
            renames.append({"parent": coll, "key": ka, "old": gi, "new": nj,
                            "path": "%s<%s=%s>" % (coll, ka, nj)})
            new.remove(nj)
    return renames


def apply_renames(added, removed, renames):
    """把 rename 实体的全部叶子路径从 added/removed 里剔除。"""
    if not renames:
        return added, removed

    def hit(p, r, ident):
        return p.startswith("%s<%s=%s>" % (r["parent"], r["key"], ident))

    kept_r = [p for p in removed if not any(hit(p, r, r["old"]) for r in renames)]
    kept_a = [p for p in added if not any(hit(p, r, r["new"]) for r in renames)]
    return kept_a, kept_r


def classify(path, etype):
    """返回 'high' | 'medium' | 'low'。路径形如 $.clients<clientId=x>.enabled。"""
    if etype == "added" and ".clients<" in path:
        return "high"
    if etype == "added" and ".identityProviders<" in path:
        return "high"
    if etype == "removed" and re.search(r"\.roles\b|roleMappings|RoleMappings", path):
        return "high"
    if etype == "changed" and LIFECYCLE_RE.search(path):
        return "high"
    if etype == "removed" and ".clients<" in path:
        return "medium"
    if etype == "removed" and ".users<" in path:
        return "medium"
    if ".identityProviders<" in path:
        return "medium"
    if ".clients<" in path or ".protocolMappers" in path:
        return "medium"
    if ".users<" in path:
        return "low"
    return "low"


def build_events(added, removed, changed):
    events = []
    for p in added:
        events.append({"type": "added", "path": p})
    for p in removed:
        events.append({"type": "removed", "path": p})
    for p, old, new in changed:
        events.append({"type": "changed", "path": p,
                       "display": render_pair(p.split(".")[-1], old, new)})
    return events


# ---------------------------------------------------------------- 报告

def mask_events_for_report(events):
    out = []
    for e in events:
        d = {"type": e["type"], "path": e["path"]}
        if "display" in e:
            d["display"] = e["display"]
        out.append(d)
    return out


def write_report(path, report, force):
    if os.path.exists(path) and not force:
        return False, "报告目标已存在(怕覆盖历史证据，加 --force 才允许): %s" % path
    try:
        txt = json.dumps(report, ensure_ascii=False, indent=1)
    except (TypeError, ValueError) as e:
        return False, "报告序列化失败: %s" % e
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(txt)
    os.chmod(path, 0o600)
    return True, None


def append_ledger(path, row):
    """CSV 台账 append-only；首建 0600。row 全部是元数据。"""
    new = not os.path.exists(path)
    if new:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["ts", "a_sha8", "b_sha8", "verdict", "added", "removed",
                        "changed", "renamed", "report"])
        w.writerow(row)


# ---------------------------------------------------------------- 展示

def explain(path):
    leaf = path.split(".")[-1]
    if "<" in leaf:
        leaf = leaf.split("<")[0]
    return EXPLAIN.get(leaf, "")


def short(path, width=86):
    return path if len(path) <= width else path[:width - 1] + "…"


def print_diff_report(rep, max_show=40):
    cprint("bold", "kcfilet v%s — realm 档案差异解剖" % VERSION)
    print()
    cnt = rep["counts"]
    cprint("b", "== 变更摘要 ==")
    print("  + %d added   - %d removed   ~ %d changed   ⇄ %d renamed"
          % (cnt["added"], cnt["removed"], cnt["changed"], cnt["renamed"]))
    print("  高危 %d / 中危 %d / 低危 %d" % (cnt["high"], cnt["medium"], cnt["low"]))
    print()
    if cnt["high"]:
        cprint("r", "== 高危 (必须逐条签收) ==")
        for e in rep["risk"]["high"][:max_show]:
            line = "  [%s] %s" % ({"added": "ADD", "removed": "DEL",
                                   "changed": "CHG"}[e["type"]],
                                  short(e["path"]))
            if "display" in e:
                line += ": " + e["display"]
            ex = explain(e["path"])
            if ex:
                line += "   (%s)" % ex
            print(line)
        if cnt["high"] > max_show:
            print("  …另有 %d 条高危，见报告文件" % (cnt["high"] - max_show))
        print()
    if cnt["medium"]:
        cprint("y", "== 中危 ==")
        for e in rep["risk"]["medium"][:max_show]:
            line = "  [%s] %s" % ({"added": "ADD", "removed": "DEL",
                                   "changed": "CHG"}[e["type"]],
                                  short(e["path"]))
            if "display" in e:
                line += ": " + e["display"]
            print(line)
        if cnt["medium"] > max_show:
            print("  …另有 %d 条中危，见报告文件" % (cnt["medium"] - max_show))
        print()
    if cnt["low"]:
        cprint("dim", "== 低危 ==")
        for e in rep["risk"]["low"][:10]:
            print("  [%s] %s" % (e["type"], short(e["path"])))
        if cnt["low"] > 10:
            print("  …另有 %d 条低危，见报告文件" % (cnt["low"] - 10))
        print()
    if rep["renames"]:
        cprint("g", "== 重命名 ⇄ (内容一致，仅名字动了) ==")
        for r in rep["renames"]:
            print("  %s → %s   @ %s" % (r["old"], r["new"], r["parent"]))
        print()
    if rep["caveats"]:
        cprint("y", "== 口径说明 ==")
        for cv in sorted(set(rep["caveats"]))[:8]:
            print("  · " + cv)
        print()
    verdict = rep["verdict"]
    color = "r" if verdict == "ALERT" else ("y" if verdict == "NOTICE" else "g")
    cprint(color, "verdict: %s (rc=%d)" % (verdict, 1 if verdict == "ALERT" else 0))
    if verdict == "ALERT":
        print("  %d 处生命周期级变化——迁移/加固是否计划内？对照 risklist 逐条签收。"
              % cnt["high"])
    elif verdict == "CLEAN":
        if cnt["renamed"]:
            print("  唯一的动静是重命名（⇄）——内容没变，只是改了名。")
        else:
            print("  两份档案零差异——realm 没被任何人动过。")


# ---------------------------------------------------------------- 子命令

def _risk_of(events):
    h, m, l = [], [], []
    for e in events:
        r = classify(e["path"], e["type"])
        {"high": h, "medium": m, "low": l}[r].append(e)
    return h, m, l


def _archive_paths_arg(p):
    return os.path.abspath(p)


def cmd_diff(args):
    pa, pb = _archive_paths_arg(args.a), _archive_paths_arg(args.b)
    da, ea = load_archive(pa)
    db, eb = load_archive(pb)
    if ea or eb:
        cprint("r", "FAIL " + (ea or eb))
        return 2

    caveats = []
    fa, fb = {}, {}
    flatten(realm_body(da), "$", fa, caveats)
    flatten(realm_body(db), "$", fb, caveats)

    ents_a, ents_b = {}, {}
    collect_entities(realm_body(da), "$", ents_a)
    collect_entities(realm_body(db), "$", ents_b)
    added, removed, changed = diff_flat(fa, fb)
    renames = detect_renames(ents_a, ents_b)
    added, removed = apply_renames(added, removed, renames)
    events = build_events(added, removed, changed)
    h, m, l = _risk_of(events)

    verdict = "ALERT" if h else ("NOTICE" if (m or l) else "CLEAN")
    rep = {
        "tool": "kcfilet", "version": VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "a": {"path": pa, "sha256": sha256_file(pa), "bytes": os.path.getsize(pa)},
        "b": {"path": pb, "sha256": sha256_file(pb), "bytes": os.path.getsize(pb)},
        "counts": {"added": len(added), "removed": len(removed),
                   "changed": len(changed), "renamed": len(renames),
                   "high": len(h), "medium": len(m), "low": len(l)},
        "verdict": verdict,
        "renames": renames,
        "added": added,
        "removed": removed,
        "changed": [{"path": p, "display": render_pair(p.split(".")[-1], o, n)}
                    for p, o, n in changed],
        "risk": {"high": mask_events_for_report(h),
                 "medium": mask_events_for_report(m),
                 "low": mask_events_for_report(l)},
        "caveats": sorted(set(caveats)),
    }

    if args.report:
        ok, err = write_report(args.report, rep, args.force)
        if not ok:
            cprint("r", "FAIL " + err)
            return 2
        print("report -> %s (mode=%s)" % (args.report, oct(os.stat(args.report).st_mode & 0o777)))

    if args.ledger:
        append_ledger(args.ledger, [
            time.strftime("%Y-%m-%d %H:%M:%S"),
            rep["a"]["sha256"][:8], rep["b"]["sha256"][:8], verdict,
            len(added), len(removed), len(changed), len(renames),
            os.path.abspath(args.report) if args.report else "",
        ])
        print("ledger -> %s" % args.ledger)

    print_diff_report(rep)
    return 1 if verdict == "ALERT" else 0


def cmd_inventory(args):
    pa = _archive_paths_arg(args.archive)
    d, err = load_archive(pa)
    if err:
        cprint("r", "FAIL " + err)
        return 2
    caveats = []
    flat = {}
    flatten(realm_body(d), "$", flat, caveats)
    def _idents(prefix):
        vals = set()
        for p in flat:
            if p.startswith(prefix + "<"):
                m2 = re.match(r"<[^=]+=([^>]*)>", p[len(prefix):])
                if m2:
                    vals.add(m2.group(1))
        return sorted(vals)

    clients = _idents("$.clients")
    users = [p for p in flat if re.match(r"^\$\.users<", p)]
    secrets = [p for p in flat if SECRET_KEY_RE.search(p)]
    idps = _idents("$.identityProviders")
    rep = {
        "tool": "kcfilet", "version": VERSION, "mode": "inventory",
        "archive": {"path": pa, "sha256": sha256_file(pa), "bytes": os.path.getsize(pa)},
        "counts": {"leaves": len(flat), "clients": len(clients),
                   "user_leaves": len(users), "secret_fields": len(secrets),
                   "identity_providers": len(idps)},
        "clients": clients, "identity_providers": idps,
        "caveats": sorted(set(caveats)),
    }
    cprint("bold", "kcfilet v%s — 档案体检" % VERSION)
    print("  %s" % os.path.basename(pa))
    print("  sha8=%s  %dB  叶子 %d" % (rep["archive"]["sha256"][:8],
                                      rep["archive"]["bytes"], len(flat)))
    print("  clients: %s" % (", ".join(clients) if clients else "(无)"))
    print("  identityProviders: %s" % (", ".join(idps) if idps else "(无)"))
    print("  机密类字段: %d 处（值已指纹口径管理，本工具永不展示）" % len(secrets))
    for cv in sorted(set(caveats))[:5]:
        print("  · " + cv)
    if args.report:
        ok, err = write_report(args.report, rep, args.force)
        if not ok:
            cprint("r", "FAIL " + err)
            return 2
        print("report -> %s" % args.report)
    return 0


def cmd_list(args):
    d = _archive_paths_arg(args.dir)
    if not os.path.isdir(d):
        cprint("r", "FAIL 目录不存在: %s" % d)
        return 2
    rows = []
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        if not (os.path.isfile(p) and n.endswith(".json")):
            continue
        data, err = load_archive(p)
        if err or not isinstance(data, dict):
            rows.append((n, "-", "-", "unreadable"))
            continue
        body = realm_body(data)
        rows.append((n, body.get("realm", "?"),
                     sha256_file(p)[:8],
                     "%d clients" % len(body.get("clients", []) or [])))
    cprint("bold", "kcfilet v%s — 档案目录 (%s)" % (VERSION, d))
    for n, realm, s8, extra in rows:
        print("  %-52s realm=%-12s sha8=%-9s %s" % (n, realm, s8, extra))
    print("  共 %d 份档案" % len(rows))
    return 0


# ---------------------------------------------------------------- selftest

def _mk(tmp, name, obj):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    return p


def _realm_a():
    return {
        "realm": "itai", "enabled": True, "sslRequired": "external",
        "bruteForceProtected": True, "accessTokenLifespan": 900,
        "attributes": {"frontendUrl": ""},
        "clients": [
            {"clientId": "portal", "enabled": True, "protocol": "openid-connect",
             "publicClient": False, "secret": "portal-secret-ORIGINAL-123",
             "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
             "protocolMappers": [
                 {"name": "email", "protocol": "openid-connect",
                  "protocolMapper": "oidc-usermodel-property-mapper",
                  "config": {"user.attribute": "email"}}]},
            {"clientId": "legacy-app", "enabled": True, "protocol": "openid-connect",
             "publicClient": True, "standardFlowEnabled": True},
        ],
        "roles": {"realm": [
            {"name": "admin", "description": " admins"},
            {"name": "user", "description": "base"}]},
        "users": [
            {"username": "alice", "enabled": True,
             "credentials": [{"type": "password", "value": "alice-pw-xxx"}]},
            {"username": "bob", "enabled": True},
        ],
        "identityProviders": [
            {"alias": "github-sso", "providerId": "github", "enabled": True,
             "config": {"clientId": "gh-1"}}],
    }


def run_selftest():
    import tempfile
    import shutil
    tmp = tempfile.mkdtemp(prefix="kcfilet-selftest-")
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    def run_cli(argv, env_extra=None):
        import subprocess
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        r = subprocess.run([sys.executable, os.path.abspath(__file__)] + argv,
                           capture_output=True, text=True, env=env,
                           cwd=tmp, timeout=120)
        return r.returncode, r.stdout + r.stderr

    # ---- 基础夹具
    a = _realm_a()
    pa = _mk(tmp, "a.json", a)
    b = json.loads(json.dumps(a))
    b["sslRequired"] = "none"
    b["bruteForceProtected"] = False
    b["accessTokenLifespan"] = 86400
    b["clients"][0]["directAccessGrantsEnabled"] = True
    b["clients"][0]["secret"] = "portal-secret-ROTATED-456"
    b["clients"][1]["enabled"] = False
    b["clients"].append({"clientId": "shadow-sync", "enabled": True,
                         "publicClient": True, "protocol": "openid-connect"})
    del b["roles"]["realm"][0]            # 删 admin 角色
    b["users"] = [u for u in b["users"] if u["username"] != "bob"]
    pb = _mk(tmp, "b.json", b)

    # I6 空差异
    rc, out = run_cli(["diff", pa, pa])
    check("I6 相同档案 CLEAN rc=0", rc == 0 and "CLEAN" in out and "+ 0 added" in out)

    # I2 档案零改动
    ma, mb = os.stat(pa).st_mtime_ns, os.stat(pb).st_mtime_ns
    sa, sb = sha256_file(pa), sha256_file(pb)
    rc, out = run_cli(["diff", pa, pb])
    check("I2 diff 后档案 sha/mtime 不变",
          sha256_file(pa) == sa and sha256_file(pb) == sb
          and os.stat(pa).st_mtime_ns == ma and os.stat(pb).st_mtime_ns == mb)

    # I4 生命周期必报 + rc=1
    check("I4 生命周期变化 ALERT rc=1",
          rc == 1 and "ALERT" in out and "sslRequired" in out)

    # I1 指纹化：机密新值不出现
    full = out
    rc2, out2 = run_cli(["diff", pa, pb, "--report", os.path.join(tmp, "r1.json")])
    rep_txt = out2 + open(os.path.join(tmp, "r1.json"), encoding="utf-8").read()
    check("I1 机密指纹化(新值不出现)",
          "portal-secret-ROTATED-456" not in rep_txt
          and "portal-secret-ORIGINAL-123" not in rep_txt
          and "redacted len=" in rep_txt)
    check("I1b 控制台同样指纹化",
          "portal-secret-ROTATED" not in full and "alice-pw-xxx" not in full)

    # I3 报告拒绝覆盖 + 0600
    rc3, out3 = run_cli(["diff", pa, pb, "--report", os.path.join(tmp, "r1.json")])
    check("I3 报告已存在默认拒绝 rc=2", rc3 == 2 and "已存在" in out3)
    rc4, _ = run_cli(["diff", pa, pb, "--report", os.path.join(tmp, "r2.json"), "--force"])
    mode = os.stat(os.path.join(tmp, "r2.json")).st_mode & 0o777
    check("I3b --force 覆盖且新报告 0600", rc4 == 1 and mode == 0o600)

    # I5 重命名识别（github-sso → github-oauth，内容一致）
    c = json.loads(json.dumps(a))
    c["identityProviders"][0]["alias"] = "github-oauth"
    pc = _mk(tmp, "c.json", c)
    rc5, out5 = run_cli(["diff", pa, pc])
    check("I5 重命名判 rename 不误报删+增",
          rc5 == 0 and "github-sso" in out5 and "github-oauth" in out5
          and " ⇄ 1 renamed" in out5 and "+ 0 added" in out5)

    # I7 截断档案拒判
    bad = os.path.join(tmp, "bad.json")
    with open(bad, "w", encoding="utf-8") as f:
        f.write('{"realm": "itai", "enabled": tru')
    rc6, out6 = run_cli(["diff", bad, pa])
    check("I7 截断 JSON 拒判 rc=2", rc6 == 2 and "截断" in out6)

    # I8 匿名集合宁报不漏
    d = json.loads(json.dumps(a))
    d["attributes"] = {"someList": [{"z": 1}, {"z": 2}]}
    pe = _mk(tmp, "e.json", d)
    f = json.loads(json.dumps(d))
    f["attributes"]["someList"] = [{"z": 1}, {"z": 3}]
    pf = _mk(tmp, "f.json", f)
    rc7, out7 = run_cli(["diff", pe, pf])
    check("I8 匿名集合按索引+声明口径",
          rc7 == 0 and "匿名集合按索引对比" in out7 and "someList" in out7)

    # I9 台账只写元数据
    led = os.path.join(tmp, "ledger.csv")
    rc8, _ = run_cli(["diff", pa, pb, "--ledger", led])
    led_txt = open(led, encoding="utf-8").read()
    check("I9 台账零字段值", rc8 == 1 and "portal-secret" not in led_txt
          and "sslRequired" not in led_txt and led_txt.count("\n") == 2)
    os.chmod(led, 0o644)
    run_cli(["diff", pa, pb, "--ledger", led])
    check("I9b 台账 append-only 不清史",
          open(led, encoding="utf-8").read().count("\n") == 3)

    # S10 全新安装→加固 15 处变化
    base = _realm_a()
    base["bruteForceProtected"] = False
    base["sslRequired"] = "none"
    pbase = _mk(tmp, "base.json", base)
    hard = json.loads(json.dumps(base))
    hard["bruteForceProtected"] = True
    hard["sslRequired"] = "external"
    hard["accessTokenLifespan"] = 300
    hard["clients"][1]["enabled"] = False
    hard["clients"][1]["directAccessGrantsEnabled"] = False
    hard["clients"][1]["publicClient"] = False
    hard["clients"][1]["standardFlowEnabled"] = False
    hard["clients"][0]["fullScopeAllowed"] = False
    hard["attributes"]["frontendUrl"] = "https://sso.example.com"
    phard = _mk(tmp, "hard.json", hard)
    rc9, out9 = run_cli(["diff", pbase, phard])
    check("S10 加固审计 ALERT+高危计数", rc9 == 1 and out9.count("高危") >= 1)

    # S11 纯外观变化不误报高危
    cos = json.loads(json.dumps(a))
    cos["attributes"]["uiTheme"] = "dark"
    pcos2 = _mk(tmp, "cos2.json", cos)
    rc10, out10 = run_cli(["diff", pa, pcos2])
    check("S11 外观变化 rc=0 无高危", rc10 == 0 and "高危 0" in out10)

    # S12 漂移：新增 client 必现 ALERT 且点名
    rc11, out11 = run_cli(["diff", pa, pb])
    check("S12 新增 client 点名+ALERT", rc11 == 1 and "shadow-sync" in out11)

    # S12b lifespan 类数值字段可读展示（不因含 token 字样被指纹化）
    g = json.loads(json.dumps(a))
    g["accessTokenLifespan"] = 300
    pg = _mk(tmp, "g.json", g)
    rc12, out12 = run_cli(["diff", pa, pg])
    check("S12b lifespan 数值可读不指纹化",
          rc12 == 1 and "900 → 300" in out12 and "访问令牌有效期" in out12)

    # S13 inventory
    rc12, out12 = run_cli(["inventory", pa])
    check("S13 inventory 计数正确", rc12 == 0 and "clients: legacy-app, portal" in out12
          and "机密类字段" in out12)

    # S14 list
    rc13, out13 = run_cli(["list", tmp])
    check("S14 list 清点档案", rc13 == 0 and "共" in out13 and "份档案" in out13)

    shutil.rmtree(tmp, ignore_errors=True)
    fails = [n for n, okk in results if not okk]
    for n, okk in results:
        print(("PASS " if okk else "FAIL ") + n)
    print("selftest: %d/%d" % (len(results) - len(fails), len(results)))
    return 0 if not fails else 1


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        prog="kcfilet", description="Keycloak realm 档案差异解剖刀")
    ap.add_argument("--version", action="version", version="kcfilet " + VERSION)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("diff", help="对比两份档案")
    p1.add_argument("a"), p1.add_argument("b")
    p1.add_argument("--report"), p1.add_argument("--ledger")
    p1.add_argument("--force", action="store_true")
    p1.set_defaults(fn=cmd_diff)

    p2 = sub.add_parser("inventory", help="单份档案体检")
    p2.add_argument("archive")
    p2.add_argument("--report"), p2.add_argument("--force")
    p2.set_defaults(fn=cmd_inventory)

    p3 = sub.add_parser("list", help="清点档案目录")
    p3.add_argument("dir")
    p3.set_defaults(fn=cmd_list)

    p4 = sub.add_parser("selftest", help="不变量自测")
    p4.set_defaults(fn=lambda a: run_selftest())

    args = ap.parse_args()
    try:
        sys.exit(args.fn(args))
    except KeyboardInterrupt:
        sys.exit(2)
    except BrokenPipeError:
        sys.exit(2)


if __name__ == "__main__":
    main()
