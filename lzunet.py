#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lzunet.py — 兰州大学校园网（深澜 Srun Portal，ac_id=2）自动登录/注销脚本
适用于软路由（OpenWrt 等，仅需 Python3 标准库）或任意 Linux 主机。

逆向自 http://10.10.0.166/static/themes/pro/js/Portal.js（2026-09 版本）：
  - GET /cgi-bin/get_challenge           取 challenge token（60 秒有效）
  - GET /cgi-bin/srun_portal?action=login    登录（{MD5}hmac-md5 + {SRBX1}XXTEA + sha1 chksum）
  - GET /cgi-bin/rad_user_dm                 注销（MacAuth 无感知环境下必须用此接口，unbind=1 解绑 MAC）
  - GET /cgi-bin/rad_user_info           查询在线状态

账号类型（页面"账号认证"域下拉框）：
  - 校园网账号（@lzu.edu.cn）：domain = ""
  - eLearning 账号（@study）： domain = "@study"
（"统一认证"标签页走的是 CAS 单点登录 /v1/srun_portal_sso，不适合脚本化；
  两种账号均可通过本脚本的账号认证接口登录。）

多账号（配置在脚本同目录 lzunet.conf.json，见文件内注释/ README）：
  - login：主账号优先，任何失败（密码错、设备数达上限等）随机顺序尝试全部副账号，
    任一成功即停；不改变主副配置。
  - switch <用户名>：把某副账号提升为主账号（参数为裸用户名，不带域后缀）。
    严格先注销后登录：DM 注销并轮询确认真离线（被 MacAuth 无感知认证拉回则重试）→
    登录目标账号 → 成功则重写配置完成提升；失败自动回退原主账号（配置不变）；
    回退也失败则随机尝试其余副账号保住在线（不设为主账号）。

用法：
  python3 lzunet.py login             登录（主账号优先，失败时随机尝试副账号）
  python3 lzunet.py logout            注销当前 IP 的在线会话
  python3 lzunet.py status            查询在线状态
  python3 lzunet.py list              列出已保存账号并标注当前在线账号
  python3 lzunet.py switch <用户名>    把副账号提升为主账号（裸用户名，不带域后缀）
"""

import hashlib
import hmac as hmac_mod
import json
import os
import random
import sys
import time
import urllib.parse
import urllib.request

# ===================== 配置区 =====================
# 账号不在本文件里，在脚本同目录的 lzunet.conf.json（含密码，权限应为 600）：
# {
#   "primary":  {"username": "主账号", "password": "密码"},
#   "backups":  [{"username": "副账号1", "password": "密码"}, ...],
#   "domain":   "",                     可选；校园网账号留空，eLearning 填 "@study"
#   "ac_id":    "2",                    可选；门户 ac_id（10.10.0.166 固定为 2）
#   "auth_url": "http://10.10.0.166"    可选
# }
# username 一律为裸用户名（不带 @study 等后缀），domain 由脚本统一拼接。
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lzunet.conf.json")
DEFAULT_DOMAIN   = ""
DEFAULT_AC_ID    = "2"
DEFAULT_AUTH_URL = "http://10.10.0.166"
# ==================================================

ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
_B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64MAP = str.maketrans(_B64STD, ALPHA)

_CONFIG_SAMPLE = """配置样例（请写入 %s）：
{
  "primary":  {"username": "主账号", "password": "密码"},
  "backups":  [{"username": "副账号1", "password": "密码"}],
  "domain":   "",
  "ac_id":    "2",
  "auth_url": "http://10.10.0.166"
}"""

CFG = None  # load_config() 的缓存，首次 cfg() 时加载


def cfg() -> dict:
    global CFG
    if CFG is None:
        CFG = load_config()
    return CFG


def load_config() -> dict:
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        print(f"缺少配置文件，可从 lzunet.conf.example.json 复制修改。\n"
              + _CONFIG_SAMPLE % CONFIG_PATH)
        sys.exit(2)
    except (json.JSONDecodeError, OSError) as e:
        print(f"配置文件 {CONFIG_PATH} 解析失败: {e}\n" + _CONFIG_SAMPLE % CONFIG_PATH)
        sys.exit(2)
    if not isinstance(raw, dict):
        print(f"配置文件 {CONFIG_PATH} 顶层必须是 JSON 对象")
        sys.exit(2)

    def _check(acc, where):
        if not isinstance(acc, dict) or not acc.get("username") or not acc.get("password"):
            print(f"配置文件 {where} 必须是含非空 username/password 的对象")
            sys.exit(2)
        return {"username": str(acc["username"]), "password": str(acc["password"])}

    if "primary" not in raw:
        print(f"配置文件缺少 primary 账号\n" + _CONFIG_SAMPLE % CONFIG_PATH)
        sys.exit(2)
    backups = raw.get("backups", [])
    if not isinstance(backups, list):
        print("配置文件 backups 必须是数组")
        sys.exit(2)
    return {
        "primary": _check(raw["primary"], "primary"),
        "backups": [_check(a, f"backups[{i}]") for i, a in enumerate(backups)],
        "domain": str(raw.get("domain", DEFAULT_DOMAIN)),
        "ac_id": str(raw.get("ac_id", DEFAULT_AC_ID)),
        "auth_url": str(raw.get("auth_url", DEFAULT_AUTH_URL)).rstrip("/"),
    }


def save_config(c: dict) -> None:
    """原子重写配置文件（switch 提升主账号时调用），权限固定 600。"""
    data = {
        "primary": c["primary"],
        "backups": c["backups"],
        "domain": c["domain"],
        "ac_id": c["ac_id"],
        "auth_url": c["auth_url"],
    }
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)
    global CFG
    CFG = dict(c)


def _xxtea_encode(data: str, key: str) -> bytes:
    """Portal.js _encodeUserInfo 中的 XXTEA 变体（标准 delta，32 位掩码）。"""
    def str_to_longs(s: str, append_len: bool):
        c = len(s)
        v = []
        for i in range(0, c, 4):
            v.append(
                (ord(s[i]) if i < c else 0)
                | ((ord(s[i + 1]) if i + 1 < c else 0) << 8)
                | ((ord(s[i + 2]) if i + 2 < c else 0) << 16)
                | ((ord(s[i + 3]) if i + 3 < c else 0) << 24)
            )
        if append_len:
            v.append(c)
        return v

    if not data:
        return b""
    v = str_to_longs(data, True)
    k = str_to_longs(key, False)
    while len(k) < 4:
        k.append(0)
    n = len(v) - 1
    z = v[n]
    delta = 0x9E3779B9  # 0x86014019|0x183639A0
    q = 6 + 52 // (n + 1)
    d = 0
    while q > 0:
        q -= 1
        d = (d + delta) & 0xFFFFFFFF
        e = (d >> 2) & 3
        for p in range(n):
            y = v[p + 1]
            m = ((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) & 0xFFFFFFFF
            m = (m + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)) ^ (d ^ y))) & 0xFFFFFFFF
            m = (m + (k[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF
            z = v[p] = (v[p] + m) & 0xFFFFFFFF
        y = v[0]
        m = ((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) & 0xFFFFFFFF
        m = (m + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)) ^ (d ^ y))) & 0xFFFFFFFF
        m = (m + (k[(n & 3) ^ e] ^ z)) & 0xFFFFFFFF
        z = v[n] = (v[n] + m) & 0xFFFFFFFF
    out = bytearray()
    for word in v:
        out += bytes((word & 0xFF, (word >> 8) & 0xFF, (word >> 16) & 0xFF, (word >> 24) & 0xFF))
    return bytes(out)


def _b64_custom(raw: bytes) -> str:
    """等价于 $.base64.setAlpha(ALPHA)：标准 base64 后做字母表替换。"""
    import base64
    return base64.b64encode(raw).decode().translate(_B64MAP)


def encode_info(info: dict, token: str) -> str:
    payload = json.dumps(info, separators=(",", ":"), ensure_ascii=False)
    return "{SRBX1}" + _b64_custom(_xxtea_encode(payload, token))


def _get(path: str, params: dict) -> dict:
    """JSONP GET：剥掉 callback(...) 外壳后按 JSON 解析。"""
    q = dict(params)
    q["callback"] = "jQuery"
    q["_"] = int(time.time() * 1000)
    url = cfg()["auth_url"] + path + "?" + urllib.parse.urlencode(q)
    with urllib.request.urlopen(url, timeout=10) as resp:
        text = resp.read().decode("utf-8", "replace")
    if text.startswith("jQuery(") and text.endswith(")"):
        text = text[len("jQuery("):-1]
    return json.loads(text)


def get_client_ip() -> str:
    res = _get("/cgi-bin/get_challenge",
               {"username": cfg()["primary"]["username"] + cfg()["domain"], "ip": ""})
    return res.get("client_ip") or res.get("online_ip") or ""


def _status_raw() -> dict:
    """查询 rad_user_info，原样返回；请求异常时返回 error=request_failed 不抛异常。"""
    try:
        return _get("/cgi-bin/rad_user_info", {})
    except Exception as e:
        return {"error": "request_failed", "error_msg": str(e)}


def status() -> None:
    res = _status_raw()
    if res.get("error") == "ok":
        print(f"在线：{res.get('user_name')}@{res.get('domain')}  "
              f"IP={res.get('online_ip')}  设备数={res.get('online_device_total')}  "
              f"产品={res.get('products_name')}(id={res.get('products_id')},组={res.get('group_id')})  "
              f"已用流量={res.get('sum_bytes', 0) / 2**30:.2f} GiB")
    else:
        print(f"未在线：{res.get('error')} {res.get('error_msg', '')}")
    return res


def _login_attempt(username: str, password: str, strict: bool = False) -> tuple[bool, str]:
    """用指定账号登录一次。返回 (是否成功, 描述)。
    strict=True 时 ip_already_online_error 视为失败（switch 流程要求确定性，
    防止上游旧会话未刷新造成"假成功"）。"""
    c = cfg()
    user = username + c["domain"]
    ac_id = c["ac_id"]
    try:
        ch = _get("/cgi-bin/get_challenge", {"username": user, "ip": ""})
        if ch.get("error") != "ok":
            return False, f"获取 challenge 失败: {ch}"
        token = ch["challenge"]
        ip = ch.get("client_ip") or ch.get("online_ip") or ""

        hmd5 = hmac_mod.new(token.encode(), password.encode(), hashlib.md5).hexdigest()
        info = encode_info(
            {"username": user, "password": password, "ip": ip,
             "acid": ac_id, "enc_ver": "srun_bx1"},
            token,
        )
        n, type_ = "200", "1"
        chkstr = (token + user + token + hmd5 + token + ac_id + token + ip
                  + token + n + token + type_ + token + info)
        chksum = hashlib.sha1(chkstr.encode()).hexdigest()

        res = _get("/cgi-bin/srun_portal", {
            "action": "login",
            "username": user,
            "password": "{MD5}" + hmd5,
            "os": "Linux",
            "name": "Linux",
            "double_stack": "0",
            "chksum": chksum,
            "info": info,
            "ac_id": ac_id,
            "ip": ip,
            "n": n,
            "type": type_,
        })
    except Exception as e:
        return False, f"{username} 登录请求异常: {e}"
    if res.get("error") == "ok" or res.get("suc_msg"):
        return True, f"{username} 登录成功"
    if res.get("error_msg") == "ip_already_online_error":
        if strict:
            return False, f"{username} 登录失败: ip_already_online_error（上游旧会话未刷新）"
        return True, f"{username}: 该 IP 已在线"
    return False, f"{username} 登录失败: {res.get('error')} {res.get('ecode')} {res.get('error_msg')}"


def _wait_offline(timeout: float = 10.0) -> bool:
    """轮询 rad_user_info 直到确认不在线（防 MacAuth 无感知认证毫秒级拉回）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _status_raw().get("error") != "ok":
            return True
        time.sleep(2)
    return _status_raw().get("error") != "ok"


def _verify_online_as(username: str, tries: int = 3) -> bool:
    """登录后确认在线身份确实是 username（裸用户名），防上游刷新延迟造成假成功。"""
    for _ in range(tries):
        info = _status_raw()
        if info.get("error") == "ok" and info.get("user_name") == username:
            return True
        time.sleep(2)
    return False


def _logout_dm() -> tuple[bool, str]:
    """DM 注销当前会话。返回 (是否成功, 描述)。
    本校门户开启了 MacAuth 无感知认证（CONFIG.portal.MacAuth=true），
    前端此时走 DM 注销 /cgi-bin/rad_user_dm（unbind=1 同时解绑 MAC），
    否则普通的 srun_portal?action=logout 虽返回 ok，会话会被无感知认证立刻重建。
    用户名用裸用户名（不带域后缀），与前端 _logoutDm 一致。"""
    info = _status_raw()
    if info.get("error") != "ok":
        return True, "当前不在线，无需注销"
    ip = info.get("online_ip") or ""
    username = info.get("user_name") or cfg()["primary"]["username"]  # 裸用户名，不带 @domain
    ts = str(int(time.time()))
    unbind = "1"
    sign = hashlib.sha1((ts + username + ip + unbind + ts).encode()).hexdigest()
    res = _get("/cgi-bin/rad_user_dm", {
        "ip": ip,
        "username": username,
        "time": ts,
        "unbind": unbind,
        "sign": sign,
    })
    if res.get("error") == "ok":
        return True, f"注销成功（{username}）"
    return False, f"注销失败: {res.get('error')} {res.get('error_msg')}"


def _logout_until_offline(max_tries: int = 3) -> bool:
    """DM 注销并实测确认真离线；被无感知认证瞬间拉回则重试。返回是否已确认离线。"""
    for i in range(1, max_tries + 1):
        ok, msg = _logout_dm()
        print(msg)
        if not ok:
            continue
        if _wait_offline():
            return True
        print(f"注销后会话仍在线（可能被无感知认证拉回），重试 ({i}/{max_tries})...")
    return False


def login() -> None:
    """主账号优先；主账号任何失败（密码错、设备数达上限等）随机顺序尝试副账号，
    任一成功即停止。不改动主副配置。"""
    c = cfg()
    ok, msg = _login_attempt(c["primary"]["username"], c["primary"]["password"])
    print(msg)
    if ok:
        return
    backups = list(c["backups"])
    if not backups:
        print("无可用副账号，登录失败")
        sys.exit(1)
    print("主账号登录失败，尝试副账号...")
    random.shuffle(backups)
    for acc in backups:
        ok, msg = _login_attempt(acc["username"], acc["password"])
        print(msg)
        if ok:
            return
    print("所有账号均登录失败")
    sys.exit(1)


def logout() -> None:
    ok, msg = _logout_dm()
    print(msg)
    if not ok:
        sys.exit(1)


def list_accounts() -> None:
    """列出已保存账号（密码打码），并标注当前在线账号。"""
    c = cfg()
    info = _status_raw()
    online_user = info.get("user_name") if info.get("error") == "ok" else None

    def show(tag, acc):
        pw = acc["password"]
        masked = (pw[:2] + "*" * max(len(pw) - 3, 4) + pw[-1:]) if len(pw) > 2 else "***"
        mark = "  ← 当前在线" if acc["username"] == online_user else ""
        print(f"[{tag}] {acc['username']}  {masked}{mark}")

    show("主", c["primary"])
    for acc in c["backups"]:
        show("副", acc)
    if not c["backups"]:
        print("（无副账号）")
    if online_user is None:
        print("当前不在线")


def _login_and_verify(username: str, password: str) -> bool:
    """switch 专用：strict 登录 + 核实在线身份，打印结果。"""
    ok, msg = _login_attempt(username, password, strict=True)
    print(msg)
    if not ok:
        return False
    if _verify_online_as(username):
        return True
    print(f"{username} 登录返回成功，但在线身份未确认为该账号（上游刷新延迟或会话异常）")
    return False


def switch(target: str) -> None:
    """把副账号 target 提升为主账号。严格先注销后登录：
    注销并确认真离线 → 登录目标账号 → 成功则持久化主副调换；
    失败回退原主账号；回退也失败则随机尝试其余副账号（不设为主账号）。"""
    c = cfg()
    old = c["primary"]
    backups = c["backups"]
    if target == old["username"]:
        print(f"{target} 已是主账号，执行登录确保在线...")
        ok, msg = _login_attempt(old["username"], old["password"])
        print(msg)
        sys.exit(0 if ok else 1)
    new = next((a for a in backups if a["username"] == target), None)
    if new is None:
        print(f"未找到已保存账号: {target}（参数为裸用户名、不带域后缀；用 list 查看已保存账号）")
        sys.exit(2)

    print(f"切换主账号: {old['username']} → {target}")
    # 1. 先注销旧会话（DM + unbind=1），并轮询确认真离线——
    #    防无感知认证"看似退出实际毫秒级重认证"，旧会话没退干净绝不登新账号。
    if not _logout_until_offline():
        print("无法确认旧会话已注销（可能被无感知认证持续拉回），中止切换，配置未改动")
        sys.exit(1)

    # 2. 登录目标账号，成功则持久化：目标升主、原主转副
    if _login_and_verify(new["username"], new["password"]):
        c["primary"] = new
        c["backups"] = [old] + [a for a in backups if a["username"] != target]
        save_config(c)
        print(f"切换成功：{target} 已设为主账号，{old['username']} 转为副账号")
        status()
        return

    # 3. 回退原主账号（配置不变）
    print(f"切换失败，回退原主账号 {old['username']}...")
    if _login_and_verify(old["username"], old["password"]):
        print("已回退，主账号配置未改动")
        sys.exit(1)

    # 4. 回退也失败：随机尝试其余副账号保住在线（不设为主账号）
    rest = [a for a in backups if a["username"] not in (target, old["username"])]
    if rest:
        print("回退失败，尝试其余备用账号（不设为主账号）...")
        random.shuffle(rest)
        for acc in rest:
            if _login_and_verify(acc["username"], acc["password"]):
                print(f"当前以副账号 {acc['username']} 在线；主账号配置未改动")
                sys.exit(1)
    print("所有账号均登录失败，当前离线")
    sys.exit(1)


USAGE = """用法:
  python3 lzunet.py login             登录（主账号优先，失败时随机尝试副账号）
  python3 lzunet.py logout            注销当前 IP 的在线会话
  python3 lzunet.py status            查询在线状态
  python3 lzunet.py list              列出已保存账号并标注当前在线账号
  python3 lzunet.py switch <用户名>    把副账号提升为主账号（裸用户名，不带域后缀）"""

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "switch":
        if len(sys.argv) < 3:
            print(USAGE)
            sys.exit(2)
        switch(sys.argv[2])
    elif cmd in ("login", "logout", "status"):
        {"login": login, "logout": logout, "status": status}[cmd]()
    elif cmd == "list":
        list_accounts()
    else:
        print(f"未知命令: {cmd}\n{USAGE}")
        sys.exit(2)
