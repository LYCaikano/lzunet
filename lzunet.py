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
  - 校园网账号（@lzu.edu.cn）：DOMAIN = ""
  - eLearning 账号（@study）： DOMAIN = "@study"
（"统一认证"标签页走的是 CAS 单点登录 /v1/srun_portal_sso，不适合脚本化；
  两种账号均可通过本脚本的账号认证接口登录。）

用法：
  python3 lzunet.py login     # 登录
  python3 lzunet.py logout    # 注销当前 IP 的在线会话
  python3 lzunet.py status    # 查询在线状态
"""

import hashlib
import hmac as hmac_mod
import json
import sys
import time
import urllib.parse
import urllib.request

# ===================== 配置区 =====================
USERNAME = "your_username"   # 上网账号（不含域后缀）
PASSWORD = "your_password"   # 上网密码
DOMAIN   = ""                # 校园网账号留空；eLearning 账号填 "@study"
AC_ID    = "2"               # 门户 ac_id（10.10.0.166 固定为 2）
AUTH_URL = "http://10.10.0.166"
# ==================================================

ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
_B64STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64MAP = str.maketrans(_B64STD, ALPHA)


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
    url = AUTH_URL + path + "?" + urllib.parse.urlencode(q)
    with urllib.request.urlopen(url, timeout=10) as resp:
        text = resp.read().decode("utf-8", "replace")
    if text.startswith("jQuery(") and text.endswith(")"):
        text = text[len("jQuery("):-1]
    return json.loads(text)


def get_client_ip() -> str:
    res = _get("/cgi-bin/get_challenge", {"username": USERNAME + DOMAIN, "ip": ""})
    return res.get("client_ip") or res.get("online_ip") or ""


def status() -> None:
    res = _get("/cgi-bin/rad_user_info", {})
    if res.get("error") == "ok":
        print(f"在线：{res.get('user_name')}@{res.get('domain')}  "
              f"IP={res.get('online_ip')}  设备数={res.get('online_device_total')}  "
              f"产品={res.get('products_name')}(id={res.get('products_id')},组={res.get('group_id')})  "
              f"已用流量={res.get('sum_bytes', 0) / 2**30:.2f} GiB")
    else:
        print(f"未在线：{res.get('error')} {res.get('error_msg', '')}")
    return res


def login() -> None:
    username = USERNAME + DOMAIN
    ch = _get("/cgi-bin/get_challenge", {"username": username, "ip": ""})
    if ch.get("error") != "ok":
        print("获取 challenge 失败:", ch)
        sys.exit(1)
    token = ch["challenge"]
    ip = ch.get("client_ip") or ch.get("online_ip") or ""

    hmd5 = hmac_mod.new(token.encode(), PASSWORD.encode(), hashlib.md5).hexdigest()
    info = encode_info(
        {"username": username, "password": PASSWORD, "ip": ip,
         "acid": AC_ID, "enc_ver": "srun_bx1"},
        token,
    )
    n, type_ = "200", "1"
    chkstr = (token + username + token + hmd5 + token + AC_ID + token + ip
              + token + n + token + type_ + token + info)
    chksum = hashlib.sha1(chkstr.encode()).hexdigest()

    res = _get("/cgi-bin/srun_portal", {
        "action": "login",
        "username": username,
        "password": "{MD5}" + hmd5,
        "os": "Linux",
        "name": "Linux",
        "double_stack": "0",
        "chksum": chksum,
        "info": info,
        "ac_id": AC_ID,
        "ip": ip,
        "n": n,
        "type": type_,
    })
    print(json.dumps(res, ensure_ascii=False))
    if res.get("error") == "ok" or res.get("suc_msg"):
        print("登录成功")
    elif res.get("error_msg") == "ip_already_online_error":
        print("该 IP 已在线")
    else:
        print("登录失败:", res.get("error"), res.get("ecode"), res.get("error_msg"))
        sys.exit(1)


def logout() -> None:
    """注销。本校门户开启了 MacAuth 无感知认证（CONFIG.portal.MacAuth=true），
    前端此时走 DM 注销 /cgi-bin/rad_user_dm（unbind=1 同时解绑 MAC），
    否则普通的 srun_portal?action=logout 虽返回 ok，会话会被无感知认证立刻重建。
    用户名用裸用户名（不带域后缀），与前端 _logoutDm 一致。"""
    info = status()
    if info.get("error") != "ok":
        return
    ip = info.get("online_ip") or ""
    username = info.get("user_name", USERNAME)  # 裸用户名，不带 @domain
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
    print(json.dumps(res, ensure_ascii=False))
    if res.get("error") == "ok":
        print("注销成功")
    else:
        print("注销失败:", res.get("error"), res.get("error_msg"))
        sys.exit(1)


if __name__ == "__main__":
    if USERNAME.startswith("your_"):
        print("请先编辑脚本顶部配置区填写账号密码")
        sys.exit(2)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    {"login": login, "logout": logout, "status": status}.get(
        cmd, lambda: (print(f"未知命令: {cmd}"), sys.exit(2))
    )()
