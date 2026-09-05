#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lzuself.py — 兰州大学自助服务平台（https://login.lzu.edu.cn:8800）信息查询脚本。

登录方式（逆向自 Portal.js toSelfService，免验证码）：
  GET /site/sso?data=base64("zh-CN:{用户名}:{md5(密码)}")
  （已在线时也可只传 base64("zh-CN:{用户名}")；标准 Base64 字母表）

用法：
  python3 lzuself.py            # 全部信息
  python3 lzuself.py user       # 用户信息（姓名/状态/钱包）
  python3 lzuself.py online     # 在线设备（IP/上线时间/产品/下线ID）
  python3 lzuself.py mac        # 无感知认证 MAC 绑定列表
  python3 lzuself.py log [N]    # 最近 N 条上网明细（默认 10）

注意：写操作（下线 /home/delete、解绑 /user/delete-mac-auth、锁定 /user/lock-mac、
开关无感知 /user/open、增加 MAC POST /user/mac-auth）均为 POST 且需 _csrf-8800，
本脚本只做只读查询，写接口参数见 README.md。
"""

import base64
import hashlib
import html
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request

# ===================== 配置区 =====================
USERNAME = "your_username"   # 上网账号（不含域后缀）
PASSWORD = "your_password"   # 上网密码
# ==================================================

BASE = "https://login.lzu.edu.cn:8800"

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE  # 校内自签证书


def make_session() -> urllib.request.OpenerDirector:
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=_CTX),
    )


def sso_login(opener) -> None:
    data = base64.b64encode(
        f"zh-CN:{USERNAME}:{hashlib.md5(PASSWORD.encode()).hexdigest()}".encode()
    ).decode()
    resp = opener.open(BASE + "/site/sso?data=" + urllib.parse.quote(data), timeout=10)
    page = resp.read().decode("utf-8", "replace")
    if "退出" not in page and "/site/logout" not in page:
        print("自助服务 SSO 登录失败（检查账号密码）")
        sys.exit(1)


def _text_lines(page: str):
    page = re.sub(r"<(script|style)[\s\S]*?</\1>", "", page)
    txt = re.sub(r"<[^>]+>", "\n", page)
    return [l.strip() for l in html.unescape(txt).splitlines() if l.strip()]


def show_user(page: str) -> None:
    lines = _text_lines(page)
    try:
        i = lines.index("用户信息")
        j = lines.index("在线信息")
    except ValueError:
        print("用户信息解析失败")
        return
    seg = lines[i + 1:j]
    print("== 用户信息 ==")
    for k in range(0, len(seg) - 1, 2):
        print(f"  {seg[k]}: {seg[k + 1]}")


def show_online(page: str) -> None:
    rows = re.findall(
        r'data-key="(\d+)">.*?'                       # rad_online_id
        r'data-col-seq="0">([^<]*)</td>.*?'           # 用户名
        r'data-col-seq="1">([^<]*)</td>.*?'           # IP
        r'data-col-seq="3">([^<]*)</td>.*?'           # 上线时间
        r'data-col-seq="10">([^<]*)</td>',            # 产品名称
        page, re.S)
    print("== 在线设备 ==")
    for rid, user, ip, since, product in rows:
        print(f"  {user}  {ip:<16}  {since}  {product}  (id={rid})")
    if not rows:
        print("  (无在线设备或解析失败)")


def show_mac(page: str) -> None:
    print("== 无感知认证 MAC 绑定 ==")
    toggle = "开启" if re.search(r"无感知认证<span[^>]*>开启", page) else "关闭/未知"
    print(f"  无感知认证总开关: {toggle}")
    for mac in re.findall(r'delete-mac-auth\?mac=([0-9a-fA-F%3A]+)', page):
        print(" ", urllib.parse.unquote(mac))


def show_log(page: str, n: int) -> None:
    print(f"== 上网明细（最近 {n} 条）==")
    # 明细表格无 col-seq，直接按行解析
    rows = re.findall(r"<tr[^>]*data-key[^>]*>([\s\S]*?)</tr>", page)
    for row in rows[:n]:
        cells = [html.unescape(re.sub(r"<[^>]+>", "", c)).strip()
                 for c in re.findall(r"<td[^>]*>([\s\S]*?)</td>", row)]
        cells = [c for c in cells if c]
        if len(cells) >= 6:
            print("  " + "  ".join(cells[:8]))


def main() -> None:
    if USERNAME.startswith("your_"):
        print("请先编辑脚本顶部配置区填写账号密码")
        sys.exit(2)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    opener = make_session()
    sso_login(opener)
    home = opener.open(BASE + "/home", timeout=10).read().decode("utf-8", "replace")

    if cmd in ("all", "user"):
        show_user(home)
    if cmd in ("all", "online"):
        show_online(home)
    if cmd in ("all", "mac"):
        mac_page = opener.open(BASE + "/user/mac-auth", timeout=10).read().decode("utf-8", "replace")
        show_mac(mac_page)
    if cmd in ("all", "log"):
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 10
        log_page = opener.open(BASE + "/log/detail", timeout=10).read().decode("utf-8", "replace")
        show_log(log_page, n)


if __name__ == "__main__":
    main()
