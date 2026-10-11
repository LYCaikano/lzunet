# LZU 校园网认证接口逆向（深澜 Srun Portal）

目标：`http://10.10.0.166/`（兰州大学，SRunCGIAuthIntfSvr V1.18，sysver 1.01.20260715）
逆向来源：`/static/themes/pro/js/Portal.js`（登录/注销逻辑）、`all.min.js`（md5/sha1 库）。

## 账号类型

门户"账号认证"页有两种账号，**走同一个接口**，仅用户名后缀不同：

| 账号类型 | 域后缀 | 登录用户名 |
|---|---|---|
| 校园网账号（页面标注 @lzu.edu.cn，实际域为 `ilzu`） | 空 | `用户名` |
| eLearning 账号（@study） | `@study` | `用户名@study` |

实测域后缀（rad_user_info 的 `domain` 字段）：账号认证登录后为 `@ilzu`；
无感知 MAC 认证会话为 `@maci`。页面上的"@lzu.edu.cn"只是显示标签。

（页面上的"统一认证"标签页是 CAS 单点登录 `/v1/srun_portal_sso`，需浏览器交互，不适合路由器脚本化；
两种账号均可通过本脚本的账号认证接口登录。）

## 接口一览

### 1. 查询在线状态（只读）
```
GET /cgi-bin/rad_user_info?callback=jQuery
```
在线返回 `error:"ok"` + 账号/IP/流量/在线设备等；未在线返回 `error:"not_online_error"`。

### 2. 获取 challenge（登录第一步，只读）
```
GET /cgi-bin/get_challenge?callback=jQuery&username={用户名}&ip=
```
返回 `challenge`（60 秒有效）和 `client_ip`（本机校园网 IP，后续参数以它为准）。

### 3. 登录
```
GET /cgi-bin/srun_portal?callback=jQuery&action=login
    &username={用户名}
    &password={MD5}{hmd5}
    &os=Linux&name=Linux&double_stack=0
    &chksum={sha1}
    &info={SRBX1}{...}
    &ac_id=2&ip={client_ip}&n=200&type=1
```
参数构造（顺序敏感）：
- `hmd5` = HMAC-MD5(key=challenge, msg=密码) 的 hex
- `info` = JSON `{"username":..,"password":..,"ip":..,"acid":"2","enc_ver":"srun_bx1"}`
  经 XXTEA 加密（key=challenge，标准 delta 0x9E3779B9，长度前缀附加在尾部）→
  base64（自定义字母表 `LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA`）→ 加前缀 `{SRBX1}`
- `chksum` = SHA1(`token+username + token+hmd5 + token+"2" + token+ip + token+"200" + token+"1" + token+info`)

成功：`{"error":"ok","suc_msg":...}`；已在线：`ip_already_online_error`。
验证码默认不启用（`/v2/srun_portal_captcha_image_info` 返回 `data:"0"`），脚本无需处理。

### 4. 注销（注意：必须用 DM 注销）

本校门户开启了 **MacAuth 无感知认证**（页面配置 `MacAuth:true`），普通注销接口
`GET /cgi-bin/srun_portal?action=logout&username=...&ip=...&ac_id=2` 虽然返回
`error:"ok"`，但会话会被无感知认证立刻重建（流量计数清零、add_time 刷新），
**实际踢不掉**。前端此时改走 DM 注销：

```
GET /cgi-bin/rad_user_dm?callback=jQuery
    &ip={在线IP}&username={裸用户名，不带域后缀}
    &time={unix秒}&unbind=1
    &sign=SHA1({time}{username}{ip}1{time})
```
`unbind=1` 同时解绑 MAC，注销后不会被自动重登。成功返回 `error:"ok"`。

## 使用

`lzunet.py`：纯 Python3 标准库实现。账号配置在脚本同目录的 `lzunet.conf.json`
（含密码，权限应为 600，已被 .gitignore 忽略；仓库附带样例 `lzunet.conf.example.json`，
复制改名后填账号即可。`username` 一律为裸用户名，不带域后缀）：

```json
{
  "primary":  {"username": "主账号", "password": "密码"},
  "backups":  [{"username": "副账号1", "password": "密码"}],
  "domain":   "",
  "ac_id":    "2",
  "auth_url": "http://10.10.0.166"
}
```

`primary` 必填，`backups` 可为空数组；`domain/ac_id/auth_url` 可省略（默认
校园网域空、ac_id=2、http://10.10.0.166）。

```sh
python3 lzunet.py login             # 登录：主账号优先，任何失败随机尝试全部副账号
python3 lzunet.py logout            # 注销（DM + unbind=1）
python3 lzunet.py status            # 查在线状态
python3 lzunet.py list              # 列出已保存账号（密码打码），标注当前在线账号
python3 lzunet.py switch <用户名>    # 把副账号提升为主账号（裸用户名，不带后缀）
```

**故障转移（login）**：主账号登录失败（密码错、在线设备数达上限等任何原因）→
随机顺序尝试全部副账号，任一成功即停；不改动主副配置。

**切换主账号（switch）**：严格**先注销后登录**——

1. DM 注销当前会话（`unbind=1`）并轮询 `rad_user_info` 确认真离线；若被
   MacAuth 无感知认证毫秒级拉回则重试注销（≤3 次），仍在线则中止切换、不碰登录
   （杜绝旧会话没退干净就登新账号导致的上游串号/回退失败）。
2. 登录目标账号（`ip_already_online_error` 此时算失败），并核实在线身份确为目标账号；
   成功则原子重写 `lzunet.conf.json`：目标升为主账号，原主账号转为副账号。
3. 目标登录失败 → 自动回退原主账号（配置不变）。
4. 回退也失败 → 随机尝试其余备用账号保住在线（**不设为主账号**）。

部署到路由时 `lzunet.py` 与 `lzunet.conf.json` 必须放同一目录。

OpenWrt 软路由：`opkg install python3`（x86 软路由直接可用），把两个文件放到
`/etc/`（或 `/opt/lzunet/`），再配 cron 保活，例如每 5 分钟检测、掉线自动重登：

```cron
*/5 * * * * /usr/bin/python3 /etc/lzunet.py status | grep -q 未在线 && /usr/bin/python3 /etc/lzunet.py login
```

## 自助服务平台（login.lzu.edu.cn:8800）

深澜自助服务系统（Yii/PHP，v5.2.4）。网页登录 `/login` 有验证码，**免验证码 SSO 通道**
（逆向自 Portal.js `toSelfService`）：

```
GET https://login.lzu.edu.cn:8800/site/sso?data={std_base64("zh-CN:用户名:md5(密码)")}
→ 302 到 /home，Set-Cookie: PHPSESSID_8800（后续请求带 cookie 即可）
```

主要接口（只读 GET 可直接用；写操作均为 POST 且需 `_csrf-8800` token，
取自任意页面的 `<meta name="csrf-token">`）：

| 路径 | 方法 | 功能 |
|---|---|---|
| /home | GET | 用户信息（姓名/状态/钱包）+ 在线设备表（含 rad_online_id、产品名） |
| /home/delete?id={rad_online_id}&user_mac={mac} | POST | 指定会话下线 |
| /home/manual-open | POST | 手动开通（返回 JSON {success,message}） |
| /user/mac-auth | GET | 无感知认证 MAC 绑定列表 |
| /user/mac-auth | POST | 增加 MAC 绑定 / 编辑备注（表单字段见页面） |
| /user/delete-mac-auth?mac={mac} | POST | 解绑无感知 MAC |
| /user/lock-mac?mac={mac}&device= | POST | 锁定绑定 |
| /user/open | GET | 无感知认证总开关切换 |
| /log/detail | GET | 上网明细（上线/下线时间、MAC、IP、流量、时长），支持 CSV/TEXT/EXCEL 导出 |
| /site/logout | POST | 退出自助服务 |

`lzuself.py` 为只读查询实现：`python3 lzuself.py [user|online|mac|log [N]]`。

## 账号在线数配额（实测）

- 普通上网账号：**3** 个并发会话；eLearning（@study）：**1** 个；合计 4。
- 按**接入位置（NAS）**映射域和产品，与账号后缀无关：账号认证会话 宿舍区→`@ilzu`/学生校园(id=9)、
  办公区→`@office`/学生办公(id=12)；MAC 无感知会话则对应 `@maci`（宿舍）/`@maco`（办公）。
- 办公区用普通账号登录**仍占用普通账号的 3 个名额**（产品变成"学生办公"，但配额按账号类型算）。

## 验证记录（2026-09-05）

- 假账号完整登录请求 → 服务器返回 `E2531: User not found`（账号级错误），
  证明 chksum/info 解密校验全部通过，协议实现正确。
- 真实账号端到端实测通过：`rad_user_dm` 注销 → `not_online_error`（不再被
  无感知认证拉回）→ 账号登录 → `E0000: Login is successful` → 恢复在线。
- 注意：`srun_portal?action=logout` 返回 ok 但无效（MacAuth 秒级重连），
  必须用 `rad_user_dm` + `unbind=1`。
