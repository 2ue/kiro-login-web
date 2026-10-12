# Kiro Login Web

独立批量登录站点：粘贴 AWS IAM Identity Center / 学生号 / Microsoft 365 / Gmail / GitHub 账号，后端用 Playwright（社交登录用 Camoufox）无头登录 Kiro，自动处理 MFA、检查可用性、按需开通 API Key，导出扁平 JSON 或 API Key 清单。

当前版本 **1.0.13**（含未发布的登录后改密 / 2FA 能力）。变更记录见 [CHANGELOG.md](CHANGELOG.md)。

## 功能

- **五种登录方式**
  - AWS IAM Identity Center（IDC）设备码
  - Kiro 学生号（AWS Builder ID 设备码 + 大学 Outlook 邮箱验证码）
  - Microsoft 365 / Entra ID 组织 SSO（OAuth auth-code + PKCE + 本地回环回调）
  - Gmail / Google 个人号（Kiro 门户社交登录）
  - GitHub 个人号
- **MFA 自动处理**：绑定 TOTP、复用已有密钥；已绑定 MFA 但无预设密钥时秒退并给出准确提示
- **凭据导出**：总 JSON、按数量拆分的 ZIP、API Key 清单、MFA 密钥、账号密码、任务日志
- **API Key 开通**：登录时同步开通，或上传已有 JSON ZIP 只开通 Key
- **登录后改密 / 2FA**：独立页面 `/security`，和获取 JSON 分开。登录 IDC / 学生号 / GitHub 个人号后到对应账号设置改密码和/或设置 2FA，不导出 token。可只改密码、只改 2FA，或两项一起改。学生号改 AWS Builder ID 密码（PASS AWS），Outlook 不动；GitHub 直接进入 GitHub 安全设置替换 Authenticator app
- **密码模式**：固定新密码 / 每号随机；密码中的全角符号可转半角。登录任务只在首次强制改密时写入；改密页勾选「修改密码」时会改每个已能登录的号；只改 2FA 时不必填新密码。改密会先把目标新密码写入台账，成功或失败后再更新状态
- **客户空间隔离**：按客户密码隔离任务、日志、下载文件
- **代理池**：粘贴一批代理轮流分配；可按客户持久化保存
- **防风控换 IP**：撞 captcha / 代理报错时自动换出口
  - 本机配了 mihomo → 切节点换 IP
  - 无 mihomo 但有代理池 → 在池内轮换到不同代理
- **排队调度**：超并发上限的任务自动排队，有容量时 FIFO 启动
- **自定义数据保留**：导出文件 / 日志默认保留 24 小时，可按任务在 5 分钟 ~ 7 天间自定义，过期自动删除
- **格式转换页** `/convert`：把各种 IDC 文本块转成可粘贴的标准账号行

## 目录结构

```text
kiro-login-web/
├── app.py                          # Flask 入口：任务调度、解析账号、导出、客户登录
├── run.sh                          # 用 .venv 启动 app.py
├── requirements.txt
├── customers.example.json          # 预置客户配置样例（复制为 customers.json）
├── kiro-login-web.service.example  # systemd 单元样例
├── CHANGELOG.md
│
├── device_code_auth.py             # AWS SSO OIDC 设备码（RegisterClient / CreateToken / ListProfiles）
├── idc_browser_login.py            # IDC 浏览器填表、改密、MFA
├── builder_id_browser_login.py     # 学生号 / Builder ID 浏览器流程
├── outlook_otp.py                  # Graph 读取 Outlook 里的 AWS 6 位验证码
├── m365_sso_login.py               # M365 SSO 编排（PKCE + 回环回调 + 换 token）
├── m365_browser_login.py           # M365 浏览器填邮箱/密码/MFA
├── google_browser_login.py         # Google 个人号浏览器流程
├── github_browser_login.py         # GitHub 个人号浏览器流程
├── stealth_browser.py              # Camoufox / Firefox 反检测启动
├── mfa_totp.py                     # TOTP 计算、从页面抠 MFA 密钥
├── proxy_util.py                   # 代理字符串规范化（含 ip:port:user:pass）
├── mihomo_controller.py            # mihomo 切节点换出口 IP
│
├── templates/
│   ├── login.html                  # 客户密码入口
│   ├── index.html                  # 主工作台（获取 JSON）
│   ├── security.html               # 登录后改密 / 2FA
│   └── converter.html              # IDC 格式转换
│
├── data/                           # 运行时：任务历史 job_history.json
├── exports/                        # 运行时：按客户隔离的导出文件
├── logs/                           # 运行时：app.log（2MB × 5 份轮转）
├── debug_mfa/                      # 运行时自动生成：IDC/M365/学生号调试截图
└── debug_social/                   # 运行时自动生成：Google/GitHub 调试截图
```

运行时还会在项目根生成 `.flask-secret`（session 密钥）和 `customers.json`（客户哈希）。不要提交这两个文件。

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
python -m camoufox fetch
```

Google / GitHub 个人号依赖 Camoufox（Firefox 反检测内核）和 Xvfb。Debian / Ubuntu：

```bash
sudo apt-get install -y libgtk-3-0 xvfb
```

依赖：`Flask>=3.0.0`、`playwright>=1.40.0`、`pyotp>=2.9.0`、`camoufox[geoip]>=0.4.11`。

## 启动

推荐用项目自带虚拟环境和脚本：

```bash
./run.sh
```

等价于：

```bash
.venv/bin/python app.py --host 0.0.0.0 --port 7888
```

浏览器访问：

```text
http://你的公网IP:7888
```

默认已支持 HTTP/IP 登录：监听 `0.0.0.0`，session cookie 使用 `KIRO_LOGIN_COOKIE_SECURE=auto`（HTTP 不加 `Secure`，HTTPS 自动加）。放到只允许 HTTPS 的反向代理后，可设 `KIRO_LOGIN_COOKIE_SECURE=true`。

也可下载 [Releases](https://github.com/TWLW9784/kiro-login-web/releases) 里对应平台的单文件可执行程序，免装 Python。打 tag `v*` 会走 GitHub Actions 用 PyInstaller 打包 linux / windows / macos。

### systemd（可选）

```bash
sudo cp kiro-login-web.service.example /etc/systemd/system/kiro-login-web.service
# 把 WorkingDirectory / ExecStart 改成实际路径，例如 /root/kiro-login-web
sudo systemctl daemon-reload
sudo systemctl enable --now kiro-login-web
```

## 客户密码隔离

网站入口会强制要求输入客户专属密码。不同密码对应不同客户空间，任务、日志、下载文件都按客户隔离。

- 密码已存在：直接进入对应空间，按 `customers.json` 原样匹配，不再检查强度。
- 密码第一次使用：自动创建新客户空间，可填客户名称；新建时密码至少 8 位，且同时包含大写、小写和数字。
- 新自助客户只存 `passwordHash`（PBKDF2-SHA256）与登录查找索引 `lookupHash`，不保存明文。

登录先用 `lookupHash`（HMAC-SHA256，密钥派生自 Flask secret）O(1) 定位候选，再做 PBKDF2 校验。客户数再多也是毫秒级。老数据首次登录会自动补写索引。

也可以预先编辑 `customers.json` 固定客户（可从 `customers.example.json` 复制）：

```json
{
  "customer-a": { "name": "客户A", "password": "明文（首次登录后会自动转 hash）" },
  "customer-b": { "name": "客户B", "passwordHash": "pbkdf2_sha256$..." }
}
```

公网 IP 直连时，建议先放一个自己知道的固定密码，再打开 `http://你的公网IP:7888`。

## 登录方式与账号格式

页面默认**自动识别**。`|` 和 `----` 都是字段分隔符，IDC / M365 / Google / GitHub / 学生号通用。

```text
user@example.com|Password123
user@example.com----Password123----MFASECRET
```

学生号选择「Kiro 学生号」时，一行三个字段：学校邮箱、Outlook 密码、AWS Builder ID 密码。两种分隔符等价，可和标签块、TYPE 块混贴。登录后改密改的是第三段 AWS 密码，也可只改 2FA：

```text
student@university.edu|Outlook密码|AWS密码
student@university.edu----Outlook密码----AWS密码

MAIL: student@university.edu
PASS MAIL: Outlook密码
PASS AWS: AWS密码

TYPE: STUDENT
LOGIN: student@university.edu
MAIL_PASSWORD: Outlook密码
PASSWORD: AWS密码
```

TYPE 块只从带 `TYPE:` 的段落里取，不会盖掉同一段文本里的 `|` / `----` 行。`MFA_SECRET` 可省略。

IDC 仍可用每行自带 Start URL 的管道格式，或单独填全局 Start URL。

### Microsoft 365 组织 SSO

无需 Start URL。门户自动做 home realm discovery。账号一般是 `email:password`，可带 TOTP / 代理。

### Gmail / GitHub 个人号

无需 Start URL。默认 Camoufox（Xvfb + Windows 指纹 + 拟人输入），启动失败回退 Playwright Firefox。Google 对机房 IP 仍可能弹出 reCAPTCHA，建议挂住宅 / 移动代理。

GitHub 个人号在 `/security` 页面还支持登录后改密 / 更换 TOTP。账号格式仍是：

```text
github@example.com|GitHubPassword123|CURRENT_TOTP_SECRET
```

改 GitHub 密码时，新密码会写入独立密码台账；更换 GitHub Authenticator app 时，新 TOTP secret 会即时写入 MFA 文件。若 GitHub 登录要求已有 2FA，必须提供当前 TOTP secret。

## 导出字段

扁平 JSON，字段随登录方式略有不同：

| 场景 | 字段 |
| --- | --- |
| 通用 | `email / idp / profileArn / machineId / priority / status / accessToken / refreshToken / clientId / region / expiresAt` |
| IDC | 额外 `clientSecret / startUrl` |
| 学生号 / Builder ID | `authMethod=builder-id`、`provider=BuilderId`、`idp=Personal`，带 `clientSecret / startUrl` |
| M365 / external_idp | `authMethod=external_idp`、额外 `issuer_url / token_endpoint / scopes`，无 `clientSecret`（public client + PKCE） |

下载入口：总 JSON、拆分 ZIP、API Key、账号密码、MFA 密钥、任务日志。任务结束后页面会列出失败账号。

## 代理与防风控

在「更多配置 → 代理池」粘贴代理（每行一个），轮流分配给未单独指定代理的账号。勾选「保存代理池」会写进该客户配置。

支持：

```text
http://user:pass@1.2.3.4:8080
https://host:port
socks5://host:port
1.2.3.4:8080
1.2.3.4:8080:user:pass
user:pass:1.2.3.4:8080
```

`ip:port:username:password` 会规范成 `http://user:pass@host:port`，Playwright 启动时把账密拆到 `username` / `password`。

机房代理下并发越高越容易撞 captcha，默认并行数为 2；挂住宅 / 移动代理可适当调高。单任务最多 10 线程，全局浏览器槽位 20，单任务最多 50 个账号。超限任务进入队列，不直接拒绝。

撞 captcha / 代理连接失败时自动换 IP 重试。Builder ID 密码页的 `Security check` / Arkose 也按 captcha 处理。

用户填写的代理禁止指向回环 / 内网。管理员可用 `KIRO_DEFAULT_PROXY` 配本机 mihomo（例如 `http://127.0.0.1:7890`）。

## 数据保留与运行时目录

导出 JSON / API Key / MFA / 账号密码 / 日志默认保留 **24 小时**，可在「更多配置 → 账号数据保留时长」按任务自定义（5 分钟 ~ 7 天）。过期自动删除、下载链接失效。含明文密码 / MFA 密钥，请及时下载。

| 路径 | 作用 |
| --- | --- |
| `data/job_history.json` | 任务历史（重启后可恢复未过期任务） |
| `exports/c_<客户id>/` | 该客户的 JSON / ZIP / 日志等 |
| `logs/app.log` | 业务审计日志 |
| `debug_mfa/`、`debug_social/` | 登录失败排查截图，运行时自动创建 |

## 页面与接口

| 路径 | 说明 |
| --- | --- |
| `GET/POST /login` `POST /logout` | 客户密码入口 |
| `GET /` | 主工作台 |
| `GET /convert` | IDC 账号格式转换 |
| `POST /api/jobs` | 提交登录任务（获取 JSON） |
| `POST /api/change-password` | 提交登录后改密 / 2FA（不导出 JSON；`changePassword` / `changeMfa`） |
| `GET /api/jobs/<id>` | 任务状态 / 日志 |
| `POST /api/jobs/<id>/stop` | 中断 |
| `POST /api/jobs/<id>/retry` | 重试失败项 |
| `GET /api/jobs/<id>/failed-accounts` | 失败账号 |
| `GET /api/jobs/<id>/download` 以及 `download-split`、`api-keys`、`mfa-secrets`、`accounts-passwords`、`logs` | 各类下载 |
| `POST /api/json-api-keys` | 上传 JSON ZIP 开通 Key |
| `GET/POST /api/proxy-pool` | 客户代理池 |
| `GET /api/history` | 历史批次 |
| `GET /api/v1/healthz` | 健康检查，返回 `{"status":"ok"}` |

写操作会校验 `Origin`，跨站 POST 直接 403。

## 环境变量（可选）

| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `KIRO_LOGIN_HOST` | 监听地址；公网直连需 `0.0.0.0` | `0.0.0.0` |
| `KIRO_LOGIN_PORT` | 监听端口 | `7888` |
| `KIRO_LOGIN_COOKIE_SECURE` | session cookie 的 `Secure`：`auto` / `true` / `false` | `auto` |
| `KIRO_DEFAULT_PROXY` | 服务端兜底默认代理 | 无 |
| `KIRO_MIHOMO_CONTROLLER` | mihomo 外部控制器 | `http://127.0.0.1:9090` |
| `KIRO_MIHOMO_SECRET` | mihomo 控制器密钥 | 无 |
| `KIRO_MIHOMO_GROUP` | mihomo 代理组名 | `KiroLogin` |
| `KIRO_MIHOMO_PROBE_PROXY` | 探测真实出口 IP 用的代理 | `http://127.0.0.1:7895` |
| `KIRO_SOCIAL_BROWSER` | Google/GitHub 引擎：`camoufox` / `firefox` / `chromium` | `camoufox` |

mihomo 相关变量仅本地部署换 IP 时需要；用代理池即可获得同等的换 IP 能力。
