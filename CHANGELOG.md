# Changelog

本项目所有值得记录的变更都写在这里。版本遵循语义化版本 `MAJOR.MINOR.PATCH`。

## [Unreleased]

### 新增

- **登录后改密 / 2FA 独立页**：改密和改 2FA 从获取 JSON 工作台拆到 `/security`。可单独勾选「修改密码」或「设置/更换 2FA」，也可两项一起改。密码模式（每号随机 / 固定密码）在改密页直接设置，只改 2FA 时不必填新密码。账号解析、代理池、并发、超时、任务控制台复用原有逻辑。接口仍是 `POST /api/change-password`。
- **GitHub 个人号改密 / 2FA**：仅在独立 `/security` 页面增加 GitHub 登录方式。任务直接登录 `github.com`，支持修改 GitHub 密码、按官方 Password and authentication 页面更换 Authenticator app，并即时保存新 TOTP secret；获取 JSON 页面保持不变。
- **改密先落盘再改状态**：生成目标新密码后立刻写入 `kiro-password-ledger-{jobId}.json` 和 `kiro-changed-passwords-{jobId}.txt`（status=pending），站点接受后再标 applied，任务成功/失败后再更新状态。即使后续步骤报错，新密码也不会丢。页面可下载「账号密码」和「密码台账」。
- **更换 2FA 会删除旧设备**：Builder ID「Register device」是新增 authenticator，不会替换已有设备。现会在绑定成功并点 Done 后，选中更换前的 MFA 设备再 Delete。删失败时任务失败，新密钥仍落盘。`removeOldMfa` 可在不注册新设备的情况下只删掉除最新一台以外的 MFA。

### 修复

- **学生号 Security 页被误当成改密表单**：资料页 Signed in devices 文案含 “change your password”，旧逻辑没等弹窗打开就去填 New password。现只在改密 dialog / 密码输入框真正出现时才填表，并会先点 Authentication 的 Change password。
- **学生号资料页改密误判未登录**：Builder ID 登录后资料页「My details」含 Email address，旧逻辑把任意可见输入当成邮箱登录页并立刻失败；点侧栏 Security 触发二次密码/2FA 时也不会填写。现仅在 Get started 页判定邮箱登录，登录后等到资料页再改密，侧栏精确点 Security，并处理二次验证。
- **账号解析不再被学生号 TYPE 块独占**：默认回到自动识别。`|` 与 `----` 对 IDC / M365 / Google / GitHub / 学生号都继续有效。学生号 TYPE / LOGIN / MAIL_PASSWORD / PASSWORD 块只从带 `TYPE:` 的段落里取，可与分隔符行混贴、互不抢行。
- **获取 JSON 登录路径不被改密任务提前掐掉**：IDC / 学生号 JSON 登录仍等到总超时和 Allow access。密码提交后的短超时、资料页标记、跳过 Allow access 只在「登录后改密」任务生效。IDC 首次登录改密提交按钮与原先一致。
- **本机 mihomo 时浏览器真正走本地出口**：配了控制器后，任务会改走 `KIRO_MIHOMO_PROBE_PROXY`（默认 `127.0.0.1:7895`）。原先即使用户代理池只有 1 个 IP，切节点也不会作用到 Playwright。
- **未生效的预写新密码不再拿去登录**：重试/失败账号回填只使用台账里 `applied` 的密码。写盘但站点未接受的 pending 密码不会覆盖当前登录密码。
- **粘贴旧密码时自动改用历史上已生效的密码**：提交任务时按密码台账复用最近一次站点已接受的密码，避免改密成功后再用原密码登录。
- **Builder ID 密码不匹配不再当成 captcha**：没有 Security check 时，`doesn't quite match our records` 按密码错误失败，不再换 IP 连点 Continue。有 Security check / Invalid captcha 时仍换出口重试。

## [1.0.13] - 2026-09-28

### 修复

- **Builder ID Security check 被误当成密码错误**：AWS Builder ID 密码页弹出 `Security check` / Arkose 人机验证时，原先会反复点 Continue，最终报 `doesn't quite match our records`。现识别为 captcha 并走代理池/mihomo 换 IP 重试。

## [1.0.12] - 2026-09-28

### 新增

- **代理格式 `ip:port:username:password`**：代理池和账号行里的代理支持 `1.2.3.4:8080:user:pass`（以及 `user:pass:host:port`）。会规范成 `http://user:pass@host:port`，Playwright 启动时把账密拆到 `username` / `password`，不再把整串塞进 `server`。

## [1.0.11] - 2026-09-24

### 新增

- **学生号专用输入框**：登录方式移到账号导入第一步。选「Kiro 学生号」后，输入框切换为 MAIL / PASS MAIL / PASS AWS 格式，并显示字段说明与 Outlook/AWS 密码预览。账号格式下拉新增「学生号格式」，选中后自动切到学生号登录。

## [1.0.10] - 2026-09-24

### 新增

- **Kiro 学生号登录**：AWS Builder ID 设备码 + 大学 Outlook 邮箱验证码。登录方式选「Kiro 学生号」，无需 Start URL。账号格式：

  ```text
  MAIL: student@university.edu
  PASS MAIL: Outlook邮箱密码
  PASS AWS: AWS Builder ID密码
  ```

  `MAIL` 同时是 Builder ID 账号和 Outlook 邮箱。后端用 Graph 读 `no-reply@login.awsapps.com` 的 6 位验证码，走 Get started → 密码 → 邮箱 OTP → Confirm and continue → Allow access。

## [1.0.9] - 2026-09-22

### 新增

- **四横线 `----` 作为通用分隔符**：`----` 只负责切字段，不固定为 mail/password/2fa。各段按内容识别 Start URL（含 `idc::`）、region、代理、TOTP 密钥，剩下的按顺序取账号和密码。可与 `email:password`、管道、标签块等混贴，按行识别、互不抢行。三横线 `---` 仍可作为分隔符，但不会切开 `email:password` 里密码中的 `---`。

## [1.0.8] - 2026-09-22

### 修复

- **Google 个人号「身份异常 / JavaScript 已关闭」**：Playwright Chromium 会被 Google 判定为无 JS 自动化浏览器（`accounts.google.com/signin/rejected`），日志误报成「账号不存在或被封」。Gmail / GitHub 个人号改为默认使用 Camoufox（Xvfb 虚拟显示 + Windows 指纹 + 拟人输入），启动失败时回退 Playwright Firefox。
- **社交登录撞 reCAPTCHA 可换 IP 重试**：与 IDC 路径一致，Google/GitHub 人机验证或代理失败时走 mihomo / 代理池换出口。

## [1.0.7] - 2026-07-11

### 新增

- **中文标签账号格式**：支持中文/英文标签的账号粘贴格式，无需按固定分隔符排列。
  - 多行块：每字段独占一行（`登录地址: / 用户名: / 密码: / 区域:`），多账号用空行或重复必填字段分隔，`登录地址`/`区域` 可跨块继承。
  - 单行内联：`登录地址: xx 用户名: yy 密码: zz 区域: ww` 全部挤在一行也能正确解析，按标签位置切分，密码含空格/冒号/特殊符都完整保留。
  - 解析优先级：管道格式 → 中文多行块 → 中文单行内联 → 表头块 → mmostore 块 → 通用分隔符。
- **AWS IdC 8 列导出格式**：前端预览与后端解析支持 AWS IdC 的 8 列导出格式，自动识别 MFA 密钥。
- **任务完成后失败账号摘要**：任务结束直接在前端展示失败账号列表，便于快速定位。

### 修复

- **Start URL 缺 `/start` 自动补全**：`https://d-xxx.awsapps.com/`（根路径/截断，缺 `/start`）原会被误判为合法静默放行，导致传给 AWS 报 `Invalid start url`。现自动补成 `.../start`；新版 portal URL 不受影响。
- **改密仅在通过后保存新密码**：改密策略错误时不再错误保存未生效的新密码，识别为策略错误时换更强密码重试一次。
- **登录索引锁死修复**：修复 Flask secret 旋转后登录查找索引锁死问题；孤儿清理改按任务 TTL 执行。

### 其他

- 清理未用导入/死代码，pyflakes 零告警。

## [1.0.6] - 2026-07-09

### 性能

- **登录 O(1) 查找索引**：原先登录要遍历所有客户、对每个都跑一次 20 万轮 PBKDF2 校验，客户越多越慢（~140 客户时单次登录约 27 秒，线性增长，多客户场景会卡到超时）。现在每个客户存一个确定性查找索引 `lookupHash`（HMAC-SHA256，密钥派生自服务端 Flask secret），登录先 O(1) 定位候选再做 PBKDF2 校验。已迁移/新客户登录 **27 秒 → 0.22 秒（约 130 倍）**。PBKDF2 慢哈希照旧保留（防离线爆破），安全性不降。老数据首次登录时自动补写 `lookupHash`（自愈迁移），无需手动处理。

### 新增

- **账号数据保留时长可自定义**：默认保留时长由 60 分钟改为 **24 小时**。「更多配置」新增「账号数据保留时长（分钟）」输入框，可按任务在 **5 分钟 ~ 7 天** 间自定义。任务级保留时长持久化，清理 / 过期判断 / 剩余倒计时均按各自任务生效；重试任务继承原任务保留时长。孤儿文件清理以 7 天为上限兜底，不会误删长保留任务的文件。
- **代理功能通用化**（开源友好）：
  - 代理池可按客户持久化保存（`customers.json` 的 `proxyPool` 字段），新增 `GET/POST /api/proxy-pool`；前端加「保存代理池」勾选与「立即保存」按钮，页面加载自动回填。
  - 防风控换 IP 通用化：撞 captcha / 代理报错时，有 mihomo 走切节点换 IP，无 mihomo 但有代理池则在池内轮换到不同代理；两者都无则明确停止重试（避免撞同样风控空转）。
  - 代理串日志脱敏，只显 host。

## [1.0.5] - 2026-06-29

### 新增

- Microsoft 365 / Entra ID 组织 SSO 登录（OAuth auth-code + PKCE + 本地回环回调）
- 前端登录方式切换：AWS IDC 设备码 / 组织 SSO
- M365 路径并发安全（每任务独立回环端口）
- external_idp 凭据导出（含 `issuer_url / token_endpoint / scopes`，无 `clientSecret`）

## [1.0.4] 及更早

- 一键提取账号密码下载（`email:password`，改密后取最终密码）
- job 日志记录改密后新密码明文 + 完成行标注改密/沿用状态
- 过期清理补齐 MFA / 账号密码属性 + 目录级孤儿兜底扫描（含明文密码/MFA 文件超时即焚）
- MFA 页识别：区分注册页与已绑定验证页，已绑账号无预设密钥时秒退并给准确错误
- 换 IP 时校验真实出口 IP 确变（共用 VPS 则继续找不同 IP）+ 撞 captcha 后冷却 + 默认并发降至 2
- headless Chromium 启动参数省 CPU、出口节点预热健康检查、日志节流与轮转等性能优化

[1.0.6]: https://github.com/TWLW9784/kiro-login-web/releases/tag/v1.0.6
[1.0.5]: https://github.com/TWLW9784/kiro-login-web/releases/tag/v1.0.5
