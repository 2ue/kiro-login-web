# Kiro Login Web

独立批量登录站点：批量填写 AWS IAM Identity Center 账号，后端用 Playwright 无头登录 Kiro device-code flow，导出扁平 JSON 数组。

## 安装

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

## 启动

```bash
python app.py --host 0.0.0.0 --port 7888
```

## 客户密码隔离

网站入口会强制要求输入客户专属密码。不同密码对应不同客户空间，任务、日志、下载文件都按客户隔离。

- 如果密码已存在：进入对应客户空间。
- 如果密码第一次使用：自动创建新的客户空间，可填写客户名称。
- 新自助客户只存 `passwordHash`，不保存明文密码。

也可以预先编辑 `customers.json` 固定客户：

```json
{
  "customer-a": { "name": "客户A", "password": "***" },
  "customer-b": { "name": "客户B", "passwordHash": "sha256..." }
}
```

导出 JSON / API Key / 日志只保留 60 分钟，过期自动删除，下载链接失效。

## 账号格式

每行一个：

```text
email:password
email|password|proxy
email,password,proxy
```

导出字段为扁平格式：`email/idp/profileArn/machineId/priority/status/accessToken/refreshToken/clientId/clientSecret/authMethod/provider/region/startUrl/expiresAt`。
