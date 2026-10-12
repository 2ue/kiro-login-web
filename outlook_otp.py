# -*- coding: utf-8 -*-
"""Read AWS Builder ID email OTP from a university Outlook mailbox.

IMAP basic auth is disabled on outlook.office365.com for most tenants.
The working path is Microsoft Graph ROPC with the Outlook mobile public
client, which can list Mail.Read messages for organizational mailboxes
that still allow username/password (no mailbox MFA).
"""
from __future__ import annotations

import datetime as dt
import html
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from proxy_util import normalize_proxy_url

LogFn = Callable[[str], None]

OUTLOOK_MOBILE_CLIENT_ID = "27922004-5251-4030-b22d-91ecd9a37ea4"
TOKEN_URL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
GRAPH_SCOPE = "https://graph.microsoft.com/Mail.Read offline_access openid"
GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/messages"

AWS_OTP_SENDERS = (
    "no-reply@login.awsapps.com",
    "noreply@login.awsapps.com",
    "no-reply@signin.aws",
    "noreply@signin.aws",
)
AWS_OTP_SUBJECT_MARKERS = (
    "verify your identity",
    "verification code",
    "verifikasi",
    "verify your email",
    "verifikasi alamat email",
)
CODE_RES = (
    re.compile(r"verification code[^\d]{0,80}(\d{6})", re.I),
    re.compile(r"kode verifikasi[^\d]{0,80}(\d{6})", re.I),
    re.compile(r"verify your identity[^\d]{0,120}(\d{6})", re.I),
)


def _opener(proxy: str = "") -> urllib.request.OpenerDirector:
    handlers: list[urllib.request.BaseHandler] = []
    raw = normalize_proxy_url(proxy)
    if raw:
        handlers.append(urllib.request.ProxyHandler({"http": raw, "https": raw}))
    return urllib.request.build_opener(*handlers) if handlers else urllib.request.build_opener()


def _request_json(
    url: str,
    *,
    data: bytes | None = None,
    headers: Optional[dict[str, str]] = None,
    method: str = "GET",
    proxy: str = "",
    timeout: float = 30.0,
) -> tuple[int, dict[str, Any]]:
    h = {"Accept": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    opener = _opener(proxy)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return getattr(resp, "status", 200), json.loads(raw) if raw else {}
            except Exception:
                return getattr(resp, "status", 200), {"_raw": raw}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw) if raw else {"_raw": raw}
        except Exception:
            return exc.code, {"_raw": raw}
    except Exception as exc:
        return 0, {"_raw": str(exc)}


def _parse_iso(value: str) -> float:
    text = (value or "").strip()
    if not text:
        return 0.0
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return dt.datetime.fromisoformat(text).timestamp()
    except Exception:
        return 0.0


def _from_address(msg: dict[str, Any]) -> str:
    addr = ((msg.get("from") or {}).get("emailAddress") or {}).get("address") or ""
    return str(addr).strip().lower()


def _message_text(msg: dict[str, Any]) -> str:
    subject = str(msg.get("subject") or "")
    preview = str(msg.get("bodyPreview") or "")
    body = msg.get("body") if isinstance(msg.get("body"), dict) else {}
    content = str((body or {}).get("content") or "")
    if str((body or {}).get("contentType") or "").lower() == "html":
        content = re.sub(r"<[^>]+>", " ", content)
    content = html.unescape(content)
    text = " ".join((subject, preview, content))
    text = re.sub(r"[\u200b-\u200f\u00a0]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:20000]


def _extract_code(text: str) -> str:
    for cre in CODE_RES:
        m = cre.search(text or "")
        if m:
            return m.group(1)
    return ""


def _is_aws_otp_mail(msg: dict[str, Any]) -> bool:
    sender = _from_address(msg)
    subject = str(msg.get("subject") or "").lower()
    if sender in AWS_OTP_SENDERS:
        return True
    if any(marker in subject for marker in AWS_OTP_SUBJECT_MARKERS) and "aws" in (sender + " " + subject):
        return True
    return False


def describe_graph_error(status: int, data: dict[str, Any]) -> str:
    raw = str(data.get("error_description") or data.get("error") or data.get("message") or data.get("_raw") or data)
    low = raw.lower()
    if "aadsts50126" in low or "invalid username or password" in low:
        return "Outlook 邮箱密码不正确（Microsoft 拒绝用户名/密码）"
    if "aadsts50076" in low or "aadsts50079" in low or "multi-factor" in low or "mfa" in low:
        return "Outlook 邮箱开了 MFA，无法用密码直接读信。请关掉邮箱 MFA 或改用应用密码"
    if "aadsts65001" in low or "aadsts70000" in low:
        return "Outlook 租户未允许 Graph 读信（ROPC/Mail.Read 被拒）"
    if "aadsts9001023" in low:
        return "该 Outlook 租户不允许 /common ROPC，请使用组织账号"
    if "basic authentication is disabled" in low:
        return "Outlook IMAP 基本认证已关闭"
    if status:
        return f"读取 Outlook 失败（HTTP {status}）：{raw[:180]}"
    return f"读取 Outlook 失败：{raw[:180]}"


class GraphMailbox:
    """Organizational Outlook mailbox via Graph ROPC."""

    def __init__(
        self,
        email: str,
        password: str,
        *,
        proxy: str = "",
        log: LogFn = print,
    ) -> None:
        self.email = (email or "").strip()
        self.password = password or ""
        self.proxy = proxy or ""
        self.log = log
        self.access_token = ""
        self.used_codes: set[str] = set()

    def ensure_token(self) -> str:
        if self.access_token:
            return self.access_token
        if not self.email or not self.password:
            raise RuntimeError("缺少 Outlook 邮箱或邮箱密码，无法读取 AWS 验证码")
        body = urllib.parse.urlencode(
            {
                "client_id": OUTLOOK_MOBILE_CLIENT_ID,
                "grant_type": "password",
                "username": self.email,
                "password": self.password,
                "scope": GRAPH_SCOPE,
            }
        ).encode("utf-8")
        status, data = _request_json(
            TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
            proxy=self.proxy,
        )
        token = str(data.get("access_token") or "")
        if status >= 400 or not token:
            raise RuntimeError(describe_graph_error(status, data))
        self.access_token = token
        return token

    def list_messages(self, top: int = 20) -> list[dict[str, Any]]:
        token = self.ensure_token()
        query = urllib.parse.urlencode(
            {
                "$top": str(max(1, min(int(top), 50))),
                "$orderby": "receivedDateTime desc",
                "$select": "subject,from,receivedDateTime,bodyPreview,body",
            },
            safe="$",
        )
        status, data = _request_json(
            GRAPH_MESSAGES_URL + "?" + query,
            headers={"Authorization": f"Bearer {token}"},
            proxy=self.proxy,
        )
        if status == 401:
            self.access_token = ""
            token = self.ensure_token()
            status, data = _request_json(
                GRAPH_MESSAGES_URL + "?" + query,
                headers={"Authorization": f"Bearer {token}"},
                proxy=self.proxy,
            )
        if status >= 400:
            raise RuntimeError(describe_graph_error(status, data))
        items = data.get("value")
        return items if isinstance(items, list) else []

    def find_otp(self, since_ts: float, *, leeway_s: float = 8.0) -> str:
        messages = self.list_messages()
        cutoff = max(0.0, since_ts - leeway_s)
        ranked: list[tuple[int, float, str]] = []
        for msg in messages:
            if not isinstance(msg, dict) or not _is_aws_otp_mail(msg):
                continue
            received = _parse_iso(str(msg.get("receivedDateTime") or ""))
            if received and received < cutoff:
                continue
            text = _message_text(msg)
            code = _extract_code(text)
            if not code or code in self.used_codes:
                continue
            sender = _from_address(msg)
            # Prefer the login OTP sender over the Builder ID signup mail.
            rank = 0 if sender.endswith("login.awsapps.com") else 1
            ranked.append((rank, -received, code))
        if not ranked:
            return ""
        ranked.sort()
        return ranked[0][2]

    def wait_for_otp(
        self,
        since_ts: float,
        *,
        timeout_s: float = 120.0,
        interval_s: float = 3.0,
        stop_event=None,
    ) -> str:
        deadline = time.time() + max(5.0, float(timeout_s))
        last_err = ""
        attempt = 0
        while time.time() < deadline:
            if stop_event is not None and stop_event.is_set():
                raise RuntimeError("已中断（任务被手动停止）")
            attempt += 1
            try:
                code = self.find_otp(since_ts)
                if code:
                    self.used_codes.add(code)
                    return code
            except Exception as exc:
                last_err = str(exc)
                if attempt == 1 or attempt % 5 == 0:
                    self.log(f"    读邮箱失败：{last_err[:160]}")
            remain = deadline - time.time()
            if remain <= 0:
                break
            if attempt == 1 or attempt % 4 == 0:
                self.log(f"    等待 AWS 验证码邮件（已等 {int(timeout_s - remain)}s）")
            sleep_for = min(interval_s, remain)
            if stop_event is not None:
                stop_event.wait(timeout=sleep_for)
            else:
                time.sleep(sleep_for)
        if last_err:
            raise RuntimeError(f"邮箱里未找到 AWS 登录验证码：{last_err[:160]}")
        raise RuntimeError("邮箱里未找到 AWS 登录验证码（超时）")


def wait_for_aws_otp(
    email: str,
    password: str,
    *,
    since_ts: float,
    proxy: str = "",
    log: LogFn = print,
    timeout_s: float = 120.0,
    stop_event=None,
    mailbox: Optional[GraphMailbox] = None,
) -> str:
    box = mailbox or GraphMailbox(email, password, proxy=proxy, log=log)
    return box.wait_for_otp(since_ts, timeout_s=timeout_s, stop_event=stop_event)
