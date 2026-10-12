# -*- coding: utf-8 -*-
"""Playwright driver for AWS Builder ID device-code login and password change.

Student / Builder ID pages live on us-east-1.signin.aws/platform/... and are
not the IAM Identity Center AWSUI username form. Flow:

    1. Get started          -> email + Continue
    2. Builder ID password  -> password + trusted-device + Continue
    3. Verify your identity -> authenticator TOTP（有 2FA 密钥时）和/或 Outlook 邮件 OTP
    4. Authorization requested -> Confirm and continue
    5. Allow kiro-oauth-client -> Allow access

Password-change is a separate route: same login interaction, then open
profile.aws.amazon.com Security and submit the change-password form.
It does not collect device-code tokens / JSON.
"""
from __future__ import annotations

import random
import re
import time
from typing import Callable, Optional

from playwright.sync_api import sync_playwright

import idc_browser_login as idc
import mfa_totp
import stealth_browser as stealth
from idc_browser_login import LoginOutcome
from outlook_otp import GraphMailbox
from proxy_util import playwright_proxy

LogFn = Callable[[str], None]

EMAIL_SELECTORS = (
    "input[type=email]:visible",
    "input[name*=email i]:visible",
    "input[autocomplete=username]:visible",
    "input[type=text]:visible",
)
OTP_SELECTORS = (
    "input[autocomplete=one-time-code]:visible",
    "input[name*=code i]:visible",
    "input[name*=otp i]:visible",
    "input[inputmode=numeric]:visible",
    "input[type=tel]:visible",
    "input[type=text]:visible",
)
OTP_PAGE_MARKERS = (
    "verify your identity",
    "verification code",
    "we just sent a verification code",
    "code expires in",
    "resend code",
)
EMAIL_OTP_MARKERS = (
    "we just sent a verification code",
    "sent a verification code",
    "resend code",
    "code expires in",
    "sent to your email",
    "sent to the email",
)
TOTP_PAGE_MARKERS = (
    "authenticator app",
    "from your authenticator",
    "additional verification required",
    "enter the six digit code",
    "enter the 6 digit code",
    "one-time passcode",
    "multi-factor",
    "mfa device",
    "identity verification app",
)
EMAIL_PAGE_MARKERS = (
    "get started",
    "continue with google",
    "continue with github",
    "create an aws builder id",
)
INCORRECT_MARKERS = (
    "incorrect", "is not correct", "could not sign", "couldn't sign",
    "authentication failed", "username or password", "invalid password",
    "we couldn't", "no account", "does not exist", "couldn't find",
    "passwords do not match", "password doesn't match",
    "doesn't quite match our records",
    "does not quite match our records",
    "didn't catch that",
    "did not catch that",
    "some information you entered",
)
OTP_REJECT_MARKERS = (
    "incorrect", "invalid", "not valid", "isn't valid", "does not match",
    "doesn't match", "wrong", "expired", "try again",
)
# AWS Builder ID 密码页会在风控时插入 Arkose/FunCaptcha「Security check」。
# 继续点 Continue 只会反复报 doesn't quite match our records，必须当 captcha 退出换 IP。
CAPTCHA_MARKERS = (
    "security check",
    "security challenge",
    "click verify to start",
    "please click verify",
    "start your security challenge",
    "are you human",
    "funcaptcha",
    "arkose",
    "recaptcha",
)
# 邮箱 Continue 后 AWS 有时直接弹 ERR-837（Account issue）。页面仍停在 Get started，
# 旧逻辑会当成「邮箱填不对」连点 3 次。按风控处理，立刻退出换 IP。
ACCOUNT_ISSUE_MARKERS = (
    "err-837",
    "err 837",
    "issue with your builder id account",
    "issue with your builder id",
)
BUILDER_ID_PROFILE_URL = "https://profile.aws.amazon.com/"
BUILDER_ID_SECURITY_URLS = (
    "https://profile.aws.amazon.com/",
    "https://us-east-1.signin.aws/platform/profile",
)
# 已登录资料页（My details / Security）正文。sidebar 里也有 "Security"，
# 不能单靠这个词判断已经打开安全设置。
PROFILE_BODY_MARKERS = (
    "personal information",
    "security settings",
    "account settings",
    "my information",
    "aws account connections",
    "contact information",
    "my details",
    "privacy & data",
    "profile information",
)
# 资料页 Security 内容（不含侧栏那个单词本身）。
SECURITY_PAGE_MARKERS = (
    "security settings",
    "change password",
    "multi-factor authentication",
    "assign mfa",
    "mfa device",
    "passkey",
)
# 登录/二次验证的 TOTP 页，不是资料页上的 MFA 介绍文案。
TOTP_CHALLENGE_MARKERS = (
    "verify your identity",
    "additional verification required",
    "enter the six digit code",
    "enter the 6 digit code",
    "six digit code from your authenticator",
    "code from your authenticator app",
)
PROFILE_READY_JS = """() => {
    const t = (document.body && document.body.innerText || '').toLowerCase();
    const u = (location.href || '').toLowerCase();
    if (t.includes('allow access') || t.includes('authorization requested')
        || t.includes('confirm and continue')) return true;
    if (t.includes('my details') || t.includes('contact information')
        || t.includes('privacy & data') || t.includes('security settings')
        || t.includes('personal information') || t.includes('profile information')) return true;
    if (u.includes('profile.aws.amazon.com') && t.includes('aws builder id')) return true;
    return false;
}"""
SECURITY_OR_REAUTH_JS = """() => {
    const t = (document.body && document.body.innerText || '').toLowerCase();
    const n = document.querySelectorAll('input[type=password]').length;
    if (t.includes('sign in with your aws builder id') && n === 1) return false;
    if (t.includes('verify your identity') || t.includes('verification code')
        || t.includes('we just sent a verification code')) return true;
    if (t.includes('change your password') || t.includes('new password')
        || t.includes('confirm new password')) return true;
    if (t.includes('register device') || t.includes('mfa devices')
        || t.includes('multi-factor authentication')) return true;
    if (t.includes('my details') && t.includes('security') && n === 0) return true;
    return false;
}"""
REAUTH_LEFT_JS = """() => {
    const t = (document.body && document.body.innerText || '').toLowerCase();
    const n = document.querySelectorAll('input[type=password]').length;
    if (t.includes('sign in with your aws builder id') && n === 1) return false;
    if (t.includes('verify your identity') || t.includes('verification code')) return true;
    if (n !== 1) return true;
    return false;
}"""
MFA_ACTION_BUTTONS = [
    "Register device",
    "Register MFA device",
    "Assign MFA device",
    "Add MFA device",
    "Replace MFA device",
    "Replace device",
    "Change MFA device",
    "Remove MFA device",
    "Delete MFA device",
    "Unregister",
    "Set up MFA",
    "Add another device",
    "Enable MFA",
    "Manage MFA",
    "更换 MFA",
    "替换设备",
    "删除 MFA",
    "添加 MFA",
    "注册设备",
]
# Register 会新增一台 authenticator，不能和 Delete 混在同一个点击列表里。
MFA_REGISTER_ACTION_BUTTONS = [
    "Register device",
    "Register MFA device",
    "Assign MFA device",
    "Add MFA device",
    "Replace MFA device",
    "Replace device",
    "Change MFA device",
    "Set up MFA",
    "Add another device",
    "Enable MFA",
    "Manage MFA",
    "更换 MFA",
    "替换设备",
    "添加 MFA",
    "注册设备",
]
# 必须 exact「Delete」，避免点到「Delete all active sessions」。
MFA_DELETE_ACTION_BUTTONS = (
    "Delete",
    "Delete MFA device",
    "Unregister",
    "Remove MFA device",
    "删除 MFA",
    "删除",
)
MFA_DELETE_CONFIRM_BUTTONS = (
    "Delete MFA device",
    "Delete",
    "Confirm",
    "Yes",
    "删除 MFA",
    "删除",
    "确认",
)
MFA_REGISTERED_DIALOG_MARKERS = (
    "authenticator app registered",
    "authenticator app has been successfully registered",
    "your authenticator app has been successfully registered",
)
PASSWORD_ACTION_BUTTONS = [
    "Change password",
    "Update password",
    "Manage password",
    "Edit password",
    "修改密码",
    "更改密码",
]
PASSWORD_CHANGED_MARKERS = (
    "password updated",
    "password has been updated",
    "password has been changed",
    "password successfully",
    "successfully changed",
    "successfully updated",
    "your password has been",
    "password saved",
    "密码已",
    "密码修改成功",
    "已更新密码",
)
CHANGE_PASSWORD_FORM_MARKERS = (
    "change your password",
    "current password",
    "new password",
    "confirm new password",
    "confirm password",
    "re-enter password",
    "reenter password",
    "修改密码",
    "当前密码",
    "新密码",
    "确认密码",
)
MFA_CHANGED_MARKERS = (
    "mfa device assigned",
    "successfully assigned",
    "authenticator app added",
    "mfa device added",
    "registered successfully",
    "device registered",
    "successfully registered",
    "successfully added",
    "authenticator app is ready",
    "2fa enabled",
    "mfa enabled",
)


def drive_login(
    verification_uri_complete: str,
    email: str,
    password: str,
    mail_password: str = "",
    new_password: str = "",
    log: LogFn = print,
    headless: bool = True,
    stop_event=None,
    proxy: str = "",
    timeout_s: int = 220,
    failure_wait_s: int = 60,
    window_index: int = 0,
    window_count: int = 1,
    screen_w: int = 1920,
    screen_h: int = 1040,
    debug_dir: str = "",
    mailbox: Optional[GraphMailbox] = None,
    mfa_secret: str = "",
    profile_dir: str = "",
) -> LoginOutcome:
    launch_args = [
        "--disable-blink-features=AutomationControlled",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--disable-renderer-backgrounding",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-background-timer-throttling",
        "--disable-hang-monitor",
        "--disable-features=TranslateUI,BackForwardCache",
        "--metrics-recording-only",
        "--no-first-run",
        "--mute-audio",
    ]
    if not headless:
        launch_args += idc._tile_args(window_index, window_count, screen_w, screen_h)
    launch_kwargs: dict = {"headless": headless, "args": launch_args}
    proxy_cfg = playwright_proxy(proxy)
    if proxy_cfg:
        launch_kwargs["proxy"] = proxy_cfg

    if profile_dir:
        closer = None
        try:
            page, closer = stealth.open_camoufox_unique_profile(
                profile_dir=profile_dir,
                headless=headless,
                proxy_cfg=proxy_cfg,
                log=log,
            )
            ctx = page.context
            try:
                ctx.route(
                    "**/*",
                    lambda route: route.abort()
                    if route.request.resource_type in ("image", "media", "font")
                    else route.continue_(),
                )
            except Exception:
                pass
            page.set_default_timeout(45000 if proxy else 15000)
            return _flow(
                page,
                verification_uri_complete,
                email,
                password,
                mail_password=mail_password or password,
                new_password=new_password,
                log=log,
                stop_event=stop_event,
                timeout_s=timeout_s,
                failure_wait_s=failure_wait_s,
                debug_dir=debug_dir,
                mailbox=mailbox,
                proxy=proxy,
                mfa_secret=mfa_secret,
            )
        except Exception as exc:
            return LoginOutcome(False, error=f"loi browser: {exc}")
        finally:
            if closer:
                try:
                    closer()
                except Exception:
                    pass

    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch_kwargs)
        ctx_kwargs: dict = {}
        if headless:
            ctx_kwargs["viewport"] = {"width": 1280, "height": 900}
        else:
            ctx_kwargs["no_viewport"] = True
        ctx = browser.new_context(**ctx_kwargs)
        try:
            ctx.route(
                "**/*",
                lambda route: route.abort()
                if route.request.resource_type in ("image", "media", "font")
                else route.continue_(),
            )
        except Exception:
            pass
        page = ctx.new_page()
        page.set_default_timeout(45000 if proxy else 15000)
        try:
            return _flow(
                page,
                verification_uri_complete,
                email,
                password,
                mail_password=mail_password or password,
                new_password=new_password,
                log=log,
                stop_event=stop_event,
                timeout_s=timeout_s,
                failure_wait_s=failure_wait_s,
                debug_dir=debug_dir,
                mailbox=mailbox,
                proxy=proxy,
                mfa_secret=mfa_secret,
            )
        except Exception as exc:
            return LoginOutcome(False, error=f"loi browser: {exc}")
        finally:
            try:
                browser.close()
            except Exception:
                pass


def drive_change_password(
    email: str,
    password: str,
    new_password: str,
    mail_password: str = "",
    log: LogFn = print,
    headless: bool = True,
    stop_event=None,
    proxy: str = "",
    timeout_s: int = 220,
    failure_wait_s: int = 60,
    window_index: int = 0,
    window_count: int = 1,
    screen_w: int = 1920,
    screen_h: int = 1040,
    debug_dir: str = "",
    mailbox: Optional[GraphMailbox] = None,
    mfa_secret: str = "",
    on_password_changed=None,
    on_secret=None,
    start_url: str = "",
    do_change_password: bool = True,
    do_change_mfa: bool = False,
    do_remove_old_mfa: bool = False,
    profile_dir: str = "",
) -> LoginOutcome:
    """Log in to Builder ID, then change password and/or 2FA on the profile page.

    This is a separate route from JSON/token collection. It reuses the same
    email / password / Outlook OTP / TOTP interaction as ``drive_login``.
    """
    if do_change_mfa:
        do_remove_old_mfa = True
    if not do_change_password and not do_change_mfa and not do_remove_old_mfa:
        return LoginOutcome(False, error="未选择要修改的项（密码或 2FA）")
    if do_change_password:
        if not new_password:
            return LoginOutcome(False, error="未提供新密码")
        if new_password == password:
            return LoginOutcome(False, error="新密码与当前密码相同")
    elif not new_password or new_password == password:
        new_password = idc.DEFAULT_NEW_PASSWORD
        if new_password == password:
            new_password = idc.DEFAULT_NEW_PASSWORD + "9"
    launch_args = [
        "--disable-blink-features=AutomationControlled",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--disable-renderer-backgrounding",
        "--disable-gpu",
        "--disable-extensions",
        "--disable-background-timer-throttling",
        "--disable-hang-monitor",
        "--disable-features=TranslateUI,BackForwardCache",
        "--metrics-recording-only",
        "--no-first-run",
        "--mute-audio",
    ]
    if not headless:
        launch_args += idc._tile_args(window_index, window_count, screen_w, screen_h)
    launch_kwargs: dict = {"headless": headless, "args": launch_args}
    proxy_cfg = playwright_proxy(proxy)
    if proxy_cfg:
        launch_kwargs["proxy"] = proxy_cfg

    if profile_dir:
        closer = None
        try:
            page, closer = stealth.open_camoufox_unique_profile(
                profile_dir=profile_dir,
                headless=headless,
                proxy_cfg=proxy_cfg,
                log=log,
            )
            page.set_default_timeout(45000 if proxy else 15000)
            return _change_password_flow(
                page,
                email,
                password,
                new_password=new_password,
                mail_password=mail_password or password,
                log=log,
                stop_event=stop_event,
                timeout_s=timeout_s,
                failure_wait_s=failure_wait_s,
                debug_dir=debug_dir,
                mailbox=mailbox,
                proxy=proxy,
                mfa_secret=mfa_secret,
                on_password_changed=on_password_changed,
                on_secret=on_secret,
                start_url=start_url or BUILDER_ID_PROFILE_URL,
                do_change_password=do_change_password,
                do_change_mfa=do_change_mfa,
                do_remove_old_mfa=do_remove_old_mfa,
            )
        except Exception as exc:
            return LoginOutcome(False, error=f"loi browser: {exc}")
        finally:
            if closer:
                try:
                    closer()
                except Exception:
                    pass

    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch_kwargs)
        ctx_kwargs: dict = {}
        if headless:
            ctx_kwargs["viewport"] = {"width": 1280, "height": 900}
        else:
            ctx_kwargs["no_viewport"] = True
        ctx = browser.new_context(**ctx_kwargs)
        page = ctx.new_page()
        page.set_default_timeout(45000 if proxy else 15000)
        try:
            return _change_password_flow(
                page,
                email,
                password,
                new_password=new_password,
                mail_password=mail_password or password,
                log=log,
                stop_event=stop_event,
                timeout_s=timeout_s,
                failure_wait_s=failure_wait_s,
                debug_dir=debug_dir,
                mailbox=mailbox,
                proxy=proxy,
                mfa_secret=mfa_secret,
                on_password_changed=on_password_changed,
                on_secret=on_secret,
                start_url=start_url or BUILDER_ID_PROFILE_URL,
                do_change_password=do_change_password,
                do_change_mfa=do_change_mfa,
                do_remove_old_mfa=do_remove_old_mfa,
            )
        except Exception as exc:
            return LoginOutcome(False, error=f"loi browser: {exc}")
        finally:
            try:
                browser.close()
            except Exception:
                pass


def _flow(
    page,
    url: str,
    email: str,
    password: str,
    *,
    mail_password: str,
    new_password: str,
    log: LogFn,
    stop_event,
    timeout_s: int,
    failure_wait_s: int,
    debug_dir: str,
    mailbox: Optional[GraphMailbox],
    proxy: str,
    mfa_secret: str = "",
) -> LoginOutcome:
    safe = "".join(c if c.isalnum() else "_" for c in (email or "acc"))[:20]
    shot = {"i": 0}

    def _shot(tag: str) -> None:
        if not debug_dir:
            return
        try:
            from pathlib import Path as _P
            _P(debug_dir).mkdir(exist_ok=True, parents=True)
            page.screenshot(path=str(_P(debug_dir) / f"{safe}_{shot['i']:02d}_{tag}.png"))
        except Exception:
            pass
        shot["i"] += 1

    secret = mfa_totp.normalize_secret(mfa_secret) if mfa_secret else ""
    box = mailbox
    if box is None and mail_password:
        box = GraphMailbox(email, mail_password, proxy=proxy, log=log)
    if secret:
        log(f"    2FA: 已注入预设密钥（{secret[:4]}…{secret[-4:]}），验证码页按页面要求处理")

    time.sleep(random.uniform(0.02, 0.12))
    log("    打开 Builder ID 登录页")
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=60000)
    except Exception as exc:
        raise RuntimeError(f"打开页面超时（代理或网络）：{exc}") from exc
    try:
        page.wait_for_selector("input, button", timeout=12000)
    except Exception:
        pass
    _shot("landing")

    return _run_login_loop(
        page,
        email,
        password,
        new_password=new_password,
        log=log,
        stop_event=stop_event,
        timeout_s=timeout_s,
        failure_wait_s=failure_wait_s,
        box=box,
        secret=secret,
        _shot=_shot,
        require_consent=True,
    )


def _run_login_loop(
    page,
    email: str,
    password: str,
    *,
    new_password: str,
    log: LogFn,
    stop_event,
    timeout_s: int,
    failure_wait_s: int,
    box: Optional[GraphMailbox],
    secret: str,
    _shot,
    require_consent: bool,
) -> LoginOutcome:
    deadline = time.time() + timeout_s
    changed = False
    email_attempts = 0
    password_attempts = 0
    otp_attempts = 0
    totp_attempts = 0
    change_pw_attempts = 0
    password_clicked_at = 0.0
    seen_password = False
    seen_otp = False
    idle_rounds = 0

    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            return LoginOutcome(False, changed, "Da huy")

        idc._maybe_cookie_accept(page, log)
        body = (idc._body_text(page) or "").lower()
        pw_n = idc._count_visible(page, "input[type=password]")
        has_allow = idc._is_button_visible(page, "Allow access")
        has_confirm = idc._is_button_visible(page, "Confirm and continue")

        if any(m in body for m in idc.SUCCESS_MARKERS):
            log("    -> approved")
            _shot("approved")
            return LoginOutcome(True, changed)

        if has_allow:
            if require_consent:
                if idc._click_button(page, ["Allow access"], log):
                    time.sleep(0.8)
                    _shot("after_allow")
                    return LoginOutcome(True, changed)
            else:
                log("    已出现授权页，登录完成（改密不需要 Allow access）")
                _shot("signed_in")
                return LoginOutcome(True, changed)

        if has_confirm:
            if require_consent:
                idc._click_button(page, ["Confirm and continue"], log)
                idle_rounds = 0
                time.sleep(0.8)
                _shot("after_confirm")
                continue
            log("    已进入授权确认，登录完成（改密不需要 Confirm and continue）")
            _shot("signed_in")
            return LoginOutcome(True, changed)

        if (
            (not require_consent)
            and seen_password
            and not _is_otp_page(page, body, pw_n)
            and not _is_email_page(page, body, pw_n)
            and _is_signed_in_profile(page, body, pw_n)
        ):
            log("    已通过 Builder ID 登录，准备进入资料页改密")
            _shot("signed_in")
            return LoginOutcome(True, changed)

        if _is_security_check(page, body):
            detail = idc._visible_error_text(page) or "Security check"
            _shot("captcha")
            return LoginOutcome(
                False,
                changed,
                f"触发 AWS 人机验证 captcha（{detail}）：请换 IP 后重试",
            )

        if _is_builder_account_issue(body):
            detail = idc._visible_error_text(page) or "ERR-837 Account issue"
            _shot("account_issue")
            return LoginOutcome(
                False,
                changed,
                f"触发 AWS 风控 ERR-837（{detail}）：请换 IP 后重试",
            )

        if any(m in body for m in INCORRECT_MARKERS) and seen_password and "verification code" not in body:
            detail = idc._visible_error_text(page) or "密码不正确"
            _shot("password_error")
            return LoginOutcome(False, changed, f"Builder ID 密码不正确：{detail}")

        if pw_n >= 2:
            change_pw_attempts += 1
            if not new_password:
                _shot("change_password")
                return LoginOutcome(False, changed, "AWS 要求设置新密码，但未提供可用新密码")
            if change_pw_attempts > 3:
                detail = idc._visible_error_text(page)
                return LoginOutcome(False, changed, f"首次登录改密码失败：{detail or '页面未进入下一步'}")
            log(f"    检测到设置新密码表单，写入新密码")
            idc.fill_and_submit_password_form(page, password, new_password, log)
            changed = True
            password = new_password
            idle_rounds = 0
            time.sleep(1.0)
            continue

        if _is_totp_page(page, body, pw_n) and not secret and not _is_email_otp_page(page, body, pw_n):
            _shot("mfa_already_bound")
            return LoginOutcome(False, changed, "账号已绑定 MFA，需提供已有 authenticator 密钥")

        if secret and _is_otp_page(page, body, pw_n) and not _is_email_otp_page(page, body, pw_n):
            totp_attempts += 1
            if totp_attempts > 4:
                _shot("totp_failed")
                return LoginOutcome(False, changed, "2FA 验证码多次未通过")
            if any(m in body for m in OTP_REJECT_MARKERS) and totp_attempts > 1:
                wait = 31 - (int(time.time()) % 30)
                log(f"    2FA 验证码被拒绝，等待 {wait}s 换新码")
                time.sleep(min(wait, 32))
            log("    验证码页：使用 authenticator 2FA")
            _shot("totp_page")
            if not _submit_totp(page, secret, log, _shot):
                return LoginOutcome(False, changed, "找不到 2FA 验证码输入框")
            seen_otp = True
            idle_rounds = 0
            try:
                if require_consent:
                    page.wait_for_selector(
                        "button:has-text('Allow access'), button:has-text('Confirm and continue')",
                        timeout=12000,
                    )
                else:
                    _wait_for_profile_or_consent(page, timeout_ms=20000)
                    done = _finish_change_login_if_ready(page, log, _shot, changed)
                    if done is not None:
                        return done
            except Exception:
                time.sleep(1.2)
            if not require_consent:
                done = _finish_change_login_if_ready(page, log, _shot, changed)
                if done is not None:
                    return done
            continue

        if _is_otp_page(page, body, pw_n):
            seen_otp = True
            if any(m in body for m in OTP_REJECT_MARKERS) and otp_attempts:
                log("    验证码被拒绝，等待新邮件")
            otp_attempts += 1
            if otp_attempts > 4:
                _shot("otp_failed")
                return LoginOutcome(False, changed, "邮箱验证码多次未通过")
            if box is None:
                return LoginOutcome(False, changed, "需要 Outlook 邮件验证码，但邮箱无法读取")
            since = password_clicked_at or (time.time() - 15)
            log("    验证码页：从 Outlook 读取 AWS 邮件验证码")
            _shot("otp_page")
            try:
                code = box.wait_for_otp(
                    since,
                    timeout_s=min(120, max(30, deadline - time.time())),
                    stop_event=stop_event,
                )
            except Exception as exc:
                err = str(exc)
                low = err.lower()
                if any(tok in low for tok in ("mfa", "无法用密码", "密码不正确", "租户未允许")):
                    return LoginOutcome(False, changed, err)
                if otp_attempts == 1:
                    _click_resend(page, log)
                    time.sleep(2.0)
                    continue
                return LoginOutcome(False, changed, err)
            log(f"    填入验证码 {code}")
            if not _fill_otp(page, code):
                return LoginOutcome(False, changed, "找不到验证码输入框")
            _shot("otp_filled")
            idc._wait_metadata1(page)
            if not idc._click_button(page, ["Continue", "Submit", "Verify"], log):
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
            idle_rounds = 0
            try:
                if require_consent:
                    page.wait_for_selector(
                        "button:has-text('Allow access'), button:has-text('Confirm and continue')",
                        timeout=12000,
                    )
                else:
                    _wait_for_profile_or_consent(page, timeout_ms=20000)
                    done = _finish_change_login_if_ready(page, log, _shot, changed)
                    if done is not None:
                        return done
            except Exception:
                time.sleep(1.2)
            if not require_consent:
                done = _finish_change_login_if_ready(page, log, _shot, changed)
                if done is not None:
                    return done
            continue

        if pw_n == 1:
            password_attempts += 1
            if password_attempts > 3:
                detail = idc._visible_error_text(page)
                _shot("password_stuck")
                return LoginOutcome(False, changed, f"无法完成 Builder ID 密码页：{detail or '提交后未进入下一步'}")
            log("    输入 AWS Builder ID 密码")
            idc._fill_first_visible(page, "input[type=password]", password)
            _check_trusted_device(page, log)
            _shot("password_filled")
            idc._wait_metadata1(page)
            if not idc._click_button(page, ["Continue", "Sign in", "Submit"], log):
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
            password_clicked_at = time.time()
            seen_password = True
            idle_rounds = 0
            try:
                # JSON 登录只等到验证码/授权/风控；改密额外等到资料页。
                wait_js = """() => {
                    const t = (document.body && document.body.innerText || '').toLowerCase();
                    const u = (location.href || '').toLowerCase();
                    if (t.includes('verification code') || t.includes('verify your identity')
                        || t.includes('authenticator') || t.includes('multi-factor')
                        || t.includes('allow access') || t.includes('authorization requested')
                        || t.includes('security check') || t.includes('security challenge')
                        || t.includes("didn't catch that") || t.includes("doesn't quite match our records")
                        || t.includes('invalid captcha')) {
                        return true;
                    }
                    return %s && (t.includes('personal information')
                        || t.includes('security settings')
                        || t.includes('my details')
                        || t.includes('contact information')
                        || t.includes('privacy & data')
                        || u.includes('profile.aws.amazon.com'));
                }""" % ("true" if not require_consent else "false")
                page.wait_for_function(wait_js, timeout=12000)
            except Exception:
                time.sleep(1.0)
            continue

        if _click_builder_id_entry(page, log, body):
            idle_rounds = 0
            time.sleep(1.0)
            continue

        if _is_email_page(page, body, pw_n):
            email_attempts += 1
            if email_attempts > 3:
                detail = idc._visible_error_text(page) or ""
                _shot("email_stuck")
                if _is_builder_account_issue(body) or "err-837" in detail.lower():
                    return LoginOutcome(
                        False,
                        changed,
                        f"触发 AWS 风控 ERR-837（{detail or 'Account issue'}）：请换 IP 后重试",
                    )
                return LoginOutcome(
                    False,
                    changed,
                    f"无法完成 Builder ID 邮箱页（{detail or '邮箱可能不正确'}）",
                )
            log("    输入 Builder ID 邮箱")
            filled = False
            for sel in EMAIL_SELECTORS:
                if idc._fill_first_visible(page, sel, email, timeout=4000):
                    filled = True
                    break
            if not filled:
                return LoginOutcome(False, changed, "找不到 Builder ID 邮箱输入框")
            _shot("email_filled")
            try:
                page.keyboard.press("Tab")
                time.sleep(0.15)
                page.keyboard.press("Enter")
                log("    -> press Tab+Enter")
            except Exception:
                pass
            try:
                page.mouse.click(683, 374)
                log("    -> mouse click Continue")
            except Exception:
                pass
            try:
                page.mouse.click(990, 346)
                log("    -> mouse click Continue (wide)")
            except Exception:
                pass
            try:
                page.wait_for_function(
                    """() => {
                      const t = (document.body && document.body.innerText || '').toLowerCase();
                      const pw = document.querySelectorAll('input[type=password]').length;
                      if (pw > 0) return true;
                      if (t.includes('verify your identity') || t.includes('verification code')
                          || t.includes('security check') || t.includes('security challenge')
                          || t.includes("didn't catch that") || t.includes("doesn't quite match")) return true;
                      return false;
                    }""",
                    timeout=8000,
                )
            except Exception:
                time.sleep(0.6)
            continue
            idle_rounds = 0
            try:
                page.wait_for_function(
                    """() => {
                        const t = (document.body && document.body.innerText || '').toLowerCase();
                        return !!document.querySelector('input[type=password]')
                            || t.includes('err-837')
                            || t.includes('issue with your builder id');
                    }""",
                    timeout=10000,
                )
            except Exception:
                time.sleep(1.0)
            continue

        idle_rounds += 1
        if email_attempts == 0 and password_attempts == 0 and idle_rounds >= 20:
            _shot("blank_login")
            return LoginOutcome(
                False,
                changed,
                "登录页空白或未出现邮箱输入框（代理或页面未加载）",
            )
        if password_attempts >= 1 and idle_rounds in (4, 10, 20) and not seen_otp:
            log("    已提交密码，等待验证码/授权页")
        if (not require_consent) and password_attempts >= 1:
            waited = time.time() - (password_clicked_at or time.time())
            if waited >= max(1, int(failure_wait_s or 60)) and idle_rounds > 8:
                if seen_password:
                    body_now = (idc._body_text(page) or "").lower()
                    pw_now = idc._count_visible(page, "input[type=password]")
                    if pw_now == 0 and not _is_otp_page(page, body_now, pw_now) and not _is_email_page(page, body_now, pw_now):
                        log("    登录后页面未出现授权确认，按已登录继续改密")
                        _shot("signed_in_idle")
                        return LoginOutcome(True, changed)
                _shot("post_password_timeout")
                return LoginOutcome(
                    False,
                    changed,
                    "密码提交后等待授权确认页面超过 %d 秒" % max(1, int(failure_wait_s or 60)),
                )
        time.sleep(0.6)

    _shot("timeout")
    return LoginOutcome(False, changed, "Timeout - khong hoan tat login trong thoi gian cho.")


def _change_password_flow(
    page,
    email: str,
    password: str,
    *,
    new_password: str,
    mail_password: str,
    log: LogFn,
    stop_event,
    timeout_s: int,
    failure_wait_s: int,
    debug_dir: str,
    mailbox: Optional[GraphMailbox],
    proxy: str,
    mfa_secret: str,
    on_password_changed,
    on_secret=None,
    start_url: str,
    do_change_password: bool = True,
    do_change_mfa: bool = False,
    do_remove_old_mfa: bool = False,
) -> LoginOutcome:
    safe = "".join(c if c.isalnum() else "_" for c in (email or "acc"))[:20]
    shot = {"i": 0}

    def _shot(tag: str) -> None:
        if not debug_dir:
            return
        try:
            from pathlib import Path as _P
            _P(debug_dir).mkdir(exist_ok=True, parents=True)
            page.screenshot(path=str(_P(debug_dir) / f"{safe}_{shot['i']:02d}_{tag}.png"))
        except Exception:
            pass
        shot["i"] += 1

    secret = mfa_totp.normalize_secret(mfa_secret) if mfa_secret else ""
    box = mailbox
    if box is None and mail_password:
        candidate = GraphMailbox(email, mail_password, proxy=proxy, log=log)
        try:
            candidate.ensure_token()
            box = candidate
        except Exception as exc:
            log(f"    Outlook Graph 无法读信：{exc}")
            box = None
    if secret:
        log(f"    2FA: 已注入预设密钥（{secret[:4]}…{secret[-4:]}），验证码页按页面要求处理")

    time.sleep(random.uniform(0.02, 0.12))
    log("    打开 Builder ID 资料页，准备登录后改密")
    try:
        page.goto(start_url, wait_until="domcontentloaded", timeout=60000)
    except Exception as exc:
        raise RuntimeError(f"打开页面超时（代理或网络）：{exc}") from exc
    try:
        page.wait_for_selector("input, button, a", timeout=12000)
    except Exception:
        pass
    _shot("landing")
    try:
        page.wait_for_function(
            """() => {
                const t = ((document.body && document.body.innerText) || '').trim().toLowerCase();
                const inputs = document.querySelectorAll('input');
                return (inputs.length > 0 && t.length > 20)
                    || t.includes('builder id')
                    || t.includes('sign in')
                    || t.includes('amazon web services');
            }""",
            timeout=15000,
        )
    except Exception:
        _shot("blank_landing")
        return LoginOutcome(False, False, "登录页空白或未加载（代理或网络）")

    login_timeout = max(60, min(int(timeout_s or 220), 220))
    outcome = _run_login_loop(
        page,
        email,
        password,
        new_password=new_password,
        log=log,
        stop_event=stop_event,
        timeout_s=login_timeout,
        failure_wait_s=failure_wait_s,
        box=box,
        secret=secret,
        _shot=_shot,
        require_consent=False,
    )
    if not outcome.ok:
        return outcome
    changed_password = outcome.changed_password
    if changed_password:
        log("    登录过程中已被要求设置新密码，已写入目标新密码")
        if on_password_changed:
            try:
                on_password_changed(new_password)
            except Exception:
                pass
        if do_change_password and not do_change_mfa and not do_remove_old_mfa:
            return LoginOutcome(True, True)

    remaining = max(40, int(timeout_s or 220) - login_timeout + 90)
    current_password = new_password if changed_password else password
    changed_mfa = False
    secret = mfa_totp.normalize_secret(mfa_secret) if mfa_secret else secret
    _ensure_profile_home(page, log, _shot)
    if do_change_password and not changed_password:
        changed_on_profile = _change_password_on_profile(
            page,
            current_password,
            new_password,
            log=log,
            stop_event=stop_event,
            timeout_s=remaining,
            _shot=_shot,
            on_password_changed=on_password_changed,
            current_secret=secret,
            mailbox=box,
        )
        if not changed_on_profile.ok:
            return LoginOutcome(
                False,
                changed_on_profile.changed_password,
                changed_on_profile.error,
                mfa_secret=secret,
            )
        changed_password = True
        current_password = new_password
    elif do_change_password:
        log("    登录过程中已经改过密码，跳过资料页改密")

    if do_change_mfa or do_remove_old_mfa:
        mfa_out = _change_mfa_on_profile(
            page,
            log=log,
            stop_event=stop_event,
            timeout_s=max(90, remaining),
            _shot=_shot,
            on_secret=on_secret,
            current_secret=secret,
            current_password=current_password,
            mailbox=box,
            register_new=bool(do_change_mfa),
        )
        if mfa_out.mfa_secret:
            secret = mfa_out.mfa_secret
        if not mfa_out.ok:
            return LoginOutcome(
                False, changed_password, mfa_out.error,
                mfa_secret=secret, changed_mfa=bool(mfa_out.changed_mfa),
            )
        changed_mfa = bool(mfa_out.changed_mfa or do_change_mfa)
    return LoginOutcome(True, changed_password, mfa_secret=secret, changed_mfa=changed_mfa)


def _visible_locator(loc):
    try:
        el = loc.first
        if el.count() and el.is_visible():
            return el
    except Exception:
        return None
    return None


def _set_input_value(el, value: str) -> bool:
    def _got() -> str:
        try:
            return el.input_value() or ""
        except Exception:
            return ""

    try:
        el.click(timeout=2500)
        try:
            el.fill("")
        except Exception:
            pass
        el.fill(value)
        if _got() == value:
            return True
        try:
            el.evaluate(
                """(node, v) => {
                    const proto = node instanceof HTMLInputElement
                        ? window.HTMLInputElement.prototype
                        : window.HTMLTextAreaElement.prototype;
                    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
                    if (desc && desc.set) desc.set.call(node, v);
                    else node.value = v;
                    node.dispatchEvent(new Event('input', { bubbles: true }));
                    node.dispatchEvent(new Event('change', { bubbles: true }));
                }""",
                value,
            )
        except Exception:
            pass
        if _got() == value:
            return True
        try:
            el.click(timeout=2500)
            el.press("Control+A")
            el.press("Backspace")
            el.press_sequentially(value, delay=20)
        except Exception:
            pass
        return _got() == value
    except Exception:
        return False


def _modal_pair_inputs(page):
    scopes = []
    try:
        dialog = page.get_by_role("dialog")
        if dialog.count():
            scopes.append(dialog.first)
    except Exception:
        pass
    scopes.append(page)
    for scope in scopes:
        try:
            loc = scope.locator(
                "input[type=password]:visible, input[type=text]:visible"
            )
            found = []
            for i in range(min(loc.count(), 8)):
                el = loc.nth(i)
                try:
                    if not el.is_visible():
                        continue
                    itype = (el.get_attribute("type") or "text").lower()
                    name = (el.get_attribute("name") or "").lower()
                    if itype in ("hidden", "checkbox", "radio", "submit", "button", "email"):
                        continue
                    if "email" in name:
                        continue
                    found.append(el)
                except Exception:
                    continue
            if len(found) >= 2:
                return found[0], found[1]
        except Exception:
            continue
    return None, None


def _fill_builder_change_password_modal(page, new_password: str, log: LogFn) -> bool:
    """Fill the 2-field Builder ID modal (New + Confirm) and click its submit."""
    new_el = (
        _visible_locator(page.get_by_label("New password", exact=True))
        or _visible_locator(page.get_by_label("New password", exact=False))
        or _visible_locator(page.get_by_placeholder("Enter password", exact=False))
    )
    confirm_el = (
        _visible_locator(page.get_by_label("Confirm new password", exact=True))
        or _visible_locator(page.get_by_label("Confirm new password", exact=False))
        or _visible_locator(page.get_by_placeholder("Re-enter password", exact=False))
    )
    if new_el is None or confirm_el is None:
        new_el, confirm_el = _modal_pair_inputs(page)
    if new_el is None or confirm_el is None:
        log("    改密表单：找不到 New password / Confirm 输入框")
        return False
    time.sleep(0.4)
    if not _set_input_value(new_el, new_password):
        log("    改密表单：未能填入 New password")
        return False
    if not _set_input_value(confirm_el, new_password):
        log("    改密表单：未能填入 Confirm new password")
        return False
    try:
        got_new = new_el.input_value() or ""
        got_confirm = confirm_el.input_value() or ""
    except Exception:
        got_new, got_confirm = new_password, new_password
    if got_new != new_password or got_confirm != new_password:
        log(
            f"    改密表单：填入后校验失败，未提交 "
            f"(new={len(got_new)}/{len(new_password)} confirm={len(got_confirm)}/{len(new_password)})"
        )
        # Firefox 有时第一次 fill 被 React 清掉，再写一遍。
        _set_input_value(new_el, new_password)
        _set_input_value(confirm_el, new_password)
        try:
            got_new = new_el.input_value() or ""
            got_confirm = confirm_el.input_value() or ""
        except Exception:
            got_new, got_confirm = new_password, new_password
        if got_new != new_password or got_confirm != new_password:
            log("    改密表单：第二次填入仍不匹配")
            return False
    log(f"    改密表单已填入新密码（{len(new_password)} 位）")
    try:
        dialog = page.get_by_role("dialog")
        if dialog.count() and dialog.first.is_visible():
            btn = dialog.get_by_role("button", name="Change password", exact=True).first
            if btn.count() and btn.is_visible():
                btn.click(timeout=2500)
                log("    -> click modal 'Change password'")
                return True
    except Exception:
        pass
    if idc._click_button(page, ["Change password"], log):
        return True
    try:
        page.keyboard.press("Enter")
        return True
    except Exception:
        return False


def _change_password_on_profile(
    page,
    current_password: str,
    new_password: str,
    *,
    log: LogFn,
    stop_event,
    timeout_s: int,
    _shot,
    on_password_changed,
    current_secret: str = "",
    mailbox: Optional[GraphMailbox] = None,
) -> LoginOutcome:
    deadline = time.time() + max(30, int(timeout_s or 90))
    opened_security = False
    tried_profile_home = False
    submit_attempts = 0
    step_up = {"reauth": 0, "totp": 0, "error": ""}
    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            return LoginOutcome(False, False, "Da huy")
        idc._maybe_cookie_accept(page, log)
        body = (idc._body_text(page) or "").lower()
        pw_n = idc._count_visible(page, "input[type=password]")

        if any(m in body for m in PASSWORD_CHANGED_MARKERS):
            log("    资料页显示密码已更新")
            _shot("password_changed")
            if on_password_changed:
                try:
                    on_password_changed(new_password)
                except Exception:
                    pass
            return LoginOutcome(True, True)

        if _is_security_check(page, body):
            detail = idc._visible_error_text(page) or "Security check"
            _shot("captcha")
            return LoginOutcome(False, False, f"触发 AWS 人机验证 captcha（{detail}）：请换 IP 后重试")

        step = _try_profile_step_up(
            page, body, pw_n,
            current_password=current_password,
            current_secret=current_secret,
            log=log, _shot=_shot, counters=step_up,
            mailbox=mailbox, stop_event=stop_event,
        )
        if step == "error":
            return LoginOutcome(False, False, step_up.get("error") or "资料页二次验证失败")
        if step == "handled":
            continue

        if _page_has_little_content(body):
            time.sleep(0.8)
            continue

        if not _is_signed_in_profile(page, body, pw_n) and not opened_security:
            if _is_email_page(page, body, pw_n):
                return LoginOutcome(False, False, "尚未完成登录，无法打开资料页改密")
            if _is_otp_page(page, body, pw_n):
                step_up["error"] = ""
                step = _try_profile_step_up(
                    page, body, pw_n,
                    current_password=current_password,
                    current_secret=current_secret,
                    log=log, _shot=_shot, counters=step_up,
                    mailbox=mailbox, stop_event=stop_event,
                )
                if step == "handled":
                    continue
                if step == "error":
                    return LoginOutcome(False, False, step_up.get("error") or "资料页二次验证失败")
                return LoginOutcome(False, False, "尚未完成登录，无法打开资料页改密")

        if _looks_like_change_password_form(page, body):
            submit_attempts += 1
            if submit_attempts > 3:
                detail = idc._visible_error_text(page)
                _shot("change_password_stuck")
                return LoginOutcome(False, False, f"资料页改密失败：{detail or '页面未进入下一步'}")
            if any(m in body for m in INCORRECT_MARKERS) and submit_attempts > 1:
                detail = idc._visible_error_text(page) or "当前密码不正确或新密码不符合策略"
                _shot("change_password_rejected")
                return LoginOutcome(False, False, f"资料页改密被拒绝：{detail}")
            log("    填写资料页改密表单")
            _shot("change_password_form")
            filled = _fill_builder_change_password_modal(page, new_password, log)
            if not filled:
                _shot("change_password_fill_failed")
                time.sleep(1.0)
                continue
            time.sleep(2.5)
            body_after = (idc._body_text(page) or "").lower()
            if any(m in body_after for m in PASSWORD_CHANGED_MARKERS):
                log("    资料页改密成功")
                _shot("password_changed")
                if on_password_changed:
                    try:
                        on_password_changed(new_password)
                    except Exception:
                        pass
                return LoginOutcome(True, True)
            if "invalid password" in body_after or (
                any(m in body_after for m in INCORRECT_MARKERS)
                and _looks_like_change_password_form(page, body_after)
            ):
                detail = idc._visible_error_text(page) or "当前密码不正确或新密码不符合策略"
                _shot("change_password_rejected")
                return LoginOutcome(False, False, f"资料页改密被拒绝：{detail}")
            if not _looks_like_change_password_form(page, body_after):
                log("    改密表单已消失，视为密码已更新")
                _shot("password_changed")
                if on_password_changed:
                    try:
                        on_password_changed(new_password)
                    except Exception:
                        pass
                return LoginOutcome(True, True)
            continue

        if _open_security_or_change_password(page, log, body):
            opened_security = True
            try:
                page.wait_for_selector("input[type=password]", timeout=12000)
            except Exception:
                try:
                    page.wait_for_function(SECURITY_OR_REAUTH_JS, timeout=8000)
                except Exception:
                    time.sleep(1.2)
            _shot("opened_security")
            continue

        if "page not found" in body or "typed the address incorrectly" in body:
            log("    资料页路由无效，回到 Builder ID 资料首页")
            try:
                page.goto(BUILDER_ID_PROFILE_URL, wait_until="domcontentloaded")
                time.sleep(1.0)
                _shot("profile_home")
            except Exception:
                pass
            continue

        if not tried_profile_home:
            tried_profile_home = True
            dest = BUILDER_ID_PROFILE_URL
            try:
                log(f"    打开 Builder ID 资料页 {dest}")
                page.goto(dest, wait_until="domcontentloaded")
                time.sleep(1.0)
                _shot("profile_home")
            except Exception:
                pass
            continue

        time.sleep(0.6)

    _shot("change_password_timeout")
    return LoginOutcome(False, False, "登录成功但未能完成资料页改密")


def _looks_like_change_password_form(page, body: str) -> bool:
    """True only when the New/Confirm password form is actually open.

    The Security settings page includes the sentence "change your password and
    sign out everywhere", which must not be treated as the form.
    """
    try:
        dialog = page.get_by_role("dialog")
        if dialog.count() and dialog.first.is_visible():
            dtext = (dialog.first.inner_text() or "").lower()
            if any(m in dtext for m in CHANGE_PASSWORD_FORM_MARKERS) or "change password" in dtext:
                return True
    except Exception:
        pass
    pw_n = 0
    try:
        pw_n = idc._count_visible(page, "input[type=password]")
    except Exception:
        pw_n = 0
    if pw_n < 1:
        return False
    text = (body or "").lower()
    form_markers = (
        "new password",
        "confirm new password",
        "confirm password",
        "current password",
        "re-enter password",
        "reenter password",
        "新密码",
        "确认密码",
        "当前密码",
    )
    if any(m in text for m in form_markers):
        return True
    try:
        labels = " ".join(
            (page.locator("label, legend, h1, h2, h3").all_inner_texts() or [])
        ).lower()
    except Exception:
        labels = ""
    return any(m in labels for m in form_markers)


def _open_security_or_change_password(page, log: LogFn, body: str, prefer_mfa: bool = False) -> bool:
    if _is_security_settings_page(body):
        if prefer_mfa:
            return True
        return _click_profile_button(page, PASSWORD_ACTION_BUTTONS, log)
    if _click_profile_nav(page, "Security", log):
        return True
    if _click_profile_nav(page, "安全设置", log) or _click_profile_nav(page, "安全", log):
        return True
    if prefer_mfa:
        return False
    return _click_profile_button(page, PASSWORD_ACTION_BUTTONS, log)


MFA_DEVICE_NAMES_JS = """() => {
  const names = [];
  const seen = new Set();
  const norm = (v) => String(v || '').replace(/\\s+/g, ' ').trim();
  const addName = (raw) => {
    const name = norm(raw);
    if (!name || name.length > 120) return;
    const low = name.toLowerCase();
    if (
      low === 'name' || low === 'type' || low === 'totp' || low === '-' ||
      low.includes('loading') || low.includes('registered date') ||
      low.includes('make and model') || low.includes('select row') ||
      low.includes("haven't registered any mfa devices") ||
      low.includes('have not registered any mfa devices') ||
      low.includes('no mfa devices') || low.includes('no devices') ||
      /^oct\\s+\\d{1,2},\\s+\\d{4}$/i.test(name) ||
      /^[a-z]{3}\\s+\\d{1,2},\\s+\\d{4}$/i.test(name)
    ) return;
    if (seen.has(low)) return;
    seen.add(low);
    names.push(name);
  };

  const textOf = (el) => norm(el && (el.innerText || el.textContent || ''));
  const all = Array.from(document.querySelectorAll('body *'));
  const mfaHeader = all.find((el) => /multi-factor authentication\\s*\\(mfa\\)\\s*devices/i.test(textOf(el)));
  const signedHeader = all.find((el) => /^signed in devices\\b/i.test(textOf(el)));
  const mfaTop = mfaHeader ? mfaHeader.getBoundingClientRect().top : null;
  const signedTop = signedHeader ? signedHeader.getBoundingClientRect().top : null;

  const rows = Array.from(document.querySelectorAll('table tbody tr, [role=row]'));
  for (const row of rows) {
    const rowText = textOf(row);
    if (!rowText || /loading/i.test(rowText)) continue;
    const box = row.getBoundingClientRect();
    if (mfaTop !== null && box.top <= mfaTop) continue;
    if (signedTop !== null && box.top >= signedTop) continue;
    if (/\\b(ip address|sign-in date|signed in devices|device\\s+ip address)\\b/i.test(rowText)) continue;

    const cells = Array.from(row.querySelectorAll('[role=cell], td, th'));
    if (cells.length) {
      for (const cell of cells) {
        const value = textOf(cell);
        if (!value) continue;
        addName(value);
        if (names.length && names[names.length - 1].toLowerCase() === value.toLowerCase()) break;
      }
      continue;
    }

    const m = rowText.match(/([^\\n]+?['’]s MFA\\s*\\d+)/i) || rowText.match(/\\b([A-Za-z0-9._@+'’\\- ]{2,80} MFA\\s*\\d+)\\b/i);
    if (m) addName(m[1]);
  }

  if (!names.length) {
    const text = (document.body && document.body.innerText) || '';
    const re = /([^\\n]+?['’]s MFA\\s*\\d+)/gi;
    let m;
    while ((m = re.exec(text))) addName(m[1]);
  }
  return names;
}"""


def _mfa_device_names(page) -> list[str]:
    try:
        names = page.evaluate(MFA_DEVICE_NAMES_JS)
    except Exception:
        names = []
    out: list[str] = []
    seen: set[str] = set()
    for raw in names or []:
        name = " ".join(str(raw or "").split())
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    if out:
        return out
    body = idc._body_text(page) or ""
    for m in re.finditer(r"([^\n]+?['’']s MFA\s*\d+)", body, re.I):
        name = " ".join(m.group(1).split())
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out


def _newest_mfa_name(names: list[str]) -> str:
    best = ""
    best_n = -1
    for name in names or []:
        m = re.search(r"MFA\s*(\d+)\s*$", name, re.I)
        if not m:
            continue
        num = int(m.group(1))
        if num >= best_n:
            best_n = num
            best = name
    if best:
        return best
    return names[-1] if names else ""


def _wait_mfa_table_ready(page, timeout_s: float = 18) -> None:
    try:
        page.wait_for_function(
            """() => {
              const t = (document.body && document.body.innerText || '').toLowerCase();
              if (!t.includes('mfa devices') && !t.includes('register device')) return false;
              if (t.includes('loading...')) return false;
              return /mfa\\s*\\d+/i.test(t) || t.includes("register device");
            }""",
            timeout=max(3, int(timeout_s * 1000)),
        )
    except Exception:
        time.sleep(1.2)


def _select_mfa_device(page, name: str, log: LogFn) -> bool:
    if not name:
        return False
    try:
        result = page.evaluate(
            """(name) => {
              const norm = (v) => String(v || '').replace(/\\s+/g, ' ').trim();
              const textOf = (el) => norm(el && (el.innerText || el.textContent || ''));
              const all = Array.from(document.querySelectorAll('body *'));
              const mfaHeader = all.find((el) => /multi-factor authentication\\s*\\(mfa\\)\\s*devices/i.test(textOf(el)));
              const signedHeader = all.find((el) => /^signed in devices\\b/i.test(textOf(el)));
              const mfaTop = mfaHeader ? mfaHeader.getBoundingClientRect().top : null;
              const signedTop = signedHeader ? signedHeader.getBoundingClientRect().top : null;
              const wanted = norm(name).toLowerCase();
              const rows = Array.from(document.querySelectorAll('table tbody tr, [role=row]'));
              const hit = rows.find((r) => {
                const box = r.getBoundingClientRect();
                if (mfaTop !== null && box.top <= mfaTop) return false;
                if (signedTop !== null && box.top >= signedTop) return false;
                const cells = Array.from(r.querySelectorAll('[role=cell], td, th'))
                  .map(textOf).filter(Boolean);
                return cells.some((value) => value.toLowerCase() === wanted);
              });
              if (!hit) return false;
              const radio = hit.querySelector('input[type=radio], [role=radio]');
              const cell = hit.querySelector('td, [role=cell], [role=gridcell], label');
              const target = radio || cell || hit;
              target.click();
              if (radio && radio instanceof HTMLInputElement) {
                radio.checked = true;
                radio.dispatchEvent(new Event('input', {bubbles: true}));
                radio.dispatchEvent(new Event('change', {bubbles: true}));
              }
              return true;
            }""",
            name,
        )
        if result:
            log(f"    选中 MFA 设备（脚本）：{name}")
            return True
    except Exception:
        pass
    try:
        el = page.get_by_text(name, exact=True).first
        if el.count() and el.is_visible():
            el.click(timeout=2500, force=True)
            log(f"    选中 MFA 设备（点名称）：{name}")
            return True
    except Exception:
        pass
    return False


def _mfa_delete_enabled(page) -> bool:
    try:
        buttons = page.get_by_role("button", name="Delete", exact=True)
        n = min(buttons.count(), 8)
        for i in range(n):
            if _button_is_usable(buttons.nth(i), "Delete"):
                return True
    except Exception:
        pass
    try:
        loc = page.locator("button").filter(has_text=re.compile(r"^\s*Delete\s*$"))
        n = min(loc.count(), 8)
        for i in range(n):
            if _button_is_usable(loc.nth(i), "Delete"):
                return True
    except Exception:
        pass
    return False


def _button_is_usable(el, want: str) -> bool:
    try:
        if not el.is_visible():
            return False
        text = " ".join((el.inner_text() or "").split())
        if "all active sessions" in text.lower():
            return False
        if want == "Delete" and text and text != "Delete":
            return False
        aria = (el.get_attribute("aria-disabled") or "").lower()
        if aria in ("true", "1"):
            return False
        if el.get_attribute("disabled") is not None:
            return False
        try:
            if not el.is_enabled():
                return False
        except Exception:
            pass
        return True
    except Exception:
        return False


def _click_exact_enabled_button(page, labels, log: LogFn) -> bool:
    """Click a visible, enabled button by exact name. Never matches longer labels."""
    for t in labels:
        try:
            buttons = page.get_by_role("button", name=t, exact=True)
            n = min(buttons.count(), 8)
        except Exception:
            continue
        for i in range(n):
            try:
                el = buttons.nth(i)
                if not _button_is_usable(el, t):
                    continue
                el.click(timeout=2500)
                log(f"    -> click '{t}'")
                return True
            except Exception:
                continue
        try:
            loc = page.locator("button").filter(has_text=re.compile(rf"^\s*{re.escape(t)}\s*$"))
            n = min(loc.count(), 8)
            for i in range(n):
                el = loc.nth(i)
                if not _button_is_usable(el, t):
                    continue
                el.click(timeout=2500)
                log(f"    -> click '{t}'")
                return True
        except Exception:
            continue
    return False


def _js_click_mfa_delete(page) -> str:
    try:
        return str(page.evaluate(
            """() => {
              const btns = Array.from(document.querySelectorAll('button, [role=button]'));
              const match = (b) => {
                const t = (b.innerText || b.getAttribute('aria-label') || '').replace(/\\s+/g, ' ').trim();
                return t === 'Delete';
              };
              const visible = (b) => {
                const st = window.getComputedStyle(b);
                if (st.display === 'none' || st.visibility === 'hidden' || st.opacity === '0') return false;
                const r = b.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
              };
              const enabled = (b) => !b.disabled && (b.getAttribute('aria-disabled') || '').toLowerCase() !== 'true';
              const del = btns.find((b) => match(b) && visible(b) && enabled(b));
              if (del) { del.click(); return 'clicked'; }
              const any = btns.find((b) => match(b) && visible(b));
              if (any) { any.click(); return 'clicked-anyway'; }
              return 'missing';
            }"""
        ) or "missing")
    except Exception as exc:
        return f"error:{exc}"


def _click_dialog_or_exact_button(page, labels, log: LogFn) -> bool:
    dialog = page.locator("[role=dialog], [aria-modal=true], [class*='modal' i], [class*='dialog' i]")
    try:
        n = min(dialog.count(), 6)
        for i in range(n):
            scope = dialog.nth(i)
            try:
                if not scope.is_visible():
                    continue
            except Exception:
                continue
            for t in labels:
                try:
                    el = scope.get_by_role("button", name=t, exact=True).last
                    if el.count() and el.is_visible():
                        el.click(timeout=2500)
                        log(f"    -> 确认 '{t}'")
                        return True
                except Exception:
                    continue
    except Exception:
        pass
    return _click_exact_enabled_button(page, labels, log)


def _looks_like_mfa_delete_confirm(body: str) -> bool:
    text = (body or "").lower()
    return "delete mfa device" in text and ("are you sure" in text or "cancel" in text)


def _confirm_mfa_delete_dialog(page, log: LogFn) -> bool:
    if _click_dialog_or_exact_button(page, MFA_DELETE_CONFIRM_BUTTONS, log):
        return True
    try:
        state = page.evaluate(
            """() => {
              const nodes = Array.from(document.querySelectorAll('body *'));
              let modal = null, best = Infinity;
              for (const el of nodes) {
                const t = el.innerText || '';
                if (!/delete mfa device/i.test(t) || !/cancel/i.test(t)) continue;
                if (t.length < best && t.length < 800) { best = t.length; modal = el; }
              }
              if (!modal) return 'no-modal';
              const btn = Array.from(modal.querySelectorAll('button, [role=button]')).find((b) => {
                const t = (b.innerText || b.getAttribute('aria-label') || '').replace(/\\s+/g, ' ').trim();
                return t === 'Delete';
              });
              if (!btn) return 'no-btn';
              btn.click();
              return 'clicked';
            }"""
        )
        log(f"    确认删除 MFA：{state}")
        return str(state) == "clicked"
    except Exception as exc:
        log(f"    确认删除 MFA 失败：{exc}")
        return False


def _read_mfa_name_field(page) -> str:
    locators = []
    try:
        locators.append(page.get_by_label("MFA name", exact=False))
    except Exception:
        pass
    locators.extend([
        page.locator("input[aria-label*='MFA name' i]"),
        page.locator("input[name*='mfa' i]:visible"),
    ])
    for loc in locators:
        try:
            el = loc.first
            if el.count() and el.is_visible():
                val = (el.input_value() or "").strip()
                if val:
                    return val
        except Exception:
            continue
    body = idc._body_text(page) or ""
    m = re.search(r"([^\n]+?['’']s MFA\s*\d+)", body, re.I)
    return " ".join(m.group(1).split()) if m else ""


def _looks_like_mfa_registered_dialog(body: str) -> bool:
    text = (body or "").lower()
    return any(m in text for m in MFA_REGISTERED_DIALOG_MARKERS)


def _dismiss_mfa_registered_dialog(page, log: LogFn) -> bool:
    if _click_exact_enabled_button(page, ("Done", "Close", "Continue", "完成"), log):
        return True
    return idc._click_button(page, ["Done", "Close", "Continue", "完成"], log)


def _ensure_security_settings_page(page, log: LogFn, _shot, tag: str = "security") -> bool:
    body = (idc._body_text(page) or "").lower()
    if _is_security_settings_page(body):
        return True
    if _looks_like_mfa_registered_dialog(body):
        return False
    clicked = (
        _click_profile_nav(page, "Security", log)
        or _click_profile_nav(page, "安全设置", log)
        or _click_profile_nav(page, "安全", log)
    )
    if not clicked:
        return False
    time.sleep(1.0)
    _shot(tag)
    body = (idc._body_text(page) or "").lower()
    return _is_security_settings_page(body)


def _devices_to_delete(names: list[str], keep_name: str, snapshot: list[str] | None = None) -> list[str]:
    keep = (keep_name or "").strip()
    if not keep:
        return []
    keep_key = keep.lower()
    if snapshot:
        snap_keys = {n.lower() for n in snapshot}
        return [n for n in names if n.lower() in snap_keys and n.lower() != keep_key]
    return [n for n in names if n.lower() != keep_key]


def _delete_named_mfa_devices(
    page,
    names: list[str],
    *,
    keep_name: str,
    current_password: str,
    current_secret: str,
    log: LogFn,
    _shot,
    mailbox: Optional[GraphMailbox],
    stop_event,
    deadline: float,
) -> list[str]:
    leftover: list[str] = []
    counters = {"reauth": 0, "totp": 0, "email_otp": 0, "error": ""}
    targets = [n for n in names if n and n != keep_name]
    for name in targets:
        if time.time() >= deadline or (stop_event is not None and stop_event.is_set()):
            leftover.append(name)
            leftover.extend(targets[targets.index(name) + 1 :])
            break
        if not _ensure_security_settings_page(page, log, _shot, "before_delete"):
            leftover.append(name)
            continue
        time.sleep(0.4)
        present = _mfa_device_names(page)
        if name not in present:
            log(f"    旧 MFA 已不在列表：{name}")
            continue
        _wait_mfa_table_ready(page, timeout_s=12)
        if not _select_mfa_device(page, name, log):
            log(f"    无法选中 MFA 设备：{name}")
            leftover.append(name)
            continue
        enabled = False
        for _ in range(16):
            if _mfa_delete_enabled(page):
                enabled = True
                break
            time.sleep(0.25)
        if not enabled:
            _select_mfa_device(page, name, log)
            time.sleep(0.4)
        _shot("mfa_selected")
        clicked_delete = False
        for _ in range(12):
            if _click_exact_enabled_button(page, MFA_DELETE_ACTION_BUTTONS, log):
                clicked_delete = True
                break
            time.sleep(0.25)
        if not clicked_delete:
            js_state = _js_click_mfa_delete(page)
            log(f"    Delete 按钮脚本点击：{js_state}")
            clicked_delete = js_state.startswith("clicked")
        if not clicked_delete:
            log("    找不到可用的 Delete 按钮，未点击「Delete all active sessions」")
            leftover.append(name)
            continue
        try:
            page.wait_for_selector("[role=dialog], [aria-modal=true], [class*='modal' i], [class*='dialog' i]", timeout=4000)
        except Exception:
            time.sleep(0.5)
        _shot("mfa_delete_confirm")
        if not _confirm_mfa_delete_dialog(page, log):
            log("    未能点击删除确认框里的 Delete")
            leftover.append(name)
            continue
        gone = False
        wait_end = min(deadline, time.time() + 50)
        while time.time() < wait_end:
            if stop_event is not None and stop_event.is_set():
                break
            idc._maybe_cookie_accept(page, log)
            body = (idc._body_text(page) or "").lower()
            pw_n = idc._count_visible(page, "input[type=password]")
            if _is_security_check(page, body):
                leftover.append(name)
                break
            if _looks_like_mfa_delete_confirm(body):
                _confirm_mfa_delete_dialog(page, log)
                time.sleep(0.6)
                continue
            step = _try_profile_step_up(
                page, body, pw_n,
                current_password=current_password,
                current_secret=current_secret,
                log=log, _shot=_shot, counters=counters,
                mailbox=mailbox, stop_event=stop_event,
            )
            if step == "error":
                log(f"    删除 MFA 二次验证失败：{counters.get('error') or ''}")
                leftover.append(name)
                break
            if step == "handled":
                continue
            if _looks_like_mfa_registered_dialog(body):
                _dismiss_mfa_registered_dialog(page, log)
                time.sleep(0.6)
                continue
            if _is_security_settings_page(body):
                now_names = _mfa_device_names(page)
                if name not in now_names:
                    log(f"    已删除旧 MFA：{name}")
                    _shot("mfa_deleted")
                    gone = True
                    break
            elif _ensure_security_settings_page(page, log, _shot, "after_delete"):
                continue
            time.sleep(0.7)
        if not gone and name not in leftover:
            leftover.append(name)
    return leftover


def _finish_mfa_after_bind(
    page,
    *,
    bound_secret: str,
    keep_name: str,
    old_names: list[str],
    current_password: str,
    log: LogFn,
    _shot,
    mailbox: Optional[GraphMailbox],
    stop_event,
    deadline: float,
) -> LoginOutcome:
    if _looks_like_mfa_registered_dialog((idc._body_text(page) or "").lower()):
        keep_name = keep_name or _read_mfa_name_field(page)
        _shot("mfa_registered_dialog")
        _dismiss_mfa_registered_dialog(page, log)
        time.sleep(1.0)
    _ensure_security_settings_page(page, log, _shot, "security_after_bind")
    time.sleep(0.6)
    names = _mfa_device_names(page)
    if not names:
        return LoginOutcome(
            False, False,
            "新2FA已绑定但无法读取 MFA 设备列表，未删除任何旧设备",
            mfa_secret=bound_secret, changed_mfa=True,
        )
    name_by_key = {n.casefold(): n for n in names}
    if keep_name:
        keep_name = name_by_key.get(keep_name.casefold(), "")
    if not keep_name and old_names:
        old_keys = {n.casefold() for n in old_names}
        new_names = [n for n in names if n.casefold() not in old_keys]
        if len(new_names) == 1:
            keep_name = new_names[0]
    if not keep_name:
        if len(names) == 1:
            keep_name = names[0]
        else:
            return LoginOutcome(
                False, False,
                f"新2FA已绑定但无法确认要保留的 MFA 设备（检测到 {len(names)} 台），未删除任何设备",
                mfa_secret=bound_secret, changed_mfa=True,
            )
    to_delete = _devices_to_delete(names, keep_name)
    if not to_delete:
        log("    新 2FA 已绑定，没有需要删除的旧设备")
        _shot("mfa_changed")
        return LoginOutcome(True, mfa_secret=bound_secret, changed_mfa=True)
    log(f"    准备删除除新 MFA 外的其他设备：{to_delete}；保留 {keep_name or '最新一台'}")
    leftover = _delete_named_mfa_devices(
        page, to_delete,
        keep_name=keep_name,
        current_password=current_password,
        current_secret=bound_secret,
        log=log, _shot=_shot, mailbox=mailbox, stop_event=stop_event,
        deadline=deadline,
    )
    if leftover:
        return LoginOutcome(
            False, False,
            "新2FA已绑定但未能删除旧设备：" + "、".join(leftover),
            mfa_secret=bound_secret, changed_mfa=True,
        )
    log("    旧 2FA 设备已删除")
    _shot("mfa_changed")
    return LoginOutcome(True, mfa_secret=bound_secret, changed_mfa=True)


def _change_mfa_on_profile(
    page,
    *,
    log: LogFn,
    stop_event,
    timeout_s: int,
    _shot,
    on_secret,
    current_secret: str,
    current_password: str = "",
    mailbox: Optional[GraphMailbox] = None,
    register_new: bool = True,
) -> LoginOutcome:
    deadline = time.time() + max(30, int(timeout_s or 90))
    opened_security = False
    tried_profile_home = False
    register_attempts = 0
    old_names: list[str] = []
    keep_name = ""
    bound_secret = current_secret
    registered = False
    step_up = {"reauth": 0, "totp": 0, "error": ""}
    if register_new:
        log("    开始在 Builder ID 资料页设置/更换 2FA（绑定成功后删除旧设备）")
    else:
        log("    开始在 Builder ID 资料页删除旧 2FA（不注册新设备）")
    _shot("profile_mfa")
    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            return LoginOutcome(
                False, False, "Da huy",
                mfa_secret=bound_secret, changed_mfa=registered,
            )
        idc._maybe_cookie_accept(page, log)
        body = (idc._body_text(page) or "").lower()
        pw_n = idc._count_visible(page, "input[type=password]")
        if _is_security_check(page, body):
            detail = idc._visible_error_text(page) or "Security check"
            _shot("captcha")
            return LoginOutcome(
                False, False, f"触发 AWS 人机验证 captcha（{detail}）：请换 IP 后重试",
                mfa_secret=bound_secret, changed_mfa=registered,
            )
        step_secret = bound_secret if registered else current_secret
        step = _try_profile_step_up(
            page, body, pw_n,
            current_password=current_password,
            current_secret=step_secret,
            log=log, _shot=_shot, counters=step_up,
            mailbox=mailbox, stop_event=stop_event,
        )
        if step == "error":
            return LoginOutcome(
                False, False, step_up.get("error") or "资料页二次验证失败",
                mfa_secret=bound_secret, changed_mfa=registered,
            )
        if step == "handled":
            continue
        if _looks_like_change_password_form(page, body):
            log("    关闭改密弹窗，继续 2FA")
            if not idc._click_button(page, ["Cancel", "Close"], log):
                try:
                    page.keyboard.press("Escape")
                except Exception:
                    pass
            time.sleep(0.8)
            continue
        if _page_has_little_content(body):
            time.sleep(0.8)
            continue
        if not _is_signed_in_profile(page, body, pw_n) and not opened_security:
            if _is_email_page(page, body, pw_n) or (
                _is_otp_page(page, body, pw_n) and not current_secret
            ):
                return LoginOutcome(False, False, "尚未完成登录，无法打开资料页 2FA", mfa_secret=current_secret)
        if _looks_like_mfa_registered_dialog(body):
            keep_name = keep_name or _read_mfa_name_field(page)
            _shot("mfa_registered_dialog")
            _dismiss_mfa_registered_dialog(page, log)
            time.sleep(1.0)
            continue
        if registered:
            return _finish_mfa_after_bind(
                page,
                bound_secret=bound_secret,
                keep_name=keep_name,
                old_names=old_names,
                current_password=current_password,
                log=log, _shot=_shot, mailbox=mailbox, stop_event=stop_event,
                deadline=deadline,
            )
        has_register = any(m in body for m in idc.MFA_REGISTER_MARKERS)
        if not register_new and has_register:
            log("    仅删除旧 2FA，关闭注册页，不会再点 Register")
            if not idc._click_button(page, ["Cancel", "Close", "Back"], log):
                try:
                    page.keyboard.press("Escape")
                except Exception:
                    pass
            time.sleep(0.8)
            continue
        if register_new and has_register:
            register_attempts += 1
            if register_attempts > 3:
                return LoginOutcome(False, False, "资料页 2FA 绑定多次未完成", mfa_secret=current_secret)
            log("    检测到 2FA 绑定页，开始注册 authenticator")
            ok_mfa, sec = idc._handle_mfa_registration(
                page, log, _shot, known_secret="", on_secret=on_secret, settings_page=True,
            )
            if ok_mfa and sec:
                log("    资料页 2FA 绑定成功，接着删除旧设备")
                _shot("mfa_changed")
                registered = True
                bound_secret = sec
                keep_name = keep_name or _read_mfa_name_field(page)
                continue
            time.sleep(1.0)
            continue
        if current_secret and any(m in body for m in idc.MFA_VERIFY_MARKERS):
            idc._fill_current_totp_if_present(page, current_secret, log)
            time.sleep(0.8)
            continue
        if _is_security_settings_page(body):
            opened_security = True
            _wait_mfa_table_ready(page, timeout_s=18)
            names = _mfa_device_names(page)
            if register_new:
                if not old_names and names:
                    old_names = list(names)
                    log(f"    更换前已有 MFA 设备：{old_names}")
                if _click_profile_button(page, MFA_REGISTER_ACTION_BUTTONS, log):
                    try:
                        page.wait_for_function(
                            """() => {
                                const t = (document.body && document.body.innerText || '').toLowerCase();
                                return t.includes('secret key') || t.includes('qr code')
                                    || t.includes('scan the qr') || t.includes('show secret')
                                    || t.includes('enter key manually') || t.includes('authenticator app')
                                    || t.includes('verify your identity')
                                    || t.includes('we just sent a verification code');
                            }""",
                            timeout=12000,
                        )
                    except Exception:
                        time.sleep(1.2)
                    _shot("opened_replace_mfa")
                    continue
            else:
                if not names:
                    time.sleep(0.8)
                    continue
                # AWS does not expose which listed device owns current_secret.
                # Never guess when multiple devices exist: deleting the wrong
                # device would be irreversible from this workflow.
                if len(names) == 1:
                    keep_name = names[0]
                    log("    当前只有一台 MFA 设备，无需删除；为安全起见不执行删除")
                    _shot("mfa_no_old")
                    return LoginOutcome(True, mfa_secret=current_secret, changed_mfa=False)
                return LoginOutcome(
                    False, False,
                    f"检测到 {len(names)} 台 MFA 设备，但无法从提供的密钥确认要保留哪一台；为安全起见未删除任何设备",
                    mfa_secret=current_secret,
                )
        if not _is_security_settings_page(body) and _open_security_or_change_password(
            page, log, body, prefer_mfa=True
        ):
            opened_security = True
            try:
                page.wait_for_function(SECURITY_OR_REAUTH_JS, timeout=12000)
            except Exception:
                time.sleep(1.2)
            _shot("opened_security_mfa")
            continue
        if "page not found" in body or "typed the address incorrectly" in body:
            log("    资料页路由无效，回到 Builder ID 资料首页")
            try:
                page.goto(BUILDER_ID_PROFILE_URL, wait_until="domcontentloaded")
                time.sleep(1.0)
                _shot("profile_home")
            except Exception:
                pass
            continue
        if not tried_profile_home:
            tried_profile_home = True
            dest = BUILDER_ID_PROFILE_URL
            try:
                log(f"    打开 Builder ID 资料页 {dest}")
                page.goto(dest, wait_until="domcontentloaded")
                time.sleep(1.0)
                _shot("profile_home")
            except Exception:
                pass
            continue
        time.sleep(0.6)
    _shot("change_mfa_timeout")
    if registered and bound_secret:
        return LoginOutcome(
            False, False, "新2FA已绑定但未能删除旧设备",
            mfa_secret=bound_secret, changed_mfa=True,
        )
    if register_new:
        return LoginOutcome(False, False, "登录成功但未能完成资料页 2FA 设置", mfa_secret=current_secret)
    return LoginOutcome(False, False, "登录成功但未能删除旧 2FA 设备", mfa_secret=current_secret)


def _page_url(page) -> str:
    try:
        return (page.url or "").lower()
    except Exception:
        return ""


def _page_has_little_content(body: str) -> bool:
    return len((body or "").strip()) < 80


def _looks_like_profile_body(body: str, url: str = "") -> bool:
    text = (body or "").lower()
    if any(m in text for m in PROFILE_BODY_MARKERS):
        return True
    if "sign out" in text and "aws builder id" in text:
        return True
    url = (url or "").lower()
    if "profile.aws.amazon.com" in url and "aws builder id" in text:
        return True
    return False


def _is_security_settings_page(body: str) -> bool:
    text = (body or "").lower()
    if "mfa devices" in text or "register device" in text:
        return True
    if "change password" in text and any(
        m in text for m in ("multi-factor", "authenticator", "passkey", "mfa device", "recovery email")
    ):
        return True
    if "security settings" in text:
        return True
    return False


def _wait_for_profile_or_consent(page, timeout_ms: int = 20000) -> None:
    try:
        page.wait_for_function(PROFILE_READY_JS, timeout=timeout_ms)
    except Exception:
        pass


def _finish_change_login_if_ready(page, log: LogFn, _shot, changed: bool):
    """After OTP/TOTP in a change-password job, wait for the profile (not Allow access)."""
    _wait_for_profile_or_consent(page, timeout_ms=8000)
    body_now = (idc._body_text(page) or "").lower()
    pw_now = idc._count_visible(page, "input[type=password]")
    if _is_otp_page(page, body_now, pw_now) or _is_email_page(page, body_now, pw_now):
        return None
    if _is_security_check(page, body_now):
        return None
    log("    验证已通过，登录完成")
    _shot("signed_in")
    return LoginOutcome(True, changed)


def _ensure_profile_home(page, log: LogFn, _shot) -> None:
    body = (idc._body_text(page) or "").lower()
    pw_n = idc._count_visible(page, "input[type=password]")
    if _is_signed_in_profile(page, body, pw_n):
        return
    try:
        log(f"    打开 Builder ID 资料页 {BUILDER_ID_PROFILE_URL}")
        page.goto(BUILDER_ID_PROFILE_URL, wait_until="domcontentloaded")
        _wait_for_profile_or_consent(page, timeout_ms=20000)
    except Exception:
        time.sleep(1.5)
    _shot("profile_home")


def _click_profile_button(page, labels, log: LogFn) -> bool:
    """Click a visible button by exact name (Register device / Change password)."""
    for t in labels:
        try:
            el = page.get_by_role("button", name=t, exact=True).first
            if el.count() and el.is_visible():
                el.click(timeout=2500)
                log(f"    -> click '{t}'")
                return True
        except Exception:
            pass
    return idc._click_button(page, labels, log)


def _click_profile_nav(page, label: str, log: LogFn) -> bool:
    """Click the profile sidebar item (My details / Security / Privacy & data)."""
    scopes = (
        page.locator("nav"),
        page.locator("aside"),
        page.locator("[role=navigation]"),
        page.locator("[class*='side' i]"),
        page.locator("[class*='nav' i]"),
    )
    for scope in scopes:
        try:
            el = scope.get_by_text(label, exact=True).first
            if el.count() and el.is_visible():
                el.click(timeout=2500)
                log(f"    -> 资料页侧栏 '{label}'")
                return True
        except Exception:
            pass
    for role in ("link", "tab", "menuitem"):
        try:
            el = page.get_by_role(role, name=label, exact=True).first
            if el.count() and el.is_visible():
                el.click(timeout=2500)
                log(f"    -> 资料页 {role} '{label}'")
                return True
        except Exception:
            pass
    try:
        el = page.get_by_text(label, exact=True).first
        if el.count() and el.is_visible():
            el.click(timeout=2500)
            log(f"    -> 资料页 '{label}'")
            return True
    except Exception:
        pass
    return False


def _try_profile_step_up(
    page,
    body: str,
    pw_n: int,
    *,
    current_password: str,
    current_secret: str,
    log: LogFn,
    _shot,
    counters: dict,
    mailbox: Optional[GraphMailbox] = None,
    stop_event=None,
) -> str:
    """Fill step-up password / email OTP / TOTP when Security requires re-auth.

    Returns 'handled', 'error', or '' if this is not a step-up challenge.
    """
    if pw_n == 1 and not _looks_like_change_password_form(page, body):
        if not current_password:
            counters["error"] = "资料页二次验证需要当前密码"
            return "error"
        counters["reauth"] = int(counters.get("reauth") or 0) + 1
        if counters["reauth"] > 3:
            detail = idc._visible_error_text(page)
            counters["error"] = f"资料页二次验证密码多次未通过：{detail or '提交后未进入下一步'}"
            return "error"
        if any(m in (body or "") for m in INCORRECT_MARKERS) and counters["reauth"] > 1:
            detail = idc._visible_error_text(page) or "密码不正确"
            counters["error"] = f"资料页二次验证密码被拒绝：{detail}"
            return "error"
        log("    资料页要求重新输入 Builder ID 密码")
        idc._fill_first_visible(page, "input[type=password]", current_password)
        _check_trusted_device(page, log)
        _shot("reauth_password_filled")
        idc._wait_metadata1(page)
        if not idc._click_button(page, ["Continue", "Sign in", "Submit"], log):
            try:
                page.keyboard.press("Enter")
            except Exception:
                pass
        try:
            page.wait_for_function(REAUTH_LEFT_JS, timeout=15000)
        except Exception:
            time.sleep(1.5)
        return "handled"
    if _is_otp_page(page, body, pw_n):
        if any(m in (body or "") for m in idc.MFA_REGISTER_MARKERS):
            return ""
        if _is_email_otp_page(page, body, pw_n):
            if mailbox is None:
                counters["error"] = "资料页二次验证需要邮箱验证码，但邮箱无法读取"
                return "error"
            counters["email_otp"] = int(counters.get("email_otp") or 0) + 1
            if counters["email_otp"] > 4:
                counters["error"] = "资料页二次验证邮箱验证码多次未通过"
                return "error"
            log("    资料页二次验证：从 Outlook 读取 AWS 邮件验证码")
            _shot("reauth_email_otp")
            try:
                code = mailbox.wait_for_otp(
                    time.time() - 20,
                    timeout_s=90,
                    stop_event=stop_event,
                )
            except Exception as exc:
                counters["error"] = f"资料页二次验证读邮箱失败：{exc}"
                return "error"
            log(f"    填入验证码 {code}")
            if not _fill_otp(page, code):
                counters["error"] = "资料页二次验证找不到验证码输入框"
                return "error"
            idc._wait_metadata1(page)
            if not idc._click_button(page, ["Continue", "Submit", "Verify"], log):
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
            time.sleep(1.2)
            return "handled"
        if not current_secret:
            counters["error"] = "资料页二次验证需要 2FA，但没有可用密钥"
            return "error"
        counters["totp"] = int(counters.get("totp") or 0) + 1
        if counters["totp"] > 4:
            counters["error"] = "资料页二次验证 2FA 多次未通过"
            return "error"
        log("    资料页二次验证：填入 authenticator 验证码")
        if not _submit_totp(page, current_secret, log, _shot):
            counters["error"] = "资料页二次验证找不到 2FA 输入框"
            return "error"
        try:
            page.wait_for_function(SECURITY_OR_REAUTH_JS, timeout=12000)
        except Exception:
            time.sleep(1.2)
        return "handled"
    return ""


def _is_signed_in_profile(page, body: str, pw_n: int) -> bool:
    if pw_n:
        return False
    text = (body or "").lower()
    if "page not found" in text or "typed the address incorrectly" in text:
        return False
    if _is_email_page(page, body, pw_n):
        return False
    if _is_otp_page(page, body, pw_n):
        return False
    url = _page_url(page)
    if any(tok in url for tok in ("/login", "/signin", "oauth", "authorize")):
        if "platform/profile" not in url and "profile.aws.amazon.com" not in url:
            return False
    if _looks_like_profile_body(text, url):
        return True
    if "profile.aws.amazon.com" in url and "sign out" in text:
        return True
    if "signin.aws" in url and "platform/profile" in url:
        return True
    return False


def _is_builder_account_issue(body: str) -> bool:
    """邮箱页 ERR-837 / Builder ID account issue。"""
    text = (body or "").lower()
    return any(m in text for m in ACCOUNT_ISSUE_MARKERS)


def _is_security_check(page, body: str) -> bool:
    """Builder ID 密码页的人机验证（Security check / Arkose），不是邮箱 OTP。"""
    text = (body or "").lower()
    if any(m in text for m in CAPTCHA_MARKERS):
        return True
    try:
        url = (getattr(page, "url", "") or "").lower()
    except Exception:
        url = ""
    if "arkoselabs" in url or "funcaptcha" in url or "captcha" in url:
        return True
    try:
        frames = list(page.frames)
    except Exception:
        frames = []
    for frame in frames:
        try:
            furl = (frame.url or "").lower()
        except Exception:
            continue
        if any(tok in furl for tok in ("arkoselabs", "funcaptcha", "recaptcha", "captcha")):
            return True
    return False


def _is_otp_page(page, body: str, pw_n: int) -> bool:
    if pw_n:
        return False
    if _is_totp_page(page, body, pw_n) or _is_email_otp_page(page, body, pw_n):
        return True
    text = (body or "").lower()
    if not any(m in text for m in OTP_PAGE_MARKERS):
        return False
    if _looks_like_profile_body(text, _page_url(page)):
        return False
    return True


def _is_email_otp_page(page, body: str, pw_n: int) -> bool:
    if pw_n:
        return False
    return any(m in body for m in EMAIL_OTP_MARKERS)


def _is_totp_page(page, body: str, pw_n: int) -> bool:
    if pw_n:
        return False
    text = (body or "").lower()
    if not any(m in text for m in TOTP_PAGE_MARKERS):
        return False
    if _looks_like_profile_body(text, _page_url(page)):
        return any(m in text for m in TOTP_CHALLENGE_MARKERS)
    return True


def _submit_totp(page, secret: str, log: LogFn, _shot) -> bool:
    remaining = 30 - (int(time.time()) % 30)
    if remaining <= 8:
        log(f"    2FA: 当前验证码即将过期，等 {remaining + 1}s 换新码")
        time.sleep(remaining + 1)
    code = mfa_totp.totp_now(secret)
    log(f"    2FA: 填入验证码 {code}")
    if not _fill_otp(page, code):
        return False
    _shot("totp_filled")
    idc._wait_metadata1(page)
    if not idc._click_button(page, ["Continue", "Submit", "Verify", "Next"], log):
        try:
            page.keyboard.press("Enter")
        except Exception:
            pass
    return True


def _is_email_page(page, body: str, pw_n: int) -> bool:
    if pw_n:
        return False
    text = (body or "").lower()
    if _looks_like_profile_body(text, _page_url(page)):
        return False
    if _is_otp_page(page, body, pw_n):
        return False
    if idc._is_button_visible(page, "Allow access") or idc._is_button_visible(page, "Confirm and continue"):
        return False
    text_n = idc._count_visible(page, "input[type=text], input[type=email]")
    if text_n < 1:
        return False
    if any(m in text for m in EMAIL_PAGE_MARKERS):
        return True
    if "sign in with your aws builder id" in text and "password" not in text:
        return True
    return False


def _click_builder_id_entry(page, log: LogFn, body: str) -> bool:
    if "builder id" not in body and "builderid" not in body:
        return False
    return idc._click_button(
        page,
        [
            "Sign in with AWS Builder ID",
            "Sign in with Builder ID",
            "Continue with AWS Builder ID",
            "Use AWS Builder ID",
        ],
        log,
    )


def _check_trusted_device(page, log: LogFn) -> None:
    try:
        labeled = page.get_by_label(re.compile(r"trusted device|perangkat tepercaya", re.I))
        if labeled.count():
            el = labeled.first
            if el.is_visible() and not el.is_checked():
                el.check()
                log("    勾选 This is a trusted device")
                return
    except Exception:
        pass
    try:
        loc = page.locator("label:has-text('trusted device'), label:has-text('Trusted device')").first
        if loc.count() and loc.is_visible():
            loc.click(timeout=1500)
            log("    勾选 This is a trusted device")
            return
    except Exception:
        pass
    try:
        boxes = page.locator("input[type=checkbox]:visible")
        n = min(boxes.count(), 8)
        for i in range(n):
            box = boxes.nth(i)
            try:
                label = (box.evaluate(
                    """el => {
                        const id = el.getAttribute('id');
                        if (id) {
                            const l = document.querySelector('label[for="'+id+'"]');
                            if (l) return l.innerText || '';
                        }
                        return (el.closest('label') || el.parentElement || {}).innerText || '';
                    }"""
                ) or "").lower()
            except Exception:
                label = ""
            if "show password" in label or "forgot password" in label:
                continue
            if "trusted" in label or "tepercaya" in label or (label.strip() == "" and i == n - 1):
                if not box.is_checked():
                    box.check()
                    log("    勾选信任此设备")
                return
    except Exception:
        pass


def _fill_otp(page, code: str) -> bool:
    for sel in OTP_SELECTORS:
        try:
            loc = page.locator(f"{sel}").first
            if not loc.count() or not loc.is_visible():
                continue
            loc.click(timeout=2000)
            loc.fill("")
            loc.type(code, delay=20)
            try:
                if (loc.input_value(timeout=500) or "").strip() == code:
                    return True
            except Exception:
                return True
        except Exception:
            continue
    # Six separate digit boxes.
    try:
        boxes = page.locator("input[maxlength='1']:visible")
        if boxes.count() >= 6 and len(code) >= 6:
            for i, ch in enumerate(code[:6]):
                boxes.nth(i).fill(ch)
            return True
    except Exception:
        pass
    return False


def _click_resend(page, log: LogFn) -> None:
    if idc._click_button(page, ["Resend code", "Resend", "Send new code"], log):
        return
