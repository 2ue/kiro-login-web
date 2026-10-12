# -*- coding: utf-8 -*-
"""Drive Kiro personal GitHub sign-in with Camoufox / Playwright."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Callable, Any
from urllib.parse import parse_qs, unquote, urlsplit

import idc_browser_login as idc
import mfa_totp
import stealth_browser as stealth


KIRO_SIGNIN_URL = "https://app.kiro.dev/signin"
GITHUB_LOGIN_URL = "https://github.com/login"
GITHUB_SETTINGS_SECURITY_URL = "https://github.com/settings/security"
_GITHUB_HOSTS = ("github.com", "kiro.dev", "amazoncognito.com")


def drive_github_login(
    signin_url: str = KIRO_SIGNIN_URL,
    email: str = "",
    password: str = "",
    *,
    mfa_secret: str = "",
    log: Callable[[str], None] = lambda m: None,
    headless: bool = True,
    proxy: str = "",
    timeout_s: int = 300,
    failure_wait_s: int = 60,
    stop_event=None,
    debug_dir: str = "",
    profile_dir: str = "",
) -> tuple[bool, str, dict[str, Any]]:
    safe = "".join(c if c.isalnum() else "_" for c in (email or "acc"))[:24]
    shot_i = {"n": 0}

    def shot(tag: str, page=None) -> None:
        if not debug_dir or page is None:
            return
        try:
            Path(debug_dir).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(debug_dir) / f"{safe}_{shot_i['n']:02d}_{tag}.png"))
        except Exception:
            pass
        shot_i["n"] += 1

    def stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    try:
        session = stealth.launch_social_browser(headless=headless, proxy=proxy, log=log, profile_dir=profile_dir)
    except Exception as exc:
        return False, f"启动浏览器失败：{exc}", {}

    with session as (page, ctx, _engine):
        def current():
            return stealth.relevant_page(ctx, page, _GITHUB_HOSTS)

        try:
            try:
                page.goto(signin_url or KIRO_SIGNIN_URL, wait_until="domcontentloaded", timeout=45000)
            except Exception as exc:
                return False, f"打开 Kiro 登录页失败：{exc}", {}
            stealth.wait_ready(page)
            stealth.accept_cookies(page)
            shot("01_landing", page)

            if not stealth.click_any(page, [
                'button:has-text("GitHub")',
                'button:has-text("Sign in with GitHub")',
                'button:has-text("Continue with GitHub")',
                '[role=button]:has-text("GitHub")',
            ]):
                return False, "未找到 GitHub 登录入口", {}
            stealth.wait_ready(page)
            page = current()
            shot("02_github", page)

            tokens = stealth.extract_kiro_tokens(ctx)
            if tokens:
                return True, "", tokens
            if "github.com" not in page.url.lower():
                try:
                    page.wait_for_url("**/github.com/**", timeout=20000)
                except Exception:
                    pass
                page = current()
            if "github.com" not in page.url.lower():
                return False, f"未跳转到 GitHub，当前：{page.url}", {}

            login_field = stealth.first_visible(page, [
                "input[name='login']",
                "#login_field",
                "input[type='email']",
                "input[type='text']",
            ], timeout_s=15)
            password_field = stealth.first_visible(page, [
                "input[name='password']",
                "#password",
                "input[type='password']",
            ], timeout_s=15)
            if login_field and password_field:
                stealth.human_fill(login_field, email)
                stealth.human_fill(password_field, password)
                if not stealth.click_any(page, ["input[name='commit']", "button[type=submit]", "input[type=submit]"]):
                    page.keyboard.press("Enter")
                stealth.wait_ready(page)
                shot("03_after_password", page)

            deadline = time.time() + timeout_s
            idle_since = 0.0
            submitted_totp_steps: set[int] = set()
            while time.time() < deadline:
                if stopped():
                    return False, "已中断", {}
                page = current()
                tokens = stealth.extract_kiro_tokens(ctx)
                if tokens:
                    return True, "", tokens
                hint = stealth.body_text(page)
                lower = hint.lower()
                url = page.url.lower()
                if "incorrect username or password" in lower or "incorrect password" in lower:
                    return False, "GitHub 账号或密码错误", {}
                if "too many codes have been submitted" in lower:
                    return False, stealth.compact_hint(hint, "GitHub 2FA 验证码提交过多，请等待冷却后携带正确 TOTP secret 重试"), {}
                if "captcha" in url or ("verify" in lower and "account" in lower):
                    return False, stealth.compact_hint(hint, "GitHub 需要人工验证"), {}

                if _is_totp_page(page):
                    if not mfa_totp.is_valid_secret(mfa_secret):
                        return False, "GitHub 需要 2FA TOTP secret；请在账号后追加 ----TOTP_SECRET 后重试", {}
                    if _handle_totp(page, email, mfa_secret, log, submitted_totp_steps):
                        shot("04_totp", page)
                        continue
                    if not idle_since:
                        idle_since = time.time()
                    if time.time() - idle_since >= max(5, int(failure_wait_s or 60)):
                        return False, stealth.page_error(page, "GitHub 2FA 页面未能提交验证码"), {}
                    time.sleep(1.5)
                    continue
                if _click_authorize(page):
                    stealth.wait_ready(page)
                    shot("05_authorize", page)
                    continue
                if stealth.click_any(page, [
                    'button:has-text("Continue")',
                    'button:has-text("Verify")',
                    "button[type=submit]",
                    "input[type=submit]",
                ]):
                    stealth.wait_ready(page)
                    continue

                if "github.com" in url or "kiro.dev" in url or "amazoncognito.com" in url:
                    if not idle_since:
                        idle_since = time.time()
                    if time.time() - idle_since >= max(5, int(failure_wait_s or 60)):
                        return False, stealth.page_error(page, "GitHub 登录流程未完成"), {}
                time.sleep(1.5)

            return False, "GitHub 登录流程超时（未拿到 Kiro RefreshToken）", {}
        except Exception as exc:
            return False, f"GitHub 登录异常：{exc}", {}


def _click_authorize(page) -> bool:
    return stealth.click_any(page, [
        'button:has-text("Authorize")',
        'input[value*="Authorize"]',
        "button[name='authorize']",
    ])


def _is_totp_page(page) -> bool:
    lower = stealth.body_text(page).lower()
    url = page.url.lower()
    marker = (
        "two-factor" in url
        or "2fa" in url
        or "authentication code" in lower
        or "two-factor" in lower
        or "verification code" in lower
    )
    if not marker:
        return False
    # GitHub's security settings page also contains "two-factor
    # authentication" in its explanatory copy. Require the actual visible
    # code input so that page is not mistaken for the login challenge.
    try:
        return page.locator(
            "input[name='otp']:visible, "
            "input[name='app_otp']:visible, "
            "#app_otp:visible, "
            "input[autocomplete='one-time-code']:visible, "
            "input[type='tel']:visible, "
            "input[inputmode='numeric']:visible"
        ).count() > 0
    except Exception:
        return False


def _handle_totp(
    page,
    email: str,
    secret: str,
    log: Callable[[str], None],
    submitted_steps: set[int] | None = None,
) -> bool:
    if not mfa_totp.is_valid_secret(secret):
        return False
    if not _is_totp_page(page):
        return False
    field = stealth.first_visible(page, [
        "input[name='otp']",
        "input[name='app_otp']",
        "#app_otp",
        "input[autocomplete='one-time-code']",
        "input[type='tel']",
        "input[inputmode='numeric']",
    ], timeout_s=8)
    if not field:
        return False
    _wait_totp_window()
    step = int(time.time() // 30)
    if submitted_steps is not None and step in submitted_steps:
        time.sleep(1.5)
        return True
    code = mfa_totp.totp_now(secret)
    stealth.human_fill(field, code)
    if not stealth.click_any(page, ['button:has-text("Verify")', 'button:has-text("Continue")', "button[type=submit]", "input[type=submit]"]):
        page.keyboard.press("Enter")
    stealth.wait_ready(page)
    if submitted_steps is not None:
        submitted_steps.add(step)
    log("已提交 GitHub 2FA 验证码")
    return True


def _wait_totp_window(min_remaining: int = 8, period: int = 30) -> None:
    remaining = period - (int(time.time()) % period)
    if remaining < min_remaining:
        time.sleep(remaining + 1)


def drive_github_change_security(
    email: str = "",
    password: str = "",
    new_password: str = "",
    *,
    mfa_secret: str = "",
    log: Callable[[str], None] = lambda m: None,
    headless: bool = True,
    proxy: str = "",
    timeout_s: int = 300,
    failure_wait_s: int = 60,
    stop_event=None,
    debug_dir: str = "",
    profile_dir: str = "",
    on_password_changed=None,
    on_secret=None,
    do_change_password: bool = True,
    do_change_mfa: bool = False,
) -> idc.LoginOutcome:
    """Log in to github.com and update the personal account security settings.

    This deliberately uses GitHub's own login/settings pages instead of the
    Kiro OAuth flow.  The caller only needs the GitHub account credentials and
    the existing TOTP secret when GitHub asks for 2FA during sign-in.
    """
    if not do_change_password and not do_change_mfa:
        return idc.LoginOutcome(False, error="未选择要修改的 GitHub 安全项")
    if do_change_password:
        if not new_password:
            return idc.LoginOutcome(False, error="GitHub 改密未提供新密码")
        if new_password == password:
            return idc.LoginOutcome(False, error="GitHub 新密码与当前密码相同")
    normalized_mfa_secret = mfa_totp.normalize_secret(mfa_secret) if mfa_secret else ""

    safe = "".join(c if c.isalnum() else "_" for c in (email or "acc"))[:24]
    shot_i = {"n": 0}

    def shot(tag: str, page=None) -> None:
        if not debug_dir or page is None:
            return
        try:
            Path(debug_dir).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(debug_dir) / f"{safe}_{shot_i['n']:02d}_{tag}.png"))
        except Exception:
            pass
        shot_i["n"] += 1

    def stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    try:
        session = stealth.launch_social_browser(
            headless=headless,
            proxy=proxy,
            log=log,
            profile_dir=profile_dir,
        )
    except Exception as exc:
        return idc.LoginOutcome(False, error=f"启动浏览器失败：{exc}")

    with session as (page, ctx, _engine):
        try:
            try:
                page.goto(GITHUB_LOGIN_URL, wait_until="domcontentloaded", timeout=45000)
            except Exception as exc:
                return idc.LoginOutcome(False, error=f"打开 GitHub 登录页失败：{exc}")
            stealth.wait_ready(page)
            stealth.accept_cookies(page)
            shot("01_login", page)

            page, login_error = _github_login_for_security(
                page,
                ctx,
                email=email,
                password=password,
                mfa_secret=normalized_mfa_secret,
                log=log,
                timeout_s=timeout_s,
                failure_wait_s=failure_wait_s,
                stop_event=stop_event,
                shot=shot,
            )
            if login_error:
                return idc.LoginOutcome(False, error=login_error)

            current_password = password
            changed_mfa = False
            secret = normalized_mfa_secret

            # Reconfigure 2FA first. GitHub's password update can invalidate
            # other sessions; completing the authenticator replacement while
            # this authenticated session is fresh avoids losing that step.
            if do_change_mfa:
                mfa_outcome = _change_github_mfa(
                    page,
                    current_password=current_password,
                    current_secret=secret,
                    log=log,
                    stop_event=stop_event,
                    timeout_s=timeout_s,
                    shot=shot,
                    on_secret=on_secret,
                )
                if mfa_outcome.mfa_secret:
                    secret = mfa_outcome.mfa_secret
                changed_mfa = bool(mfa_outcome.changed_mfa)
                if not mfa_outcome.ok:
                    return idc.LoginOutcome(
                        False,
                        False,
                        mfa_outcome.error,
                        mfa_secret=secret,
                        changed_mfa=changed_mfa,
                    )
                log("GitHub 2FA 更换成功")

            changed_password = False
            if do_change_password:
                password_outcome = _change_github_password(
                    page,
                    current_password=current_password,
                    new_password=new_password,
                    log=log,
                    stop_event=stop_event,
                    timeout_s=timeout_s,
                    shot=shot,
                    on_password_changed=on_password_changed,
                )
                if not password_outcome.ok:
                    return idc.LoginOutcome(
                        False,
                        False,
                        password_outcome.error,
                        mfa_secret=secret,
                        changed_mfa=changed_mfa,
                    )
                changed_password = True
                current_password = new_password
                log("GitHub 密码更换成功")

            return idc.LoginOutcome(
                True,
                changed_password,
                mfa_secret=secret,
                changed_mfa=changed_mfa,
            )
        except Exception as exc:
            return idc.LoginOutcome(False, error=f"GitHub 改密/2FA 异常：{exc}")


def _github_login_for_security(
    page,
    ctx,
    *,
    email: str,
    password: str,
    mfa_secret: str,
    log: Callable[[str], None],
    timeout_s: int,
    failure_wait_s: int,
    stop_event,
    shot,
):
    """Complete a direct GitHub login and return the authenticated page."""
    login_submitted = False
    idle_since = 0.0
    submitted_totp_steps: set[int] = set()

    login_field = stealth.first_visible(page, [
        "input[name='login']",
        "#login_field",
        "input[type='email']",
        "input[type='text']",
    ], timeout_s=15)
    password_field = stealth.first_visible(page, [
        "input[name='password']",
        "#password",
        "input[type='password']",
    ], timeout_s=15)
    if login_field and password_field:
        stealth.human_fill(login_field, email)
        stealth.human_fill(password_field, password)
        if not stealth.click_any(page, [
            "input[name='commit']",
            "button:has-text('Sign in')",
            "button[type=submit]",
            "input[type=submit]",
        ]):
            page.keyboard.press("Enter")
        login_submitted = True
        stealth.wait_ready(page)
        shot("02_after_password", page)
    else:
        # A retry may reuse the persistent profile from the same job. If that
        # profile is still authenticated, do not force a second login.
        login_submitted = _github_is_authenticated(page, ctx, True)

    deadline = time.time() + max(30, int(timeout_s or 300))
    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            return page, "已中断"
        page = stealth.relevant_page(ctx, page, ("github.com",))
        body = stealth.body_text(page)
        lower = body.lower()
        url = (page.url or "").lower()

        if _github_login_error(lower):
            return page, stealth.compact_hint(body, "GitHub 账号或密码错误")
        if "too many codes have been submitted" in lower:
            return page, "GitHub 2FA 验证码提交过多，请等待冷却后重试"
        if _github_human_verification(lower, url):
            return page, stealth.compact_hint(body, "GitHub 需要人工验证")
        if _github_needs_unhandled_verification(lower, url):
            return page, stealth.compact_hint(body, "GitHub 需要额外身份验证，当前流程无法自动读取该验证码")

        if _is_totp_page(page):
            if not mfa_totp.is_valid_secret(mfa_secret):
                return page, "GitHub 登录需要已有 2FA TOTP secret；请在账号后追加 ----TOTP_SECRET"
            if _handle_totp(page, email, mfa_secret, log, submitted_totp_steps):
                shot("03_totp", page)
                idle_since = 0.0
                continue

        if _github_is_authenticated(page, ctx, login_submitted):
            shot("04_authenticated", page)
            return page, ""

        if stealth.click_any(page, [
            'button:has-text("Continue")',
            'button:has-text("Verify")',
            "button[type=submit]",
            "input[type=submit]",
        ]):
            stealth.wait_ready(page)
            idle_since = 0.0
            continue

        if not idle_since:
            idle_since = time.time()
        if time.time() - idle_since >= max(5, int(failure_wait_s or 60)):
            return page, stealth.page_error(page, "GitHub 登录流程未完成")
        time.sleep(1.0)

    return page, "GitHub 登录流程超时"


def _github_login_error(lower: str) -> bool:
    return any(marker in (lower or "") for marker in (
        "incorrect username or password",
        "incorrect password",
        "invalid username or password",
        "password is incorrect",
        "authentication failed",
    ))


def _github_human_verification(lower: str, url: str) -> bool:
    return any(marker in (lower or "") for marker in (
        "captcha",
        "are you human",
        "verify you are human",
        "verify you're human",
        "security challenge",
        "unusual traffic",
    )) or "captcha" in (url or "")


def _github_needs_unhandled_verification(lower: str, url: str) -> bool:
    if _is_totp_url(url):
        return False
    return any(marker in (lower or "") for marker in (
        "verify your identity",
        "verify your email",
        "device verification",
        "enter the code we sent",
        "security code sent",
        "authentication code sent to",
    ))


def _is_totp_url(url: str) -> bool:
    low = (url or "").lower()
    return "/sessions/two-factor" in low or "/two-factor" in low or "2fa" in low


def _github_is_authenticated(page, ctx, login_submitted: bool) -> bool:
    url = (page.url or "").lower()
    if not login_submitted or "github.com" not in url:
        return False
    if "/login" in url or "/sessions/" in url or _is_totp_url(url):
        return False
    try:
        for cookie in ctx.cookies():
            name = str(cookie.get("name") or "").lower()
            value = str(cookie.get("value") or "").lower()
            if name == "logged_in" and value in {"yes", "true", "1"}:
                return True
            if name in {"user_session", "dotcom_user"} and value:
                return True
    except Exception:
        pass
    lower = stealth.body_text(page).lower()
    if any(marker in lower for marker in ("sign out", "your repositories", "dashboard")):
        return True
    return "github.com/" in url and "sign in to github" not in lower and "password" not in lower


def _change_github_password(
    page,
    *,
    current_password: str,
    new_password: str,
    log: Callable[[str], None],
    stop_event,
    timeout_s: int,
    shot,
    on_password_changed,
) -> idc.LoginOutcome:
    try:
        page.goto(GITHUB_SETTINGS_SECURITY_URL, wait_until="domcontentloaded", timeout=45000)
    except Exception as exc:
        return idc.LoginOutcome(False, error=f"打开 GitHub 安全设置页失败：{exc}")
    stealth.wait_ready(page)
    shot("05_password_page", page)

    deadline = time.time() + max(45, int(timeout_s or 300))
    submitted = False
    filled = False
    opened_form = False
    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            return idc.LoginOutcome(False, error="已中断")
        lower = stealth.body_text(page).lower()
        if _github_human_verification(lower, (page.url or "").lower()):
            return idc.LoginOutcome(False, error="GitHub 改密页需要人工验证")
        if _github_password_success(lower, page, submitted):
            if on_password_changed:
                try:
                    on_password_changed(new_password)
                except Exception:
                    pass
            shot("06_password_changed", page)
            return idc.LoginOutcome(True, True)
        if submitted and _github_password_error(lower):
            detail = stealth.compact_hint(stealth.body_text(page))
            shot("06_password_rejected", page)
            return idc.LoginOutcome(False, error=f"GitHub 改密被拒绝：{detail or '密码不符合要求'}")

        fields = _github_password_fields(page)
        if fields["new"] is None and fields["confirm"] is None and not opened_form:
            if stealth.click_any(page, [
                "a:has-text('Change password')",
                "button:has-text('Change password')",
                "a:has-text('Update password')",
                "button:has-text('Update password')",
                "a[href*='/settings/password']",
            ], timeout_ms=2500):
                opened_form = True
                log("已打开 GitHub Change password 表单")
                stealth.wait_ready(page)
                shot("05_open_password_form", page)
                continue
        if fields["new"] is not None and fields["confirm"] is not None and not filled:
            if fields["current"] is not None:
                stealth.human_fill(fields["current"], current_password)
            stealth.human_fill(fields["new"], new_password)
            stealth.human_fill(fields["confirm"], new_password)
            filled = True
            log("GitHub 改密表单已填入")
            shot("05_password_filled", page)
            if not stealth.click_any(page, [
                "button:has-text('Update password')",
                "input[value*='Update password' i]",
                "button:has-text('Change password')",
                "input[value*='Change password' i]",
                "button[type=submit]",
                "input[type=submit]",
            ]):
                try:
                    page.keyboard.press("Enter")
                except Exception:
                    pass
            submitted = True
            stealth.wait_ready(page)
            continue

        if not filled and ("password" in lower or "change your password" in lower):
            time.sleep(0.8)
            continue
        if "sign in" in lower and "/login" in (page.url or "").lower():
            return idc.LoginOutcome(False, error="GitHub 改密前登录状态已失效")
        time.sleep(0.8)

    shot("06_password_timeout", page)
    return idc.LoginOutcome(False, error="GitHub 改密超时或未找到改密表单")


def _github_password_fields(page) -> dict[str, Any]:
    current = _github_visible_locator(page, [
        "input[name='user[old_password]']",
        "input[name='old_password']",
        "input[name*='old_password' i]",
        "#old_password",
        "input[autocomplete='current-password']",
        "input[placeholder*='Current password' i]",
    ], labels=("Current password", "Old password"))
    new = _github_visible_locator(page, [
        "input[name='user[password]']",
        "input[name='new_password']",
        "input[name*='new_password' i]",
        "#new_password",
        "input[autocomplete='new-password']",
        "input[placeholder*='New password' i]",
    ], labels=("New password",))
    confirm = _github_visible_locator(page, [
        "input[name='user[password_confirmation]']",
        "input[name='new_password_confirmation']",
        "input[name*='confirmation' i]",
        "#new_password_confirmation",
        "input[placeholder*='Confirm' i]",
        "input[placeholder*='confirmation' i]",
    ], labels=("Confirm new password", "Confirm password", "Password confirmation"))

    if new is None or confirm is None:
        try:
            inputs = page.locator("input[type=password]:visible")
            values = [inputs.nth(i) for i in range(min(inputs.count(), 5))]
            if len(values) >= 3:
                current = current or values[0]
                new = new or values[1]
                confirm = confirm or values[2]
            elif len(values) == 2:
                new = new or values[0]
                confirm = confirm or values[1]
        except Exception:
            pass
    return {"current": current, "new": new, "confirm": confirm}


def _github_visible_locator(page, selectors: list[str], labels: tuple[str, ...] = ()):
    for selector in selectors:
        try:
            locator = page.locator(selector)
            count = locator.count()
            for i in range(min(count, 5)):
                item = locator.nth(i)
                if item.is_visible(timeout=500) and item.is_enabled(timeout=500):
                    return item
        except Exception:
            continue
    for label in labels:
        try:
            locator = page.get_by_label(label, exact=False).first
            if locator.count() and locator.is_visible(timeout=500) and locator.is_enabled(timeout=500):
                return locator
        except Exception:
            continue
    return None


def _github_password_success(lower: str, page, submitted: bool) -> bool:
    if any(marker in (lower or "") for marker in (
        "password was successfully updated",
        "password updated successfully",
        "your password has been updated",
        "your password has been changed",
        "password successfully changed",
        "password changed successfully",
    )):
        return True
    if not submitted:
        return False
    if _github_password_error(lower):
        return False
    fields = _github_password_fields(page)
    return fields["new"] is None and fields["confirm"] is None


def _github_password_error(lower: str) -> bool:
    return any(marker in (lower or "") for marker in (
        "old password is incorrect",
        "current password is incorrect",
        "incorrect password",
        "new password doesn't match",
        "new password does not match",
        "password is too short",
        "password is too common",
        "password is too weak",
        "new password and confirmation",
        "invalid password",
    ))


def _change_github_mfa(
    page,
    *,
    current_password: str,
    current_secret: str,
    log: Callable[[str], None],
    stop_event,
    timeout_s: int,
    shot,
    on_secret,
) -> idc.LoginOutcome:
    try:
        page.goto(GITHUB_SETTINGS_SECURITY_URL, wait_until="domcontentloaded", timeout=45000)
    except Exception as exc:
        return idc.LoginOutcome(False, error=f"打开 GitHub 2FA 设置页失败：{exc}", mfa_secret=current_secret)
    stealth.wait_ready(page)
    shot("07_security_page", page)

    deadline = time.time() + max(60, int(timeout_s or 300))
    clicked_edit = False
    submitted = False
    reauth_submitted = False
    new_mfa_attempts = 0
    submitted_totp_steps: set[int] = set()
    secret = mfa_totp.normalize_secret(current_secret) if current_secret else ""
    captured = False
    last_secret_attempt = 0.0
    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            return idc.LoginOutcome(False, error="已中断", mfa_secret=secret)
        lower = stealth.body_text(page).lower()
        url = (page.url or "").lower()
        if _github_human_verification(lower, url):
            return idc.LoginOutcome(False, error="GitHub 2FA 设置需要人工验证", mfa_secret=secret)
        if "/login" in url and "github.com" in url:
            return idc.LoginOutcome(False, error="GitHub 2FA 设置前登录状态已失效", mfa_secret=secret)

        if _github_has_password_reauth(page, lower):
            if reauth_submitted:
                if _github_login_error(lower):
                    return idc.LoginOutcome(
                        False,
                        error=f"GitHub 2FA 二次验证失败：{stealth.compact_hint(stealth.body_text(page), '当前密码不正确')}",
                        mfa_secret=secret,
                    )
                time.sleep(0.8)
                continue
            password_field = _github_visible_locator(
                page,
                [
                    "input[type=password]:visible",
                    "input[autocomplete='current-password']",
                    "input[name*='password' i]:visible",
                ],
                labels=("Password", "Current password"),
            )
            if password_field:
                stealth.human_fill(password_field, current_password)
                if not stealth.click_any(page, [
                    "button:has-text('Continue')",
                    "button:has-text('Verify')",
                    "button[type=submit]",
                    "input[type=submit]",
                ]):
                    try:
                        page.keyboard.press("Enter")
                    except Exception:
                        pass
                stealth.wait_ready(page)
                reauth_submitted = True
                continue

        if _is_totp_page(page) and "verify the code from the app" not in lower:
            if mfa_totp.is_valid_secret(current_secret):
                _handle_totp(page, "", current_secret, log, submitted_totp_steps)
                stealth.wait_ready(page)
                continue

        if not clicked_edit:
            state = _click_github_authenticator_edit(page)
            if state == "menu":
                menu_clicked = stealth.click_any(page, [
                    "[role=menuitem]:has-text('Edit')",
                    "[role=menu] button:has-text('Edit')",
                    "[role=menu] a:has-text('Edit')",
                    "button:has-text('Edit')",
                    "a:has-text('Edit')",
                ])
                state = "edit" if menu_clicked else "none"
            if state == "edit":
                clicked_edit = True
                log("已打开 GitHub Authenticator app 更换页面")
                stealth.wait_ready(page)
                shot("08_edit_authenticator", page)
                continue
            if state == "enable":
                clicked_edit = True
                log("已打开 GitHub Authenticator app 设置页面")
                stealth.wait_ready(page)
                shot("08_enable_authenticator", page)
                continue

        if clicked_edit and not captured and time.time() - last_secret_attempt >= 1.0:
            last_secret_attempt = time.time()
            _click_github_setup_key(page, log)
            candidate_secret = _extract_github_totp_secret(page, log)
            # The current secret is still present in the login/session context.
            # Never treat it as the newly generated setup key when GitHub's QR
            # code is still loading.
            if candidate_secret and candidate_secret != mfa_totp.normalize_secret(current_secret):
                secret = candidate_secret
                captured = True
                if on_secret:
                    try:
                        on_secret(secret)
                    except Exception:
                        pass
                log(f"已抓取 GitHub 新 TOTP secret（{len(secret)} 位）")
                _dismiss_github_setup_key_modal(page)
                shot("09_new_mfa_secret", page)
            elif candidate_secret:
                log("抓取到的 TOTP secret 与旧密钥相同，等待 GitHub 新密钥加载")

        if captured and not submitted:
            code_field = _github_visible_locator(page, [
                "input[name='otp']",
                "input[name='app_otp']",
                "input[name*='otp' i]",
                "input[name*='code' i]",
                "input[autocomplete='one-time-code']",
                "input[inputmode='numeric']",
                "input[type='tel']",
            ], labels=("Verification code", "Authentication code", "Code"))
            if code_field:
                _wait_totp_window()
                stealth.human_fill(code_field, mfa_totp.totp_now(secret))
                new_mfa_attempts += 1
                if not stealth.click_any(page, [
                    "button:has-text('Save')",
                    "input[value='Save' i]",
                    "button:has-text('Enable')",
                    "button:has-text('Continue')",
                    "button[type=submit]",
                    "input[type=submit]",
                ]):
                    try:
                        page.keyboard.press("Enter")
                    except Exception:
                        pass
                submitted = True
                stealth.wait_ready(page)
                shot("10_submit_new_mfa", page)
                continue

        if submitted:
            if _github_mfa_error(lower):
                if new_mfa_attempts < 2:
                    log("GitHub 新 2FA 验证码被拒，等待下一个 TOTP 时间窗重试一次")
                    submitted = False
                    time.sleep(1.0)
                    continue
                detail = stealth.compact_hint(stealth.body_text(page))
                return idc.LoginOutcome(
                    False,
                    error=f"GitHub 新 2FA 验证失败：{detail or '验证码不正确'}",
                    mfa_secret=secret,
                )
            if _github_recovery_codes_page(lower):
                if stealth.click_any(page, [
                    "button:has-text('I have saved my recovery codes')",
                    "button:has-text('Continue')",
                    "button:has-text('Done')",
                    "input[value*='saved my recovery codes' i]",
                ]):
                    stealth.wait_ready(page)
                    continue
            if _github_mfa_success(lower, page):
                shot("11_mfa_changed", page)
                return idc.LoginOutcome(True, mfa_secret=secret, changed_mfa=True)

        if not clicked_edit and "two-factor" not in lower and "authenticator" not in lower:
            time.sleep(0.8)
            continue
        time.sleep(0.8)

    shot("12_mfa_timeout", page)
    return idc.LoginOutcome(
        False,
        error="GitHub 登录成功但未能完成 Authenticator app 2FA 更换",
        mfa_secret=secret,
    )


def _click_github_authenticator_edit(page) -> str:
    """Click Edit for the Authenticator app method without touching other Edit buttons."""
    try:
        state = page.evaluate(
            """() => {
              const norm = (v) => String(v || '').replace(/\\s+/g, ' ').trim();
              const visible = (el) => {
                if (!el) return false;
                const style = window.getComputedStyle(el);
                const r = el.getBoundingClientRect();
                return style.display !== 'none' && style.visibility !== 'hidden'
                  && r.width > 0 && r.height > 0;
              };
              const controls = (root) => Array.from(root.querySelectorAll(
                'button, a, [role=button], summary'
              )).filter(visible);
              const isEdit = (el) => /^edit$/i.test(norm(
                el.innerText || el.getAttribute('aria-label') || ''
              ));
              const isManage = (el) => /manage.*authenticator|authenticator.*manage/i.test(
                norm(el.getAttribute('aria-label') || el.innerText || '')
              );
              const labels = Array.from(document.querySelectorAll('body *')).filter((el) => {
                const text = norm(el.innerText || el.textContent || '');
                return text && text.length < 80 && /^authenticator app$/i.test(text) && visible(el);
              });
              for (const label of labels) {
                let root = label;
                for (let depth = 0; root && depth < 8; depth++, root = root.parentElement) {
                  const own = controls(root);
                  const edit = own.find(isEdit);
                  if (edit) { edit.click(); return 'edit'; }
                  const manage = own.find(isManage);
                  if (manage) { manage.click(); return 'menu'; }
                }
              }
              const manage = controls(document).find(isManage);
              if (manage) { manage.click(); return 'menu'; }
              const enable = controls(document).find((el) => /enable two-factor authentication/i.test(
                norm(el.innerText || el.getAttribute('aria-label') || '')
              ));
              if (enable) { enable.click(); return 'enable'; }
              return 'none';
            }"""
        )
        if state in {"edit", "menu", "enable"}:
            return str(state)
    except Exception:
        pass
    if stealth.click_any(page, [
        "a:has-text('Enable two-factor authentication')",
        "button:has-text('Enable two-factor authentication')",
        "a:has-text('Enable 2FA')",
        "button:has-text('Enable 2FA')",
    ]):
        return "enable"
    return "none"


def _click_github_setup_key(page, log: Callable[[str], None]) -> bool:
    clicked = stealth.click_any(page, [
        "a:has-text('setup key')",
        "button:has-text('setup key')",
        "a:has-text('Setup key')",
        "button:has-text('Setup key')",
        "a:has-text(\"Can't scan\")",
        "button:has-text(\"Can't scan\")",
        "a:has-text('Enter key manually')",
        "button:has-text('Enter key manually')",
        "[role=button]:has-text('setup key')",
        "[role=button]:has-text(\"Can't scan\")",
    ], timeout_ms=2500)
    if clicked:
        log("已展开 GitHub 2FA setup key")
        time.sleep(0.5)
        return True
    try:
        clicked = bool(page.evaluate(
            """() => {
              const nodes = Array.from(document.querySelectorAll('a,button,[role=button],summary'));
              const el = nodes.find((node) => {
                const text = (node.innerText || node.textContent || '').toLowerCase();
                return text.includes('setup key') || text.includes("can't scan") ||
                  text.includes('enter key manually') || text.includes('manual');
              });
              if (!el) return false;
              el.click();
              return true;
            }"""
        ))
    except Exception:
        clicked = False
    if clicked:
        log("已展开 GitHub 2FA setup key")
        time.sleep(0.5)
        return True
    return clicked


def _extract_github_totp_secret(page, log: Callable[[str], None]) -> str:
    values: list[dict[str, str]] = []
    try:
        values = page.evaluate(
            """() => {
              const out = [];
              const attrs = ['href', 'src', 'value', 'data-url', 'data-otpauth',
                'data-secret', 'data-clipboard-text', 'aria-label', 'title'];
              for (const el of document.querySelectorAll('*')) {
                const text = (el.innerText || el.textContent || '').trim();
                for (const attr of attrs) {
                  const value = el.getAttribute && el.getAttribute(attr);
                  if (value) out.push({
                    attr,
                    value,
                    text: text.slice(0, 240),
                    tag: (el.tagName || '').toLowerCase(),
                    id: el.id || '',
                    cls: String(el.className || ''),
                  });
                }
              }
              return out;
            }"""
        ) or []
    except Exception:
        values = []
    for item in values:
        raw = str((item or {}).get("value") or "")
        candidate = _secret_from_otpauth(raw) or _secret_from_query(raw)
        if candidate:
            return candidate
    for item in values:
        if not isinstance(item, dict):
            continue
        attr = str(item.get("attr") or "").lower()
        raw = str(item.get("value") or "")
        context = " ".join([
            str(item.get("text") or ""),
            str(item.get("id") or ""),
            str(item.get("cls") or ""),
            attr,
        ]).lower()
        direct_attrs = {"value", "data-secret", "data-clipboard-text", "data-otpauth"}
        if attr in direct_attrs or "setup key" in context or "secret" in context:
            candidate = _normalize_github_secret_candidate(raw)
            if candidate:
                return candidate

    explicit_texts: list[str] = []
    try:
        explicit_texts = page.evaluate(
            """() => {
              const selectors = [
                'code', 'pre', 'clipboard-copy', 'input[readonly]',
                '[data-secret]', '[data-clipboard-text]', '[class*=secret i]',
                '[id*=secret i]', '[class*=setup i]', '[id*=setup i]'
              ];
              const out = [];
              for (const sel of selectors) {
                for (const el of document.querySelectorAll(sel)) {
                  const values = [
                    el.value || '',
                    el.getAttribute && el.getAttribute('value') || '',
                    el.getAttribute && el.getAttribute('data-secret') || '',
                    el.getAttribute && el.getAttribute('data-clipboard-text') || '',
                    el.innerText || el.textContent || '',
                  ];
                  for (const value of values) {
                    if (value) out.push(String(value));
                  }
                }
              }
              return out;
            }"""
        ) or []
    except Exception:
        explicit_texts = []
    for raw in explicit_texts:
        candidate = _secret_from_otpauth(str(raw)) or _secret_from_query(str(raw)) or _normalize_github_secret_candidate(str(raw))
        if candidate:
            return candidate

    try:
        body = stealth.body_text(page)
    except Exception:
        body = ""
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    for i, line in enumerate(lines):
        if "setup key" not in line.lower() and "secret" not in line.lower():
            continue
        same_line = re.sub(r"(?i)^.*?(?:setup key|secret(?: key)?)\s*[:：]?\s*", "", line).strip()
        for candidate_line in [same_line] + lines[i + 1:i + 5]:
            candidate = _normalize_github_secret_candidate(candidate_line)
            if candidate:
                return candidate
    return ""


def _dismiss_github_setup_key_modal(page) -> None:
    dismissed = stealth.click_any(page, [
        "[role=dialog] button[aria-label='Close']",
        "[role=dialog] button:has-text('Close')",
        "button[aria-label='Close']",
        "button:has-text('Close')",
    ], timeout_ms=1200)
    if not dismissed:
        try:
            page.keyboard.press("Escape")
        except Exception:
            pass
    time.sleep(0.4)


def _secret_from_otpauth(value: str) -> str:
    raw = unquote(value or "")
    match = re.search(r'''otpauth://[^\s"'<>]+''', raw, re.IGNORECASE)
    if not match:
        return ""
    try:
        query = parse_qs(urlsplit(match.group(0)).query)
    except Exception:
        return ""
    secret = (query.get("secret") or [""])[0]
    normalized = mfa_totp.normalize_secret(secret)
    return normalized if mfa_totp.is_valid_secret(normalized) else ""


def _secret_from_query(value: str) -> str:
    raw = unquote(value or "")
    match = re.search(r"(?:^|[?&#])(?:secret|otp_secret|totp_secret)=([A-Z2-7a-z2-7%20%2D_+-]{16,})", raw)
    if not match:
        return ""
    normalized = mfa_totp.normalize_secret(unquote(match.group(1)))
    return normalized if mfa_totp.is_valid_secret(normalized) else ""


def _normalize_github_secret_candidate(value: str) -> str:
    raw = re.sub(r"(?i)^(?:setup key|secret(?: key)?|key)\s*[:：]\s*", "", value or "").strip()
    if not re.fullmatch(r"[A-Z2-7a-z2-7][A-Z2-7a-z2-7\s-]{14,}[A-Z2-7a-z2-7]", raw):
        return ""
    candidate = mfa_totp.normalize_secret(raw)
    if len(candidate) < 16 or len(candidate) > 64 or len(candidate) % 8 != 0:
        return ""
    return candidate if mfa_totp.is_valid_secret(candidate) else ""


def _github_has_password_reauth(page, lower: str) -> bool:
    url = (page.url or "").lower()
    if "/sessions/" in url or "verify" in url or "reauth" in url:
        try:
            return page.locator("input[type=password]:visible").count() > 0
        except Exception:
            return False
    if "confirm your password" in (lower or "") or "verify your password" in (lower or ""):
        try:
            return page.locator("input[type=password]:visible").count() > 0
        except Exception:
            return False
    return False


def _github_recovery_codes_page(lower: str) -> bool:
    return "recovery codes" in (lower or "") and (
        "saved your recovery codes" in (lower or "")
        or "i've saved" in (lower or "")
        or "i have saved" in (lower or "")
    )


def _github_mfa_error(lower: str) -> bool:
    return any(marker in (lower or "") for marker in (
        "invalid authentication code",
        "incorrect authentication code",
        "the code you entered is invalid",
        "incorrect verification code",
        "verification code is invalid",
        "two-factor code verification failed",
        "code verification failed",
    ))


def _github_mfa_success(lower: str, page) -> bool:
    if any(marker in (lower or "") for marker in (
        "two-factor authentication method updated",
        "authenticator app updated",
        "two-factor authentication is enabled",
        "successfully enabled two-factor authentication",
        "successfully updated",
        "saved successfully",
    )):
        return True
    if "settings/security" not in (page.url or "").lower():
        return False
    try:
        has_code = page.locator(
            "input[name*='otp' i]:visible, input[name*='code' i]:visible, "
            "input[autocomplete='one-time-code']:visible"
        ).count()
        return has_code == 0 and "setup authenticator app" not in (lower or "")
    except Exception:
        return False
