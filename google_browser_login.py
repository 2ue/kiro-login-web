# -*- coding: utf-8 -*-
"""Drive Kiro personal Google sign-in with Camoufox / Playwright.

Personal Google/GitHub sign-in differs from organization SSO: Kiro's Cognito
social flow does not accept the localhost PKCE redirect used by M365. The
durable tokens are available as Kiro app cookies after a successful portal
login, matching the legacy kiro_login.py behavior.

Google rejects stock Playwright Chromium as a no-JS browser
(accounts.google.com/signin/rejected). Social login therefore uses Camoufox.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Any

import mfa_totp
import stealth_browser as stealth


KIRO_SIGNIN_URL = "https://app.kiro.dev/signin"
_GOOGLE_HOSTS = ("accounts.google.com", "kiro.dev", "amazoncognito.com")


def drive_google_login(
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
            return stealth.relevant_page(ctx, page, _GOOGLE_HOSTS)

        try:
            try:
                page.goto(signin_url or KIRO_SIGNIN_URL, wait_until="domcontentloaded", timeout=45000)
            except Exception as exc:
                return False, f"打开 Kiro 登录页失败：{exc}", {}
            stealth.wait_ready(page)
            stealth.accept_cookies(page)
            shot("01_landing", page)

            if not stealth.click_any(page, [
                'button:has-text("Google")',
                'button:has-text("Sign in with Google")',
                'button:has-text("Continue with Google")',
                '[role=button]:has-text("Google")',
            ]):
                return False, "未找到 Google 登录入口", {}
            stealth.wait_ready(page)
            page = current()
            shot("02_google", page)

            tokens = stealth.extract_kiro_tokens(ctx)
            if tokens:
                return True, "", tokens
            if "accounts.google.com" not in page.url:
                try:
                    page.wait_for_url("**/accounts.google.com/**", timeout=20000)
                except Exception:
                    pass
                page = current()
            if "accounts.google.com" not in page.url:
                blocked = _browser_blocked(page)
                if blocked:
                    return False, blocked, {}
                return False, f"未跳转到 Google，当前：{page.url}", {}

            blocked = _browser_blocked(page)
            if blocked:
                shot("02b_blocked", page)
                return False, blocked, {}

            email_field = stealth.first_visible(page, [
                "#identifierId",
                "input[name='identifier']",
                "input[autocomplete*='username']",
                "input[type='email']",
                "input[type='text']",
            ], timeout_s=15)
            if not email_field:
                blocked = _browser_blocked(page)
                if blocked:
                    return False, blocked, {}
                if _is_captcha(stealth.body_text(page).lower(), page.url.lower()):
                    return False, "Google 要求人机验证（Confirm you're not a robot）", {}
                return False, stealth.page_error(page, "未找到可见邮箱输入框"), {}
            stealth.human_fill(email_field, email)
            stealth.click_any(page, ["#identifierNext", 'button:has-text("Next")', "button[type=submit]"]) or page.keyboard.press("Enter")
            for _ in range(20):
                stealth.wait_ready(page, timeout_ms=4000)
                page = current()
                url = page.url.lower()
                body = stealth.body_text(page).lower()
                if _browser_blocked(page) or _is_captcha(body, url):
                    break
                if "challenge/pwd" in url or "challenge/totp" in url or "challenge/selection" in url:
                    break
                try:
                    if page.locator("input[name='Passwd']").first.is_visible(timeout=400):
                        break
                except Exception:
                    pass
                time.sleep(0.4)
            shot("03_after_email", page)

            blocked = _browser_blocked(page)
            if blocked:
                return False, blocked, {}
            if _is_captcha(stealth.body_text(page).lower(), page.url.lower()):
                if _try_pass_recaptcha(page, log):
                    stealth.wait_ready(page)
                    page = current()
                    shot("03b_after_captcha", page)
                else:
                    return False, "Google 要求人机验证（Confirm you're not a robot）", {}

            password_field = stealth.first_visible(page, [
                "input[name='Passwd']",
                "input[type='password']:not([aria-hidden='true'])",
            ], timeout_s=20)
            if not password_field:
                hint = stealth.body_text(page).lower()
                if _is_captcha(hint, page.url.lower()):
                    if _try_pass_recaptcha(page, log):
                        password_field = stealth.first_visible(page, [
                            "input[name='Passwd']",
                            "input[type='password']:not([aria-hidden='true'])",
                        ], timeout_s=15)
                    if not password_field:
                        return False, "Google 要求人机验证（Confirm you're not a robot）", {}
                if not password_field:
                    blocked = _browser_blocked(page)
                    if blocked:
                        return False, blocked, {}
                    return False, stealth.page_error(page, "未找到可见密码输入框"), {}
            stealth.human_fill(password_field, password)
            stealth.click_any(page, ["#passwordNext", 'button:has-text("Next")', "button[type=submit]"]) or page.keyboard.press("Enter")
            stealth.wait_ready(page)
            page = current()
            shot("04_after_password", page)

            deadline = time.time() + timeout_s
            post_password_failed_since = 0.0
            submitted_totp = False
            while time.time() < deadline:
                if stopped():
                    return False, "已中断", {}
                try:
                    page = current()
                    tokens = stealth.extract_kiro_tokens(ctx)
                    if tokens:
                        return True, "", tokens
                    hint = stealth.body_text(page)
                    lower = hint.lower()
                    url = page.url.lower()
                    if "wrong password" in lower or "incorrect password" in lower:
                        return False, "Google 密码错误", {}
                    if "couldn't find your google account" in lower or "couldn’t find your google account" in lower:
                        return False, stealth.compact_hint(hint, "Google 账号不存在"), {}
                    if "account disabled" in lower or "locked it to protect" in lower or "unusual activity" in lower:
                        return False, stealth.compact_hint(hint, "Google 账号被锁定/停用"), {}
                    blocked = _browser_blocked(page)
                    if blocked:
                        return False, blocked, {}
                    if _is_captcha(lower, url):
                        if _try_pass_recaptcha(page, log):
                            stealth.wait_ready(page)
                            continue
                        return False, "Google 要求人机验证（Confirm you're not a robot）", {}
                    if _needs_recovery_email(lower):
                        return False, "Google 需要辅助邮箱验证，当前输入格式未提供 recovery email", {}

                    if _click_challenge_method(page, mfa_secret):
                        stealth.wait_ready(page)
                        continue
                    if not submitted_totp and _handle_totp(page, email, mfa_secret, log):
                        submitted_totp = True
                        shot("05_totp", page)
                        stealth.wait_ready(page)
                        continue

                    if stealth.click_any(page, [
                        'button:has-text("Allow")',
                        'button:has-text("Continue")',
                        'button:has-text("Next")',
                        "button[type=submit]",
                        "input[type=submit]",
                    ]):
                        stealth.wait_ready(page)
                        continue

                    if "signin/oauth" in url or "accounts.google.com" in url or "kiro.dev" in url:
                        if "kiro.dev" in url and "code=" in url:
                            log("已回到 Kiro OAuth 回调，等待 AccessToken/RefreshToken cookie")
                        if not post_password_failed_since:
                            post_password_failed_since = time.time()
                        if time.time() - post_password_failed_since >= max(5, int(failure_wait_s or 60)):
                            names = []
                            try:
                                names = [c.get("name") for c in ctx.cookies()]
                            except Exception:
                                pass
                            return False, stealth.page_error(page, f"Google 登录流程未完成 cookies={names[:24]}"), {}
                    time.sleep(1.5)
                except Exception as exc:
                    page = current()
                    url = ""
                    try:
                        url = page.url or ""
                    except Exception:
                        pass
                    if "kiro.dev" in url.lower():
                        log(f"页面已跳转 Kiro，忽略中间点击超时：{exc}")
                        time.sleep(1.0)
                        continue
                    return False, f"Google 登录异常：{exc}", {}

            return False, "Google 登录流程超时（未拿到 Kiro RefreshToken）", {}
        except Exception as exc:
            return False, f"Google 登录异常：{exc}", {}


def _handle_totp(page, email: str, secret: str, log: Callable[[str], None]) -> bool:
    if not mfa_totp.is_valid_secret(secret):
        return False
    lower = stealth.body_text(page).lower()
    url = page.url.lower()
    if not ("challenge/totp" in url or "authenticator" in lower or "verification code" in lower):
        return False
    field = stealth.first_visible(page, [
        "input[type='tel']",
        "input[name='totpPin']",
        "input[autocomplete='one-time-code']",
        "input[inputmode='numeric']",
        "input[type='text']",
        "input[type='number']",
    ], timeout_s=5)
    if not field:
        return False
    _wait_totp_window()
    code = mfa_totp.totp_now(secret)
    stealth.human_fill(field, code)
    if not stealth.click_any(page, ["#totpNext", 'button:has-text("Next")', 'button:has-text("Verify")', "button[type=submit]"]):
        try:
            page.keyboard.press("Enter")
        except Exception:
            pass
    stealth.wait_ready(page)
    log("已提交 Google 2FA 验证码")
    return True


def _click_challenge_method(page, mfa_secret: str) -> bool:
    url = page.url.lower()
    lower = stealth.body_text(page).lower()
    if "challenge/selection" not in url and "choose how you want to sign in" not in lower:
        return False
    selectors = [
        'div[data-challengetype="6"]',
        'div:has-text("Google Authenticator")',
        'div:has-text("authenticator app")',
        'li:has-text("Authenticator")',
    ]
    if not mfa_totp.is_valid_secret(mfa_secret):
        selectors = [
            'div[data-challengetype="12"]',
            'div:has-text("password")',
            *selectors,
        ]
    return stealth.click_any(page, selectors)


def _wait_totp_window(min_remaining: int = 8, period: int = 30) -> None:
    remaining = period - (int(time.time()) % period)
    if remaining < min_remaining:
        time.sleep(remaining + 1)


def _browser_blocked(page) -> str:
    url = (page.url or "").lower()
    body = stealth.body_text(page).lower()
    js_off = (
        "javascript turned off" in body
        or "doesn't support javascript" in body
        or "does not support javascript" in body
        or "doesn’t support javascript" in body
    )
    insecure = (
        "browser or app may not be secure" in body
        or "couldn’t sign you in" in body
        or "couldn't sign you in" in body
    )
    if "signin/rejected" in url or js_off:
        return stealth.compact_hint(
            stealth.body_text(page),
            "Google 判定当前浏览器身份异常（反自动化拦截，不是账号被封）",
        )
    if insecure and "password" not in body:
        return stealth.compact_hint(
            stealth.body_text(page),
            "Google 判定当前浏览器不安全",
        )
    return ""


def _is_captcha(body_lower: str, url_lower: str) -> bool:
    return (
        "recaptcha" in url_lower
        or "challenge/recaptcha" in url_lower
        or "confirm you're not a robot" in body_lower
        or "confirm you’re not a robot" in body_lower
        or "i'm not a robot" in body_lower
        or "i’m not a robot" in body_lower
        or ("not a robot" in body_lower and ("google" in body_lower or "verify" in body_lower))
    )


def _try_pass_recaptcha(page, log: Callable[[str], None]) -> bool:
    log("检测到 Google reCAPTCHA，尝试点击复选框")
    clicked = False
    frames = []
    try:
        frames = list(page.frames)
    except Exception:
        frames = []
    for frame in frames:
        for sel in ("#recaptcha-anchor", ".recaptcha-checkbox-border", "span[role=checkbox]"):
            try:
                loc = frame.locator(sel).first
                if loc.count() and loc.is_visible(timeout=800):
                    loc.click(timeout=8000)
                    clicked = True
                    break
            except Exception:
                continue
        if clicked:
            break
    if not clicked:
        clicked = stealth.click_any(page, [
            'iframe[title*="reCAPTCHA"]',
            'span:has-text("I\'m not a robot")',
            'span:has-text("I’m not a robot")',
        ], timeout_ms=4000)
    if not clicked:
        return False
    deadline = time.time() + 12
    while time.time() < deadline:
        url = (page.url or "").lower()
        body = stealth.body_text(page).lower()
        if not _is_captcha(body, url):
            return True
        try:
            if page.locator("input[name='Passwd']").first.is_visible(timeout=400):
                return True
        except Exception:
            pass
        time.sleep(0.8)
    return False


def _needs_recovery_email(body_lower: str) -> bool:
    return "recovery email" in body_lower or "confirm your recovery email" in body_lower
