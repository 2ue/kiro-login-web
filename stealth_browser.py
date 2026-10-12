# -*- coding: utf-8 -*-
"""Stealth browser for Google/GitHub social login.

Stock Playwright Chromium is fingerprinted by Google as a browser with
JavaScript disabled (accounts.google.com/signin/rejected). Camoufox
(anti-detect Firefox + Xvfb) is the primary engine; Playwright Firefox
is the fallback.
"""
from __future__ import annotations

import os
import random
import time
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from proxy_util import playwright_proxy

LogFn = Callable[[str], None]

_VIRTUAL_DISPLAY_SIZE = "1920x1080x24"
_STEALTH_INIT = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
"""


def proxy_config(proxy: str) -> dict[str, str] | None:
    return playwright_proxy(proxy)


@contextmanager
def launch_social_browser(
    *,
    headless: bool = True,
    proxy: str = "",
    log: LogFn = lambda m: None,
    profile_dir: str = "",
) -> Iterator[tuple[Any, Any, str]]:
    """Yield (page, context, engine_name)."""
    proxy_cfg = proxy_config(proxy)
    if profile_dir:
        closer = None
        try:
            page, closer = open_camoufox_unique_profile(
                profile_dir=profile_dir,
                headless=headless,
                proxy_cfg=proxy_cfg,
                log=log,
            )
            log("已启动 camoufox 独立 profile 浏览器")
            yield page, page.context, "camoufox"
            return
        except Exception as exc:
            raise RuntimeError(f"无法启动 Camoufox 独立 profile：{exc}") from exc
        finally:
            if closer:
                try:
                    closer()
                except Exception:
                    pass

    preferred = (os.environ.get("KIRO_SOCIAL_BROWSER") or "camoufox").strip().lower()
    last_err: Exception | None = None
    engines = _engine_order(preferred)
    for engine in engines:
        closer = None
        launched = False
        try:
            if engine == "camoufox":
                page, closer = _open_camoufox(headless, proxy_cfg, log)
            elif engine == "firefox":
                page, closer = _open_playwright(headless, proxy_cfg, "firefox")
            else:
                page, closer = _open_playwright(headless, proxy_cfg, "chromium")
            launched = True
            log(f"已启动 {engine} 浏览器")
            yield page, page.context, engine
            return
        except Exception as exc:
            if launched:
                raise
            last_err = exc
            log(f"{engine} 启动失败：{exc}")
        finally:
            if closer:
                try:
                    closer()
                except Exception:
                    pass
    raise RuntimeError(f"无法启动社交登录浏览器：{last_err}")


def _engine_order(preferred: str) -> list[str]:
    if preferred in ("firefox", "chromium"):
        rest = [e for e in ("camoufox", "firefox", "chromium") if e != preferred]
        return [preferred, *rest]
    return ["camoufox", "firefox", "chromium"]


def _camoufox_page(browser_or_ctx):
    pages = getattr(browser_or_ctx, "pages", None)
    if pages:
        return pages[0]
    return browser_or_ctx.new_page()


def _start_camoufox(options: dict[str, Any], timeout_ms: int = 45000):
    from camoufox.sync_api import Camoufox

    cm = Camoufox(**options)
    try:
        browser = cm.__enter__()
        page = _camoufox_page(browser)
        page.set_default_timeout(timeout_ms)
    except Exception:
        try:
            cm.__exit__(None, None, None)
        except Exception:
            pass
        raise
    return page, lambda: cm.__exit__(None, None, None)


def _open_camoufox(headless: bool, proxy_cfg: dict[str, str] | None, log: LogFn):
    from camoufox import DefaultAddons

    os.environ.setdefault("CAMOUFOX_VIRTUAL_DISPLAY_SIZE", _VIRTUAL_DISPLAY_SIZE)
    kwargs: dict[str, Any] = {
        "os": "windows",
        "locale": "en-US",
        "humanize": 0.35,
        "exclude_addons": [DefaultAddons.UBO],
        "disable_coop": True,
        "window": (1366, 768),
        "geoip": True,
        "i_know_what_im_doing": True,
        "headless": "virtual" if headless else False,
    }
    if proxy_cfg:
        kwargs["proxy"] = proxy_cfg
    try:
        return _start_camoufox(kwargs)
    except Exception as exc:
        log(f"Camoufox geoip 启动失败，去掉 geoip 重试：{exc}")
        kwargs.pop("geoip", None)
        return _start_camoufox(kwargs)


def open_camoufox_unique_profile(
    *,
    profile_dir: str,
    headless: bool = False,
    proxy_cfg: dict[str, str] | None = None,
    os_name: str = "windows",
    locale: str = "en-US",
    log: LogFn = lambda m: None,
):
    """Launch Camoufox with a fresh persistent profile and unique fingerprint."""
    from pathlib import Path as _P

    from camoufox import DefaultAddons
    from camoufox.fingerprints import generate_fingerprint

    os.environ.setdefault("CAMOUFOX_VIRTUAL_DISPLAY_SIZE", _VIRTUAL_DISPLAY_SIZE)
    dest = _P(profile_dir)
    dest.mkdir(parents=True, exist_ok=True)
    fp_os = os_name if os_name in ("windows", "macos", "linux") else "windows"
    fingerprint = generate_fingerprint(os=fp_os)
    kwargs: dict[str, Any] = {
        "os": fp_os,
        "locale": locale,
        "humanize": 0.4,
        "exclude_addons": [DefaultAddons.UBO],
        "disable_coop": True,
        "window": (1366, 768),
        "geoip": True,
        "i_know_what_im_doing": True,
        "headless": "virtual" if headless else False,
        "persistent_context": True,
        "user_data_dir": str(dest),
        "fingerprint": fingerprint,
    }
    if proxy_cfg:
        kwargs["proxy"] = proxy_cfg
    log(f"Camoufox profile={dest.name} os={fp_os}")
    try:
        return _start_camoufox(kwargs, timeout_ms=45000)
    except Exception as exc:
        log(f"Camoufox geoip 启动失败，去掉 geoip 重试：{exc}")
        kwargs.pop("geoip", None)
        return _start_camoufox(kwargs, timeout_ms=45000)


def _open_playwright(headless: bool, proxy_cfg: dict[str, str] | None, browser_name: str):
    from playwright.sync_api import sync_playwright

    pw = sync_playwright().start()
    launcher = pw.firefox if browser_name == "firefox" else pw.chromium
    launch_kwargs: dict[str, Any] = {"headless": headless}
    if proxy_cfg:
        launch_kwargs["proxy"] = proxy_cfg
    if browser_name == "chromium":
        launch_kwargs["args"] = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-blink-features=AutomationControlled",
            "--no-first-run",
        ]
    browser = launcher.launch(**launch_kwargs)
    ctx = browser.new_context(
        ignore_https_errors=True,
        locale="en-US",
        viewport={"width": 1366, "height": 768},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) "
            "Gecko/20100101 Firefox/128.0"
            if browser_name == "firefox"
            else (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/128.0.0.0 Safari/537.36"
            )
        ),
    )
    ctx.add_init_script(_STEALTH_INIT)
    page = ctx.new_page()
    page.set_default_timeout(15000)

    def closer() -> None:
        try:
            browser.close()
        finally:
            pw.stop()

    return page, closer


def extract_kiro_tokens(ctx) -> dict[str, Any]:
    try:
        cookies = ctx.cookies()
    except Exception:
        return {}
    by_name = {c.get("name"): c for c in cookies}
    access = (by_name.get("AccessToken") or {}).get("value") or ""
    refresh = (by_name.get("RefreshToken") or {}).get("value") or ""
    if not refresh:
        return {}
    expires = int((by_name.get("AccessToken") or {}).get("expires") or 0)
    expires_in = max(0, expires - int(time.time())) if expires > 0 else 3600
    return {"accessToken": access, "refreshToken": refresh, "expiresIn": expires_in}


def wait_ready(page, timeout_ms: int = 15000) -> None:
    try:
        page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    time.sleep(0.8)


def first_visible(page, selectors: list[str], timeout_s: int = 10):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for sel in selectors:
            try:
                loc = page.locator(sel)
                count = loc.count()
                for i in range(min(count, 5)):
                    item = loc.nth(i)
                    if item.is_visible(timeout=500) and item.is_enabled(timeout=500):
                        return item
            except Exception:
                continue
        time.sleep(0.4)
    return None


def click_any(page, selectors: list[str], timeout_ms: int = 8000) -> bool:
    for sel in selectors:
        try:
            el = page.locator(sel).first
            if not el.count() or not el.is_visible(timeout=1200):
                continue
            try:
                el.click(timeout=timeout_ms)
                return True
            except Exception:
                try:
                    el.click(timeout=3000, force=True)
                    return True
                except Exception:
                    el.evaluate("node => node.click()")
                    return True
        except Exception:
            continue
    return False


def human_fill(locator, text: str) -> None:
    try:
        locator.click(timeout=2500)
    except Exception:
        try:
            locator.click(timeout=1500, force=True)
        except Exception:
            try:
                locator.evaluate("node => node.focus()")
            except Exception:
                pass
    try:
        locator.fill("")
    except Exception:
        try:
            locator.press("Control+A")
            locator.press("Backspace")
        except Exception:
            pass
    delay = random.randint(35, 90)
    try:
        locator.press_sequentially(text, delay=delay)
    except Exception:
        locator.fill(text)
    time.sleep(random.uniform(0.15, 0.45))


def body_text(page) -> str:
    try:
        return page.inner_text("body", timeout=3000)
    except Exception:
        return ""


def compact_hint(text: str, prefix: str = "") -> str:
    hint = " ".join((text or "").split())[:220]
    return f"{prefix}：{hint}" if prefix and hint else (prefix or hint)


def page_error(page, prefix: str) -> str:
    hint = compact_hint(body_text(page))
    return f"{prefix}：{hint or page.url}"


def accept_cookies(page) -> None:
    click_any(page, [
        "button:has-text('Accept')",
        "button:has-text('Accept all')",
        "button:has-text('I agree')",
    ], timeout_ms=2500)


def relevant_page(context, page, hosts: tuple[str, ...]):
    try:
        pages = list(context.pages)
    except Exception:
        return page
    for candidate in reversed(pages):
        try:
            url = (candidate.url or "").lower()
        except Exception:
            continue
        if any(host in url for host in hosts):
            return candidate
    return page
