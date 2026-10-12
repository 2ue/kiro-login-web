#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reset MFA for the two accounts in job 177917627bc55de6.

The script intentionally keeps credentials out of source code. It reads the
target account list from the failed job and the current working AWS password /
MFA secret from the later successful apply job.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import builder_id_browser_login as b  # noqa: E402
import idc_browser_login as idc  # noqa: E402
import mfa_totp  # noqa: E402
import stealth_browser as stealth  # noqa: E402
from outlook_otp import GraphMailbox  # noqa: E402
from proxy_util import playwright_proxy  # noqa: E402

TARGET_JOB_ID = "177917627bc55de6"
SOURCE_JOB_ID = "cb865ccab9c1e8b8"
EXPORT_DIR = ROOT / "exports" / "c_f5bb9399b54f"
OUT_PATH = EXPORT_DIR / "kiro-mfa-reset-177917627bc55de6-20261010.txt"
EARLY_SECRET_PATH = EXPORT_DIR / "kiro-mfa-reset-early-secrets-177917627bc55de6-20261010.txt"
DEBUG_BASE = ROOT / "debug_mfa" / "mfa-reset-177917627bc55de6-v3"
PROFILE_BASE = ROOT / "data" / "camoufox_profiles" / "mfa_reset_177917627bc55de6_v3"
DEFAULT_PROXY = "http://127.0.0.1:7895"

HEADER = [
    "# MFA reset for accounts from job 177917627bc55de6",
    "# Generated: 2026-10-10",
    "# Format: email|emailpass|awspass|mfa",
]


def ts() -> str:
    return time.strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"[{ts()}] {msg}", flush=True)


def safe_email(email: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", email).strip("_")


def load_jobs() -> list[dict]:
    return json.loads((ROOT / "data" / "job_history.json").read_text(encoding="utf-8"))


def find_job(jobs: list[dict], job_id: str) -> dict:
    for job in jobs:
        if job.get("id") == job_id:
            return job
    raise RuntimeError(f"job not found: {job_id}")


def existing_success_emails() -> set[str]:
    if not OUT_PATH.exists():
        return set()
    emails: set[str] = set()
    for line in OUT_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        emails.add(line.split("|", 1)[0].strip().lower())
    return emails


def ensure_output_file() -> None:
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)
    if not OUT_PATH.exists() or not OUT_PATH.read_text(encoding="utf-8", errors="ignore").strip():
        OUT_PATH.write_text("\n".join(HEADER) + "\n", encoding="utf-8")
    os.chmod(OUT_PATH, 0o600)
    if not EARLY_SECRET_PATH.exists():
        EARLY_SECRET_PATH.write_text(
            "# Early MFA secrets captured during reset\n# Format: email:mfa\n",
            encoding="utf-8",
        )
    os.chmod(EARLY_SECRET_PATH, 0o600)


def upsert_pipe_row(path: Path, email: str, row: str) -> None:
    ensure_output_file()
    existing = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    comments = [ln for ln in existing if ln.startswith("#")]
    if not comments:
        comments = HEADER
    rows: list[str] = []
    replaced = False
    for ln in existing:
        if not ln.strip() or ln.startswith("#"):
            continue
        if ln.split("|", 1)[0].strip().lower() == email.lower():
            if not replaced:
                rows.append(row)
                replaced = True
            continue
        rows.append(ln)
    if not replaced:
        rows.append(row)
    path.write_text("\n".join(comments + rows) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def append_early_secret(email: str, secret: str) -> None:
    if not secret:
        return
    ensure_output_file()
    lines = EARLY_SECRET_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    rows = [ln for ln in lines if ln.startswith("#")]
    data = [ln for ln in lines if ln.strip() and not ln.startswith("#")]
    row = f"{email}:{secret}"
    data = [ln for ln in data if not ln.lower().startswith(email.lower() + ":")]
    data.append(row)
    EARLY_SECRET_PATH.write_text("\n".join(rows + data) + "\n", encoding="utf-8")
    os.chmod(EARLY_SECRET_PATH, 0o600)


def collect_accounts(filter_email: str = "") -> list[dict]:
    jobs = load_jobs()
    target_job = find_job(jobs, TARGET_JOB_ID)
    source_job = find_job(jobs, SOURCE_JOB_ID)
    source_results = {
        (r.get("email") or "").lower(): r for r in (source_job.get("results") or [])
    }
    source_accounts = {
        (a.get("email") or "").lower(): a for a in (source_job.get("accounts") or [])
    }
    accounts: list[dict] = []
    for acc in target_job.get("accounts") or []:
        email = (acc.get("email") or "").strip()
        if not email:
            continue
        if filter_email and email.lower() != filter_email.lower():
            continue
        src = source_results.get(email.lower()) or {}
        src_acc = source_accounts.get(email.lower()) or {}
        final_password = src.get("finalPassword") or src_acc.get("password") or acc.get("password") or ""
        current_secret = src.get("mfaSecret") or src_acc.get("mfaSecret") or acc.get("mfaSecret") or ""
        mail_password = acc.get("mailPassword") or src_acc.get("mailPassword") or ""
        proxy = acc.get("proxy") or src_acc.get("proxy") or DEFAULT_PROXY
        if not final_password:
            raise RuntimeError(f"{email}: missing current AWS password")
        if not mail_password:
            raise RuntimeError(f"{email}: missing mailbox password")
        if not current_secret:
            raise RuntimeError(f"{email}: missing current MFA secret")
        accounts.append(
            {
                "idx": acc.get("idx") or len(accounts) + 1,
                "email": email,
                "mail_password": mail_password,
                "aws_password": final_password,
                "current_secret": mfa_totp.normalize_secret(current_secret),
                "proxy": proxy,
            }
        )
    return accounts


def make_shot(page, email: str):
    d = DEBUG_BASE / safe_email(email)
    d.mkdir(parents=True, exist_ok=True)
    counter = {"i": 0}

    def shot(tag: str) -> None:
        try:
            page.screenshot(path=str(d / f"{counter['i']:02d}_{tag}.png"), full_page=True)
        except Exception:
            pass
        counter["i"] += 1

    return shot


def dialog_confirm_delete(page, logger=log) -> bool:
    """Confirm AWS's MFA delete dialog, including the last-device type-delete case."""

    def type_confirmation_input() -> bool:
        filled = False
        try:
            inputs = page.locator("input:visible, textarea:visible")
            count = min(inputs.count(), 8)
        except Exception:
            count = 0
        for i in range(count):
            inp = inputs.nth(i)
            try:
                if not inp.is_visible(timeout=300) or not inp.is_enabled(timeout=300):
                    continue
                box = inp.bounding_box(timeout=500)
                if not box or box.get("width", 0) < 35 or box.get("height", 0) < 12:
                    continue
                inp.click(timeout=1000)
                page.keyboard.press("Control+A")
                page.keyboard.type("delete", delay=35)
                page.wait_for_timeout(350)
                filled = True
            except Exception:
                continue
        return filled

    def try_with_locator() -> bool:
        selectors = "[role=dialog], [aria-modal=true], [class*='modal' i], [class*='dialog' i]"
        dialogs = page.locator(selectors)
        try:
            count = min(dialogs.count(), 12)
        except Exception:
            count = 0
        for i in reversed(range(count)):
            scope = dialogs.nth(i)
            try:
                if not scope.is_visible(timeout=500):
                    continue
                text = (scope.inner_text(timeout=800) or "").lower()
            except Exception:
                continue
            if not any(k in text for k in ("delete", "删除", "confirmation", "确认")):
                continue
            try:
                inputs = scope.locator("input, textarea")
                for j in range(min(inputs.count(), 4)):
                    inp = inputs.nth(j)
                    try:
                        if inp.is_visible(timeout=300) and inp.is_enabled(timeout=300):
                            inp.click(timeout=800)
                            inp.fill("", timeout=800)
                            inp.type("delete", delay=35, timeout=1500)
                            page.wait_for_timeout(250)
                    except Exception:
                        continue
            except Exception:
                pass
            try:
                btns = scope.get_by_role(
                    "button",
                    name=re.compile(r"^\s*(Delete MFA device|Delete|Confirm|Yes|删除 MFA|删除|确认)\s*$", re.I),
                )
                for j in reversed(range(min(btns.count(), 8))):
                    btn = btns.nth(j)
                    try:
                        if btn.is_visible(timeout=300) and btn.is_enabled(timeout=300):
                            btn.click(timeout=1800)
                            logger("    确认删除 MFA：dialog button clicked")
                            return True
                    except Exception:
                        continue
            except Exception:
                pass
        return False

    js = r"""() => {
      const norm = (v) => String(v || '').replace(/\s+/g, ' ').trim();
      const textOf = (el) => norm(el && (el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || ''));
      const visible = (el) => {
        if (!el) return false;
        const st = getComputedStyle(el);
        if (st.display === 'none' || st.visibility === 'hidden' || st.opacity === '0') return false;
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
      };
      const setValue = (input) => {
        input.focus();
        const proto = input.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
        const desc = Object.getOwnPropertyDescriptor(proto, 'value');
        if (desc && desc.set) desc.set.call(input, 'delete');
        else input.value = 'delete';
        input.dispatchEvent(new InputEvent('input', {bubbles: true, inputType: 'insertText', data: 'delete'}));
        input.dispatchEvent(new Event('change', {bubbles: true}));
        input.dispatchEvent(new KeyboardEvent('keydown', {bubbles: true, key: 'e'}));
        input.dispatchEvent(new KeyboardEvent('keyup', {bubbles: true, key: 'e'}));
      };
      const hasDeleteButton = (root) => Array.from(root.querySelectorAll('button, [role=button], input[type=button], input[type=submit]'))
        .some((btn) => /^(delete mfa device|delete|confirm|yes|删除 mfa|删除|确认)$/i.test(textOf(btn)));
      const allInputs = Array.from(document.querySelectorAll('input, textarea')).filter((el) => visible(el) && !el.disabled);
      let input = null;
      for (const candidate of allInputs) {
        let t = '';
        let p = candidate;
        for (let i = 0; i < 7 && p; i++, p = p.parentElement) t += ' ' + textOf(p).toLowerCase();
        const ph = String(candidate.getAttribute('placeholder') || '').toLowerCase();
        if (t.includes('for confirmation') || t.includes("type 'delete'") || ph.includes('delete')) {
          input = candidate;
          break;
        }
      }
      input = input || allInputs[0] || null;
      if (input) setValue(input);

      let root = null;
      if (input) {
        let best = null;
        let p = input;
        for (let depth = 0; depth < 12 && p && p !== document.body; depth++, p = p.parentElement) {
          const r = p.getBoundingClientRect();
          const t = textOf(p).toLowerCase();
          if (r.width >= 250 && r.height >= 100 && hasDeleteButton(p)
              && (t.includes('delete mfa') || t.includes('for confirmation') || t.includes('delete this device'))) {
            best = p;
            break;
          }
        }
        root = best;
      }
      if (!root) {
        const roots = Array.from(document.querySelectorAll('[role=dialog], [aria-modal=true], [class*="modal" i], [class*="dialog" i]'))
          .filter(visible);
        const candidates = roots.filter((el) => {
          const t = textOf(el).toLowerCase();
          return t.includes('delete mfa') || t.includes('confirmation') || t.includes('确认') || t.includes('删除');
        });
        root = candidates[candidates.length - 1] || roots[roots.length - 1] || null;
      }
      if (!root) {
        const nodes = Array.from(document.querySelectorAll('body *')).filter(visible);
        let best = null;
        let bestLen = Infinity;
        for (const el of nodes) {
          const t = textOf(el).toLowerCase();
          if (!(t.includes('delete mfa') || t.includes("type 'delete'") || t.includes('for confirmation'))) continue;
          if (t.length < bestLen && t.length < 1500) {
            best = el;
            bestLen = t.length;
          }
        }
        root = best || document.body;
      }
      const inputs = Array.from(root.querySelectorAll('input, textarea')).filter((el) => visible(el) && !el.disabled);
      for (const input of inputs) {
        setValue(input);
      }
      const buttons = Array.from(root.querySelectorAll('button, [role=button], input[type=button], input[type=submit]'))
        .filter(visible);
      const wanted = /^(delete mfa device|delete|confirm|yes|删除 mfa|删除|确认)$/i;
      const matches = buttons.filter((btn) => wanted.test(textOf(btn)));
      const enabled = matches.filter((btn) => {
        const cls = String(btn.className || '').toLowerCase();
        return !btn.disabled && (btn.getAttribute('aria-disabled') || '').toLowerCase() !== 'true' && !cls.includes('disabled');
      });
      const btn = enabled[enabled.length - 1];
      if (btn) {
        btn.click();
        return 'clicked';
      }
      return `filled=${inputs.length};allInputs=${allInputs.length};matches=${matches.length};enabled=${enabled.length};input=${input ? input.value : ''};root=${textOf(root).slice(0, 80)}`;
    }"""

    last = ""
    end = time.time() + 16
    while time.time() < end:
        type_confirmation_input()
        if try_with_locator():
            return True
        try:
            state = str(page.evaluate(js) or "")
        except Exception as exc:
            state = f"error:{exc}"
        if state == "clicked":
            logger("    确认删除 MFA：js clicked")
            return True
        if state != last:
            logger(f"    确认删除 MFA：{state}")
            last = state
        page.wait_for_timeout(450)
    return False


def patch_delete_confirm() -> None:
    b._confirm_mfa_delete_dialog = dialog_confirm_delete


def open_security(
    page,
    *,
    current_password: str,
    current_secret: str,
    mailbox: GraphMailbox | None,
    shot,
    timeout_s: int = 90,
) -> None:
    deadline = time.time() + timeout_s
    counters = {"reauth": 0, "totp": 0, "email_otp": 0, "error": ""}
    tried_home = False
    while time.time() < deadline:
        idc._maybe_cookie_accept(page, log)
        body = (idc._body_text(page) or "").lower()
        pw_n = idc._count_visible(page, "input[type=password]")
        if b._is_security_check(page, body):
            detail = idc._visible_error_text(page) or "Security check"
            shot("security_captcha")
            raise RuntimeError(f"触发 AWS 人机验证 captcha：{detail}")
        step = b._try_profile_step_up(
            page,
            body,
            pw_n,
            current_password=current_password,
            current_secret=current_secret,
            log=log,
            _shot=shot,
            counters=counters,
            mailbox=mailbox,
            stop_event=None,
        )
        if step == "error":
            raise RuntimeError(counters.get("error") or "资料页二次验证失败")
        if step == "handled":
            continue
        if b._is_security_settings_page(body):
            b._wait_mfa_table_ready(page, timeout_s=14)
            return
        if b._open_security_or_change_password(page, log, body, prefer_mfa=True):
            try:
                page.wait_for_function(b.SECURITY_OR_REAUTH_JS, timeout=14000)
            except Exception:
                page.wait_for_timeout(1200)
            shot("opened_security")
            continue
        if not tried_home:
            tried_home = True
            log(f"    打开 Builder ID 资料页 {b.BUILDER_ID_PROFILE_URL}")
            page.goto(b.BUILDER_ID_PROFILE_URL, wait_until="domcontentloaded", timeout=60000)
            try:
                page.wait_for_function(b.PROFILE_READY_JS, timeout=18000)
            except Exception:
                page.wait_for_timeout(1500)
            shot("profile_home")
            continue
        page.wait_for_timeout(700)
    shot("open_security_timeout")
    raise RuntimeError("未能打开 Security 设置页")


def delete_all_mfa(
    page,
    *,
    current_password: str,
    current_secret: str,
    mailbox: GraphMailbox | None,
    shot,
) -> None:
    open_security(
        page,
        current_password=current_password,
        current_secret=current_secret,
        mailbox=mailbox,
        shot=shot,
        timeout_s=100,
    )
    for round_no in range(1, 5):
        names = b._mfa_device_names(page)
        log(f"    当前 MFA 设备数：{len(names)}")
        if not names:
            shot("mfa_empty")
            return
        deadline = time.time() + 210
        leftover = b._delete_named_mfa_devices(
            page,
            list(names),
            keep_name="",
            current_password=current_password,
            current_secret=current_secret,
            log=log,
            _shot=shot,
            mailbox=mailbox,
            stop_event=None,
            deadline=deadline,
        )
        if leftover:
            log(f"    本轮仍有 MFA 未删除：{len(leftover)}")
        open_security(
            page,
            current_password=current_password,
            current_secret=current_secret,
            mailbox=mailbox,
            shot=shot,
            timeout_s=70,
        )
        names_after = b._mfa_device_names(page)
        log(f"    删除后 MFA 设备数：{len(names_after)}")
        if not names_after:
            shot("mfa_empty")
            return
        page.wait_for_timeout(1000 + round_no * 500)
    raise RuntimeError("多轮尝试后 MFA 仍未删空")


def register_new_mfa(
    page,
    *,
    email: str,
    current_password: str,
    mailbox: GraphMailbox | None,
    shot,
    timeout_s: int,
) -> str:
    captured = {"secret": ""}

    def on_secret(secret: str) -> None:
        sec = mfa_totp.normalize_secret(secret)
        if not sec:
            return
        captured["secret"] = sec
        append_early_secret(email, sec)
        log("    新 MFA 密钥已即时落盘")

    open_security(
        page,
        current_password=current_password,
        current_secret="",
        mailbox=mailbox,
        shot=shot,
        timeout_s=90,
    )
    out = b._change_mfa_on_profile(
        page,
        log=log,
        stop_event=None,
        timeout_s=timeout_s,
        _shot=shot,
        on_secret=on_secret,
        current_secret="",
        current_password=current_password,
        mailbox=mailbox,
        register_new=True,
    )
    secret = mfa_totp.normalize_secret(out.mfa_secret or captured["secret"])
    if out.ok and secret:
        log("    新 MFA 绑定流程返回成功")
    elif out.changed_mfa and secret:
        log(f"    新 MFA 已抓取并提交，后续校验列表：{out.error}")
    else:
        raise RuntimeError(out.error or "新 MFA 绑定失败")

    # Verify the post-reset state. Some AWS pages return before the table has
    # fully repainted, so give the profile page a few chances to settle.
    verify_error = ""
    for attempt in range(1, 5):
        try:
            open_security(
                page,
                current_password=current_password,
                current_secret=secret,
                mailbox=mailbox,
                shot=shot,
                timeout_s=75,
            )
            names = b._mfa_device_names(page)
            log(f"    新 MFA 校验第 {attempt} 次，设备数：{len(names)}")
            if len(names) == 1:
                shot("mfa_reset_verified")
                return secret
            if len(names) > 1:
                keep_name = b._newest_mfa_name(names)
                leftovers = b._delete_named_mfa_devices(
                    page,
                    [n for n in names if n != keep_name],
                    keep_name=keep_name,
                    current_password=current_password,
                    current_secret=secret,
                    log=log,
                    _shot=shot,
                    mailbox=mailbox,
                    stop_event=None,
                    deadline=time.time() + 150,
                )
                if not leftovers:
                    page.wait_for_timeout(1200)
                    names2 = b._mfa_device_names(page)
                    if len(names2) == 1:
                        shot("mfa_reset_verified_after_cleanup")
                        return secret
                verify_error = f"新 MFA 绑定后仍检测到 {len(names)} 台设备"
            else:
                verify_error = "新 MFA 绑定后暂时未读到设备列表"
        except Exception as exc:
            verify_error = str(exc)
        page.wait_for_timeout(1800)
    raise RuntimeError(verify_error or "新 MFA 绑定后校验失败")


def login_and_reset_account(account: dict, *, headless: bool, timeout_s: int) -> None:
    email = account["email"]
    proxy = account["proxy"] or DEFAULT_PROXY
    profile_dir = PROFILE_BASE / safe_email(email)
    profile_dir.mkdir(parents=True, exist_ok=True)
    DEBUG_BASE.mkdir(parents=True, exist_ok=True)
    log(f"#{account['idx']} {email}: 开始删除全部 MFA 后新增 MFA")

    box: GraphMailbox | None = None
    try:
        candidate = GraphMailbox(email, account["mail_password"], proxy=proxy, log=log)
        candidate.ensure_token()
        box = candidate
        log("    Outlook 邮箱可读取")
    except Exception as exc:
        log(f"    Outlook Graph 无法读信，后续只使用 TOTP/密码：{exc}")

    proxy_cfg = playwright_proxy(proxy)
    page = None
    closer = None
    try:
        page, closer = stealth.open_camoufox_unique_profile(
            profile_dir=str(profile_dir),
            headless=headless,
            proxy_cfg=proxy_cfg,
            log=log,
        )
        page.set_default_timeout(45000 if proxy else 18000)
        shot = make_shot(page, email)
        secret = account["current_secret"]
        log("    注入当前 MFA，打开 Builder ID 资料页")
        page.goto(b.BUILDER_ID_PROFILE_URL, wait_until="domcontentloaded", timeout=60000)
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
                timeout=16000,
            )
        except Exception:
            shot("blank_landing")
            raise RuntimeError("登录页空白或未加载（代理或网络）")
        shot("landing")

        new_pw_if_forced = idc.DEFAULT_NEW_PASSWORD
        if new_pw_if_forced == account["aws_password"]:
            new_pw_if_forced += "9"
        outcome = b._run_login_loop(
            page,
            email,
            account["aws_password"],
            new_password=new_pw_if_forced,
            log=log,
            stop_event=None,
            timeout_s=min(timeout_s, 240),
            failure_wait_s=60,
            box=box,
            secret=secret,
            _shot=shot,
            require_consent=False,
        )
        if not outcome.ok:
            raise RuntimeError(outcome.error or "Builder ID 登录失败")
        current_password = new_pw_if_forced if outcome.changed_password else account["aws_password"]
        if outcome.changed_password:
            log("    登录过程中 AWS 要求改密，已使用脚本默认新密码")

        b._ensure_profile_home(page, log, shot)
        delete_all_mfa(
            page,
            current_password=current_password,
            current_secret=secret,
            mailbox=box,
            shot=shot,
        )
        fresh_secret = register_new_mfa(
            page,
            email=email,
            current_password=current_password,
            mailbox=box,
            shot=shot,
            timeout_s=max(180, timeout_s),
        )
        row = f"{email}|{account['mail_password']}|{current_password}|{fresh_secret}"
        upsert_pipe_row(OUT_PATH, email, row)
        log(f"{email}: 完成，结果已写入 {OUT_PATH.name}")
    finally:
        if closer:
            try:
                closer()
            except Exception:
                pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", default="", help="Only process one email")
    parser.add_argument("--headless", action="store_true", default=True)
    parser.add_argument("--headed", dest="headless", action="store_false")
    parser.add_argument("--timeout", type=int, default=260)
    parser.add_argument("--force", action="store_true", help="Process even if output row already exists")
    args = parser.parse_args()

    ensure_output_file()
    patch_delete_confirm()
    accounts = collect_accounts(args.email)
    if not accounts:
        raise SystemExit("no matching accounts")
    done = existing_success_emails()
    failures: list[tuple[str, str]] = []
    for account in accounts:
        if not args.force and account["email"].lower() in done:
            log(f"{account['email']}: 输出文件已有成功行，跳过（如需重做加 --force）")
            continue
        try:
            login_and_reset_account(account, headless=args.headless, timeout_s=args.timeout)
        except Exception as exc:
            failures.append((account["email"], str(exc)))
            log(f"{account['email']}: 失败：{exc}")
            traceback.print_exc()
    if failures:
        log("失败账号：" + ", ".join(email for email, _ in failures))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
