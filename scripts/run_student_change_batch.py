#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run a student Builder ID password/MFA change batch from a pipe file.

Input format per line:
    email|emailpass|awspass|mfa
or:
    email|emailpass|awspass
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app as webapp  # noqa: E402


def parse_accounts(path: Path) -> list[webapp.AccountInput]:
    accounts: list[webapp.AccountInput] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) not in (3, 4):
            raise SystemExit(f"bad line {line_no}: expected 3 or 4 fields")
        email, email_pass, aws_pass = parts[:3]
        mfa = parts[3] if len(parts) == 4 else ""
        if "@" not in email:
            raise SystemExit(f"bad line {line_no}: invalid email")
        key = email.lower()
        if key in seen:
            raise SystemExit(f"duplicate email: {email}")
        seen.add(key)
        accounts.append(
            webapp.AccountInput(
                idx=len(accounts) + 1,
                email=email,
                password=aws_pass,
                mfa_secret=mfa,
                mail_password=email_pass,
            )
        )
    if not accounts:
        raise SystemExit("no accounts found")
    return accounts


def final_row(acc: webapp.AccountInput, result: webapp.AccountResult | None) -> str:
    email_password = acc.mail_password or acc.password
    aws_password = result.final_password if result and result.changed_password and result.final_password else acc.password
    mfa_secret = result.mfa_secret if result and result.changed_mfa and result.mfa_secret else acc.mfa_secret
    return f"{acc.email}|{email_password}|{aws_password}|{mfa_secret}"


def is_password_invalid(message: str) -> bool:
    text = (message or "").lower()
    return (
        "密码不正确" in text
        or "password is incorrect" in text
        or "incorrect password" in text
        or "doesn't quite match" in text
        or "does not quite match" in text
        or "some information you entered" in text
    )


def partial_mfa_not_deleted(message: str) -> bool:
    text = (message or "").lower()
    return (
        "未能删除旧设备" in text
        or "无法读取 mfa 设备列表" in text
        or "old mfa" in text and "delete" in text
        or "delete failed" in text
    )


def write_final_blocks(job: webapp.Job, accounts: list[webapp.AccountInput], out_dir: Path) -> Path:
    by_email = {r.email.lower(): r for r in job.results}
    blocks: list[tuple[str, str, list[str]]] = [
        ("改了成功了", "success", []),
        ("改了但旧 MFA 没有删除", "mfa_not_deleted", []),
        ("密码失效", "password_invalid", []),
        ("无法修改", "unable", []),
    ]
    extra: dict[str, list[str]] = {}
    block_map = {key: rows for _title, key, rows in blocks}
    for acc in accounts:
        result = by_email.get(acc.email.lower())
        row = final_row(acc, result)
        if result and result.ok:
            block_map["success"].append(row)
            continue
        message = result.message if result else ""
        mutated = bool(result and (result.changed_password or result.changed_mfa))
        if mutated and partial_mfa_not_deleted(message):
            block_map["mfa_not_deleted"].append(row)
        elif mutated:
            extra.setdefault("其他部分成功", []).append(row)
        elif is_password_invalid(message):
            block_map["password_invalid"].append(row)
        else:
            block_map["unable"].append(row)

    lines = [
        "# 最终结果分块汇总",
        "# Format: email|emailpass|awspass|mfa",
        f"# Job: {job.id}",
        f"# Total accounts: {len(accounts)}",
    ]
    for title, _key, rows in blocks:
        lines.append("")
        lines.append(f"# {title}（{len(rows)} 个）")
        lines.extend(rows or ["# 无"])
    for title, rows in extra.items():
        lines.append("")
        lines.append(f"# {title}（{len(rows)} 个）")
        lines.extend(rows or ["# 无"])
    path = out_dir / f"kiro-final-credentials-by-status-{job.id}.txt"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--customer-id", default="c_f5bb9399b54f")
    parser.add_argument("--job-id", default="")
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--risk-retry", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=260)
    parser.add_argument("--failure-wait", type=int, default=60)
    parser.add_argument("--proxy-pool-file", type=Path, default=None)
    parser.add_argument("--proxy-subscription-url", default="")
    parser.add_argument("--proxy-subscription-pool-size", type=int, default=0)
    args = parser.parse_args()

    accounts = parse_accounts(args.input)
    proxy_pool: list[str] = []
    if args.proxy_pool_file:
        if not args.proxy_pool_file.exists():
            raise SystemExit(f"proxy pool file not found: {args.proxy_pool_file}")
        proxy_pool = webapp.parse_proxy_pool(args.proxy_pool_file.read_text(encoding="utf-8", errors="ignore"))
        if not proxy_pool:
            raise SystemExit(f"no usable proxies found in: {args.proxy_pool_file}")
    webapp.restore_job_history()
    job_id = args.job_id.strip() or ("manual" + secrets.token_hex(8))
    job = webapp.Job(
        id=job_id,
        customer_id=args.customer_id,
        kind="change_password",
        accounts=accounts,
        total=len(accounts),
    )
    options = {
        "start_url": "",
        "login_mode": "student",
        "oidc_region": "us-east-1",
        "kiro_region": "us-east-1",
        "new_password": webapp.DEFAULT_NEW_PASSWORD,
        "password_mode": "fixed",
        "headless": True,
        "threads": max(1, int(args.threads)),
        "login_timeout": max(240, int(args.timeout)),
        "failure_wait": int(args.failure_wait),
        "token_wait": 60,
        "create_api_keys": False,
        "api_key_only": False,
        "api_key_label": "1",
        "strict_probe": False,
        "split_accounts_per_file": 1,
        "proxy_pool": proxy_pool,
        "proxy_subscription_url": args.proxy_subscription_url.strip(),
        "proxy_subscription_pool_size": int(args.proxy_subscription_pool_size or 0),
        "job_kind": "change_password",
        "do_change_password": True,
        "do_change_mfa": True,
        "do_remove_old_mfa": True,
        "clean_mfa_only": False,
        "risk_retry": int(args.risk_retry),
    }
    job.options = dict(options)
    with webapp.JOBS_LOCK:
        webapp.JOBS[job.id] = job
        webapp.save_job_history()
    webapp.run_change_password_job(job, accounts, options)
    out_dir = Path(job.log_path).parent if job.log_path else webapp._job_out_dir(job)
    final_path = write_final_blocks(job, accounts, out_dir)
    webapp.save_job_history()
    print(f"job_id={job.id}")
    print(f"status={job.status} ok={job.ok} failed={job.failed} total={job.total}")
    print(f"combined={job.combined_credentials_path}")
    print(f"final={final_path}")
    print(f"log={job.log_path}")
    return 0 if job.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
