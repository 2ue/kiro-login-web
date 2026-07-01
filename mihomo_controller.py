"""mihomo 控制器助手：通过 external-controller API 切换出口节点(换 IP)，做风控规避。

设计：
- 登录工具走独立监听口(默认 7895)，绑定专用代理组 KiroLogin(隔离，不影响其它流量)。
- 撞 captcha / 风控时，切换 KiroLogin 组的选中节点 → 换出口 IP。
- 切节点前用 controller 的 /proxies/{name}/delay 健康探测，跳过死节点。
- 纯标准库(urllib)，不引入第三方依赖。

环境变量：
- KIRO_MIHOMO_CONTROLLER  控制器地址，默认 http://127.0.0.1:9090
- KIRO_MIHOMO_SECRET      控制器 secret(Bearer)
- KIRO_MIHOMO_GROUP       专用代理组名，默认 KiroLogin
"""
from __future__ import annotations

import json
import os
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CONTROLLER_URL = (os.environ.get("KIRO_MIHOMO_CONTROLLER", "http://127.0.0.1:9090") or "").rstrip("/")
SECRET = os.environ.get("KIRO_MIHOMO_SECRET", "") or ""
GROUP = os.environ.get("KIRO_MIHOMO_GROUP", "KiroLogin") or "KiroLogin"

# 切节点是组级全局动作(影响该组所有连接)，用锁串行化，避免并发互相打架。
_SWITCH_LOCK = threading.Lock()
# 已知不通的节点(本进程内缓存)，下次挑选时跳过。
_DEAD_NODES: set[str] = set()
# 不适合做出口的非真实节点
_SKIP_KEYWORDS = ("REJECT", "DIRECT", "Reject", "Pass", "Compatible")


def enabled() -> bool:
    """是否启用换 IP 能力：需配了 controller + secret。"""
    return bool(CONTROLLER_URL and SECRET)


def _req(method: str, path: str, body: dict | None = None, timeout: float = 8.0):
    url = CONTROLLER_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {SECRET}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.reason}
    except Exception as e:  # noqa: BLE001
        return 0, {"error": str(e)}


def list_nodes(group: str = GROUP) -> list[str]:
    """返回组内可用作出口的真实节点名(过滤 REJECT/DIRECT 等)。"""
    status, data = _req("GET", "/proxies")
    if status != 200 or not isinstance(data, dict):
        return []
    proxies = data.get("proxies", {})
    g = proxies.get(group, {})
    nodes = g.get("all", []) or []
    return [n for n in nodes if not any(k in n for k in _SKIP_KEYWORDS)]


def current_node(group: str = GROUP) -> str:
    status, data = _req("GET", "/proxies")
    if status != 200 or not isinstance(data, dict):
        return ""
    return (data.get("proxies", {}).get(group, {}) or {}).get("now", "") or ""


def node_delay(node: str, test_url: str = "https://api.ipify.org", timeout_ms: int = 5000) -> int | None:
    """探测节点延迟(ms)；不通返回 None。用 controller 的 delay 端点，不切节点。"""
    q = urllib.parse.urlencode({"url": test_url, "timeout": timeout_ms})
    enc = urllib.parse.quote(node, safe="")
    status, data = _req("GET", f"/proxies/{enc}/delay?{q}", timeout=timeout_ms / 1000 + 6)
    if status == 200 and isinstance(data, dict) and "delay" in data:
        return int(data.get("delay", 0))
    return None


def switch_node(node: str, group: str = GROUP) -> bool:
    enc = urllib.parse.quote(group, safe="")
    status, _ = _req("PUT", f"/proxies/{enc}", body={"name": node})
    return status in (200, 204)


def pick_and_switch(group: str = GROUP, exclude: str = "", log=None) -> tuple[str, int | None]:
    """随机挑一个健康节点并切过去，换出口 IP。
    返回 (节点名, 延迟ms)；全失败返回 ("", None)。
    串行化(全局锁)，避免并发切换打架。"""
    with _SWITCH_LOCK:
        nodes = [n for n in list_nodes(group) if n not in _DEAD_NODES and n != exclude]
        if not nodes:
            # 死节点缓存可能过期，清空重试一次
            _DEAD_NODES.clear()
            nodes = [n for n in list_nodes(group) if n != exclude]
        random.shuffle(nodes)
        # 最多探测 8 个，挑第一个通的
        for node in nodes[:8]:
            d = node_delay(node)
            if d is not None:
                if switch_node(node, group):
                    if log:
                        log(f"已切换出口节点 → {node}（延迟 {d}ms，换 IP 规避风控）")
                    return node, d
            else:
                _DEAD_NODES.add(node)
        # 探测都没通，硬切一个(总比不换强)
        if nodes and switch_node(nodes[0], group):
            if log:
                log(f"已切换出口节点 → {nodes[0]}（未通过探测，强切换 IP）")
            return nodes[0], None
        return "", None


def random_wait(min_s: float = 30.0, max_s: float = 90.0, stop_event=None, log=None) -> None:
    """风控规避：随机等候一段时间，模拟人类节奏，让风控降温。"""
    delay = random.uniform(min_s, max_s)
    if log:
        log(f"触发风控，随机等候 {delay:.0f}s 后换 IP 重试（避免连续触发）")
    slept = 0.0
    while slept < delay:
        if stop_event is not None and getattr(stop_event, "is_set", lambda: False)():
            return
        step = min(1.0, delay - slept)
        time.sleep(step)
        slept += step
