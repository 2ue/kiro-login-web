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

import base64
import json
import os
from pathlib import Path
import random
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

def _load_local_env() -> dict[str, str]:
    env_path = Path(os.environ.get("KIRO_MIHOMO_ENV", "") or Path(__file__).parent / "data" / "mihomo" / "env")
    if not env_path.exists():
        return {}
    loaded: dict[str, str] = {}
    try:
        for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            try:
                parts = shlex.split(value, comments=False, posix=True)
                loaded[key] = parts[0] if parts else ""
            except Exception:
                loaded[key] = value.strip("\"'")
    except Exception:
        return {}
    return loaded


_LOCAL_ENV = _load_local_env()


def _cfg(name: str, default: str = "") -> str:
    return os.environ.get(name) or _LOCAL_ENV.get(name) or default


CONTROLLER_URL = (_cfg("KIRO_MIHOMO_CONTROLLER", "http://127.0.0.1:9090") or "").rstrip("/")
SECRET = _cfg("KIRO_MIHOMO_SECRET", "")
GROUP = _cfg("KIRO_MIHOMO_GROUP", "KiroLogin") or "KiroLogin"
CONFIG_PATH = _cfg("KIRO_MIHOMO_CONFIG", str(Path(__file__).parent / "data" / "mihomo" / "config.yaml"))
BINARY_PATH = _cfg("KIRO_MIHOMO_BINARY", str(Path(__file__).parent / "data" / "mihomo" / "mihomo"))
# 通过该本地监听口探测“真实出口 IP”（KiroLogin 组绑定在 7895）。用于换节点时确认 IP 真的变了。
PROBE_PROXY = _cfg("KIRO_MIHOMO_PROBE_PROXY", "http://127.0.0.1:7895") or ""

# 切节点是组级全局动作(影响该组所有连接)，用锁串行化，避免并发互相打架。
_SWITCH_LOCK = threading.Lock()
# 已知不通的节点(本进程内缓存)，下次挑选时跳过。
_DEAD_NODES: set[str] = set()
# 节点 -> 出口IP 缓存（多个节点名常共用同一台 VPS 出口 IP，用它避免“换了节点没换 IP”）。
_NODE_IP: dict[str, str] = {}
# 不适合做出口的非真实节点
_SKIP_KEYWORDS = ("REJECT", "DIRECT", "Reject", "Pass", "Compatible")
_ENABLED_CACHE: tuple[float, bool] = (0.0, False)
_SUBSCRIPTION_MAX_PROBE = int(_cfg("KIRO_SUBSCRIPTION_MAX_PROBE", "80") or "80")


def exit_ip(timeout: float = 6.0) -> str:
    """通过 KiroLogin 监听口查当前真实出口 IP；失败返回空串。"""
    proxy = listen_proxy()
    if not proxy:
        return ""
    try:
        proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        opener = urllib.request.build_opener(proxy_handler)
        with opener.open("https://api.ipify.org", timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace").strip()
    except Exception:
        return ""


def enabled() -> bool:
    """是否启用换 IP 能力：控制器可访问即可，secret 可来自环境或 data/mihomo/env。"""
    global _ENABLED_CACHE
    if not CONTROLLER_URL:
        return False
    now = time.time()
    if now - _ENABLED_CACHE[0] < 5:
        return _ENABLED_CACHE[1]
    status, _ = _req("GET", "/version", timeout=2.0)
    ok = status == 200
    _ENABLED_CACHE = (now, ok)
    return ok


def _req(method: str, path: str, body: dict | None = None, timeout: float = 8.0):
    url = CONTROLLER_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if SECRET:
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
    if not CONTROLLER_URL:
        return []
    status, data = _req("GET", "/proxies")
    if status != 200 or not isinstance(data, dict):
        return []
    proxies = data.get("proxies", {})
    g = proxies.get(group, {})
    nodes = g.get("all", []) or []
    return [n for n in nodes if not any(k in n for k in _SKIP_KEYWORDS)]


def current_node(group: str = GROUP) -> str:
    if not CONTROLLER_URL:
        return ""
    status, data = _req("GET", "/proxies")
    if status != 200 or not isinstance(data, dict):
        return ""
    return (data.get("proxies", {}).get(group, {}) or {}).get("now", "") or ""


def node_delay(node: str, test_url: str = "https://api.ipify.org", timeout_ms: int = 3000) -> int | None:
    """探测节点延迟(ms)；不通返回 None。用 controller 的 delay 端点，不切节点。"""
    if not CONTROLLER_URL or not node:
        return None
    q = urllib.parse.urlencode({"url": test_url, "timeout": timeout_ms})
    enc = urllib.parse.quote(node, safe="")
    status, data = _req("GET", f"/proxies/{enc}/delay?{q}", timeout=timeout_ms / 1000 + 6)
    if status == 200 and isinstance(data, dict) and "delay" in data:
        return int(data.get("delay", 0))
    return None


def switch_node(node: str, group: str = GROUP) -> bool:
    if not CONTROLLER_URL or not node:
        return False
    enc = urllib.parse.quote(group, safe="")
    status, _ = _req("PUT", f"/proxies/{enc}", body={"name": node})
    return status in (200, 204)


def controller_config() -> dict:
    status, data = _req("GET", "/configs", timeout=5.0)
    return data if status == 200 and isinstance(data, dict) else {}


def listen_proxy() -> str:
    """Return the local mihomo proxy URL used by browser traffic."""
    if PROBE_PROXY:
        return PROBE_PROXY
    cfg = controller_config() if CONTROLLER_URL else {}
    try:
        port = int(cfg.get("mixed-port") or cfg.get("port") or 0) if cfg else 0
    except Exception:
        port = 0
    if port:
        return f"http://127.0.0.1:{port}"
    return "http://127.0.0.1:7895"


def healthy_nodes(count: int, group: str = GROUP, log=None, timeout_ms: int = 3000) -> list[tuple[str, int]]:
    """Return up to count healthy node names with measured delay."""
    count = max(0, int(count or 0))
    if count <= 0 or not enabled():
        return []
    nodes = [n for n in list_nodes(group) if n and n not in _DEAD_NODES]
    if not nodes:
        _DEAD_NODES.clear()
        nodes = list_nodes(group)
    random.shuffle(nodes)
    found: list[tuple[str, int]] = []
    max_probe = min(len(nodes), max(count * 3, count + 4, 8))
    for node in nodes[:max_probe]:
        delay = node_delay(node, timeout_ms=timeout_ms)
        if delay is None:
            _DEAD_NODES.add(node)
            continue
        found.append((node, delay))
        if len(found) >= count:
            break
    found.sort(key=lambda item: item[1])
    if log:
        log(f"mihomo 健康节点探测：需要 {count} 个，找到 {len(found)} 个")
    return found


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value or "node").strip("._-")[:48] or "node"


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def _find_free_port(start: int = 19000, end: int = 26000) -> int:
    base = random.randint(start, max(start, end - 200))
    for offset in range(end - start):
        port = start + ((base + offset - start) % (end - start))
        if _port_free(port):
            return port
    raise RuntimeError("找不到空闲本地端口用于 mihomo 临时代理")


def _wait_port(port: int, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _port_free(port):
            return True
        time.sleep(0.15)
    return False


def _probe_proxy(proxy_url: str, timeout: float = 8.0) -> bool:
    try:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        with opener.open("https://api.ipify.org", timeout=timeout) as resp:
            return bool(resp.read().decode("utf-8", "replace").strip())
    except Exception:
        return False


def _mask_subscription_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit((url or "").strip())
        if not parsed.scheme or not parsed.netloc:
            return "(invalid-url)"
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "...", ""))
    except Exception:
        return "(invalid-url)"


def _b64decode_text(value: str) -> str:
    text = re.sub(r"\s+", "", value or "")
    if not text:
        return ""
    text += "=" * (-len(text) % 4)
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            raw = decoder(text.encode("utf-8"))
            decoded = raw.decode("utf-8", "replace").strip()
            if decoded:
                return decoded
        except Exception:
            continue
    return ""


def _as_int(value, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _first_query(query: dict[str, list[str]], *names: str) -> str:
    for name in names:
        values = query.get(name)
        if values:
            return values[0]
    return ""


def _truthy_query(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _split_server_port(value: str) -> tuple[str, int]:
    if not value:
        return "", 0
    if value.startswith("[") and "]:" in value:
        host, port = value.rsplit(":", 1)
        return host.strip("[]"), _as_int(port)
    if ":" not in value:
        return value, 0
    host, port = value.rsplit(":", 1)
    return host.strip("[]"), _as_int(port)


def _proxy_fingerprint(item: dict) -> tuple:
    return (
        str(item.get("type") or "").lower(),
        str(item.get("server") or "").lower(),
        _as_int(item.get("port")),
        str(item.get("uuid") or item.get("password") or item.get("cipher") or ""),
    )


def _unique_proxy_items(items: list[dict]) -> list[dict]:
    out: list[dict] = []
    names: set[str] = set()
    fingerprints: set[tuple] = set()
    for raw in items:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        if not item.get("server") or not item.get("port") or not item.get("type"):
            continue
        name = str(item.get("name") or item.get("server") or "node").strip()
        if not name or any(k in name for k in _SKIP_KEYWORDS):
            continue
        fp = _proxy_fingerprint(item)
        if fp in fingerprints:
            continue
        fingerprints.add(fp)
        base_name = name
        i = 2
        while name in names:
            name = f"{base_name} #{i}"
            i += 1
        names.add(name)
        item["name"] = name
        item["port"] = _as_int(item.get("port"))
        out.append(item)
    return out


def _vmess_link_to_proxy(link: str) -> dict | None:
    decoded = _b64decode_text(link[len("vmess://"):])
    if not decoded:
        return None
    try:
        cfg = json.loads(decoded)
    except Exception:
        return None
    server = str(cfg.get("add") or "").strip()
    port = _as_int(cfg.get("port"))
    uuid = str(cfg.get("id") or "").strip()
    if not server or not port or not uuid:
        return None
    item: dict = {
        "name": urllib.parse.unquote(str(cfg.get("ps") or server)),
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": _as_int(cfg.get("aid")),
        "cipher": str(cfg.get("scy") or "auto"),
        "udp": True,
    }
    net = str(cfg.get("net") or "").strip()
    if net:
        item["network"] = net
    if str(cfg.get("tls") or "").lower() == "tls":
        item["tls"] = True
        if cfg.get("sni") or cfg.get("host"):
            item["servername"] = str(cfg.get("sni") or cfg.get("host"))
    if net == "ws":
        headers = {}
        if cfg.get("host"):
            headers["Host"] = str(cfg.get("host"))
        item["ws-opts"] = {"path": str(cfg.get("path") or "/"), "headers": headers}
    elif net == "grpc":
        item["grpc-opts"] = {"grpc-service-name": str(cfg.get("path") or "")}
    return item


def _standard_link_to_proxy(link: str) -> dict | None:
    parsed = urllib.parse.urlsplit(link)
    scheme = parsed.scheme.lower()
    if scheme not in {"vless", "trojan", "hysteria2", "hy2", "anytls", "tuic"}:
        return None
    server = parsed.hostname or ""
    port = parsed.port or 0
    if not server or not port:
        return None
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    name = urllib.parse.unquote(parsed.fragment or server)
    item: dict = {
        "name": name,
        "type": "hysteria2" if scheme == "hy2" else scheme,
        "server": server,
        "port": int(port),
        "udp": True,
    }
    user = urllib.parse.unquote(parsed.username or "")
    if scheme == "vless":
        if not user:
            return None
        item["uuid"] = user
        flow = _first_query(query, "flow")
        if flow:
            item["flow"] = flow
    else:
        item["password"] = user
    security = _first_query(query, "security")
    if security in {"tls", "reality"} or _truthy_query(_first_query(query, "tls")):
        item["tls"] = True
    sni = _first_query(query, "sni", "peer", "servername")
    if sni:
        item["servername"] = sni
    if _truthy_query(_first_query(query, "allowInsecure", "skip-cert-verify")):
        item["skip-cert-verify"] = True
    network = _first_query(query, "type", "network")
    if network in {"ws", "grpc", "http", "h2"}:
        item["network"] = network
    if network == "ws":
        headers = {}
        host = _first_query(query, "host")
        if host:
            headers["Host"] = host
        item["ws-opts"] = {"path": _first_query(query, "path") or "/", "headers": headers}
    elif network == "grpc":
        item["grpc-opts"] = {"grpc-service-name": _first_query(query, "serviceName", "service-name")}
    if security == "reality":
        reality_opts = {}
        public_key = _first_query(query, "pbk", "public-key")
        short_id = _first_query(query, "sid", "short-id")
        if public_key:
            reality_opts["public-key"] = public_key
        if short_id:
            reality_opts["short-id"] = short_id
        if reality_opts:
            item["reality-opts"] = reality_opts
    obfs = _first_query(query, "obfs")
    if obfs:
        item["obfs"] = obfs
    obfs_password = _first_query(query, "obfs-password", "obfs_password")
    if obfs_password:
        item["obfs-password"] = obfs_password
    return item


def _ss_link_to_proxy(link: str) -> dict | None:
    raw = link[len("ss://"):]
    fragment = ""
    if "#" in raw:
        raw, fragment = raw.split("#", 1)
    if "?" in raw:
        raw, _query = raw.split("?", 1)
    raw = urllib.parse.unquote(raw)
    if "@" not in raw:
        decoded = _b64decode_text(raw)
        if decoded:
            raw = decoded
    if "@" not in raw:
        return None
    userinfo, hostport = raw.rsplit("@", 1)
    if ":" not in userinfo:
        decoded_userinfo = _b64decode_text(userinfo)
        if decoded_userinfo:
            userinfo = decoded_userinfo
    if ":" not in userinfo:
        return None
    cipher, password = userinfo.split(":", 1)
    server, port = _split_server_port(hostport)
    if not server or not port or not cipher or not password:
        return None
    return {
        "name": urllib.parse.unquote(fragment or server),
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": cipher,
        "password": password,
        "udp": True,
    }


def _subscription_link_to_proxy(link: str) -> dict | None:
    line = (link or "").strip()
    if line.startswith("vmess://"):
        return _vmess_link_to_proxy(line)
    if line.startswith("ss://"):
        return _ss_link_to_proxy(line)
    if any(line.startswith(prefix) for prefix in ("vless://", "trojan://", "hysteria2://", "hy2://", "anytls://", "tuic://")):
        return _standard_link_to_proxy(line)
    return None


def _extract_subscription_proxies(text: str, log=None) -> tuple[list[dict], dict]:
    config: dict = {}
    candidates = [(text or "").strip()]
    decoded = _b64decode_text(text or "")
    if decoded and decoded not in candidates:
        candidates.append(decoded)

    try:
        import yaml  # type: ignore
    except Exception as exc:
        if log:
            log(f"订阅解析不可用：缺少 PyYAML ({exc})")
        yaml = None  # type: ignore

    for candidate in candidates:
        if not candidate:
            continue
        if yaml is not None:
            try:
                data = yaml.safe_load(candidate)
                if isinstance(data, dict) and isinstance(data.get("proxies"), list):
                    config = data
                    return _unique_proxy_items([p for p in data.get("proxies") if isinstance(p, dict)]), config
            except Exception:
                pass
        links = [
            line.strip()
            for line in candidate.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        parsed = [_subscription_link_to_proxy(line) for line in links]
        proxies = _unique_proxy_items([p for p in parsed if p])
        if proxies:
            return proxies, config
    return [], config


def load_subscription_proxies(subscription_url: str, log=None) -> tuple[list[dict], dict]:
    url = (subscription_url or "").strip()
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        if log:
            log("订阅 URL 无效：仅支持 http/https")
        return [], {}
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "clash-meta/1.18.0 mihomo/1.18.0",
            "Accept": "text/yaml, application/yaml, text/plain, */*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read(4 * 1024 * 1024)
    except Exception as exc:
        if log:
            log(f"订阅拉取失败 {_mask_subscription_url(url)}：{exc}")
        return [], {}
    text = raw.decode("utf-8", "replace")
    proxies, config = _extract_subscription_proxies(text, log=log)
    if log:
        log(f"订阅节点解析完成：{len(proxies)} 个候选节点")
    return proxies, config


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=4)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def start_node_proxy_pool(count: int, work_dir: str | Path, log=None) -> tuple[list[str], callable]:
    """Start job-scoped local mihomo mixed ports, each pinned to a different healthy node."""
    count = max(0, int(count or 0))
    if count <= 0:
        return [], lambda: None
    binary = Path(BINARY_PATH)
    if not binary.exists():
        found = shutil.which("mihomo") or shutil.which("clash") or shutil.which("clash-meta")
        binary = Path(found) if found else binary
    config_path = Path(CONFIG_PATH)
    if not binary.exists() or not config_path.exists():
        if log:
            log("mihomo 临时代理池不可用：找不到 mihomo 二进制或配置文件")
        return [], lambda: None
    try:
        import yaml  # type: ignore
    except Exception as exc:
        if log:
            log(f"mihomo 临时代理池不可用：缺少 PyYAML ({exc})")
        return [], lambda: None

    try:
        source = yaml.safe_load(config_path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        if log:
            log(f"mihomo 临时代理池不可用：读取配置失败 {exc}")
        return [], lambda: None
    if not isinstance(source, dict):
        return [], lambda: None
    proxy_by_name = {
        str(item.get("name") or ""): item
        for item in (source.get("proxies") or [])
        if isinstance(item, dict) and item.get("name")
    }
    healthy = healthy_nodes(max(count * 3, count + 5), log=log, timeout_ms=2500)
    if not healthy:
        return [], lambda: None

    root = Path(work_dir)
    root.mkdir(parents=True, exist_ok=True)
    procs: list[subprocess.Popen] = []
    proxies: list[str] = []
    used_nodes: set[str] = set()

    for node, delay in healthy:
        if node in used_nodes or node not in proxy_by_name:
            continue
        port = _find_free_port()
        inst_dir = root / f"{len(proxies) + 1:02d}_{_safe_name(node)}"
        inst_dir.mkdir(parents=True, exist_ok=True)
        proxy_item = dict(proxy_by_name[node])
        node_name = str(proxy_item.get("name") or node)
        generated = {
            "mixed-port": port,
            "allow-lan": False,
            "bind-address": "127.0.0.1",
            "mode": "rule",
            "log-level": "warning",
            "ipv6": False,
            "unified-delay": True,
            "tcp-concurrent": True,
            "dns": source.get("dns") or {
                "enable": True,
                "ipv6": False,
                "nameserver": ["8.8.8.8", "1.1.1.1"],
            },
            "proxies": [proxy_item],
            "proxy-groups": [{"name": "KiroLogin", "type": "select", "proxies": [node_name]}],
            "rules": ["MATCH,KiroLogin"],
        }
        cfg_path = inst_dir / "config.yaml"
        cfg_path.write_text(yaml.safe_dump(generated, allow_unicode=True, sort_keys=False), encoding="utf-8")
        log_path = inst_dir / "mihomo.log"
        fh = log_path.open("ab")
        try:
            proc = subprocess.Popen(
                [str(binary), "-d", str(inst_dir), "-f", str(cfg_path)],
                stdout=fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            fh.close()
        if not _wait_port(port):
            _terminate(proc)
            continue
        proxy_url = f"http://127.0.0.1:{port}"
        if not _probe_proxy(proxy_url):
            _terminate(proc)
            continue
        procs.append(proc)
        proxies.append(proxy_url)
        used_nodes.add(node)
        if log:
            log(f"已启动独立 mihomo 出口 {len(proxies)}/{count}：{node} → 127.0.0.1:{port}（延迟 {delay}ms）")
        if len(proxies) >= count:
            break

    def cleanup() -> None:
        for proc in procs:
            _terminate(proc)
        try:
            shutil.rmtree(root, ignore_errors=True)
        except Exception:
            pass

    if log and len(proxies) < count:
        log(f"可用独立 mihomo 出口只有 {len(proxies)} 个，少于请求并发 {count}")
    return proxies, cleanup


def start_subscription_proxy_pool(count: int, subscription_url: str, work_dir: str | Path, log=None) -> tuple[list[str], callable]:
    """Start job-scoped local mihomo mixed ports from a subscription URL.

    Each returned local proxy is pinned to one distinct subscription node. If the
    job has more accounts than ports, the app scheduler reuses ports only after
    they are released by a finished browser slot.
    """
    count = max(0, int(count or 0))
    if count <= 0:
        return [], lambda: None
    binary = Path(BINARY_PATH)
    if not binary.exists():
        found = shutil.which("mihomo") or shutil.which("clash") or shutil.which("clash-meta")
        binary = Path(found) if found else binary
    if not binary.exists():
        if log:
            log("订阅代理池不可用：找不到 mihomo 二进制")
        return [], lambda: None
    try:
        import yaml  # type: ignore
    except Exception as exc:
        if log:
            log(f"订阅代理池不可用：缺少 PyYAML ({exc})")
        return [], lambda: None

    candidates, source = load_subscription_proxies(subscription_url, log=log)
    if not candidates:
        return [], lambda: None
    random.shuffle(candidates)
    probe_cap = max(count, _SUBSCRIPTION_MAX_PROBE)
    max_probe = min(len(candidates), max(count * 8, count + 12), probe_cap)
    candidates = candidates[:max_probe]

    root = Path(work_dir)
    root.mkdir(parents=True, exist_ok=True)
    procs: list[subprocess.Popen] = []
    proxies: list[str] = []
    used_names: set[str] = set()

    for proxy_item in candidates:
        node_name = str(proxy_item.get("name") or "").strip()
        if not node_name or node_name in used_names:
            continue
        port = _find_free_port()
        inst_dir = root / f"{len(proxies) + 1:02d}_{_safe_name(node_name)}"
        inst_dir.mkdir(parents=True, exist_ok=True)
        generated = {
            "mixed-port": port,
            "allow-lan": False,
            "bind-address": "127.0.0.1",
            "mode": "rule",
            "log-level": "warning",
            "ipv6": False,
            "unified-delay": True,
            "tcp-concurrent": True,
            "dns": source.get("dns") if isinstance(source, dict) and source.get("dns") else {
                "enable": True,
                "ipv6": False,
                "nameserver": ["8.8.8.8", "1.1.1.1"],
            },
            "proxies": [proxy_item],
            "proxy-groups": [{"name": "KiroLogin", "type": "select", "proxies": [node_name]}],
            "rules": ["MATCH,KiroLogin"],
        }
        cfg_path = inst_dir / "config.yaml"
        cfg_path.write_text(yaml.safe_dump(generated, allow_unicode=True, sort_keys=False), encoding="utf-8")
        log_path = inst_dir / "mihomo.log"
        fh = log_path.open("ab")
        try:
            proc = subprocess.Popen(
                [str(binary), "-d", str(inst_dir), "-f", str(cfg_path)],
                stdout=fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            fh.close()
        proxy_url = f"http://127.0.0.1:{port}"
        if not _wait_port(port) or not _probe_proxy(proxy_url):
            _terminate(proc)
            continue
        procs.append(proc)
        proxies.append(proxy_url)
        used_names.add(node_name)
        if log:
            log(f"订阅节点可用 {len(proxies)}/{count}：{node_name} → 127.0.0.1:{port}")
        if len(proxies) >= count:
            break

    def cleanup() -> None:
        for proc in procs:
            _terminate(proc)
        try:
            shutil.rmtree(root, ignore_errors=True)
        except Exception:
            pass

    if log and len(proxies) < count:
        log(f"订阅可用独立出口只有 {len(proxies)} 个，少于请求并发 {count}")
    return proxies, cleanup


def pick_and_switch(group: str = GROUP, exclude: str = "", log=None) -> tuple[str, int | None]:
    """随机挑一个健康节点并切过去，换出口 IP。
    关键：优先选“出口 IP 与当前不同”的节点（多个节点名常共用同一 VPS IP，
    光切节点名不换 IP 对解 captcha 无效）。
    返回 (节点名, 延迟ms)；全失败返回 ("", None)。
    串行化(全局锁)，避免并发切换打架。"""
    with _SWITCH_LOCK:
        cur_ip = exit_ip()
        nodes = [n for n in list_nodes(group) if n not in _DEAD_NODES and n != exclude]
        if not nodes:
            # 死节点缓存可能过期，清空重试一次
            _DEAD_NODES.clear()
            nodes = [n for n in list_nodes(group) if n != exclude]
        random.shuffle(nodes)
        fallback: tuple[str, int | None] | None = None
        # 最多探测 12 个，挑“通且出口 IP 与当前不同”的
        for node in nodes[:12]:
            d = node_delay(node)
            if d is None:
                _DEAD_NODES.add(node)
                continue
            if not switch_node(node, group):
                continue
            new_ip = exit_ip()
            # 缓存节点->IP
            if new_ip:
                _NODE_IP[node] = new_ip
            # 出口 IP 确实变了 → 成功
            if new_ip and new_ip != cur_ip:
                if log:
                    log(f"已切换出口节点 → {node}（延迟 {d}ms，出口IP {new_ip}，换 IP 规避风控）")
                return node, d
            # 节点通但出口 IP 没变（共用同一 VPS），先记为兜底，继续找不同 IP
            if fallback is None:
                fallback = (node, d)
        # 没找到不同 IP 的，退而用一个“通但同 IP”的节点（总比死节点强）
        if fallback is not None:
            switch_node(fallback[0], group)
            if log:
                log(f"已切换节点 → {fallback[0]}（未找到不同出口 IP，可能同 VPS）")
            return fallback
        # 探测都没通，硬切一个
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
