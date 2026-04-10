import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

from app.core.config import settings


def normalize_target_url(raw_url: str) -> str:
    value = (raw_url or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="Target URL is required")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Target URL scheme must be http or https")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="URL must contain a valid hostname")

    path = parsed.path or "/"
    normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    return normalized


def _blocked_hosts() -> set[str]:
    return {h.strip().lower() for h in settings.BLOCKED_SCAN_HOSTS.split(",") if h.strip()}


def _protected_hosts() -> set[str]:
    return {h.strip().lower() for h in settings.PROTECTED_OWN_HOSTS.split(",") if h.strip()}


def _host_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower().strip()


def _is_private_or_reserved_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _resolve_ips(host: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return set()

    resolved = set()
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            resolved.add(sockaddr[0])
    return resolved


def _validate_public_host(host: str):
    if not host:
        raise HTTPException(status_code=400, detail="Invalid hostname")

    lowered = host.lower().strip()
    if lowered in {"localhost", "metadata.google.internal"} or lowered.endswith(".local"):
        raise HTTPException(status_code=403, detail="Target host is not allowed")

    try:
        if _is_private_or_reserved_ip(lowered):
            raise HTTPException(status_code=403, detail="Target host is not allowed")
        return
    except ValueError:
        pass

    resolved_ips = _resolve_ips(lowered)
    if not resolved_ips:
        raise HTTPException(status_code=400, detail="Target host could not be resolved")

    for ip_text in resolved_ips:
        try:
            if _is_private_or_reserved_ip(ip_text):
                raise HTTPException(status_code=403, detail="Target host is not allowed")
        except ValueError:
            continue


def validate_scan_target(url: str, is_admin: bool) -> tuple[str, str]:
    normalized = normalize_target_url(url)
    host = _host_from_url(normalized)
    is_dev_mode = settings.APP_ENV.lower() in {"dev", "development", "local"}

    blocked = _blocked_hosts()
    protected = _protected_hosts()

    if host in blocked and not is_dev_mode:
        raise HTTPException(status_code=403, detail="You do not have permission to scan this URL")
    if host in protected or host.endswith(".vulnassess.netlify.app") or host.endswith(".onrender.com"):
        if not is_admin:
            raise HTTPException(status_code=403, detail="You do not have permission to scan this URL")

    if is_dev_mode:
        return normalized, host

    _validate_public_host(host)
    return normalized, host


def validate_proxy_url(proxy_url: str, proxy_type: str = "http") -> str:
    value = (proxy_url or "").strip()
    if not value:
        raise HTTPException(status_code=400, detail="Proxy URL is required when proxy is enabled")

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https", "socks5"}:
        raise HTTPException(status_code=400, detail="Proxy URL scheme must be http, https, or socks5")
    if proxy_type and proxy_type not in {"http", "https", "socks5"}:
        raise HTTPException(status_code=400, detail="Proxy type must be http, https, or socks5")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Proxy URL must contain a valid hostname")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Proxy credentials in URL are not allowed")

    _validate_public_host(parsed.hostname)
    return value
