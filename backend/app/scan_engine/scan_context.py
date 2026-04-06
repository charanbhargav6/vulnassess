from dataclasses import dataclass, field
from typing import Optional, List, Dict

@dataclass
class ScanContext:
    target_url: str
    username: Optional[str] = None
    password: Optional[str] = None

    # Proxy settings
    proxy_enabled: bool = False
    proxy_url: Optional[str] = None
    proxy_type: str = "http"

    # Auth results
    auth_cookies: Dict = field(default_factory=dict)
    auth_headers: Dict = field(default_factory=dict)

    # Recon results
    discovered_urls: List[str] = field(default_factory=list)
    discovered_forms: List[dict] = field(default_factory=dict)
    technologies: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)

    # Risk tracking
    cumulative_risk_score: float = 0.0