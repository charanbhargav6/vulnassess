import httpx
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger(__name__)

class BaseModule:
    name = "Base"
    module_key = "base"

    async def run(self, context):
        raise NotImplementedError

    async def get_client(self, context):
        proxies = None
        if context.proxy_enabled and context.proxy_url:
            proxy_url = context.proxy_url
            proxies = {
                "http://": proxy_url,
                "https://": proxy_url,
            }
        return httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=False,
            proxies=proxies
        )


# ─── MODULE 1: SQL INJECTION ──────────────────────────────────────────────────
class SQLiModule(BaseModule):
    name = "SQL Injection"
    module_key = "sqli"

    PAYLOADS = [
        "'", '"', "' OR '1'='1", "' OR 1=1--",
        "\" OR \"1\"=\"1", "'; DROP TABLE users--",
        "1' AND '1'='1", "' UNION SELECT NULL--"
    ]

    ERROR_PATTERNS = [
        "sql syntax", "mysql_fetch", "ora-01756",
        "sqlite", "postgresql", "syntax error",
        "unclosed quotation", "quoted string not properly terminated"
    ]

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            # Get the page
            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all forms
            forms = soup.find_all('form')
            if not forms:
                context.discovered_forms = []

            for form in forms:
                action = form.get('action', '')
                form_url = urljoin(context.target_url, action)
                inputs = form.find_all('input')

                for payload in self.PAYLOADS:
                    data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name:
                            data[name] = payload

                    try:
                        resp = await client.post(form_url, data=data)
                        resp_lower = resp.text.lower()

                        for pattern in self.ERROR_PATTERNS:
                            if pattern in resp_lower:
                                vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "payload": payload,
                                    "url": form_url,
                                    "evidence": pattern
                                })
                                break
                    except Exception:
                        continue

            # Also test URL parameters
            parsed = urlparse(context.target_url)
            if parsed.query:
                for payload in self.PAYLOADS[:3]:
                    test_url = f"{context.target_url}{payload}"
                    try:
                        resp = await client.get(test_url)
                        resp_lower = resp.text.lower()
                        for pattern in self.ERROR_PATTERNS:
                            if pattern in resp_lower:
                                vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "payload": payload,
                                    "url": test_url,
                                    "evidence": pattern
                                })
                                break
                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"SQLi module error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "critical",
                "risk_score": 9.0,
                "evidence": f"Found {len(vulnerabilities)} SQLi vulnerability/vulnerabilities. Payload: {vulnerabilities[0]['payload']}",
                "remediation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries."
            }
        return {
            "vulnerabilities": [],
            "severity": "info",
            "risk_score": 0.0,
            "evidence": "No SQL injection vulnerabilities detected",
            "remediation": None
        }


# ─── MODULE 2: XSS ───────────────────────────────────────────────────────────
class XSSModule(BaseModule):
    name = "XSS"
    module_key = "xss"

    PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>"
    ]

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                form_url = urljoin(context.target_url, action)
                inputs = form.find_all('input')

                for payload in self.PAYLOADS:
                    data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        inp_type = inp.get('type', 'text')
                        if name and inp_type not in ['submit', 'hidden']:
                            data[name] = payload

                    if not data:
                        continue

                    try:
                        resp = await client.post(form_url, data=data)
                        if payload in resp.text:
                            vulnerabilities.append({
                                "type": "Reflected XSS",
                                "payload": payload,
                                "url": form_url
                            })
                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"XSS module error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "high",
                "risk_score": 7.5,
                "evidence": f"Reflected XSS found. Payload reflected unescaped: {vulnerabilities[0]['payload'][:50]}",
                "remediation": "Encode all user input before rendering in HTML. Use Content Security Policy headers."
            }
        return {
            "vulnerabilities": [],
            "severity": "info",
            "risk_score": 0.0,
            "evidence": "No XSS vulnerabilities detected",
            "remediation": None
        }


# ─── MODULE 3: CSRF ──────────────────────────────────────────────────────────
class CSRFModule(BaseModule):
    name = "CSRF"
    module_key = "csrf"

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form', method=lambda m: m and m.lower() == 'post')

            for form in forms:
                inputs = form.find_all('input')
                input_names = [
                    i.get('name', '').lower()
                    for i in inputs
                ]
                has_csrf_token = any(
                    'csrf' in n or 'token' in n or '_token' in n
                    for n in input_names
                )

                if not has_csrf_token:
                    action = form.get('action', context.target_url)
                    vulnerabilities.append({
                        "type": "CSRF",
                        "url": urljoin(context.target_url, action),
                        "evidence": "POST form missing CSRF token"
                    })

        except Exception as e:
            logger.error(f"CSRF module error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "high",
                "risk_score": 6.5,
                "evidence": f"Found {len(vulnerabilities)} form(s) without CSRF protection",
                "remediation": "Add CSRF tokens to all POST forms. Validate token on server side."
            }
        return {
            "vulnerabilities": [],
            "severity": "info",
            "risk_score": 0.0,
            "evidence": "All forms have CSRF protection",
            "remediation": None
        }


# ─── MODULE 4: PATH TRAVERSAL ─────────────────────────────────────────────────
class PathTraversalModule(BaseModule):
    name = "Path Traversal"
    module_key = "path_traversal"

    PAYLOADS = [
        "../../../../etc/passwd",
        "../../../../windows/win.ini",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    ]

    SIGNATURES = [
        "root:x:0:0", "[boot loader]",
        "daemon:", "nobody:", "www-data"
    ]

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            for payload in self.PAYLOADS:
                test_url = f"{context.target_url}?file={payload}"
                try:
                    resp = await client.get(test_url)
                    for sig in self.SIGNATURES:
                        if sig in resp.text:
                            vulnerabilities.append({
                                "type": "Path Traversal",
                                "payload": payload,
                                "url": test_url,
                                "evidence": sig
                            })
                            break
                except Exception:
                    continue

        except Exception as e:
            logger.error(f"Path traversal module error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "critical",
                "risk_score": 8.5,
                "evidence": f"Path traversal detected. System file content exposed.",
                "remediation": "Validate and sanitize file paths. Use allowlists for permitted files."
            }
        return {
            "vulnerabilities": [],
            "severity": "info",
            "risk_score": 0.0,
            "evidence": "No path traversal vulnerabilities detected",
            "remediation": None
        }


# ─── MODULE 5: SECURITY HEADERS ───────────────────────────────────────────────
class SecurityHeadersModule(BaseModule):
    name = "Security Headers"
    module_key = "sec_headers"

    REQUIRED_HEADERS = {
        "content-security-policy": "Missing Content-Security-Policy header",
        "x-frame-options": "Missing X-Frame-Options header",
        "x-content-type-options": "Missing X-Content-Type-Options header",
        "strict-transport-security": "Missing HSTS header",
        "referrer-policy": "Missing Referrer-Policy header"
    }

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            response = await client.get(context.target_url)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            for header, message in self.REQUIRED_HEADERS.items():
                if header not in headers_lower:
                    vulnerabilities.append({
                        "type": "Missing Security Header",
                        "header": header,
                        "evidence": message
                    })

            # Check for info disclosure
            if "server" in headers_lower:
                vulnerabilities.append({
                    "type": "Information Disclosure",
                    "header": "server",
                    "evidence": f"Server header exposes: {headers_lower['server']}"
                })

        except Exception as e:
            logger.error(f"Security headers module error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            severity = "medium" if len(vulnerabilities) < 3 else "high"
            risk = 4.0 if len(vulnerabilities) < 3 else 6.0
            return {
                "vulnerabilities": vulnerabilities,
                "severity": severity,
                "risk_score": risk,
                "evidence": f"Found {len(vulnerabilities)} missing security headers",
                "remediation": "Configure web server to send security headers on all responses."
            }
        return {
            "vulnerabilities": [],
            "severity": "info",
            "risk_score": 0.0,
            "evidence": "All security headers present",
            "remediation": None
        }


# ─── MODULE 6: PORT SCANNER ───────────────────────────────────────────────────
class PortScanModule(BaseModule):
    name = "Port Scanner"
    module_key = "port_scan"

    COMMON_PORTS = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 6379, 8080, 8443, 27017]

    RISKY_PORTS = {
        21: "FTP - unencrypted file transfer",
        22: "SSH - remote access",
        23: "Telnet - unencrypted remote access",
        3306: "MySQL database exposed",
        3389: "RDP - remote desktop exposed",
        5432: "PostgreSQL database exposed",
        6379: "Redis database exposed",
        27017: "MongoDB database exposed"
    }

    async def run(self, context):
        vulnerabilities = []
        parsed = urlparse(context.target_url)
        host = parsed.hostname

        open_ports = []

        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
            except Exception:
                pass

        await asyncio.gather(*[check_port(p) for p in self.COMMON_PORTS])
        context.open_ports = open_ports

        for port in open_ports:
            if port in self.RISKY_PORTS:
                vulnerabilities.append({
                    "type": "Exposed Port",
                    "port": port,
                    "evidence": self.RISKY_PORTS[port]
                })

        if vulnerabilities:
            severity = "critical" if any(
                p in open_ports for p in [3306, 5432, 27017, 6379]
            ) else "high"
            return {
                "vulnerabilities": vulnerabilities,
                "severity": severity,
                "risk_score": 7.0,
                "evidence": f"Open risky ports found: {[v['port'] for v in vulnerabilities]}",
                "remediation": "Close unnecessary ports. Use firewall rules to restrict access."
            }
        return {
            "vulnerabilities": [],
            "severity": "info",
            "risk_score": 0.0,
            "evidence": f"Open ports: {open_ports}. No risky ports detected.",
            "remediation": None
        }
    # ─── MODULE 7: NOSQL INJECTION ───────────────────────────────────────────────
class NoSQLiModule(BaseModule):
    name = "NoSQL Injection"
    module_key = "nosqli"

    PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
        '{"$regex": ".*"}',
    ]

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)
        try:
            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                form_url = urljoin(context.target_url, action)
                inputs = form.find_all('input')
                for payload in self.PAYLOADS:
                    data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name:
                            data[name] = payload
                    try:
                        resp = await client.post(form_url, data=data)
                        if any(x in resp.text.lower() for x in [
                            'error', 'invalid', 'unexpected', 'syntax'
                        ]):
                            vulnerabilities.append({
                                "type": "NoSQL Injection",
                                "payload": payload,
                                "url": form_url
                            })
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"NoSQLi error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "critical",
                "risk_score": 8.5,
                "evidence": f"NoSQL injection detected with payload: {vulnerabilities[0]['payload']}",
                "remediation": "Sanitize all inputs. Use parameterized queries for MongoDB/NoSQL databases."
            }
        return {"vulnerabilities": [], "severity": "info", "risk_score": 0.0,
                "evidence": "No NoSQL injection detected", "remediation": None}


# ─── MODULE 8: OS COMMAND INJECTION ──────────────────────────────────────────
class CommandInjectionModule(BaseModule):
    name = "OS Command Injection"
    module_key = "cmd_injection"

    PAYLOADS = [
        "; ls", "& dir", "| whoami",
        "; cat /etc/passwd", "& type C:\\Windows\\win.ini",
        "`whoami`", "$(whoami)"
    ]

    SIGNATURES = [
        "root:", "daemon:", "www-data",
        "volume in drive", "directory of",
        "uid=", "gid="
    ]

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)
        try:
            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                form_url = urljoin(context.target_url, action)
                inputs = form.find_all('input')
                for payload in self.PAYLOADS:
                    data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name:
                            data[name] = payload
                    try:
                        resp = await client.post(form_url, data=data)
                        for sig in self.SIGNATURES:
                            if sig in resp.text.lower():
                                vulnerabilities.append({
                                    "type": "Command Injection",
                                    "payload": payload,
                                    "url": form_url,
                                    "evidence": sig
                                })
                                break
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"Command injection error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "critical",
                "risk_score": 9.5,
                "evidence": f"Command injection detected! System output found in response.",
                "remediation": "Never pass user input to system commands. Use allowlists for permitted commands."
            }
        return {"vulnerabilities": [], "severity": "info", "risk_score": 0.0,
                "evidence": "No command injection detected", "remediation": None}


# ─── MODULE 9: SSL/TLS CHECK ─────────────────────────────────────────────────
class SSLTLSModule(BaseModule):
    name = "SSL/TLS Check"
    module_key = "ssl_tls"

    async def run(self, context):
        vulnerabilities = []
        parsed = urlparse(context.target_url)

        try:
            import ssl
            import socket
            host = parsed.hostname
            port = 443

            # Check if HTTPS is used
            if parsed.scheme != 'https':
                vulnerabilities.append({
                    "type": "No HTTPS",
                    "evidence": "Site is using HTTP instead of HTTPS"
                })

            # Try SSL connection
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        protocol = ssock.version()

                        # Check for weak protocols
                        if protocol in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                            vulnerabilities.append({
                                "type": "Weak TLS Version",
                                "evidence": f"Using outdated protocol: {protocol}"
                            })

                        # Check cert expiry
                        import datetime
                        expire_date = datetime.datetime.strptime(
                            cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                        )
                        days_left = (expire_date - datetime.datetime.utcnow()).days
                        if days_left < 30:
                            vulnerabilities.append({
                                "type": "Certificate Expiring Soon",
                                "evidence": f"Certificate expires in {days_left} days"
                            })
            except ssl.SSLError as e:
                vulnerabilities.append({
                    "type": "SSL Error",
                    "evidence": str(e)
                })
            except Exception:
                pass

        except Exception as e:
            logger.error(f"SSL/TLS error: {e}")

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "high",
                "risk_score": 6.5,
                "evidence": f"SSL/TLS issues found: {vulnerabilities[0]['evidence']}",
                "remediation": "Use TLS 1.2 or higher. Renew certificates before expiry. Always use HTTPS."
            }
        return {"vulnerabilities": [], "severity": "info", "risk_score": 0.0,
                "evidence": "SSL/TLS configuration looks good", "remediation": None}


# ─── MODULE 10: IDOR ─────────────────────────────────────────────────────────
class IDORModule(BaseModule):
    name = "IDOR"
    module_key = "idor"

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            # Look for numeric IDs in URLs
            import re
            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            links = soup.find_all('a', href=True)
            id_pattern = re.compile(r'[?&/](id|user_id|account|profile|order)=?(\d+)', re.I)

            tested = set()
            for link in links:
                href = link['href']
                match = id_pattern.search(href)
                if match:
                    full_url = urljoin(context.target_url, href)
                    if full_url in tested:
                        continue
                    tested.add(full_url)

                    # Try adjacent IDs
                    original_id = int(match.group(2))
                    for test_id in [original_id + 1, original_id - 1, 1, 2]:
                        test_url = full_url.replace(
                            match.group(2), str(test_id)
                        )
                        try:
                            resp = await client.get(test_url)
                            if resp.status_code == 200 and len(resp.text) > 100:
                                vulnerabilities.append({
                                    "type": "Potential IDOR",
                                    "url": test_url,
                                    "evidence": f"ID {test_id} accessible without authorization check"
                                })
                                break
                        except Exception:
                            continue

        except Exception as e:
            logger.error(f"IDOR error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "high",
                "risk_score": 7.0,
                "evidence": f"Potential IDOR found at: {vulnerabilities[0]['url']}",
                "remediation": "Implement proper authorization checks. Verify user owns the resource before returning data."
            }
        return {"vulnerabilities": [], "severity": "info", "risk_score": 0.0,
                "evidence": "No IDOR vulnerabilities detected", "remediation": None}


# ─── MODULE 11: BROKEN ACCESS CONTROL ────────────────────────────────────────
class BrokenAccessControlModule(BaseModule):
    name = "Broken Access Control"
    module_key = "broken_access"

    ADMIN_PATHS = [
        '/admin', '/admin/', '/admin/dashboard',
        '/administrator', '/wp-admin', '/manage',
        '/management', '/backend', '/control',
        '/superuser', '/root', '/system',
        '/api/admin', '/api/users', '/api/config'
    ]

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            for path in self.ADMIN_PATHS:
                test_url = f"{context.target_url.rstrip('/')}{path}"
                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 200:
                        vulnerabilities.append({
                            "type": "Exposed Admin Path",
                            "url": test_url,
                            "evidence": f"Admin path accessible: {path} (status 200)"
                        })
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"Broken access control error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "critical",
                "risk_score": 8.0,
                "evidence": f"Admin paths accessible without auth: {[v['url'] for v in vulnerabilities[:3]]}",
                "remediation": "Restrict admin paths with authentication. Use role-based access control."
            }
        return {"vulnerabilities": [], "severity": "info", "risk_score": 0.0,
                "evidence": "No broken access control detected", "remediation": None}


# ─── MODULE 12: RECON ────────────────────────────────────────────────────────
class ReconModule(BaseModule):
    name = "Reconnaissance"
    module_key = "recon"

    SENSITIVE_PATHS = [
        '/robots.txt', '/.git/HEAD', '/.env',
        '/backup.zip', '/config.php', '/wp-config.php',
        '/.htaccess', '/web.config', '/phpinfo.php',
        '/server-status', '/api/v1', '/swagger.json',
        '/sitemap.xml', '/.DS_Store'
    ]

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)
        technologies = []

        try:
            response = await client.get(context.target_url)
            headers = dict(response.headers)

            # Detect technologies
            server = headers.get('server', '')
            powered_by = headers.get('x-powered-by', '')
            if server:
                technologies.append(f"Server: {server}")
            if powered_by:
                technologies.append(f"Powered by: {powered_by}")

            context.technologies = technologies

            # Check sensitive files
            for path in self.SENSITIVE_PATHS:
                test_url = f"{context.target_url.rstrip('/')}{path}"
                try:
                    resp = await client.get(test_url)
                    if resp.status_code == 200 and len(resp.text) > 10:
                        vulnerabilities.append({
                            "type": "Sensitive File Exposed",
                            "url": test_url,
                            "evidence": f"{path} is publicly accessible"
                        })
                except Exception:
                    continue

        except Exception as e:
            logger.error(f"Recon error: {e}")
        finally:
            await client.aclose()

        all_findings = vulnerabilities
        if technologies:
            all_findings.append({
                "type": "Technology Disclosure",
                "evidence": ", ".join(technologies)
            })

        if all_findings:
            return {
                "vulnerabilities": all_findings,
                "severity": "medium",
                "risk_score": 4.5,
                "evidence": f"Found {len(vulnerabilities)} sensitive files. Technologies: {', '.join(technologies) or 'hidden'}",
                "remediation": "Remove sensitive files. Hide server version information. Restrict access to config files."
            }
        return {"vulnerabilities": [], "severity": "info", "risk_score": 0.0,
                "evidence": "No sensitive files or technology disclosure found", "remediation": None}


# ─── MODULE 13: RATE LIMITING CHECK ─────────────────────────────────────────
class RateLimitingModule(BaseModule):
    name = "Rate Limiting Check"
    module_key = "rate_limit_check"

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find login forms
            forms = soup.find_all('form')
            login_form = None
            for form in forms:
                inputs = form.find_all('input')
                input_names = [i.get('name', '').lower() for i in inputs]
                if any('pass' in n or 'pwd' in n for n in input_names):
                    login_form = form
                    break

            if login_form:
                action = login_form.get('action', '')
                form_url = urljoin(context.target_url, action)
                inputs = login_form.find_all('input')

                # Try 10 rapid requests
                blocked = False
                for i in range(10):
                    data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        if name:
                            data[name] = f'test{i}'
                    try:
                        resp = await client.post(form_url, data=data)
                        if resp.status_code == 429:
                            blocked = True
                            break
                    except Exception:
                        break

                if not blocked:
                    vulnerabilities.append({
                        "type": "No Rate Limiting",
                        "url": form_url,
                        "evidence": "10 rapid login attempts allowed without blocking"
                    })

        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "medium",
                "risk_score": 5.0,
                "evidence": "Login form has no rate limiting -- brute force attacks possible",
                "remediation": "Implement rate limiting. Block IPs after 5 failed attempts. Add CAPTCHA."
            }
        return {"vulnerabilities": [], "severity": "info", "risk_score": 0.0,
                "evidence": "Rate limiting is properly configured", "remediation": None}


# ─── MODULE 14: MASS ASSIGNMENT ──────────────────────────────────────────────
class MassAssignmentModule(BaseModule):
    name = "Mass Assignment"
    module_key = "mass_assignment"

    PRIVILEGE_PARAMS = [
        'role', 'admin', 'is_admin', 'is_superuser',
        'user_type', 'privilege', 'level', 'access'
    ]

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                action = form.get('action', '')
                form_url = urljoin(context.target_url, action)
                inputs = form.find_all('input')

                base_data = {}
                for inp in inputs:
                    name = inp.get('name', '')
                    if name:
                        base_data[name] = 'test'

                # Try injecting privilege parameters
                for param in self.PRIVILEGE_PARAMS:
                    test_data = {**base_data, param: 'true'}
                    try:
                        resp = await client.post(form_url, data=test_data)
                        if resp.status_code in [200, 302]:
                            vulnerabilities.append({
                                "type": "Potential Mass Assignment",
                                "parameter": param,
                                "url": form_url,
                                "evidence": f"Parameter '{param}' accepted without rejection"
                            })
                            break
                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"Mass assignment error: {e}")
        finally:
            await client.aclose()

        if vulnerabilities:
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "high",
                "risk_score": 7.5,
                "evidence": f"Mass assignment vulnerability found with parameter: {vulnerabilities[0]['parameter']}",
                "remediation": "Use allowlists for accepted parameters. Never bind request body directly to models."
            }
        return {"vulnerabilities": [], "severity": "info", "risk_score": 0.0,
                "evidence": "No mass assignment vulnerabilities detected", "remediation": None}


# ─── MODULE 15: AUTHENTICATION MODULE ────────────────────────────────────────
class AuthenticationModule(BaseModule):
    name = "Authentication"
    module_key = "auth_module"

    async def run(self, context):
        vulnerabilities = []
        client = await self.get_client(context)

        try:
            if context.username and context.password:
                response = await client.get(context.target_url)
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')

                for form in forms:
                    inputs = form.find_all('input')
                    input_names = [i.get('name', '').lower() for i in inputs]

                    if any('user' in n or 'email' in n for n in input_names):
                        action = form.get('action', '')
                        form_url = urljoin(context.target_url, action)
                        data = {}
                        for inp in inputs:
                            name = inp.get('name', '')
                            name_lower = name.lower()
                            if 'user' in name_lower or 'email' in name_lower:
                                data[name] = context.username
                            elif 'pass' in name_lower:
                                data[name] = context.password
                            elif name:
                                data[name] = 'test'

                        try:
                            resp = await client.post(
                                form_url, data=data,
                                follow_redirects=True
                            )
                            if resp.status_code == 200:
                                context.auth_cookies = dict(resp.cookies)
                                vulnerabilities.append({
                                    "type": "Authentication",
                                    "evidence": "Successfully authenticated to target"
                                })
                        except Exception:
                            pass

            # Check for default credentials
            default_creds = [
                ('admin', 'admin'), ('admin', 'password'),
                ('admin', '123456'), ('test', 'test')
            ]

            response = await client.get(context.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            for form in forms:
                inputs = form.find_all('input')
                input_names = [i.get('name', '').lower() for i in inputs]
                if not any('user' in n or 'email' in n for n in input_names):
                    continue

                action = form.get('action', '')
                form_url = urljoin(context.target_url, action)

                for username, password in default_creds:
                    data = {}
                    for inp in inputs:
                        name = inp.get('name', '')
                        name_lower = name.lower()
                        if 'user' in name_lower or 'email' in name_lower:
                            data[name] = username
                        elif 'pass' in name_lower:
                            data[name] = password
                        elif name:
                            data[name] = ''
                    try:
                        resp = await client.post(
                            form_url, data=data, follow_redirects=True
                        )
                        if resp.status_code == 200 and 'logout' in resp.text.lower():
                            vulnerabilities.append({
                                "type": "Default Credentials",
                                "evidence": f"Default credentials work: {username}/{password}"
                            })
                            break
                    except Exception:
                        continue

        except Exception as e:
            logger.error(f"Auth module error: {e}")
        finally:
            await client.aclose()

        if any(v['type'] == 'Default Credentials' for v in vulnerabilities):
            return {
                "vulnerabilities": vulnerabilities,
                "severity": "critical",
                "risk_score": 9.0,
                "evidence": "Default credentials accepted! Immediate password change required.",
                "remediation": "Change all default passwords immediately. Implement strong password policy."
            }
        return {
            "vulnerabilities": vulnerabilities,
            "severity": "info",
            "risk_score": 0.0,
            "evidence": "Authentication tested successfully" if vulnerabilities else "No auth issues found",
            "remediation": None
        }