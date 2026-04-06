from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse, JSONResponse
from app.db.database import get_database
from app.core.auth_utils import get_authenticated_user, get_authenticated_db_user
from app.core.config import settings
from app.core.security import create_access_token, verify_token
from bson import ObjectId
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
import io, httpx, json, re
from datetime import datetime, timedelta

router = APIRouter()

SUBSCRIPTION_CACHE_TTL_SECONDS = 300
_subscription_state_cache = {}


async def _has_active_subscription(db, user_id: str, owner: dict | None = None) -> bool:
    now = datetime.utcnow()
    cached = _subscription_state_cache.get(user_id)
    if cached and (now - cached["checked_at"]).total_seconds() < SUBSCRIPTION_CACHE_TTL_SECONDS:
        return cached["has_active_subscription"]

    user_doc = owner
    if not user_doc:
        user_doc = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user_doc:
            raise HTTPException(status_code=404, detail="User not found")

    expires_at = user_doc.get("subscription_expires_at")
    expired = bool(expires_at and expires_at < now)
    has_subscription = bool(user_doc.get("has_ai_subscription", False)) and not expired

    if expired and user_doc.get("has_ai_subscription", False):
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"has_ai_subscription": False, "subscription_status": "inactive"}},
        )

    _subscription_state_cache[user_id] = {
        "checked_at": now,
        "has_active_subscription": has_subscription,
    }
    return has_subscription


# ─────────────────────────────────────────────────────────────
# AI KEY TEST (admin only) — GET /api/reports/ai-test
# ─────────────────────────────────────────────────────────────

@router.get("/reports/ai-test")
async def test_ai_key(request: Request):
    """Quick smoke-test: verifies API key + model string work."""
    user = await get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    if not settings.ANTHROPIC_API_KEY:
        return JSONResponse({"ok": False, "error": "ANTHROPIC_API_KEY not set in environment"})
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-opus-4-5",
                    "max_tokens": 20,
                    "messages": [{"role": "user", "content": "Say OK"}],
                },
            )
        if resp.status_code == 200:
            return JSONResponse({"ok": True, "model": "claude-opus-4-5", "reply": resp.json()["content"][0]["text"]})
        else:
            try:
                body = resp.json()
                msg = body.get("error", {}).get("message", str(body))
            except Exception:
                msg = resp.text[:200]
            return JSONResponse({"ok": False, "status": resp.status_code, "error": msg})
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


async def get_current_user(request: Request, allow_query_token: bool = False):
    return await get_authenticated_user(request, allow_query_token=allow_query_token)


def _validate_report_download_token(token: str, scan_id: str):
    payload = verify_token(token)
    if not payload:
        return None
    if payload.get("purpose") != "report_download":
        return None
    if payload.get("scan_id") != scan_id:
        return None
    return payload


async def _get_report_download_user(request: Request, scan_id: str):
    try:
        return await get_current_user(request)
    except HTTPException:
        token = (request.query_params.get("token") or "").strip()
        payload = _validate_report_download_token(token, scan_id)
        if not payload:
            raise HTTPException(status_code=401, detail="Not authenticated")

        raw_user_id = (payload.get("sub") or "").strip()
        if not raw_user_id:
            raise HTTPException(status_code=401, detail="Invalid download token")

        try:
            user_id = ObjectId(raw_user_id)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid download token")

        db = get_database()
        db_user = await db.users.find_one({"_id": user_id})
        if not db_user:
            raise HTTPException(status_code=401, detail="User not found")
        if not db_user.get("is_active", True):
            raise HTTPException(status_code=403, detail="Account deactivated")

        return {
            "sub": str(db_user["_id"]),
            "role": db_user.get("role", "user"),
            "email": db_user.get("email", ""),
        }


@router.post("/reports/{scan_id}/download-token")
async def issue_report_download_token(scan_id: str, request: Request):
    user = await get_current_user(request)
    db = get_database()

    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["user_id"] != user["sub"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    expires_in_seconds = 300
    token = create_access_token(
        {
            "sub": user["sub"],
            "purpose": "report_download",
            "scan_id": scan_id,
        },
        expires_delta=timedelta(seconds=expires_in_seconds),
    )
    return {
        "token": token,
        "expires_in_seconds": expires_in_seconds,
    }


# ─────────────────────────────────────────────────────────────
# AI REMEDIATION
# ─────────────────────────────────────────────────────────────

@router.get("/reports/{scan_id}/ai-remediation")
async def get_ai_remediation(scan_id: str, request: Request):
    """AI-powered fix recommendations for every vulnerability in a scan."""
    user = await get_current_user(request)
    db = get_database()

    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["user_id"] != user["sub"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    if user.get("role") != "admin":
        owner = await get_authenticated_db_user(request)
        has_active_subscription = await _has_active_subscription(db, user["sub"], owner=owner)
        if not has_active_subscription:
            raise HTTPException(status_code=402, detail="AI Fix requires an active subscription")

    # Return cached result if available
    if scan.get("ai_remediation"):
        return JSONResponse(content=scan["ai_remediation"])

    vulnerabilities = scan.get("vulnerabilities", [])
    if not vulnerabilities:
        return JSONResponse(content={"message": "No vulnerabilities to remediate.", "remediations": []})

    if not settings.ANTHROPIC_API_KEY:
        raise HTTPException(status_code=503, detail="AI remediation unavailable: ANTHROPIC_API_KEY not configured.")

    # Build compact vuln summary (cap at 20 to manage tokens)
    vuln_summary = []
    for i, v in enumerate(vulnerabilities[:20]):
        vuln_summary.append({
            "id": i + 1,
            "type": v.get("vuln_type", "Unknown"),
            "severity": v.get("severity", "info"),
            "url": v.get("url", ""),
            "param": v.get("param", ""),
            "evidence": (v.get("evidence") or "")[:300],
            "cve_id": v.get("cve_id") or "",
        })

    prompt = f"""You are a senior application security engineer. Analyze the following vulnerabilities found on: {scan['target_url']}

Vulnerabilities:
{json.dumps(vuln_summary, indent=2)}

Return ONLY a valid JSON object (no markdown, no preamble) with this exact structure:
{{
  "executive_summary": "2-3 sentence overall risk assessment",
  "critical_action": "The single most important fix to do immediately",
  "remediations": [
    {{
      "id": 1,
      "vuln_type": "SQL Injection",
      "severity": "high",
      "priority": 1,
      "summary": "One sentence explaining why this is dangerous",
      "fix_steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
      "code_example": "// Vulnerable\\nquery = 'SELECT * FROM users WHERE id=' + id\\n\\n// Secure\\nquery = 'SELECT * FROM users WHERE id=?'\\ndb.execute(query, [id])",
      "references": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
      "estimated_effort": "Low",
      "cve_id": null
    }}
  ]
}}

Priority 1=critical, 2=high, 3=medium, 4=low, 5=info. estimated_effort must be Low, Medium, or High.

Important constraints:
- Provide complete, production-ready remediation guidance. Avoid partial or vague steps.
- Include configuration, validation, and regression-test guidance in fix_steps when relevant.
- Defensive security guidance only. Do not provide exploit instructions or offensive steps."""

    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": settings.ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-opus-4-5",
                    "max_tokens": 4096,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
        resp.raise_for_status()
        ai_text = resp.json()["content"][0]["text"]

        # Try direct parse, then regex fallback
        try:
            result = json.loads(ai_text)
        except json.JSONDecodeError:
            match = re.search(r'\{.*\}', ai_text, re.DOTALL)
            if not match:
                raise HTTPException(status_code=502, detail="AI returned invalid JSON")
            result = json.loads(match.group())

    except httpx.HTTPStatusError as e:
        try:
            body = e.response.json()
            detail = body.get("error", {}).get("message") or str(body)
        except Exception:
            detail = e.response.text[:300]
        raise HTTPException(status_code=502, detail=f"AI error {e.response.status_code}: {detail}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI remediation failed: {str(e)}")

    # Cache in MongoDB
    await db.scans.update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": {"ai_remediation": result, "ai_remediation_at": datetime.utcnow()}}
    )
    return JSONResponse(content=result)


# ─────────────────────────────────────────────────────────────
# PDF REPORT (FIXED: reads from 'vulnerabilities', not 'steps')
# ─────────────────────────────────────────────────────────────

@router.get("/reports/{scan_id}/pdf")
async def generate_pdf(scan_id: str, request: Request):
    db = get_database()
    user = await _get_report_download_user(request, scan_id)

    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["user_id"] != user["sub"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch,
    )
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("VulnAssess Security Report", ParagraphStyle(
        "T", parent=styles["Heading1"], fontSize=26,
        textColor=colors.HexColor("#1D6FEB"), spaceAfter=4, fontName="Helvetica-Bold"
    )))
    story.append(Paragraph("Automated Web Vulnerability Assessment", ParagraphStyle(
        "S", parent=styles["Normal"], fontSize=11,
        textColor=colors.HexColor("#6B7280"), spaceAfter=16
    )))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
    story.append(Spacer(1, 0.2*inch))

    # Scan Info Table
    completed_at = scan.get("completed_at")
    info_data = [
        ["Target URL",          scan["target_url"]],
        ["Scan Date",           scan["created_at"].strftime("%Y-%m-%d %H:%M UTC")],
        ["Completed",           completed_at.strftime("%Y-%m-%d %H:%M UTC") if completed_at else "—"],
        ["Status",              scan["status"].upper()],
        ["Total Risk Score",    f"{scan.get('total_risk_score', 0):.1f} / 10.0"],
        ["Pages Crawled",       str(scan.get("pages_crawled", "—"))],
        ["Requests Made",       str(scan.get("requests_made", "—"))],
        ["Total Vulnerabilities", str(scan.get("total_vulnerabilities", 0))],
    ]
    t = Table(info_data, colWidths=[2.0*inch, 4.5*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (0,-1), colors.HexColor("#EFF6FF")),
        ("TEXTCOLOR",   (0,0), (0,-1), colors.HexColor("#1D6FEB")),
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",    (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
        ("PADDING",     (0,0), (-1,-1), 7),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, colors.HexColor("#F9FAFB")]),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.25*inch))

    # Severity Breakdown
    sc = scan.get("severity_counts", {})
    if any(sc.values()):
        story.append(Paragraph("Severity Breakdown", styles["Heading2"]))
        sv = Table(
            [["Critical","High","Medium","Low","Info"],
             [str(sc.get("critical",0)), str(sc.get("high",0)),
              str(sc.get("medium",0)), str(sc.get("low",0)), str(sc.get("info",0))]],
            colWidths=[1.3*inch]*5
        )
        sv.setStyle(TableStyle([
            ("FONTNAME",  (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",  (0,0), (-1,-1), 10),
            ("ALIGN",     (0,0), (-1,-1), "CENTER"),
            ("BACKGROUND",(0,0),(0,0), colors.HexColor("#DC2626")),
            ("BACKGROUND",(1,0),(1,0), colors.HexColor("#EA580C")),
            ("BACKGROUND",(2,0),(2,0), colors.HexColor("#D97706")),
            ("BACKGROUND",(3,0),(3,0), colors.HexColor("#16A34A")),
            ("BACKGROUND",(4,0),(4,0), colors.HexColor("#2563EB")),
            ("TEXTCOLOR", (0,0),(-1,0), colors.white),
            ("FONTSIZE",  (0,1),(-1,1), 16),
            ("FONTNAME",  (0,1),(-1,1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0,1),(0,1), colors.HexColor("#DC2626")),
            ("TEXTCOLOR", (1,1),(1,1), colors.HexColor("#EA580C")),
            ("TEXTCOLOR", (2,1),(2,1), colors.HexColor("#D97706")),
            ("TEXTCOLOR", (3,1),(3,1), colors.HexColor("#16A34A")),
            ("TEXTCOLOR", (4,1),(4,1), colors.HexColor("#2563EB")),
            ("GRID",      (0,0),(-1,-1), 0.5, colors.HexColor("#E5E7EB")),
            ("PADDING",   (0,0),(-1,-1), 8),
        ]))
        story.append(sv)
        story.append(Spacer(1, 0.25*inch))

    # ── FIXED: read from 'vulnerabilities' flat list ──
    vulnerabilities = scan.get("vulnerabilities", [])
    sev_colors = {
        "critical": colors.HexColor("#DC2626"), "high": colors.HexColor("#EA580C"),
        "medium":   colors.HexColor("#D97706"), "low":  colors.HexColor("#16A34A"),
        "info":     colors.HexColor("#2563EB"),
    }
    sev_bg = {
        "critical": colors.HexColor("#FEF2F2"), "high": colors.HexColor("#FFF7ED"),
        "medium":   colors.HexColor("#FFFBEB"), "low":  colors.HexColor("#F0FDF4"),
        "info":     colors.HexColor("#EFF6FF"),
    }

    if vulnerabilities:
        story.append(Paragraph("Vulnerability Findings", styles["Heading2"]))
        story.append(Spacer(1, 0.1*inch))

        for i, v in enumerate(vulnerabilities):
            sev = v.get("severity", "info").lower()
            c   = sev_colors.get(sev, colors.grey)
            bg  = sev_bg.get(sev, colors.white)

            label = f"[{sev.upper()}]  {v.get('vuln_type','Unknown Vulnerability')}"
            if v.get("cve_id"):
                label += f"  •  {v['cve_id']}"
            story.append(Paragraph(label, ParagraphStyle(
                f"VT{i}", parent=styles["Heading3"],
                textColor=c, fontSize=11, fontName="Helvetica-Bold"
            )))

            rows = []
            if v.get("url"):    rows.append(["URL",        v["url"][:100]])
            if v.get("method"): rows.append(["Method",     v["method"]])
            if v.get("param"):  rows.append(["Parameter",  v["param"]])
            if v.get("confidence"): rows.append(["Confidence", f"{v['confidence']:.0%}"])
            if v.get("risk_score"): rows.append(["Risk Score", f"{v['risk_score']:.1f} / 10"])

            if rows:
                dt = Table(rows, colWidths=[1.2*inch, 5.3*inch])
                dt.setStyle(TableStyle([
                    ("BACKGROUND", (0,0),(-1,-1), bg),
                    ("FONTNAME",   (0,0),(0,-1), "Helvetica-Bold"),
                    ("FONTNAME",   (1,0),(1,-1), "Helvetica"),
                    ("FONTSIZE",   (0,0),(-1,-1), 8),
                    ("GRID",       (0,0),(-1,-1), 0.3, colors.HexColor("#E5E7EB")),
                    ("PADDING",    (0,0),(-1,-1), 5),
                ]))
                story.append(dt)

            if v.get("evidence"):
                story.append(Paragraph(
                    f"<b>Evidence:</b> {v['evidence'][:400]}", styles["Normal"]))
            if v.get("reproduction_steps"):
                steps = v["reproduction_steps"]
                txt = " → ".join(steps[:3]) if isinstance(steps, list) else str(steps)
                story.append(Paragraph(
                    f"<b>Reproduction:</b> {txt[:300]}", styles["Normal"]))

            story.append(Spacer(1, 0.15*inch))
    else:
        story.append(Paragraph("No vulnerabilities found.", styles["Normal"]))

    # Footer
    story.append(Spacer(1, 0.3*inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")))
    story.append(Paragraph(
        f"Generated by VulnAssess on {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC  •  Confidential",
        ParagraphStyle("F", parent=styles["Normal"], fontSize=8,
                       textColor=colors.HexColor("#9CA3AF"), spaceBefore=6)
    ))

    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=vulnassess-report-{scan_id}.pdf"},
    )


# ─────────────────────────────────────────────────────────────
# AI REMEDIATION PDF DOWNLOAD
# ─────────────────────────────────────────────────────────────

@router.get("/reports/{scan_id}/ai-remediation/pdf")
async def generate_ai_remediation_pdf(scan_id: str, request: Request):
    """
    Download the AI remediation results as a standalone PDF report.
    If AI remediation hasn't been generated yet, returns 404.
    If it exists in cache, uses it directly — no extra API call.
    """
    db = get_database()
    user = await _get_report_download_user(request, scan_id)

    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["user_id"] != user["sub"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    ai_data = scan.get("ai_remediation")
    if not ai_data:
        raise HTTPException(
            status_code=404,
            detail="AI remediation not generated yet. Open the AI Fix screen first."
        )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch,
    )
    styles = getSampleStyleSheet()
    story = []

    # ── Cover Header ──
    story.append(Paragraph("VulnAssess", ParagraphStyle(
        "Brand", parent=styles["Normal"], fontSize=13,
        textColor=colors.HexColor("#1D6FEB"), fontName="Helvetica-Bold", spaceAfter=4
    )))
    story.append(Paragraph("AI-Powered Remediation Report", ParagraphStyle(
        "Title", parent=styles["Heading1"], fontSize=24,
        textColor=colors.HexColor("#1E293B"), fontName="Helvetica-Bold", spaceAfter=4
    )))
    story.append(Paragraph(
        f"Target: {scan['target_url']}",
        ParagraphStyle("Sub", parent=styles["Normal"], fontSize=11,
                       textColor=colors.HexColor("#6B7280"), spaceAfter=4)
    ))
    story.append(Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC  •  "
        f"Scan Date: {scan['created_at'].strftime('%Y-%m-%d')}",
        ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9,
                       textColor=colors.HexColor("#9CA3AF"), spaceAfter=16)
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1D6FEB")))
    story.append(Spacer(1, 0.2*inch))

    # ── AI Badge ──
    ai_badge_data = [["  🤖  Powered by Claude AI (Anthropic)  "]]
    ai_badge = Table(ai_badge_data, colWidths=[3.5*inch])
    ai_badge.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), colors.HexColor("#EDE9FE")),
        ("TEXTCOLOR",   (0,0), (-1,-1), colors.HexColor("#6D28D9")),
        ("FONTNAME",    (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 10),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("PADDING",     (0,0), (-1,-1), 8),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(ai_badge)
    story.append(Spacer(1, 0.25*inch))

    # ── Executive Summary ──
    exec_summary = ai_data.get("executive_summary", "")
    if exec_summary:
        story.append(Paragraph("Executive Summary", ParagraphStyle(
            "ES", parent=styles["Heading2"], fontSize=14,
            textColor=colors.HexColor("#1E293B"), fontName="Helvetica-Bold", spaceAfter=8
        )))
        story.append(Paragraph(exec_summary, ParagraphStyle(
            "ESBody", parent=styles["Normal"], fontSize=11,
            textColor=colors.HexColor("#374151"), leading=18, spaceAfter=16
        )))

    # ── Critical Action ──
    critical_action = ai_data.get("critical_action", "")
    if critical_action:
        crit_data = [["⚡  IMMEDIATE ACTION REQUIRED", critical_action]]
        crit_table = Table(crit_data, colWidths=[2.0*inch, 4.5*inch])
        crit_table.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (0,0), colors.HexColor("#DC2626")),
            ("BACKGROUND",  (1,0), (1,0), colors.HexColor("#FEF2F2")),
            ("TEXTCOLOR",   (0,0), (0,0), colors.white),
            ("TEXTCOLOR",   (1,0), (1,0), colors.HexColor("#991B1B")),
            ("FONTNAME",    (0,0), (0,0), "Helvetica-Bold"),
            ("FONTNAME",    (1,0), (1,0), "Helvetica"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("PADDING",     (0,0), (-1,-1), 10),
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#FECACA")),
        ]))
        story.append(crit_table)
        story.append(Spacer(1, 0.25*inch))

    # ── Severity colour map ──
    sev_colors = {
        "critical": colors.HexColor("#DC2626"),
        "high":     colors.HexColor("#EA580C"),
        "medium":   colors.HexColor("#D97706"),
        "low":      colors.HexColor("#16A34A"),
        "info":     colors.HexColor("#2563EB"),
    }
    sev_bg = {
        "critical": colors.HexColor("#FEF2F2"),
        "high":     colors.HexColor("#FFF7ED"),
        "medium":   colors.HexColor("#FFFBEB"),
        "low":      colors.HexColor("#F0FDF4"),
        "info":     colors.HexColor("#EFF6FF"),
    }
    effort_colors = {
        "Low":    colors.HexColor("#16A34A"),
        "Medium": colors.HexColor("#D97706"),
        "High":   colors.HexColor("#DC2626"),
    }

    # ── Remediation Cards ──
    remediations = ai_data.get("remediations", [])
    if remediations:
        story.append(Paragraph("Remediation Details", ParagraphStyle(
            "RH", parent=styles["Heading2"], fontSize=14,
            textColor=colors.HexColor("#1E293B"), fontName="Helvetica-Bold", spaceAfter=12
        )))

        for r in remediations:
            sev       = (r.get("severity") or "info").lower()
            sev_c     = sev_colors.get(sev, colors.grey)
            sev_bg_c  = sev_bg.get(sev, colors.white)
            effort    = r.get("estimated_effort", "")
            effort_c  = effort_colors.get(effort, colors.grey)
            priority  = r.get("priority", "—")
            vuln_type = r.get("vuln_type", "Unknown")
            cve_id    = r.get("cve_id") or ""

            # Card title row
            title_parts = f"P{priority}  ·  {vuln_type}"
            if cve_id:
                title_parts += f"  ·  {cve_id}"

            title_row = [[
                Paragraph(title_parts, ParagraphStyle(
                    f"CT{priority}", parent=styles["Normal"],
                    fontSize=11, fontName="Helvetica-Bold",
                    textColor=colors.white
                )),
                Paragraph(sev.upper(), ParagraphStyle(
                    f"CS{priority}", parent=styles["Normal"],
                    fontSize=9, fontName="Helvetica-Bold",
                    textColor=colors.white
                )),
                Paragraph(f"{effort} effort" if effort else "", ParagraphStyle(
                    f"CE{priority}", parent=styles["Normal"],
                    fontSize=9, textColor=colors.white
                )),
            ]]
            title_table = Table(title_row, colWidths=[4.0*inch, 1.0*inch, 1.5*inch])
            title_table.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), sev_c),
                ("PADDING",    (0,0), (-1,-1), 8),
                ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ]))
            story.append(title_table)

            # Summary
            if r.get("summary"):
                sum_table = Table(
                    [[Paragraph(r["summary"], ParagraphStyle(
                        f"Sum{priority}", parent=styles["Normal"],
                        fontSize=10, textColor=colors.HexColor("#374151"), leading=15
                    ))]],
                    colWidths=[6.5*inch]
                )
                sum_table.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,-1), sev_bg_c),
                    ("PADDING",    (0,0), (-1,-1), 10),
                    ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#E5E7EB")),
                ]))
                story.append(sum_table)

            # Fix Steps
            fix_steps = r.get("fix_steps", [])
            if fix_steps:
                steps_content = "\n".join(f"{i+1}.  {step}" for i, step in enumerate(fix_steps))
                steps_table = Table(
                    [[
                        Paragraph("FIX STEPS", ParagraphStyle(
                            f"SL{priority}", parent=styles["Normal"],
                            fontSize=8, fontName="Helvetica-Bold",
                            textColor=colors.HexColor("#6B7280")
                        )),
                        Paragraph(steps_content, ParagraphStyle(
                            f"SC{priority}", parent=styles["Normal"],
                            fontSize=9, leading=15,
                            textColor=colors.HexColor("#1E293B")
                        )),
                    ]],
                    colWidths=[1.0*inch, 5.5*inch]
                )
                steps_table.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
                    ("PADDING",    (0,0), (-1,-1), 8),
                    ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#E5E7EB")),
                    ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ]))
                story.append(steps_table)

            # Code Example
            code = r.get("code_example", "")
            if code:
                code_table = Table(
                    [[
                        Paragraph("CODE", ParagraphStyle(
                            f"CL{priority}", parent=styles["Normal"],
                            fontSize=8, fontName="Helvetica-Bold",
                            textColor=colors.HexColor("#6B7280")
                        )),
                        Paragraph(
                            code[:600].replace("&","&amp;").replace("<","&lt;").replace(">","&gt;"),
                            ParagraphStyle(
                                f"CC{priority}", parent=styles["Normal"],
                                fontSize=8, fontName="Courier",
                                textColor=colors.HexColor("#E2E8F0"),
                                leading=13
                            )
                        ),
                    ]],
                    colWidths=[1.0*inch, 5.5*inch]
                )
                code_table.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#0F172A")),
                    ("PADDING",    (0,0), (-1,-1), 10),
                    ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ]))
                story.append(code_table)

            # References
            refs = r.get("references", [])
            if refs:
                refs_text = "  ·  ".join(
                    ref.replace("https://","").split("/")[0] for ref in refs[:4]
                )
                ref_table = Table(
                    [[
                        Paragraph("REFS", ParagraphStyle(
                            f"RL{priority}", parent=styles["Normal"],
                            fontSize=8, fontName="Helvetica-Bold",
                            textColor=colors.HexColor("#6B7280")
                        )),
                        Paragraph(refs_text, ParagraphStyle(
                            f"RC{priority}", parent=styles["Normal"],
                            fontSize=8, textColor=colors.HexColor("#2563EB")
                        )),
                    ]],
                    colWidths=[1.0*inch, 5.5*inch]
                )
                ref_table.setStyle(TableStyle([
                    ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#EFF6FF")),
                    ("PADDING",    (0,0), (-1,-1), 7),
                    ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#BFDBFE")),
                ]))
                story.append(ref_table)

            story.append(Spacer(1, 0.2*inch))

    else:
        story.append(Paragraph("No remediations generated.", styles["Normal"]))

    # ── Footer ──
    story.append(Spacer(1, 0.2*inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")))
    story.append(Paragraph(
        f"VulnAssess AI Remediation Report  •  {scan['target_url']}  •  "
        f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC  •  Confidential",
        ParagraphStyle("Foot", parent=styles["Normal"], fontSize=7,
                       textColor=colors.HexColor("#9CA3AF"), spaceBefore=6)
    ))

    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=vulnassess-ai-remediation-{scan_id}.pdf"
        },
    )