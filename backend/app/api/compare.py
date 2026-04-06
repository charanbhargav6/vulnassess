from fastapi import APIRouter, HTTPException, Request
from bson import ObjectId
from app.db.database import get_database
from app.core.auth_utils import get_authenticated_user

router = APIRouter()


@router.get("/compare")
async def compare_scans(scan1_id: str, scan2_id: str, request: Request):
    payload = await get_authenticated_user(request)

    db = get_database()
    try:
        scan1 = await db.scans.find_one({"_id": ObjectId(scan1_id)})
        scan2 = await db.scans.find_one({"_id": ObjectId(scan2_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid scan ID")

    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    user_id = payload.get("sub")
    role = payload.get("role")
    for scan in (scan1, scan2):
        if scan["user_id"] != user_id and role != "admin":
            raise HTTPException(status_code=403, detail="Not authorized to compare these scans")

    def get_severity_label(score):
        if score >= 9: return "Critical"
        if score >= 7: return "High"
        if score >= 4: return "Medium"
        return "Low"

    def get_severity_color(score):
        if score >= 9: return "#DC2626"
        if score >= 7: return "#EA580C"
        if score >= 4: return "#D97706"
        return "#16A34A"

    def process_scan(scan):
        # FIXED: read from flat 'vulnerabilities' list (not 'steps'/'findings')
        vulnerabilities = scan.get("vulnerabilities", [])
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        findings = []

        for v in vulnerabilities:
            raw_sev = v.get("severity", "info")
            # Normalize to title-case for display
            sev_map = {
                "critical": "Critical", "high": "High",
                "medium": "Medium", "low": "Low", "info": "Info"
            }
            sev = sev_map.get(raw_sev.lower(), "Info")
            if sev in severity_counts:
                severity_counts[sev] += 1

            findings.append({
                "module":     v.get("module", ""),
                "name":       v.get("vuln_type", ""),
                "severity":   sev,
                "risk_score": v.get("risk_score", 0),
                "url":        v.get("url", ""),
                "param":      v.get("param", ""),
                "cve_id":     v.get("cve_id", ""),
            })

        score = scan.get("total_risk_score", 0)
        return {
            "id":             str(scan["_id"]),
            "target_url":     scan["target_url"],
            "status":         scan["status"],
            "created_at":     scan["created_at"].isoformat(),
            "total_risk_score":   score,
            "severity_label": get_severity_label(score),
            "severity_color": get_severity_color(score),
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "findings":       findings,
            "pages_crawled":  scan.get("pages_crawled", 0),
            "requests_made":  scan.get("requests_made", 0),
        }

    s1 = process_scan(scan1)
    s2 = process_scan(scan2)

    # Diff: new findings in scan2 not in scan1
    s1_types = {(f["name"], f["url"]) for f in s1["findings"]}
    s2_types = {(f["name"], f["url"]) for f in s2["findings"]}

    new_findings   = [f for f in s2["findings"] if (f["name"], f["url"]) not in s1_types]
    fixed_findings = [f for f in s1["findings"] if (f["name"], f["url"]) not in s2_types]
    common_findings = [f for f in s2["findings"] if (f["name"], f["url"]) in s1_types]

    score_diff = round(s2["total_risk_score"] - s1["total_risk_score"], 2)

    return {
        "scan1": s1,
        "scan2": s2,
        "summary": {
            "score_diff":          score_diff,
            "improved":            score_diff < 0,
            "new_findings_count":  len(new_findings),
            "fixed_findings_count": len(fixed_findings),
            "common_findings_count": len(common_findings),
            "new_findings":        new_findings,
            "fixed_findings":      fixed_findings,
            "common_findings":     common_findings,
        },
    }