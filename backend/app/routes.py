from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

from backend.app.config import settings
from backend.app.services.analysis_service import (
    ALLOWED_EXTENSIONS,
    STORE,
    build_html_report,
    create_demo_analysis,
    run_real_analysis,
)
from backend.app.utils.hashing import compute_file_hash, sanitize_filename
from backend.app.utils.tshark import check_tshark_available

router = APIRouter()


def _get_analysis(analysis_id: int) -> Dict[str, Any]:
    item = STORE.get(analysis_id)
    if not item:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return item


@router.post("/analyze", status_code=202)
async def analyze_pcap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    filename = sanitize_filename(file.filename or "capture.pcap")
    extension = Path(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail="Upload a .pcap, .pcapng, or .cap capture.")

    capture_path = Path(settings.upload_dir) / f"capture_{Path(filename).stem[:80]}_{id(file)}{extension}"
    total_size = 0
    try:
        with capture_path.open("wb") as destination:
            while chunk := await file.read(1024 * 1024):
                total_size += len(chunk)
                if total_size > settings.max_upload_size:
                    raise HTTPException(status_code=413, detail="Uploaded file exceeds the configured size limit.")
                destination.write(chunk)
        file_hash = compute_file_hash(str(capture_path))
        item = STORE.create(filename, total_size, file_hash, "real", "tshark")
        background_tasks.add_task(run_real_analysis, item, str(capture_path))
        analysis_id = item["analysis"]["id"]
        return {"analysis_id": analysis_id, "status": "pending", "status_url": f"/api/analyses/{analysis_id}"}
    except HTTPException:
        capture_path.unlink(missing_ok=True)
        raise
    except Exception as error:
        capture_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"Could not store capture: {error}") from error


@router.post("/demo-analysis")
async def demo_analysis():
    return create_demo_analysis()


@router.get("/analyses")
async def list_analyses():
    return [item["analysis"] | {"summary": item["summary"], "evidence": item["evidence"]} for item in STORE.list()]


@router.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: int):
    return _get_analysis(analysis_id)


@router.get("/analyses/{analysis_id}/summary")
async def get_summary(analysis_id: int):
    return _get_analysis(analysis_id)["summary"]


@router.get("/analyses/{analysis_id}/sessions")
async def get_sessions(analysis_id: int):
    return _get_analysis(analysis_id)["sessions"]


@router.get("/analyses/{analysis_id}/findings")
async def get_findings(analysis_id: int):
    return _get_analysis(analysis_id)["findings"]


@router.get("/analyses/{analysis_id}/drift")
async def get_drift(analysis_id: int):
    return _get_analysis(analysis_id)["drift"]


@router.get("/analyses/{analysis_id}/certificates")
async def get_certificates(analysis_id: int):
    return _get_analysis(analysis_id)["certificates"]


@router.post("/analyses/{analysis_id}/simulate-remediation")
async def simulate_remediation(analysis_id: int, changes: Dict[str, Any]):
    item = _get_analysis(analysis_id)
    current = item["summary"]["risk_score"]
    reduction = 0
    applied = {}
    if changes.get("require_tls12"):
        reduction += 24
        applied["require_tls12"] = True
    if changes.get("disable_legacy_ciphers"):
        reduction += 24
        applied["disable_legacy_ciphers"] = True
    if changes.get("require_forward_secrecy"):
        reduction += 15
        applied["require_forward_secrecy"] = True
    if changes.get("renew_certificates"):
        reduction += 22
        applied["renew_certificates"] = True
    projected = max(0, round(current - reduction, 1))
    return {
        "current_risk_score": current,
        "current_risk_level": item["summary"]["risk_level"],
        "projected_risk_score": projected,
        "projected_risk_level": "SIMULATED " + ("LOW" if projected < 25 else "MEDIUM" if projected < 50 else "HIGH" if projected < 75 else "CRITICAL"),
        "changes_applied": applied,
        "findings_resolved": [finding["title"] for finding in item["findings"] if reduction > 0][: max(1, len(applied))],
        "note": "Simulation only. No mail server configuration was changed.",
    }


@router.get("/analyses/{analysis_id}/report/json")
async def get_json_report(analysis_id: int):
    return JSONResponse(_get_analysis(analysis_id))


@router.get("/analyses/{analysis_id}/report/html")
async def get_html_report(analysis_id: int):
    return HTMLResponse(build_html_report(_get_analysis(analysis_id)))


@router.get("/analyses/{analysis_id}/report/pdf")
async def get_pdf_report(analysis_id: int):
    item = _get_analysis(analysis_id)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas

        output = BytesIO()
        document = canvas.Canvas(output, pagesize=letter)
        document.drawString(50, 750, "SecureMailScope forensic report")
        document.drawString(50, 730, f"Source: {item['analysis']['source']} | File: {item['analysis']['filename']}")
        document.drawString(50, 710, f"Risk: {item['summary']['risk_score']} ({item['summary']['risk_level']})")
        y = 680
        for finding in item["findings"][:20]:
            document.drawString(50, y, f"{finding['severity']}: {finding['title']}")
            y -= 18
            if y < 50:
                document.showPage()
                y = 750
        document.save()
        return Response(output.getvalue(), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=securemailscope-report.pdf"})
    except Exception as error:
        raise HTTPException(status_code=501, detail=f"PDF generation unavailable: {error}") from error


@router.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.app_version,
        "tshark_available": check_tshark_available(settings.tshark_path),
        "ollama_available": settings.enable_ollama,
    }