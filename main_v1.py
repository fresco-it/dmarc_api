from fastapi import FastAPI, UploadFile, File
import os
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

from fastapi.responses import RedirectResponse


app = FastAPI()


@app.get("/")
async def root():
    return RedirectResponse(url="/docs")



KNOWN_IPS = {
    "2a01:111:f403:c201::6",
}

HIGH_FAIL_THRESHOLD = 20


def text_or_empty(node, path: str) -> str:
    found = node.find(path)
    return found.text.strip() if found is not None and found.text else ""


def parse_dmarc_xml(xml_bytes: bytes) -> Dict[str, Any]:
    root = ET.fromstring(xml_bytes)
    report_metadata = root.find("report_metadata")
    policy_published = root.find("policy_published")

    result = {
        "report_org": text_or_empty(report_metadata, "org_name") if report_metadata is not None else "",
        "report_id": text_or_empty(report_metadata, "report_id") if report_metadata is not None else "",
        "domain": text_or_empty(policy_published, "domain") if policy_published is not None else "",
        "records": []
    }

    for record in root.findall("record"):
        row = record.find("row")
        auth_results = record.find("auth_results")

        source_ip = text_or_empty(row, "source_ip") if row is not None else ""
        count = int(text_or_empty(row, "count") or "0") if row is not None else 0
        disposition = text_or_empty(row, "policy_evaluated/disposition") if row is not None else ""
        dkim_eval = text_or_empty(row, "policy_evaluated/dkim") if row is not None else ""
        spf_eval = text_or_empty(row, "policy_evaluated/spf") if row is not None else ""

        dkim_domain = ""
        dkim_result = ""
        first_dkim = auth_results.find("dkim") if auth_results is not None else None
        if first_dkim is not None:
            dkim_domain = text_or_empty(first_dkim, "domain")
            dkim_result = text_or_empty(first_dkim, "result")

        spf_domain = ""
        spf_result = ""
        first_spf = auth_results.find("spf") if auth_results is not None else None
        if first_spf is not None:
            spf_domain = text_or_empty(first_spf, "domain")
            spf_result = text_or_empty(first_spf, "result")

        result["records"].append({
            "source_ip": source_ip,
            "count": count,
            "disposition": disposition,
            "dkim_eval": dkim_eval,
            "spf_eval": spf_eval,
            "dkim_domain": dkim_domain,
            "dkim_result": dkim_result,
            "spf_domain": spf_domain,
            "spf_result": spf_result
        })

    return result


def classify_report(report: Dict[str, Any]) -> Dict[str, Any]:
    issues: List[Dict[str, Any]] = []
    total_messages = sum(r["count"] for r in report["records"])

    for r in report["records"]:
        ip = r["source_ip"]
        count = r["count"]
        dkim_ok = (r["dkim_eval"] == "pass" or r["dkim_result"] == "pass")
        spf_ok = (r["spf_eval"] == "pass" or r["spf_result"] == "pass")
        known_ip = ip in KNOWN_IPS

        if not known_ip and (dkim_ok or spf_ok):
            issues.append({
                "severity": "WARNING",
                "type": "NEW_IP",
                "ip": ip,
                "count": count
            })

        if not dkim_ok or not spf_ok:
            sev = "CRITICAL" if count >= HIGH_FAIL_THRESHOLD else "WARNING"
            issues.append({
                "severity": sev,
                "type": "AUTH_FAIL",
                "ip": ip,
                "count": count,
                "dkim": r["dkim_eval"] or r["dkim_result"],
                "spf": r["spf_eval"] or r["spf_result"]
            })

    status = "OK"
    if any(i["severity"] == "CRITICAL" for i in issues):
        status = "CRITICAL"
    elif issues:
        status = "WARNING"

    return {
        "status": status,
        "summary": {
            "OK": "Sin incidencias relevantes.",
            "WARNING": "Se han detectado advertencias que conviene revisar.",
            "CRITICAL": "Se han detectado incidencias críticas."
        }[status],
        "domain": report["domain"],
        "report_org": report["report_org"],
        "report_id": report["report_id"],
        "total_messages": total_messages,
        "issues": issues
    }


@app.post("/check-dmarc-zip")
async def check_dmarc_zip(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".zip"):
        return {"status": "ERROR", "summary": "El archivo no es .zip"}

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        with zipfile.ZipFile(tmp_path, "r") as z:
            xml_names = [n for n in z.namelist() if n.lower().endswith(".xml")]
            if not xml_names:
                return {"status": "ERROR", "summary": "El ZIP no contiene ningún XML"}

            with z.open(xml_names[0]) as f:
                xml_bytes = f.read()

        report = parse_dmarc_xml(xml_bytes)
        return classify_report(report)

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)