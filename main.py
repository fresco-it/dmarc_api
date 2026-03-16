from fastapi import FastAPI, Request
import os
import zipfile
import xml.etree.ElementTree as ET
import json
import base64
import gzip
import io
from typing import Dict, Any, List

appDMARC = FastAPI()

KNOWN_IPS = {
    "2a01:111:f403:c201::6",
}

TRUSTED_DKIM_DOMAINS = {
    "fresco.es",
    "sendgrid.info",
}

TRUSTED_SPF_DOMAINS = {
    "fresco.es",
    "em7851.fresco.es",
}

HIGH_FAIL_THRESHOLD = 20


@app.get("/")
def root():
    return {"message": "API DMARC en funcionamiento"}


def text_or_empty(node, path: str) -> str:
    found = node.find(path)
    return found.text.strip() if found is not None and found.text else ""


def normalize_file_bytes(raw: bytes) -> bytes:
    # Caso 1: ZIP real
    if raw[:2] == b"PK":
        return raw

    # Caso 2: GZIP real
    if raw[:2] == b"\x1f\x8b":
        return raw

    # Caso 3: XML directo
    stripped = raw.lstrip()
    if stripped.startswith(b"<"):
        return raw

    # Caso 4: base64 como texto
    try:
        text = raw.decode("utf-8").strip()
        decoded = base64.b64decode(text, validate=False)
        if decoded[:2] in (b"PK", b"\x1f\x8b") or decoded.lstrip().startswith(b"<"):
            return decoded
    except Exception:
        pass

    # Caso 5: JSON con $content
    try:
        obj = json.loads(raw.decode("utf-8"))
        if isinstance(obj, dict) and "$content" in obj:
            decoded = base64.b64decode(obj["$content"])
            if decoded[:2] in (b"PK", b"\x1f\x8b") or decoded.lstrip().startswith(b"<"):
                return decoded
    except Exception:
        pass

    raise ValueError("No se ha podido interpretar el body como ZIP, GZIP o XML válido.")


def extract_xml_bytes(file_bytes: bytes) -> bytes:
    # ZIP
    if file_bytes[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as z:
            xml_names = [n for n in z.namelist() if n.lower().endswith(".xml")]
            if not xml_names:
                raise ValueError("El ZIP no contiene ningún XML DMARC.")
            with z.open(xml_names[0]) as f:
                return f.read()

    # GZIP
    if file_bytes[:2] == b"\x1f\x8b":
        xml_bytes = gzip.decompress(file_bytes)
        if not xml_bytes.lstrip().startswith(b"<"):
            raise ValueError("El GZIP no contiene un XML válido.")
        return xml_bytes

    # XML directo
    if file_bytes.lstrip().startswith(b"<"):
        return file_bytes

    raise ValueError("Formato no soportado: no es ZIP, GZIP ni XML.")


def parse_dmarc_xml(xml_bytes: bytes) -> Dict[str, Any]:
    root = ET.fromstring(xml_bytes)

    report_metadata = root.find("report_metadata")
    policy_published = root.find("policy_published")

    result = {
        "report_org": text_or_empty(report_metadata, "org_name") if report_metadata is not None else "",
        "report_id": text_or_empty(report_metadata, "report_id") if report_metadata is not None else "",
        "domain": text_or_empty(policy_published, "domain") if policy_published is not None else "",
        "policy_p": text_or_empty(policy_published, "p") if policy_published is not None else "",
        "policy_sp": text_or_empty(policy_published, "sp") if policy_published is not None else "",
        "policy_pct": text_or_empty(policy_published, "pct") if policy_published is not None else "",
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
        header_from = text_or_empty(record, "identifiers/header_from")

        dkim_results = []
        if auth_results is not None:
            for d in auth_results.findall("dkim"):
                dkim_results.append({
                    "domain": text_or_empty(d, "domain"),
                    "result": text_or_empty(d, "result"),
                    "selector": text_or_empty(d, "selector")
                })

        spf_results = []
        if auth_results is not None:
            for s in auth_results.findall("spf"):
                spf_results.append({
                    "domain": text_or_empty(s, "domain"),
                    "result": text_or_empty(s, "result")
                })

        result["records"].append({
            "source_ip": source_ip,
            "count": count,
            "disposition": disposition,
            "dkim_eval": dkim_eval,
            "spf_eval": spf_eval,
            "header_from": header_from,
            "dkim_results": dkim_results,
            "spf_results": spf_results
        })

    return result


def classify_report(report: Dict[str, Any]) -> Dict[str, Any]:
    issues: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []
    total_messages = sum(r["count"] for r in report["records"])

    for r in report["records"]:
        ip = r["source_ip"]
        count = r["count"]

        dkim_ok = r["dkim_eval"] == "pass"
        spf_ok = r["spf_eval"] == "pass"
        known_ip = ip in KNOWN_IPS

        dkim_domains = {x["domain"] for x in r.get("dkim_results", []) if x.get("result") == "pass"}
        spf_domains = {x["domain"] for x in r.get("spf_results", []) if x.get("result") == "pass"}

        trusted_dkim = any(d in TRUSTED_DKIM_DOMAINS for d in dkim_domains)
        trusted_spf = any(s in TRUSTED_SPF_DOMAINS for s in spf_domains)

        if not dkim_ok and not spf_ok:
            sev = "CRITICAL" if count >= HIGH_FAIL_THRESHOLD else "WARNING"
            issues.append({
                "severity": sev,
                "type": "AUTH_FAIL",
                "ip": ip,
                "count": count,
                "dkim": r["dkim_eval"],
                "spf": r["spf_eval"],
                "disposition": r["disposition"]
            })
            continue

        if not known_ip:
            if trusted_dkim or trusted_spf:
                observations.append({
                    "type": "NEW_IP_BUT_AUTH_OK",
                    "ip": ip,
                    "count": count,
                    "dkim_domains": sorted(dkim_domains),
                    "spf_domains": sorted(spf_domains)
                })
            else:
                issues.append({
                    "severity": "WARNING",
                    "type": "NEW_IP_UNKNOWN_DOMAIN",
                    "ip": ip,
                    "count": count,
                    "dkim_domains": sorted(dkim_domains),
                    "spf_domains": sorted(spf_domains)
                })

    status = "OK"
    if any(i["severity"] == "CRITICAL" for i in issues):
        status = "CRITICAL"
    elif any(i["severity"] == "WARNING" for i in issues):
        status = "WARNING"

    if status == "OK":
        summary = "Todos los registros DMARC pasan autenticación."
    elif status == "WARNING":
        summary = "Se han detectado advertencias que conviene revisar."
    else:
        summary = "Se han detectado incidencias críticas."

    return {
        "status": status,
        "summary": summary,
        "domain": report["domain"],
        "report_org": report["report_org"],
        "report_id": report["report_id"],
        "total_messages": total_messages,
        "issues": issues,
        "observations": observations
    }


@app.post("/check-dmarc")
async def check_dmarc(request: Request):
    raw = await request.body()

    try:
        file_bytes = normalize_file_bytes(raw)
        xml_bytes = extract_xml_bytes(file_bytes)
    except Exception as e:
        preview = raw[:200].decode("utf-8", errors="ignore")
        return {
            "status": "ERROR",
            "summary": f"No se ha podido interpretar el fichero DMARC: {str(e)}",
            "preview": preview
        }

    try:
        report = parse_dmarc_xml(xml_bytes)
        return classify_report(report)
    except Exception as e:
        preview = xml_bytes[:200].decode("utf-8", errors="ignore")
        return {
            "status": "ERROR",
            "summary": f"Se ha producido un error al procesar el XML DMARC: {str(e)}",
            "preview": preview
        }