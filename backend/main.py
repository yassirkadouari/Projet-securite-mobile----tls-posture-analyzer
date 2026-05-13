import asyncio
import re
import os
import tempfile
import zipfile
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException, Query, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from sslyze import (
    Scanner, ServerScanRequest, ServerNetworkLocation,
    ScanCommandAttemptStatusEnum, ScanCommand
)

# Configuration de FastAPI
app = FastAPI(title="Network/TLS Posture Analyzer API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 1. SCANNER TLS (Existant & Amélioré) ---
def run_sslyze_scan(hostname: str, port: int) -> Dict[str, Any]:
    try:
        location = ServerNetworkLocation(hostname=hostname, port=port)
    except Exception as e:
        raise ValueError(f"Erreur de résolution d'hôte: {str(e)}")

    scan_commands = [
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES, ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.HEARTBLEED, ScanCommand.ROBOT, ScanCommand.OPENSSL_CCS_INJECTION,
        ScanCommand.TLS_COMPRESSION, ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.HTTP_HEADERS, ScanCommand.ELLIPTIC_CURVES, ScanCommand.TLS_FALLBACK_SCSV
    ]

    request = ServerScanRequest(server_location=location, scan_commands=scan_commands)
    scanner = Scanner()
    scanner.queue_scans([request])
    results = list(scanner.get_results())
    
    if not results:
        raise RuntimeError("Aucun résultat renvoyé par sslyze.")
        
    result = results[0]
    if result.connectivity_status.name != "COMPLETED":
        raise RuntimeError(f"Impossible de se connecter au serveur : {result.connectivity_status.name}")

    report_data = {
        "hostname": hostname, "port": port, "certificate": None,
        "protocols": {}, "vulnerabilities": {}, "security_headers": {}, "advanced_security": {}
    }

    # Extraction des résultats (simplifiée pour la lisibilité)
    cert_attempt = result.scan_result.certificate_info
    if cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and cert_attempt.result.certificate_deployments:
        cert = cert_attempt.result.certificate_deployments[0].received_certificate_chain[0]
        report_data["certificate"] = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_after": str(cert.not_valid_after_utc),
            "signature_hash_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Inconnu"
        }

    for proto_name, attempt in {
        "SSL 2.0": result.scan_result.ssl_2_0_cipher_suites, "SSL 3.0": result.scan_result.ssl_3_0_cipher_suites,
        "TLS 1.0": result.scan_result.tls_1_0_cipher_suites, "TLS 1.1": result.scan_result.tls_1_1_cipher_suites,
        "TLS 1.2": result.scan_result.tls_1_2_cipher_suites, "TLS 1.3": result.scan_result.tls_1_3_cipher_suites,
    }.items():
        if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            report_data["protocols"][proto_name] = len(attempt.result.accepted_cipher_suites) > 0

    return report_data

@app.get("/api/scan")
async def scan_endpoint(hostname: str = Query(...), port: int = Query(443)):
    try:
        result = await asyncio.to_thread(run_sslyze_scan, hostname, port)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# --- 2. ANALYSE APK (network_security_config) ---
@app.post("/api/upload-apk")
async def upload_apk(file: UploadFile = File(...)):
    if not file.filename.endswith('.apk'):
        raise HTTPException(status_code=400, detail="Veuillez fournir un fichier .apk")

    config_data = {
        "cleartextTrafficPermitted": "Non défini (Par défaut: False sous Android 9+)",
        "minSdkVersion": "Inconnue",
        "certificatePinning": False,
        "pins": []
    }
    
    try:
        content = await file.read()
        # Heuristique basique de Strings pour extraire la config sans decompilateur lourd
        content_str = content.decode('utf-8', errors='ignore')
        
        if "cleartextTrafficPermitted=\"true\"" in content_str or "cleartextTrafficPermitted=\x01\x01" in content_str:
            config_data["cleartextTrafficPermitted"] = "Oui (VULNÉRABILITÉ CRITIQUE)"
        elif "cleartextTrafficPermitted=\"false\"" in content_str:
            config_data["cleartextTrafficPermitted"] = "Non (Sécurisé)"
            
        if "<pin-set" in content_str or "pin digest=" in content_str:
            config_data["certificatePinning"] = True
            # Extraction basique des pins
            pins = re.findall(r'[A-Za-z0-9+/=]{43,}', content_str)
            config_data["pins"] = list(set(pins))[:5] # Limite à 5
            
        # Extract potential domains
        domains = re.findall(r'(https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', content_str)
        cleaned_domains = list(set([d.replace('https://', '').replace('http://', '').split('/')[0] for d in domains]))
        
        return {
            "status": "success", 
            "security_config": config_data,
            "discovered_endpoints": cleaned_domains[:20] # Top 20
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur d'analyse: {str(e)}")


# --- 3. ANALYSE LOGS PROXY ---
@app.post("/api/upload-logs")
async def upload_logs(file: UploadFile = File(...)):
    try:
        content = await file.read()
        text = content.decode('utf-8', errors='ignore')
        
        # Regex pour trouver des endpoints dans les logs (Host: xxx ou http(s)://xxx)
        endpoints = re.findall(r'(?:Host:\s*|https?://)([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', text)
        unique_endpoints = list(set(endpoints))
        
        # Filtrer les domaines parasites (w3.org, schemas.android.com...)
        filtered = [e for e in unique_endpoints if not e.startswith('schemas.') and not e.startswith('www.w3.org')]
        
        return {"status": "success", "endpoints": filtered[:50]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- 4. MOTEUR IA (SIMULÉ) ---
@app.post("/api/ai-analyze")
async def ai_analyze(endpoints: List[str]):
    # Simulation d'un prompt LLM qui catégorise les domaines
    grouped = {
        "Production API": [],
        "Test / Dev / Staging": [],
        "Third-Party (Analytics / Ads)": [],
        "Suspects (Anomalies)": []
    }
    
    for ep in endpoints:
        ep_lower = ep.lower()
        if "test" in ep_lower or "dev" in ep_lower or "staging" in ep_lower or "sandbox" in ep_lower:
            grouped["Test / Dev / Staging"].append(ep)
        elif "google-analytics" in ep_lower or "mixpanel" in ep_lower or "appsflyer" in ep_lower or "facebook" in ep_lower:
            grouped["Third-Party (Analytics / Ads)"].append(ep)
        elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ep) or ".xyz" in ep_lower or ".ru" in ep_lower:
            grouped["Suspects (Anomalies)"].append(ep)
        else:
            grouped["Production API"].append(ep)
            
    summary = "L'analyse IA indique que l'application communique majoritairement avec ses API de production. "
    if grouped["Test / Dev / Staging"]:
        summary += "⚠️ ATTENTION : Des endpoints de test/dev ont été détectés en production, ce qui augmente la surface d'attaque. "
    if grouped["Suspects (Anomalies)"]:
        summary += "🚨 CRITIQUE : Des adresses IP directes ou domaines suspects ont été trouvés. Un audit immédiat de ces flux est requis. "
    if grouped["Third-Party (Analytics / Ads)"]:
        summary += "Note : De nombreuses API tierces sont appelées, ce qui peut poser des risques de fuite de données (RGPD)."

    recommendations = [
        "S'assurer que 'cleartextTrafficPermitted' est explicitement défini sur false.",
        "Mettre en place du Certificate Pinning sur les 'Production API' pour éviter le MitM.",
        "Supprimer les endpoints de 'Test/Dev' du build final de l'APK.",
        "Vérifier le support strict de TLS 1.2 minimum sur les serveurs backend."
    ]

    return {
        "status": "success",
        "grouping": grouped,
        "summary": summary,
        "recommendations": recommendations
    }
