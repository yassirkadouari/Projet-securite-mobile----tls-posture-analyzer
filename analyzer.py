import argparse
import sys
import os
from typing import Dict, Any

from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ScanCommand
)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import jinja2

console = Console()

def print_banner():
    console.print(Panel.fit("[bold cyan]NETWORK/TLS Posture Analyser[/bold cyan]\n[italic]Mobile Security Module Project[/italic]", border_style="cyan"))

def analyze_server(hostname: str, port: int = 443):
    console.print(f"\n[bold yellow]Démarrage de l'analyse pour :[/bold yellow] [bold white]{hostname}:{port}[/bold white]\n")
    
    location = ServerNetworkLocation(hostname=hostname, port=port)
    
    scan_commands = [
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.HEARTBLEED,
        ScanCommand.ROBOT,
        ScanCommand.OPENSSL_CCS_INJECTION
    ]
    
    request = ServerScanRequest(
        server_location=location,
        scan_commands=scan_commands
    )
    
    scanner = Scanner()
    scanner.queue_scans([request])
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("[cyan]Analyse en cours...", total=None)
        results = list(scanner.get_results())
        progress.update(task, completed=100)
    
    if not results:
        console.print("[bold red]Erreur : Aucun résultat renvoyé par sslyze.[/bold red]")
        return
        
    result = results[0]
    if result.connectivity_status.name != "COMPLETED":
        console.print(f"[bold red]Impossible de se connecter au serveur : {result.connectivity_status.name}[/bold red]")
        return
        
    console.print("[bold green]Analyse terminée avec succès ![/bold green]\n")
    
    # --- Traitement des résultats ---
    report_data = {
        "hostname": hostname,
        "port": port,
        "protocols": {},
        "vulnerabilities": {},
        "certificate": None
    }
    
    # Certificats
    cert_attempt = result.scan_result.certificate_info
    if cert_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
        cert_info = cert_attempt.result
        # The first deployment contains the main cert
        if cert_info.certificate_deployments:
            deployment = cert_info.certificate_deployments[0]
            cert = deployment.received_certificate_chain[0]
            report_data["certificate"] = {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_valid_before": str(cert.not_valid_before_utc),
                "not_valid_after": str(cert.not_valid_after_utc),
            }
            
            table = Table(title="[bold blue]Informations sur le Certificat[/bold blue]")
            table.add_column("Champ", style="cyan")
            table.add_column("Valeur", style="white")
            table.add_row("Sujet", cert.subject.rfc4514_string())
            table.add_row("Emetteur", cert.issuer.rfc4514_string())
            table.add_row("Expiration", str(cert.not_valid_after_utc))
            console.print(table)
    
    # Protocoles
    protocol_commands = {
        "SSL 2.0": result.scan_result.ssl_2_0_cipher_suites,
        "SSL 3.0": result.scan_result.ssl_3_0_cipher_suites,
        "TLS 1.0": result.scan_result.tls_1_0_cipher_suites,
        "TLS 1.1": result.scan_result.tls_1_1_cipher_suites,
        "TLS 1.2": result.scan_result.tls_1_2_cipher_suites,
        "TLS 1.3": result.scan_result.tls_1_3_cipher_suites,
    }
    
    table_proto = Table(title="\n[bold blue]Protocoles Supportés[/bold blue]")
    table_proto.add_column("Protocole", style="cyan")
    table_proto.add_column("Statut", justify="center")
    
    for proto_name, attempt in protocol_commands.items():
        if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            res = attempt.result
            accepted = "✅ Supporté" if res.accepted_cipher_suites else "❌ Rejeté"
            color = "green" if not res.accepted_cipher_suites and proto_name in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"] else ("red" if res.accepted_cipher_suites and proto_name in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"] else "green")
            
            table_proto.add_row(proto_name, f"[{color}]{accepted}[/{color}]")
            report_data["protocols"][proto_name] = len(res.accepted_cipher_suites) > 0
        else:
            table_proto.add_row(proto_name, "[yellow]Erreur d'analyse[/yellow]")
    
    console.print(table_proto)

    # Vulnérabilités
    vuln_commands = {
        "Heartbleed": result.scan_result.heartbleed,
        "ROBOT": result.scan_result.robot,
        "OpenSSL CCS Injection": result.scan_result.openssl_ccs_injection
    }
    
    table_vuln = Table(title="\n[bold blue]Vulnérabilités Connues[/bold blue]")
    table_vuln.add_column("Vulnérabilité", style="cyan")
    table_vuln.add_column("Statut", justify="center")
    
    for vuln_name, attempt in vuln_commands.items():
        if attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
            res = attempt.result
            # usually there's an is_vulnerable_to_... or similar flag
            # We check the attributes dynamically to avoid crashes
            is_vuln = getattr(res, 'is_vulnerable', getattr(res, 'is_vulnerable_to_ccs_injection', getattr(res, 'is_vulnerable_to_heartbleed', getattr(res, 'robot_result_enum', False))))
            
            # Custom handling for Enums or boolean
            if hasattr(res, 'is_vulnerable_to_heartbleed'):
                is_vuln = res.is_vulnerable_to_heartbleed
            elif hasattr(res, 'is_vulnerable_to_ccs_injection'):
                is_vuln = res.is_vulnerable_to_ccs_injection
            elif hasattr(res, 'robot_result_enum'):
                is_vuln = str(res.robot_result_enum) != "RobotScanResultEnum.NOT_VULNERABLE_RSA_NOT_SUPPORTED" and str(res.robot_result_enum) != "RobotScanResultEnum.NOT_VULNERABLE_NO_ORACLE"
                
            status_text = "[red]Vulnérable ⚠️[/red]" if is_vuln else "[green]Sécurisé ✅[/green]"
            table_vuln.add_row(vuln_name, status_text)
            report_data["vulnerabilities"][vuln_name] = bool(is_vuln)
        else:
            table_vuln.add_row(vuln_name, "[yellow]Non analysé[/yellow]")
            
    console.print(table_vuln)
    
    # Generate HTML report
    generate_html_report(report_data)

def generate_html_report(data):
    html_template = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rapport de Posture TLS - {{ hostname }}</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #ffffff; margin: 0; padding: 20px; }
            h1 { color: #00d2ff; text-align: center; }
            .container { max-width: 900px; margin: 0 auto; background-color: #1e1e1e; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
            .section { margin-bottom: 30px; }
            h2 { color: #3a86ff; border-bottom: 2px solid #333; padding-bottom: 10px; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; }
            th, td { text-align: left; padding: 12px; border-bottom: 1px solid #333; }
            th { background-color: #2a2a2a; color: #00d2ff; }
            .safe { color: #06d6a0; font-weight: bold; }
            .vuln { color: #ef476f; font-weight: bold; }
            .warn { color: #ffd166; font-weight: bold; }
            .footer { text-align: center; margin-top: 40px; color: #888; font-size: 14px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Analyse de Posture TLS/Réseau</h1>
            <p style="text-align: center; font-size: 1.2em;">Cible : <strong>{{ hostname }}:{{ port }}</strong></p>
            
            {% if certificate %}
            <div class="section">
                <h2>📜 Informations sur le Certificat</h2>
                <table>
                    <tr><th>Champ</th><th>Valeur</th></tr>
                    <tr><td>Sujet</td><td>{{ certificate.subject }}</td></tr>
                    <tr><td>Émetteur</td><td>{{ certificate.issuer }}</td></tr>
                    <tr><td>Valide à partir de</td><td>{{ certificate.not_valid_before }}</td></tr>
                    <tr><td>Date d'expiration</td><td>{{ certificate.not_valid_after }}</td></tr>
                </table>
            </div>
            {% endif %}

            <div class="section">
                <h2>🔒 Protocoles Supportés</h2>
                <table>
                    <tr><th>Protocole</th><th>Statut</th><th>Évaluation</th></tr>
                    {% for proto, supported in protocols.items() %}
                    <tr>
                        <td>{{ proto }}</td>
                        <td>{{ "✅ Supporté" if supported else "❌ Rejeté" }}</td>
                        <td>
                            {% if proto in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"] %}
                                {% if supported %}<span class="vuln">Insecure</span>{% else %}<span class="safe">Sécurisé</span>{% endif %}
                            {% else %}
                                {% if supported %}<span class="safe">Sécurisé</span>{% else %}<span class="warn">Non Supporté</span>{% endif %}
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            </div>

            <div class="section">
                <h2>⚠️ Vulnérabilités Connues</h2>
                <table>
                    <tr><th>Vulnérabilité</th><th>Statut</th></tr>
                    {% for vuln, is_vuln in vulnerabilities.items() %}
                    <tr>
                        <td>{{ vuln }}</td>
                        <td>
                            {% if is_vuln %}
                                <span class="vuln">Vulnérable 🚨</span>
                            {% else %}
                                <span class="safe">Sécurisé ✅</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <div class="footer">
                Projet de Sécurité Mobile - NETWORK/TLS Posture Analyser
            </div>
        </div>
    </body>
    </html>
    """
    
    template = jinja2.Template(html_template)
    html_output = template.render(**data)
    
    report_filename = f"report_{data['hostname'].replace('.', '_')}.html"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(html_output)
    
    console.print(f"\n[bold green]Rapport HTML généré avec succès :[/bold green] [white]{report_filename}[/white]\n")


if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="NETWORK/TLS Posture Analyser")
    parser.add_argument("hostname", help="Le nom de domaine ou l'adresse IP à analyser (ex: badssl.com)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port du serveur (défaut: 443)")
    
    args = parser.parse_args()
    
    try:
        analyze_server(args.hostname, args.port)
    except KeyboardInterrupt:
        console.print("\n[bold red]Analyse annulée par l'utilisateur.[/bold red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Erreur inattendue : {str(e)}[/bold red]")
        sys.exit(1)
