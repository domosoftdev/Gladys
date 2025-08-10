#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Outil d'analyse de sécurité de site web.
Vérifie les certificats SSL/TLS et les en-têtes de sécurité HTTP.
"""

import argparse
import socket
import ssl
import sys
import urllib.parse
import requests
from datetime import datetime
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.plugins.scan_commands import ScanCommand
import dns.resolver
import whois
import json

# --- Global variables for reporting ---
report_file = None
JSON_RESULTS = {}

def output(message="", json_enabled=False):
    """Affiche un message dans la console et l'écrit dans le fichier de rapport si le format est texte."""
    print(message)
    if report_file and not json_enabled:
        report_file.write(message + '\n')

def check_host_exists(hostname):
    """Vérifie si un nom d'hôte existe via une résolution DNS."""
    try:
        socket.gethostbyname_ex(hostname)
        return True
    except socket.gaierror:
        return False

def get_hostname(url):
    """Extrait le nom d'hôte d'une URL."""
    if url.startswith('https://'):
        url = url[8:]
    if url.startswith('http://'):
        url = url[7:]
    if '/' in url:
        url = url.split('/')[0]
    return url

def check_ssl_certificate(hostname, json_enabled=False):
    output("\n--- Analyse du certificat SSL/TLS ---", json_enabled)
    results = {"status": "error", "details": {}}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = {x[0][0]: x[0][1] for x in cert.get('subject', [])}
                issuer = {x[0][0]: x[0][1] for x in cert.get('issuer', [])}
                exp_date_str = cert['notAfter']
                exp_date = datetime.strptime(exp_date_str, '%b %d %H:%M:%S %Y %Z')
                is_expired = exp_date < datetime.now()

                output(f"  Sujet du certificat : {subject.get('commonName', 'N/A')}", json_enabled)
                output(f"  Émetteur : {issuer.get('commonName', 'N/A')}", json_enabled)
                output(f"  Date d'expiration : {exp_date.strftime('%Y-%m-%d')}", json_enabled)
                output(f"  Certificat expiré : {'Oui' if is_expired else 'Non'}", json_enabled)

                results = {
                    "status": "valid" if not is_expired else "expired",
                    "details": {
                        "subject": subject.get('commonName', 'N/A'),
                        "issuer": issuer.get('commonName', 'N/A'),
                        "expiration_date": exp_date.strftime('%Y-%m-%d'),
                    }
                }
    except Exception as e:
        output(f"  Erreur : {e}", json_enabled)
        results = {"status": "error", "message": str(e)}

    output(f"\n  Pour une analyse SSL/TLS complète : https://www.ssllabs.com/ssltest/analyze.html?d={hostname}", json_enabled)
    if json_enabled:
        JSON_RESULTS['ssl_certificate'] = results

def scan_tls_protocols(hostname, json_enabled=False):
    output("\n--- Scan des protocoles SSL/TLS supportés ---", json_enabled)
    results = {}
    try:
        server_location = ServerNetworkLocation(hostname=hostname, port=443)
        scan_request = ServerScanRequest(server_location=server_location)
        scanner = Scanner()
        scanner.queue_scans([scan_request])
        output(f"  Scan en cours sur {hostname}...", json_enabled)

        for server_scan_result in scanner.get_results():
            if server_scan_result.scan_status != ServerScanStatusEnum.COMPLETED:
                error_msg = f"ERREUR: {server_scan_result.connectivity_error_trace}"
                output(f"  {error_msg}", json_enabled)
                results = {"status": "error", "message": error_msg}
                break

            res = server_scan_result.scan_result
            protos = {
                "SSLv2": res.ssl_2_0_cipher_suites, "SSLv3": res.ssl_3_0_cipher_suites,
                "TLSv1.0": res.tls_1_0_cipher_suites, "TLSv1.1": res.tls_1_1_cipher_suites,
                "TLSv1.2": res.tls_1_2_cipher_suites, "TLSv1.3": res.tls_1_3_cipher_suites
            }
            for name, result_attempt in protos.items():
                accepted_ciphers = []
                is_supported = False
                if result_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED and result_attempt.result.accepted_cipher_suites:
                    is_supported = True
                    accepted_ciphers = [cipher.cipher_suite.name for cipher in result_attempt.result.accepted_cipher_suites]

                is_compliant = ("TLSv1.2" in name or "TLSv1.3" in name) or not is_supported
                status_str = "CONFORME" if is_compliant else "NON CONFORME"
                output(f"    {'✅' if is_compliant else '❌'} {name}: {'Supporté' if is_supported else 'Non supporté'} ({status_str})", json_enabled)

                results[name] = {
                    "supported": is_supported,
                    "compliant": is_compliant,
                    "accepted_cipher_suites": accepted_ciphers
                }
            break
    except Exception as e:
        output(f"  Erreur : {e}", json_enabled)
        results = {"status": "error", "message": str(e)}

    if json_enabled:
        JSON_RESULTS['tls_protocols'] = results

def check_http_to_https_redirect(hostname, json_enabled=False):
    output("\n--- Analyse de la redirection HTTP vers HTTPS ---", json_enabled)
    results = {}
    try:
        url = f"http://{hostname}"
        response = requests.get(url, allow_redirects=False, timeout=10)
        is_redirect = 300 <= response.status_code < 400
        location = response.headers.get('Location', '')
        redirects_to_https = location.startswith('https://')

        if is_redirect and redirects_to_https:
            output(f"  SUCCÈS : Redirection vers HTTPS (Code: {response.status_code}).", json_enabled)
        else:
            output(f"  ERREUR : Pas de redirection directe vers HTTPS (Code: {response.status_code}, Location: {location}).", json_enabled)

        results = {"redirects": is_redirect, "to_https": redirects_to_https, "status_code": response.status_code, "location": location}
    except Exception as e:
        output(f"  Erreur : {e}", json_enabled)
        results = {"status": "error", "message": str(e)}

    if json_enabled:
        JSON_RESULTS['http_to_https_redirect'] = results

def check_security_headers(hostname, json_enabled=False):
    output("\n--- Analyse des en-têtes de sécurité HTTP ---", json_enabled)
    results = {}
    try:
        url = f"https://{hostname}"
        response = requests.get(url, timeout=10)
        headers = {k.lower(): v for k, v in response.headers.items()}
        output(f"  Analyse pour : {response.url}", json_enabled)

        headers_to_check = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
        for header in headers_to_check:
            key = header.lower()
            value = headers.get(key)
            output(f"  - {header}: {'Trouvé' if value else 'Manquant'}", json_enabled)
            results[key] = {"present": bool(value), "value": value}
    except Exception as e:
        output(f"  Erreur : {e}", json_enabled)
        results = {"status": "error", "message": str(e)}

    if json_enabled:
        JSON_RESULTS['security_headers'] = results

def check_email_security_dns(hostname, json_enabled=False):
    output("\n--- Analyse des enregistrements DNS de sécurité e-mail ---", json_enabled)
    records = {"dmarc": {}, "spf": {}}
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{hostname}", 'TXT')
        dmarc_record = ' '.join([b.decode('utf-8') for b in dmarc_answers[0].strings])
        output("  - DMARC: Trouvé", json_enabled)
        records["dmarc"] = {"present": True, "record": dmarc_record}
    except Exception:
        output("  - DMARC: Manquant", json_enabled)
        records["dmarc"] = {"present": False}

    try:
        txt_answers = dns.resolver.resolve(hostname, 'TXT')
        spf_record = next((s for s in (''.join(r.strings) for r in txt_answers) if s.startswith('v=spf1')), None)
        output(f"  - SPF: {'Trouvé' if spf_record else 'Manquant'}", json_enabled)
        records["spf"] = {"present": bool(spf_record), "record": spf_record}
    except Exception:
        output("  - SPF: Manquant", json_enabled)
        records["spf"] = {"present": False}

    if json_enabled:
        JSON_RESULTS['email_security_dns'] = records

def check_registrar(hostname, json_enabled=False):
    output("\n--- Analyse WHOIS du bureau d'enregistrement ---", json_enabled)
    results = {}
    try:
        w = whois.whois(hostname)
        registrar = w.registrar
        if isinstance(registrar, list): registrar = registrar[0]
        output(f"  Bureau d'enregistrement : {registrar if registrar else 'Non trouvé'}", json_enabled)
        results = {"registrar": registrar}
    except Exception as e:
        output(f"  Erreur WHOIS : {e}", json_enabled)
        results = {"status": "error", "message": str(e)}

    if json_enabled:
        JSON_RESULTS['registrar'] = results

def check_cookie_security(hostname, json_enabled=False):
    output("\n--- Analyse de la sécurité des cookies ---", json_enabled)
    results = []
    try:
        url = f"https://{hostname}"
        response = requests.get(url, timeout=10)
        if not response.cookies:
            output("  Aucun cookie trouvé.", json_enabled)
            return

        raw_cookies = response.raw.headers.get_all('Set-Cookie', [])
        for cookie_header in raw_cookies:
            parts = [p.strip().lower() for p in cookie_header.split(';')]
            name = parts[0].split('=')[0]

            is_secure = 'secure' in parts
            is_httponly = 'httponly' in parts
            samesite_attr = next((p for p in parts if p.startswith('samesite=')), None)

            output(f"  - Cookie '{name}': Secure={is_secure}, HttpOnly={is_httponly}, SameSite={samesite_attr}", json_enabled)
            if json_enabled:
                results.append({
                    "name": name,
                    "attributes": { "secure": is_secure, "httponly": is_httponly, "samesite": samesite_attr }
                })
    except Exception as e:
        output(f"  Erreur : {e}", json_enabled)
        if json_enabled: results.append({"status": "error", "message": str(e)})

    if json_enabled:
        JSON_RESULTS['cookies'] = results

def main():
    global report_file, JSON_RESULTS

    parser = argparse.ArgumentParser(description="Analyseur de sécurité de site web.")
    parser.add_argument("url", help="URL du site (ex: google.com).")
    parser.add_argument("--rapport", nargs='?', const='autoname', default=None, help="Génère un rapport.")
    parser.add_argument("--format", choices=['text', 'json'], default='text', help="Format du rapport.")
    args = parser.parse_args()

    hostname = get_hostname(args.url)
    json_enabled = (args.format == 'json')
    report_filename = None

    if args.rapport:
        if args.rapport == 'autoname':
            date_str = datetime.now().strftime('%d%m%y')
            suffix = "json" if json_enabled else "txt"
            report_filename = f"{hostname}_{date_str}.{suffix}"
        else:
            report_filename = args.rapport

        try:
            report_file = open(report_filename, 'w', encoding='utf-8')
        except IOError as e:
            print(f"Erreur: Impossible d'ouvrir '{report_filename}': {e}")
            sys.exit(1)

    try:
        output(f"Analyse de : {hostname}", json_enabled)
        if not check_host_exists(hostname):
            output(f"Erreur : Hôte '{hostname}' introuvable.", json_enabled)
            sys.exit(1)

        if json_enabled:
            JSON_RESULTS['domain'] = hostname
            JSON_RESULTS['scan_date'] = datetime.now().isoformat()

        check_ssl_certificate(hostname, json_enabled)
        scan_tls_protocols(hostname, json_enabled)
        check_http_to_https_redirect(hostname, json_enabled)
        check_security_headers(hostname, json_enabled)
        check_email_security_dns(hostname, json_enabled)
        check_registrar(hostname, json_enabled)
        check_cookie_security(hostname, json_enabled)

    finally:
        if report_file:
            if json_enabled:
                json.dump(JSON_RESULTS, report_file, indent=4)
            report_file.close()
            print(f"\nRapport sauvegardé dans : {report_filename}")

if __name__ == "__main__":
    main()
