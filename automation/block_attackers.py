#!/usr/bin/env python3
"""
T-Pot → Sucuri WAF Avtomatik IP Bloklama Skripti
Hər 30 dəqiqədən bir cron ilə işə salınır.
"""
import json
import os
import re
import requests
import logging
from datetime import datetime
from pathlib import Path

# =============================================
# KONFİQURASİYA
# =============================================
CONFIG = {
    "sucuri_api_key":    "69c1dc2900f81ff2b6bfdf34c5fc4256",
    "sucuri_api_secret": "4e0c197cdb30840f0455da8890322ccf",
    "sucuri_api_url":    "https://waf.sucuri.net/api",

    # T-Pot log faylları
    "tpot_log_paths": [
        "/data/cowrie/log/cowrie.json",
        "/data/dionaea/log/dionaea.json",
        "/data/honeytrap/log/attacker.log",
        "/data/suricata/log/eve.json",
    ],

    # Nginx honeypot redirect logları
    "nginx_honeypot_log": "/var/log/nginx/honeypot_redirects.log",

    # Xidmət faylları (Sənin yeni qovluğuna uyğunlaşdırıldı)
    "processed_ips_file": "/home/ubuntu/final_project/automation/processed_ips.json",
    "log_file":           "/home/ubuntu/final_project/automation/sucuri-auto-block.log",

    # Blok müddəti (Sucuri parametri)
    "block_reason": "T-Pot Honeypot Auto-Block",

    # Whitelist — heç vaxt bloklanmamalı olan IP-lər
    "ip_whitelist": [
        "127.0.0.1",
        "188.253.221.226", # Sənin IP ünvanın
    ],
}

# =============================================
# LOG QURAŞDIRMASI
# =============================================
logging.basicConfig(
    filename=CONFIG["log_file"],
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

def load_processed_ips():
    """Artıq bloklanmış IP-ləri yüklə."""
    if Path(CONFIG["processed_ips_file"]).exists():
        with open(CONFIG["processed_ips_file"], "r") as f:
            return json.load(f)
    return {}

def save_processed_ips(processed_ips):
    """Bloklanmış IP-ləri yadda saxla."""
    with open(CONFIG["processed_ips_file"], "w") as f:
        json.dump(processed_ips, f, indent=2)

def extract_ips_from_cowrie(log_path):
    """Cowrie JSON loglarından IP ünvanlarını çıxar."""
    ips = set()
    try:
        with open(log_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    src_ip = event.get("src_ip") or event.get("remote_host")
                    if src_ip and is_valid_ip(src_ip):
                        ips.add(src_ip)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logger.warning(f"Log faylı tapılmadı: {log_path}")
    return ips

def extract_ips_from_suricata(log_path):
    """Suricata EVE JSON loglarından hücumçu IP-ləri çıxar."""
    ips = set()
    try:
        with open(log_path, "r") as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    if event.get("event_type") == "alert":
                        src_ip = event.get("src_ip")
                        if src_ip and is_valid_ip(src_ip):
                            ips.add(src_ip)
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        logger.warning(f"Suricata log faylı tapılmadı: {log_path}")
    return ips

def extract_ips_from_nginx(log_path):
    """Nginx honeypot redirect loglarından IP-ləri çıxar."""
    ips = set()
    ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    try:
        with open(log_path, "r") as f:
            for line in f:
                match = ip_pattern.match(line)
                if match:
                    ip = match.group(1)
                    if is_valid_ip(ip):
                        ips.add(ip)
    except FileNotFoundError:
        logger.warning(f"Nginx log faylı tapılmadı: {log_path}")
    return ips

def is_valid_ip(ip):
    """IP ünvanını doğrula və whitelist-i yoxla."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        if not all(0 <= int(p) <= 255 for p in parts):
            return False
    except ValueError:
        return False
        
    private_ranges = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127."
    ]
    for r in private_ranges:
        if ip.startswith(r):
            return False
            
    if ip in CONFIG["ip_whitelist"]:
        logger.info(f"Whitelist IP atlandı: {ip}")
        return False
    return True

def block_ip_in_sucuri(ip, reason="T-Pot Auto-Block"):
    """Sucuri WAF API-si vasitəsilə IP-ni blokla."""
    try:
        response = requests.post(
            CONFIG["sucuri_api_url"],
            data={
                "k": CONFIG["sucuri_api_key"],
                "s": CONFIG["sucuri_api_secret"],
                "a": "blacklist_ip",
                "ip": ip,
                "action": "add",
                "reason": reason,
            },
            timeout=10
        )
        if response.status_code == 200:
            result = response.json()
            if result.get("status") == 1:
                logger.info(f"✓ Sucuri-də bloklandı: {ip}")
                return True
            else:
                logger.error(f"✗ Sucuri xətası ({ip}): {result.get('messages')}")
                return False
        else:
            logger.error(f"✗ HTTP xətası ({ip}): {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"✗ API bağlantı xətası ({ip}): {e}")
        return False

def main():
    """Əsas funksiya."""
    logger.info("=" * 60)
    logger.info("T-Pot → Sucuri WAF Avtomatik Bloklama Başladı")
    logger.info("=" * 60)
    
    processed_ips = load_processed_ips()
    newly_blocked = []
    all_attacker_ips = set()
    
    cowrie_log = "/data/cowrie/log/cowrie.json"
    all_attacker_ips.update(extract_ips_from_cowrie(cowrie_log))
    
    suricata_log = "/data/suricata/log/eve.json"
    all_attacker_ips.update(extract_ips_from_suricata(suricata_log))
    
    all_attacker_ips.update(extract_ips_from_nginx(CONFIG["nginx_honeypot_log"]))
    
    logger.info(f"Toplam unikal hücumçu IP: {len(all_attacker_ips)}")
    
    new_ips = [ip for ip in all_attacker_ips if ip not in processed_ips]
    logger.info(f"Yeni (hələ bloklanmamış) IP: {len(new_ips)}")
    
    success_count = 0
    for ip in new_ips:
        timestamp = datetime.now().isoformat()
        reason = f"T-Pot Honeypot | {timestamp}"
        if block_ip_in_sucuri(ip, reason):
            processed_ips[ip] = {
                "blocked_at": timestamp,
                "reason": reason
            }
            newly_blocked.append(ip)
            success_count += 1
            
    save_processed_ips(processed_ips)
    logger.info(f"Uğurla bloklandı: {success_count}/{len(new_ips)}")
    logger.info("Skript tamamlandı.")
    return newly_blocked

if __name__ == "__main__":
    main()
