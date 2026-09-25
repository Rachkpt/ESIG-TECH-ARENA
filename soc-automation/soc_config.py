#!/usr/bin/env python3
"""
soc_config.py — Configuration centralisée et modèles de données
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Charge TOUTE la configuration depuis le fichier .env.
Définit les modèles de données (dataclasses) utilisés partout.
Aucune valeur en dur dans le code — tout est dans .env
"""

import os
import ipaddress
from dataclasses import dataclass, field, asdict  # field used in dataclasses below
from datetime import datetime
from enum import Enum
from typing import Optional
from dotenv import load_dotenv

# Chercher le .env de façon robuste : à côté de ce fichier, puis CWD en fallback
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ENV_PATH = os.path.join(_THIS_DIR, ".env")
if os.path.exists(_ENV_PATH):
    load_dotenv(_ENV_PATH)
else:
    load_dotenv()  # fallback: cherche dans le répertoire courant


# ╔══════════════════════════════════════════════════════════╗
# ║                    CONFIGURATION                          ║
# ╚══════════════════════════════════════════════════════════╝

class Config:
    """Configuration centralisée — charge tout depuis .env"""

    # ── WAZUH ──────────────────────────────────────────────
    WAZUH_URL: str        = os.getenv("WAZUH_URL", "https://127.0.0.1:55000")
    WAZUH_USER: str       = os.getenv("WAZUH_USER", "wazuh")
    WAZUH_PASS: str       = os.getenv("WAZUH_PASS", "")
    WAZUH_MIN_LEVEL: int  = int(os.getenv("WAZUH_MIN_LEVEL", "5"))
    WAZUH_POLL_INTERVAL: int = int(os.getenv("WAZUH_POLL_INTERVAL", "30"))
    WAZUH_ALERT_LIMIT: int   = int(os.getenv("WAZUH_ALERT_LIMIT", "100"))

    # Commande active-response déclenchée manuellement (voir WazuhClient.run_active_response).
    # Doit exister dans ar.conf sur le manager — vérifier avant de compter dessus.
    WAZUH_AR_COMMAND: str  = os.getenv("WAZUH_AR_COMMAND", "firewall-drop0")
    WAZUH_AR_ON_MANUAL_BLOCK: bool = os.getenv("WAZUH_AR_ON_MANUAL_BLOCK", "true").lower() == "true"

    # ── WAZUH INDEXER (OpenSearch — stocke les vraies alertes) ─
    # Les alertes ne sont PAS dans l'API manager (port 55000) mais
    # dans l'Indexer OpenSearch, généralement sur le même hôte, port 9200.
    WAZUH_INDEXER_URL: str  = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
    WAZUH_INDEXER_USER: str = os.getenv("WAZUH_INDEXER_USER", "admin")
    WAZUH_INDEXER_PASS: str = os.getenv("WAZUH_INDEXER_PASS", "")

    # ── THEHIVE ───────────────────────────────────────────
    THEHIVE_URL: str  = os.getenv("THEHIVE_URL", "http://127.0.0.1:9000")
    THEHIVE_API: str  = os.getenv("THEHIVE_API", "")
    THEHIVE_TLP: int  = int(os.getenv("THEHIVE_TLP", "2"))
    THEHIVE_PAP: int  = int(os.getenv("THEHIVE_PAP", "2"))
    THEHIVE_ORG: str  = os.getenv("THEHIVE_ORG", "")

    # ── CORTEX ────────────────────────────────────────────
    CORTEX_URL: str      = os.getenv("CORTEX_URL", "http://127.0.0.1:9001")
    CORTEX_API: str      = os.getenv("CORTEX_API", "")
    CORTEX_TIMEOUT: int  = int(os.getenv("CORTEX_TIMEOUT", "180"))
    CORTEX_POLL: int     = int(os.getenv("CORTEX_POLL", "10"))
    CORTEX_TLP: int      = int(os.getenv("CORTEX_TLP", "2"))

    # ── GROQ (IA) ─────────────────────────────────────────
    GROQ_API_KEY: str    = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str      = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    GROQ_MAX_TOKENS: int = int(os.getenv("GROQ_MAX_TOKENS", "2048"))
    GROQ_TEMPERATURE: float = float(os.getenv("GROQ_TEMPERATURE", "0.3"))

    # ── GMAIL ─────────────────────────────────────────────
    GMAIL_SENDER: str    = os.getenv("GMAIL_SENDER", "")
    GMAIL_PASSWORD: str  = os.getenv("GMAIL_PASSWORD", "")
    GMAIL_RECEIVER: str  = os.getenv("GMAIL_RECEIVER", "")
    GMAIL_SMTP_HOST: str = os.getenv("GMAIL_SMTP_HOST", "smtp.gmail.com")
    GMAIL_SMTP_PORT: int = int(os.getenv("GMAIL_SMTP_PORT", "587"))

    # ── TELEGRAM ──────────────────────────────────────────
    TELEGRAM_TOKEN: str  = os.getenv("TELEGRAM_TOKEN", "")
    TELEGRAM_CHAT: str   = os.getenv("TELEGRAM_CHAT", "")

    # ── SURICATA ──────────────────────────────────────────
    SURICATA_EVE: str      = os.getenv("SURICATA_EVE", "/var/log/suricata/eve.json")
    SURICATA_ENABLE: bool  = os.getenv("SURICATA_ENABLE", "true").lower() == "true"

    # ── FAIL2BAN ──────────────────────────────────────────
    FAIL2BAN_ENABLE: bool  = os.getenv("FAIL2BAN_ENABLE", "true").lower() == "true"
    FAIL2BAN_JAIL: str     = os.getenv("FAIL2BAN_JAIL", "soc-auto")
    FAIL2BAN_BANTIME: int  = int(os.getenv("FAIL2BAN_BANTIME", "7200"))

    # ── FIREWALL ──────────────────────────────────────────
    FIREWALL_BACKEND: str  = os.getenv("FIREWALL_BACKEND", "iptables")  # iptables | nftables
    IPTABLES_CHAIN: str    = os.getenv("IPTABLES_CHAIN", "SOC_GUARD")
    NFTABLES_TABLE: str    = os.getenv("NFTABLES_TABLE", "soc_guard")
    NFTABLES_CHAIN: str    = os.getenv("NFTABLES_CHAIN", "soc_input")
    BLOCK_DURATION: int    = int(os.getenv("BLOCK_DURATION", "7200"))
    HOME_NET: str          = os.getenv("HOME_NET", "10.0.0.0/8")

    # ── WHITELIST ─────────────────────────────────────────
    _wl_raw: str = os.getenv("WHITELIST_IPS", "127.0.0.1,::1")
    WHITELIST_IPS: set = set(
        ip.strip() for ip in os.getenv("WHITELIST_IPS", "127.0.0.1,::1").split(",") if ip.strip()
    )

    # ── FICHIERS ──────────────────────────────────────────
    STATE_FILE: str = os.getenv("STATE_FILE", "/opt/soc-automation/soc_state.json")
    LOG_FILE: str   = os.getenv("LOG_FILE", "/var/log/soc_automation.log")

    # ── EMAIL EVENTS ──────────────────────────────────────
    MAIL_ON_BLOCK: bool    = os.getenv("MAIL_ON_BLOCK", "true").lower() == "true"
    MAIL_ON_CASE: bool     = os.getenv("MAIL_ON_CASE", "true").lower() == "true"
    MAIL_ON_MALWARE: bool  = os.getenv("MAIL_ON_MALWARE", "true").lower() == "true"
    MAIL_ON_SSH: bool      = os.getenv("MAIL_ON_SSH", "false").lower() == "true"
    MAIL_ON_START: bool    = os.getenv("MAIL_ON_START", "true").lower() == "true"

    @classmethod
    def validate(cls) -> list:
        """Valide la configuration et retourne la liste des erreurs."""
        errors = []
        if not cls.WAZUH_PASS:
            errors.append("WAZUH_PASS non configuré")
        if not cls.THEHIVE_API:
            errors.append("THEHIVE_API non configuré")
        if not cls.CORTEX_API:
            errors.append("CORTEX_API non configuré")
        if not cls.GROQ_API_KEY:
            errors.append("GROQ_API_KEY non configuré")
        if not cls.TELEGRAM_TOKEN or not cls.TELEGRAM_CHAT:
            errors.append("TELEGRAM_TOKEN ou TELEGRAM_CHAT manquant")
        if cls.FIREWALL_BACKEND not in ("iptables", "nftables"):
            errors.append(f"FIREWALL_BACKEND invalide: {cls.FIREWALL_BACKEND}")
        try:
            ipaddress.ip_network(cls.HOME_NET)
        except ValueError:
            errors.append(f"HOME_NET invalide: {cls.HOME_NET}")
        return errors

    @classmethod
    def is_private_network(cls, ip: str) -> bool:
        """Vérifie si une IP appartient au réseau HOME_NET."""
        try:
            addr = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(cls.HOME_NET, strict=False)
            return addr in network
        except ValueError:
            return False

    @classmethod
    def summary(cls) -> str:
        """Résumé de la configuration pour les logs."""
        return (
            f"Wazuh: {cls.WAZUH_URL} | "
            f"TheHive: {cls.THEHIVE_URL} | "
            f"Cortex: {cls.CORTEX_URL} | "
            f"Groq: {cls.GROQ_MODEL} | "
            f"FW: {cls.FIREWALL_BACKEND} | "
            f"Block: {cls.BLOCK_DURATION}s"
        )


# ╔══════════════════════════════════════════════════════════╗
# ║                      ÉNUMÉRATIONS                         ║
# ╚══════════════════════════════════════════════════════════╝

class Severity(Enum):
    """Niveaux de sévérité SOC"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_wazuh_level(cls, level: int) -> "Severity":
        if level >= 13:
            return cls.CRITICAL
        elif level >= 10:
            return cls.HIGH
        elif level >= 7:
            return cls.MEDIUM
        return cls.LOW

    def emoji(self) -> str:
        return {1: "🟡", 2: "🟠", 3: "🔴", 4: "🔥"}.get(self.value, "⚪")

    def label(self) -> str:
        return self.name


class AlertCategory(Enum):
    """Catégories d'alertes"""
    NETWORK_SCAN = "network_scan"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    WEB_ATTACK = "web_attack"
    REVERSE_SHELL = "reverse_shell"
    SSH = "ssh"
    FIM = "fim"
    DDOS = "ddos"
    RECON = "recon"
    EXPLOIT = "exploit"
    THREAT_REMOVED = "threat_removed"
    ICS_ATTACK = "ics_attack"
    OTHER = "other"


# Catégories qui déclenchent réellement une action (blocage/case/notif).
# "OTHER" et bruit générique (PAM login, sudo, etc.) sont volontairement
# exclus pour éviter de saturer Telegram avec des événements non-actionnables.
ACTIONABLE_CATEGORIES = {
    AlertCategory.NETWORK_SCAN,
    AlertCategory.BRUTE_FORCE,
    AlertCategory.MALWARE,
    AlertCategory.WEB_ATTACK,
    AlertCategory.REVERSE_SHELL,
    AlertCategory.SSH,
    AlertCategory.DDOS,
    AlertCategory.RECON,
    AlertCategory.EXPLOIT,
    AlertCategory.THREAT_REMOVED,
    AlertCategory.ICS_ATTACK,
}

# Catégories désormais bloquées NATIVEMENT par Wazuh active-response
# (configuré côté Wazuh Manager : firewall-drop sur rules_id 5710/5712/
# 5716/5720 pour le brute force SSH, et 86601 pour les scans Suricata).
# Le blocage local du script serait redondant et surtout TROMPEUR pour
# ces catégories : il bloquerait sur la machine qui fait tourner le
# script, pas sur la machine réellement attaquée. Le vrai blocage se
# fait maintenant sur l'agent ciblé, via Wazuh — plus fiable.
NATIVE_AR_CATEGORIES = {
    AlertCategory.NETWORK_SCAN,
    AlertCategory.BRUTE_FORCE,
}


class DataType(Enum):
    """Types de données pour Cortex"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    FILE = "file"


class CaseStatus(Enum):
    """Statuts des cases"""
    OPEN = "Open"
    IN_PROGRESS = "InProgress"
    RESOLVED = "Resolved"
    CLOSED = "Closed"


# ╔══════════════════════════════════════════════════════════╗
# ║                   MODÈLES DE DONNÉES                     ║
# ╚══════════════════════════════════════════════════════════╝

@dataclass
class WazuhAlert:
    """Modèle pour une alerte Wazuh"""
    id: str
    timestamp: str
    rule_id: int
    rule_description: str
    rule_level: int
    rule_groups: list
    src_ip: str
    dst_ip: str
    agent_name: str
    agent_id: str
    data: dict
    category: AlertCategory = AlertCategory.OTHER
    severity: Severity = Severity.LOW
    # Enrichissement "infrastructures critiques" (rempli par surveillance_soc)
    sector: str = "inconnu"
    block_duration: Optional[int] = None  # override durée blocage (secteur sensible)

    def __post_init__(self):
        self.severity = Severity.from_wazuh_level(self.rule_level)

    @property
    def is_private_source(self) -> bool:
        return self._is_private(self.src_ip)

    @property
    def has_valid_source_ip(self) -> bool:
        return self._is_valid_ip(self.src_ip)

    @staticmethod
    def _is_private(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


@dataclass
class BlockedIP:
    """Modèle pour une IP bloquée"""
    ip: str
    reason: str
    blocked_at: str
    unblock_at: Optional[str]
    permanent: bool
    source: str
    category: str = ""

    @property
    def is_expired(self) -> bool:
        if self.permanent or not self.unblock_at:
            return False
        try:
            return datetime.fromisoformat(self.unblock_at) <= datetime.now()
        except ValueError:
            return True

    @property
    def remaining_time(self) -> str:
        if self.permanent:
            return "🔒 Permanent"
        if not self.unblock_at:
            return "N/A"
        try:
            delta = datetime.fromisoformat(self.unblock_at) - datetime.now()
            if delta.total_seconds() <= 0:
                return "⏰ Expiré"
            hours, remainder = divmod(int(delta.total_seconds()), 3600)
            minutes = remainder // 60
            return f"{hours}h{minutes:02d}min"
        except ValueError:
            return "Erreur"


@dataclass
class SOCCase:
    """Modèle pour un Case TheHive"""
    case_id: str
    number: int | str
    title: str
    ip: str
    description: str
    severity: Severity
    status: CaseStatus
    created_at: str
    analyzed: bool = False
    cortex_results: list = field(default_factory=list)
    ia_analysis: str = ""
    data_type: DataType = DataType.IP
    extra_data: dict = field(default_factory=dict)


@dataclass
class CortexResult:
    """Modèle pour un résultat d'analyzer Cortex"""
    analyzer_name: str
    analyzer_id: str
    status: str  # Success, Failure, Timeout
    report: dict
    summary: str = ""
    score: int = 0
    is_malicious: bool = False

    def __post_init__(self):
        self._extract_summary()
        self._extract_score()

    def _extract_summary(self):
        if self.status != "Success" or not self.report:
            return
        # Essayer d'extraire le summary
        summary = self.report.get("summary", "")
        if isinstance(summary, str):
            self.summary = summary[:500]
        elif isinstance(summary, dict):
            parts = []
            for k, v in summary.items():
                parts.append(f"{k}: {v}")
            self.summary = " | ".join(parts)[:500]

    def _extract_score(self):
        """Extrait un score de malveillance 0-100"""
        if self.status != "Success" or not self.report:
            return
        taxonomies = []
        full = self.report.get("full", {})
        if isinstance(full, dict):
            taxonomies = full.get("taxonomies", [])
        for tax in taxonomies:
            level = tax.get("level", "")
            if "malicious" in level.lower():
                self.is_malicious = True
                self.score = max(self.score, 80)
            elif "suspicious" in level.lower():
                self.score = max(self.score, 50)
            elif "safe" in level.lower():
                self.score = 0
        # Essayer d'extraire des scores spécifiques
        if "VT" in self.analyzer_name.upper():
            positives = self.report.get("summary", {}).get("positives", 0)
            total = self.report.get("summary", {}).get("total", 0)
            if total > 0:
                self.score = int((positives / total) * 100)
                self.is_malicious = positives >= 5
        elif "ABUSE" in self.analyzer_name.upper():
            abuse_score = self.report.get("summary", {}).get("abuseConfidenceScore", 0)
            self.score = abuse_score
            self.is_malicious = abuse_score >= 50


@dataclass
class SOCLog:
    """Modèle pour une entrée de log"""
    timestamp: str
    action: str
    detail: str
    ip: str = ""
    category: str = ""

    def to_dict(self) -> dict:
        return {
            "ts": self.timestamp,
            "action": self.action,
            "detail": self.detail,
            "ip": self.ip,
            "category": self.category
        }


@dataclass
class SOCState:
    """État global du SOC"""
    blocked_ips: dict = field(default_factory=dict)
    whitelist: list = field(default_factory=list)
    logs: list = field(default_factory=list)
    cases: list = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {
        "total_today": 0,
        "total_week": 0,
        "total_blocked_private": 0,
        "total_cases_public": 0,
        "total_malware": 0,
        "total_bruteforce": 0,
        "total_ics": 0,
        "by_sector": {},   # secteur -> {"alerts","blocked","pending","validations"}
        "last_reset": datetime.now().strftime("%Y-%m-%d")
    })
    silence_until: Optional[str] = None
    report_requested: bool = False
    processed_alerts: list = field(default_factory=list)
    alert_throttle: dict = field(default_factory=dict)
    # File des décisions en attente de validation humaine (équipements
    # critiques : le SOC ne bloque PAS tout seul, il demande à l'admin).
    pending_decisions: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "blocked_ips": self.blocked_ips,
            "whitelist": self.whitelist,
            "logs": self.logs,
            "cases": self.cases,
            "stats": self.stats,
            "silence_until": self.silence_until,
            "report_requested": self.report_requested,
            "processed_alerts": self.processed_alerts[-10000:],
            "alert_throttle": self.alert_throttle,
            "pending_decisions": self.pending_decisions[-200:]
        }


# ╔══════════════════════════════════════════════════════════╗
# ║             RÈGLES DE DÉTECTION (SIGNATURES)             ║
# ╚══════════════════════════════════════════════════════════╝

DETECTION_RULES = {
    # ── 1. RECONNAISSANCE & SCANS ─────────────────────────
    AlertCategory.NETWORK_SCAN: {
        "keywords": [
            "nmap", "port scan", "portscan", "ping sweep", "recon",
            "xmas", "syn scan", "fin scan", "null scan", "scan",
            "masscan", "zmap", "unicornscan", "arping",
            "host discovery", "os detection", "version detection",
            "connection refused", "connection reset"
        ],
        "suricata_categories": ["attempted-recon", "network-scan", "recon"],
        "wazuh_groups": ["suricata", "nmap", "recon"],
        "min_level": 3,
        "description": "Scan réseau détecté"
    },
    
    # ── 2. BRUTE FORCE (SSH, RDP, FTP, etc.) ─────────────
    AlertCategory.BRUTE_FORCE: {
        "keywords": [
            "brute", "bruteforce", "brute-force",
            "failed password", "invalid user", "authentication failure",
            "login attempt", "multiple failed", "password failure",
            "ssh", "rdp", "ftp", "smtp", "smb"
        ],
        "suricata_categories": ["attempted-admin", "brute-force"],
        "wazuh_groups": ["authentication_failed", "sshd", "syslog", "win_authentication"],
        "min_level": 5,
        "description": "Tentative de Brute Force"
    },

    # ── 3. MALWARES (Virus, Trojans, Ransomware, Rootkits) 
    AlertCategory.MALWARE: {
        "keywords": [
            "malware", "trojan", "virus", "ransomware", "worm",
            "backdoor", "rootkit", "keylogger", "spyware",
            "coinminer", "cryptominer", "bitcoin", "monero",
            "malicious", "infected", "payload", "exploit kit"
        ],
        "suricata_categories": ["trojan-activity", "malware", "bad-unknown"],
        "wazuh_groups": ["virustotal", "yara", "fim"],
        "min_level": 5,
        "description": "Malware détecté"
    },

    # ── 4. EXECUTION & REVERSE SHELLS (Mimikatz, PS, Base64)
    AlertCategory.REVERSE_SHELL: {
        "keywords": [
            "reverse shell", "reverse_shell", "backdoor connection",
            "suspicious outbound", "potential shell",
            "cmd.exe", "powershell", "/bin/sh", "/bin/bash",
            "nc -e", "netcat", "mkfifo",
            "mimikatz", "sekurlsa", "logonpasswords", "cred dump", "credential dumping",
            "encodedcommand", "base64", "frombase64string",
            "downloadstring", "invoke-expression", "iex",
            "webshell", "cmd execution", "command injection"
        ],
        "suricata_categories": ["shellcode-detect", "bad-unknown", "attempted-user"],
        "wazuh_groups": ["attack", "win_attack", "audit"],
        "min_level": 6,
        "description": "Exécution suspecte / Reverse Shell"
    },

    # ── 5. ATTAQUES WEB (SQLi, XSS, Upload) ──────────────
    AlertCategory.WEB_ATTACK: {
        "keywords": [
            "sql injection", "sqli", "xss", "cross-site scripting",
            "rfi", "lfi", "remote file inclusion", "local file inclusion",
            "directory traversal", "path traversal",
            "web shell upload", "file upload", "php upload",
            "ssrf", "server-side request forgery"
        ],
        "suricata_categories": ["web-application-attack", "web-application-activity"],
        "wazuh_groups": ["web", "apache", "nginx", "web_appsec"],
        "min_level": 5,
        "description": "Attaque Web détectée"
    },

    # ── 6. EXPLOITATION & PRIVILEGE ESCALATION ────────────
    AlertCategory.EXPLOIT: {
        "keywords": [
            "exploit", "cve-", "vulnerability",
            "buffer overflow", "heap overflow", "stack overflow",
            "privilege escalation", "privilege-escalation",
            "local execution", "remote code execution", "rce",
            "user added", "new user", "admin added", "uid 0",
            "group changed", "sudoers", "account modification",
            "administrator creation"
        ],
        "suricata_categories": ["attempted-admin", "successful-admin", "exploit"],
        "wazuh_groups": ["attack", "privilege_escalation", "audit"],
        "min_level": 7,
        "description": "Exploitation / Élévation de privilèges"
    },

    # ── 7. DEFENSE EVASION (AV désactivé, Logs supprimés) ─
    AlertCategory.RECON: {
        "keywords": [
            "antivirus", "defender", "security center", "disabled",
            "service stopped", "service state changed", "critical service",
            "log deleted", "log cleared", "auditd", "audit log",
            "rootkit detector", "tampering"
        ],
        "suricata_categories": ["policy-violation", "misc-activity"],
        "wazuh_groups": ["ossec", "audit", "fim"],
        "min_level": 7,
        "description": "Évasion de défense / Altération système"
    },

    # ── 8. EXFILTRATION & C2 / DDoS ──────────────────────
    AlertCategory.DDOS: {
        "keywords": [
            "exfiltration", "data leak", "suspicious transfer",
            "c2", "command and control", "beacon", "cobalt strike",
            "dns tunnel", "dns anomaly", "high entropy dns", "long dns query",
            "ddos", "denial of service", "syn flood", "udp flood"
        ],
        "suricata_categories": ["denial-of-service", "trojan-activity", "bad-unknown"],
        "wazuh_groups": ["ddos", "ids", "suricata"],
        "min_level": 6,
        "description": "Exfiltration / C2 / DDoS"
    },

    # ── 9. SUPPRESSION ACTIVE DE MENACE (Active Response) ─
    AlertCategory.THREAT_REMOVED: {
        "keywords": [
            "remove-threat", "removethreat", "threat removed",
            "file removed", "file quarantined", "quarantine",
            "active response", "active-response",
            "deleted by virustotal", "deleted by antivirus",
            "malicious file deleted", "file deleted threat",
            "yara remove", "vt remove"
        ],
        "suricata_categories": [],
        "wazuh_groups": ["active-response", "active_response", "active response"],
        "min_level": 3,
        "description": "Menace supprimée automatiquement"
    },

    # ── 10. ATTAQUE ICS / SCADA / OT (Modbus, DNP3...) ────
    # Ciblée sur les infrastructures critiques industrielles (CEET).
    # Les règles Suricata dédiées (rules/soc-ics.rules) émettent des
    # messages contenant "MODBUS"/"SCADA"/"ICS"/"DNP3".
    AlertCategory.ICS_ATTACK: {
        "keywords": [
            "modbus", "scada", "dnp3", "s7comm", "iec-104", "iec104",
            "plc", "automate", "ics ", "ot attack", "ot-attack",
            "unauthorized write", "ecriture non autorisee", "écriture non autorisée",
            "coil write", "register write", "force listen only",
            "restart communication", "unauthorized command"
        ],
        "suricata_categories": ["ics-attack", "scada", "modbus"],
        "wazuh_groups": ["ics", "scada", "modbus", "ot"],
        "min_level": 3,
        "description": "Attaque système industriel (ICS/SCADA)"
    }
}


def classify_alert(alert: WazuhAlert) -> AlertCategory:
    """Classifie une alerte dans une catégorie — supporte Wazuh + Suricata."""
    desc_lower = alert.rule_description.lower()
    groups_lower = [g.lower() for g in alert.rule_groups]
    suricata_cat = alert.data.get("alert", {}).get("category", "").lower() if alert.data else ""

    # PRIORITÉ : suppression active de menace prime sur tout autre match
    # (ex: "removed by VirusTotal" contient "virus" qui matcherait MALWARE sinon)
    tr_rules = DETECTION_RULES[AlertCategory.THREAT_REMOVED]
    if alert.rule_level >= tr_rules["min_level"]:
        for wg in tr_rules.get("wazuh_groups", []):
            if any(wg.lower() in g for g in groups_lower):
                return AlertCategory.THREAT_REMOVED
        for keyword in tr_rules["keywords"]:
            if keyword in desc_lower:
                return AlertCategory.THREAT_REMOVED

    # PRIORITÉ : attaque ICS/SCADA prime aussi (le mot "scan"/"command"
    # d'une alerte Modbus matcherait sinon NETWORK_SCAN/EXPLOIT en premier).
    ics_rules = DETECTION_RULES[AlertCategory.ICS_ATTACK]
    for sc in ics_rules.get("suricata_categories", []):
        if sc in suricata_cat:
            return AlertCategory.ICS_ATTACK
    for wg in ics_rules.get("wazuh_groups", []):
        if any(wg in g for g in groups_lower):
            return AlertCategory.ICS_ATTACK
    for keyword in ics_rules["keywords"]:
        if keyword in desc_lower:
            return AlertCategory.ICS_ATTACK

    for category, rules in DETECTION_RULES.items():
        if category in (AlertCategory.THREAT_REMOVED, AlertCategory.ICS_ATTACK):
            continue  # déjà testés ci-dessus (priorité)
        if alert.rule_level < rules["min_level"]:
            continue
        # Match suricata category
        for sc in rules.get("suricata_categories", []):
            if sc.lower() in suricata_cat:
                return category
        # Match wazuh groups
        for wg in rules.get("wazuh_groups", []):
            if any(wg.lower() in g for g in groups_lower):
                return category
        # Match keywords
        for keyword in rules["keywords"]:
            if keyword in desc_lower or any(keyword in g for g in groups_lower):
                return category

    return AlertCategory.OTHER


def get_severity_for_category(category: AlertCategory, base_level: int) -> Severity:
    """Ajuste la sévérité selon la catégorie."""
    severity = Severity.from_wazuh_level(base_level)
    
    # Boosts pour certaines catégories
    if category in (AlertCategory.MALWARE, AlertCategory.REVERSE_SHELL,
                    AlertCategory.EXPLOIT, AlertCategory.ICS_ATTACK):
        if severity.value < Severity.CRITICAL.value:
            severity = Severity.CRITICAL
    elif category in (AlertCategory.NETWORK_SCAN, AlertCategory.DDOS):
        if severity.value < Severity.HIGH.value:
            severity = Severity.HIGH
    elif category == AlertCategory.BRUTE_FORCE:
        if severity.value < Severity.MEDIUM.value:
            severity = Severity.MEDIUM

    return severity


# ╔══════════════════════════════════════════════════════════╗
# ║                 PROMPTS GROQ (IA SOC)                     ║
# ╚══════════════════════════════════════════════════════════╝

GROQ_SYSTEM_PROMPT = """Tu es un analyste SOC (Security Operations Center) senior dans un système automatisé de détection et réponse aux incidents.

RÔLE :
Tu analyses les résultats des analyzers Cortex (VirusTotal, AbuseIPDB, GreyNoise, etc.) et produis une évaluation structurée en français.

FORMAT OBLIGATOIRE (sans dévier) :

🎯 RÉSUMÉ
[2-3 phrases décrivant la menace]

📊 CRITICITÉ : [Low/Medium/High/Critical]
Score moyen : [X/100] — Justification : [chiffres]

🔍 DÉTAILS PAR ANALYZER
• Analyzer1 : [résultat clé]
• Analyzer2 : [résultat clé]

💡 RECOMMANDATION
[Action précise : bloquer/surveiller/faux positif]

⚡ TÉLÉGRAM
[Résumé 2-3 lignes max pour mobile]

RÈGLES :
- Français uniquement
- Basé UNIQUEMENT sur les données fournies
- Si données insuffisantes, le dire
- Factuel et professionnel
- Ne jamais inventer de données"""


GROQ_MALWARE_PROMPT = """Tu es un analyste malware senior. Analyse ce rapport de détection :

FICHIER : {file}
MACHINE : {agent}
SHA256 : {hash}
RÉSULTATS CORTEX : {results}

FORMAT :
🦠 ANALYSE MALWARE
[Type probable, famille si identifiable]

📊 DANGER : [Low/Medium/High/Critical]
Justification : [chiffres]

🔍 INDICATEURS
• [IOC 1]
• [IOC 2]

💡 ACTION RECOMMANDÉE
[Isoler la machine / Supprimer le fichier / Quadriller le réseau]

⚡ TÉLÉGRAM
[Résumé 2-3 lignes]"""


GROQ_REPORT_PROMPT = """Tu es un analyste SOC. Génère un rapport d'activité concis à partir de ces données :

ACTIONS RÉCENTES :
{logs}

STATISTIQUES :
{stats}

Génère un rapport structuré en français (8-12 lignes max) avec :
- Résumé global
- Points d'attention
- Recommandations"""