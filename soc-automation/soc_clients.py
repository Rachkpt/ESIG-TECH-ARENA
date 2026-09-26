#!/usr/bin/env python3
"""
soc_clients.py — Clients API pour Wazuh, TheHive, Cortex, Groq, Mail
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Chaque client gère ses propres erreurs et timeouts.
"""

import json
import smtplib
import re
import logging
import requests
import urllib3
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

from soc_config import (
    Config, WazuhAlert, AlertCategory, Severity,
    SOCCase, CortexResult, DataType, CaseStatus,
    GROQ_SYSTEM_PROMPT, GROQ_MALWARE_PROMPT, GROQ_REPORT_PROMPT
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("soc.clients")


# ╔══════════════════════════════════════════════════════════╗
# ║                    CLIENT WAZUH                          ║
# ╚══════════════════════════════════════════════════════════╝

class WazuhClient:
    """Client API Wazuh avec cache de token."""

    def __init__(self):
        self.url = Config.WAZUH_URL
        self.user = Config.WAZUH_USER
        self.passwd = Config.WAZUH_PASS
        self._token = None
        self._token_expires = 0
        self.last_error = ""   # dernière erreur API (pour diagnostic Telegram)

    def _get_token(self) -> Optional[str]:
        """Récupère ou renouvelle le token JWT."""
        now = __import__('time').time()
        if self._token and now < self._token_expires:
            return self._token
        
        try:
            r = requests.post(
                f"{self.url}/security/user/authenticate",
                auth=(self.user, self.passwd),
                verify=False, timeout=15
            )
            if r.status_code == 200:
                self._token = r.json()["data"]["token"]
                self._token_expires = now + 900
                self.last_error = ""
                return self._token
            if r.status_code in (401, 403):
                self.last_error = (f"Authentification refusée (HTTP {r.status_code}) — "
                                   f"vérifie WAZUH_USER / WAZUH_PASS (compte API Wazuh, "
                                   f"pas le compte admin de l'Indexer).")
            else:
                self.last_error = f"API Wazuh a répondu HTTP {r.status_code}"
            log.error(f"Wazuh auth échouée: {r.status_code} — {r.text[:200]}")
        except requests.exceptions.ConnectionError:
            self.last_error = f"Manager Wazuh injoignable sur {self.url} (port 55000 ouvert ?)"
            log.error(f"Wazuh injoignable: {self.url}")
        except Exception as e:
            self.last_error = f"Erreur token : {str(e)[:120]}"
            log.error(f"Wazuh token erreur: {e}")
        return None

    def _headers(self) -> dict:
        token = self._get_token()
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

    def get_agents(self) -> list:
        """
        Récupère la liste des agents Wazuh et leur statut (active/disconnected/never_connected).
        Utilise l'API manager (endpoint réel, contrairement à /security/events).
        """
        # Récupère le token d'abord : si ça échoue (timeout/injoignable/creds),
        # on remonte la VRAIE cause plutôt qu'un 401 trompeur "No authorization
        # token provided" (une requête sans token renverrait 401 à tort).
        headers = self._headers()
        if not headers:
            # last_error a déjà été renseigné par _get_token()
            return []
        try:
            r = requests.get(
                f"{self.url}/agents",
                headers=headers,
                params={"limit": 500},
                verify=False, timeout=15
            )
            if r.status_code == 200:
                self.last_error = ""
                data = r.json().get("data", {})
                return data.get("affected_items", [])
            self.last_error = f"/agents a répondu HTTP {r.status_code}"
            log.error(f"Wazuh agents erreur: HTTP {r.status_code} — {r.text[:300]}")
        except requests.exceptions.ConnectionError:
            self.last_error = f"Manager Wazuh injoignable sur {self.url} (port 55000 ouvert ?)"
            log.error(f"Wazuh manager injoignable pour /agents: {self.url}")
        except Exception as e:
            self.last_error = f"Erreur /agents : {str(e)[:120]}"
            log.error(f"Wazuh agents: {e}")
        return []

    def run_active_response(self, ip: str, command: str = None,
                            action: str = "add") -> bool:
        """
        Déclenche l'active-response Wazuh sur tous les agents connectés.

        action="add"    → blocage (firewall-drop, Config.WAZUH_AR_COMMAND)
        action="delete" → déblocage : utilise Config.WAZUH_AR_UNBLOCK_COMMAND.
            ⚠️ Wazuh retire de toute façon le blocage natif à l'expiration
            du timeout configuré dans ar.conf. Le déblocage IMMÉDIAT depuis
            Telegram nécessite une commande AR dédiée côté manager (voir
            docs/03-wazuh/active-response.md). Si elle n'est pas configurée
            (WAZUH_AR_UNBLOCK_COMMAND vide), on ne fait rien et on renvoie
            False — le blocage natif expirera seul.

        Best-effort : les noms de commande AR dépendent de ce qui est
        enregistré dans ar.conf sur le manager — à vérifier sur l'instance.
        """
        if action == "delete":
            command = command or Config.WAZUH_AR_UNBLOCK_COMMAND
            if not command:
                log.info("Wazuh AR: déblocage natif non configuré "
                         "(WAZUH_AR_UNBLOCK_COMMAND vide) — expiration auto seule")
                return False
        else:
            command = command or Config.WAZUH_AR_COMMAND
        agents = self.get_agents()
        active_ids = [
            a.get("id") for a in agents
            if a.get("status") == "active" and a.get("id") != "000"
        ]
        if not active_ids:
            log.info("Wazuh AR: aucun agent actif à cibler")
            return False
        try:
            r = requests.put(
                f"{self.url}/active-response",
                headers=self._headers(),
                params={"agents_list": ",".join(active_ids)},
                json={"command": command, "arguments": [ip]},
                verify=False, timeout=15
            )
            if r.status_code == 200:
                log.info(f"Wazuh AR '{command}' ({action}) déclenché sur "
                         f"{len(active_ids)} agent(s) pour {ip}")
                return True
            log.error(f"Wazuh AR erreur: HTTP {r.status_code} — {r.text[:300]}")
        except requests.exceptions.ConnectionError:
            log.error(f"Wazuh manager injoignable pour /active-response: {self.url}")
        except Exception as e:
            log.error(f"Wazuh AR exception: {e}")
        return False

    def _indexer_search(self, query_body: dict, size: int = 100) -> list:
        """
        Interroge l'Indexer Wazuh (OpenSearch) sur l'index wazuh-alerts-*.
        C'est ICI que vivent les vraies alertes — pas dans l'API manager.
        """
        try:
            r = requests.post(
                f"{Config.WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
                auth=(Config.WAZUH_INDEXER_USER, Config.WAZUH_INDEXER_PASS),
                json=query_body,
                headers={"Content-Type": "application/json"},
                verify=False, timeout=20
            )
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                results = []
                for h in hits:
                    doc = h.get("_source", {})
                    doc["id"] = h.get("_id", "")
                    results.append(doc)
                return results
            log.error(f"Wazuh Indexer erreur: {r.status_code} — {r.text[:300]}")
        except requests.exceptions.ConnectionError:
            log.error(f"Wazuh Indexer injoignable: {Config.WAZUH_INDEXER_URL}")
        except Exception as e:
            log.error(f"Wazuh Indexer: {e}")
        return []

    def get_alerts(self, limit: int = None, min_level: int = None,
                   search: str = None, since_ts: str = None) -> list:
        """
        Récupère les alertes récentes depuis l'Indexer Wazuh (OpenSearch).
        since_ts: si fourni (ISO 8601), ne récupère QUE les alertes après ce timestamp
        — empêche de renvoyer tout l'historique à chaque démarrage/cycle.
        """
        if limit is None:
            limit = Config.WAZUH_ALERT_LIMIT
        if min_level is None:
            min_level = Config.WAZUH_MIN_LEVEL

        must = [{"range": {"rule.level": {"gte": min_level}}}]
        if search:
            must.append({"query_string": {"query": search}})
        if since_ts:
            must.append({"range": {"timestamp": {"gt": since_ts}}})

        # Avec un curseur, on trie en ASCENDANT pour traiter les alertes
        # dans l'ordre chronologique et ne jamais sauter un burst > limit.
        sort_order = "asc" if since_ts else "desc"

        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": sort_order}}],
            "query": {"bool": {"must": must}}
        }
        return self._indexer_search(query, size=limit)

    def get_ssh_alerts(self, since_ts: str = None, limit: int = 100) -> list:
        """
        Récupère les connexions SSH/PAM de FAIBLE niveau (réussies, niveau 3)
        que le filtre global (WAZUH_MIN_LEVEL) exclut normalement.
        IMPORTANT: se limite au niveau EN DESSOUS du seuil global pour ne
        jamais intercepter un vrai brute force (niveau >= 5), qui doit
        continuer à passer par le pipeline normal (get_alerts → blocage IP).
        Cette requête ne fait que COMBLER le trou des connexions réussies.
        """
        upper_bound = Config.WAZUH_MIN_LEVEL
        must = [
            {"bool": {"should": [
                {"term": {"rule.groups": "sshd"}},
                {"term": {"rule.groups": "pam"}}
            ], "minimum_should_match": 1}},
            {"range": {"rule.level": {"gte": 3, "lt": upper_bound}}}
        ]
        if since_ts:
            must.append({"range": {"timestamp": {"gt": since_ts}}})

        sort_order = "asc" if since_ts else "desc"
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": sort_order}}],
            "query": {"bool": {"must": must}}
        }
        return self._indexer_search(query, size=limit)

    def get_scan_alerts(self, since_ts: str = None, limit: int = 100) -> list:
        """
        Récupère les alertes Suricata-via-Wazuh (scan nmap, port scan, etc.)
        de FAIBLE niveau (souvent 3, ex: "ET SCAN Potential SSH Scan").
        Wazuh applique un niveau générique bas (3) à toutes les alertes
        Suricata ingérées via son décodeur intégré (rule.id 86601 et
        similaires), quelle que soit leur gravité réelle — elles sont
        donc systématiquement exclues par WAZUH_MIN_LEVEL (5 par défaut).
        Comme pour SSH, on comble uniquement le trou EN DESSOUS du seuil
        global pour ne jamais court-circuiter le pipeline de blocage normal.
        """
        upper_bound = Config.WAZUH_MIN_LEVEL
        must = [
            {"bool": {"should": [
                {"term": {"rule.groups": "suricata"}},
                {"term": {"rule.groups": "ids"}},
                {"match": {"rule.description": "SCAN"}}
            ], "minimum_should_match": 1}},
            {"range": {"rule.level": {"gte": 3, "lt": upper_bound}}}
        ]
        if since_ts:
            must.append({"range": {"timestamp": {"gt": since_ts}}})

        sort_order = "asc" if since_ts else "desc"
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": sort_order}}],
            "query": {"bool": {"must": must}}
        }
        return self._indexer_search(query, size=limit)

    def get_fim_events(self, limit: int = 50, minutes: int = 5) -> list:
        """
        Récupère les événements FIM (syscheck) des `minutes` dernières minutes
        UNIQUEMENT — jamais l'historique complet, pour éviter le flood.
        """
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"term": {"rule.groups": "syscheck"}},
                        {"range": {"timestamp": {"gte": f"now-{minutes}m"}}}
                    ]
                }
            }
        }
        docs = self._indexer_search(query, size=limit)
        # Adapter au format attendu par process_fim_event (file/type/agent/hash)
        events = []
        for d in docs:
            sc = d.get("syscheck", {})
            if not sc:
                continue
            events.append({
                "file": sc.get("path", ""),
                "path": sc.get("path", ""),
                "type": sc.get("event", ""),
                "agent": d.get("agent", {}),
                "sha256_before": sc.get("sha256_before", ""),
                "sha256_after": sc.get("sha256_after", sc.get("sha256", "")),
                "size_after": sc.get("size_after", ""),
                "perm_after": sc.get("perm_after", "")
            })
        return events

    @staticmethod
    def parse_alert(raw: dict) -> Optional[WazuhAlert]:
        """Convertit une alerte brute en objet WazuhAlert."""
        try:
            rule = raw.get("rule", {})
            agent = raw.get("agent", {}) or {}
            data = dict(raw.get("data", {}) or {})

            # Fusionner les blocs VirusTotal / Syscheck / FIM dans `data`
            # car le hash et le chemin du fichier n'y sont PAS toujours,
            # ils peuvent être à la racine de l'alerte Wazuh.
            vt = raw.get("virustotal", {}) or {}
            syscheck = raw.get("syscheck", {}) or {}

            if vt:
                data.setdefault("sha256", vt.get("sha256", vt.get("source", {}).get("sha256", "")))
                data.setdefault("sha1", vt.get("sha1", ""))
                data.setdefault("file", vt.get("source", {}).get("file", syscheck.get("path", "")))
                data["_virustotal"] = vt

            if syscheck:
                data.setdefault("sha256", syscheck.get("sha256_after", syscheck.get("sha256", "")))
                data.setdefault("file", syscheck.get("path", ""))
                data["_syscheck"] = syscheck

            # Toujours garder le texte brut — sert de fallback (regex)
            # quand les champs structurés (IP, chemin) sont absents,
            # ce qui arrive souvent pour certains types d'alertes.
            full_log = raw.get("full_log", "")
            data["_full_log"] = full_log

            src_ip = data.get("srcip", data.get("src_ip", data.get("src", "")))
            if not src_ip and full_log:
                import re
                m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", full_log)
                if m:
                    src_ip = m.group(1)

            # Wazuh renvoie rule.id et rule.level en STRING dans l'Indexer.
            # On caste en int pour que les comparaisons numériques
            # (ex: rule_id == 40704, level >= 13) fonctionnent vraiment.
            try:
                _rule_id = int(rule.get("id", 0) or 0)
            except (ValueError, TypeError):
                _rule_id = 0
            try:
                _rule_level = int(rule.get("level", 0) or 0)
            except (ValueError, TypeError):
                _rule_level = 0

            return WazuhAlert(
                id=str(raw.get("id", "") or raw.get("_id", "")),
                timestamp=raw.get("timestamp", ""),
                rule_id=_rule_id,
                rule_description=rule.get("description", "Inconnue"),
                rule_level=_rule_level,
                rule_groups=rule.get("groups", []),
                src_ip=src_ip,
                dst_ip=data.get("dstip", data.get("dst_ip", data.get("dst", ""))),
                agent_name=agent.get("name", "Inconnu") if isinstance(agent, dict) else "Inconnu",
                agent_id=agent.get("id", "") if isinstance(agent, dict) else "",
                data=data
            )
        except Exception as e:
            log.error(f"Parse alerte erreur: {e}")
            return None

    def check_connectivity(self) -> bool:
        """Vérifie la connexion à Wazuh."""
        try:
            r = requests.get(self.url, verify=False, timeout=5)
            return r.status_code < 500
        except Exception:
            return False


# ╔══════════════════════════════════════════════════════════╗
# ║                   CLIENT THEHIVE                         ║
# ╚══════════════════════════════════════════════════════════╝

class TheHiveClient:
    """Client API TheHive."""

    def __init__(self):
        self.url = Config.THEHIVE_URL
        self.api_key = Config.THEHIVE_API
        self.tlp = Config.THEHIVE_TLP
        self.pap = Config.THEHIVE_PAP
        self._assignee_idx = 0   # curseur round-robin d'attribution

    def _next_assignee(self) -> Optional[str]:
        """Retourne le prochain analyste à qui attribuer un case
        (round-robin sur Config.THEHIVE_ANALYSTS). None si liste vide."""
        analysts = Config.THEHIVE_ANALYSTS
        if not analysts:
            return None
        assignee = analysts[self._assignee_idx % len(analysts)]
        self._assignee_idx += 1
        return assignee

    def _headers(self) -> dict:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        # Force l'organisation explicitement si configurée — évite de
        # dépendre de l'org "par défaut" du compte TheHive (qui peut être
        # "admin", laquelle n'a PAS les droits de gérer des cases).
        if Config.THEHIVE_ORG:
            headers["X-Organisation"] = Config.THEHIVE_ORG
        return headers

    def create_alert(self, title: str, description: str,
                     severity: Severity, tags: list, source_ref: str,
                     alert_type: str = "soc-automation",
                     observables: list = None) -> Optional[dict]:
        """
        Crée une Alert dans TheHive — c'est le point d'entrée standard
        pour un SIEM (dédup via sourceRef, visible dans l'onglet Alerts,
        peut être triée/fusionnée avant de devenir un Case).
        """
        if not self.api_key:
            log.error("TheHive API non configurée")
            return None

        body = {
            "type": alert_type,
            "source": "SOC-Automation",
            "sourceRef": source_ref,
            "title": title,
            "description": description,
            "severity": severity.value,
            "tlp": self.tlp,
            "pap": self.pap,
            "tags": tags,
        }
        if observables:
            body["observables"] = observables

        try:
            r = requests.post(
                f"{self.url}/api/v1/alert",
                headers=self._headers(),
                json=body,
                timeout=15,
                verify=False
            )
            if r.status_code in [200, 201]:
                alert = r.json()
                log.info(f"Alert TheHive créée: {alert.get('_id')}")
                return alert
            log.error(
                f"TheHive alert create erreur: HTTP {r.status_code} — "
                f"Body envoyé: {body} — Réponse: {r.text[:500]}"
            )
        except requests.exceptions.ConnectionError:
            log.error(f"TheHive injoignable: {self.url}")
        except Exception as e:
            log.error(f"TheHive alert create: {e}")
        return None

    def promote_alert_to_case(self, alert_id: str, assignee: str = None) -> Optional[dict]:
        """Promeut une Alert en Case (workflow standard TheHive), avec
        attribution optionnelle à un analyste (assignee = login TheHive)."""
        body = {}
        if assignee:
            body["assignee"] = assignee
        try:
            r = requests.post(
                f"{self.url}/api/v1/alert/{alert_id}/case",
                headers=self._headers(),
                json=body,
                timeout=15,
                verify=False
            )
            if r.status_code in [200, 201]:
                case = r.json()
                if assignee:
                    case.setdefault("assignee", assignee)
                log.info(f"Alert {alert_id} promue en Case #{case.get('number')}"
                         f"{' → ' + assignee if assignee else ''}")
                return case
            log.error(f"TheHive promotion erreur: HTTP {r.status_code} — {r.text[:300]}")
        except Exception as e:
            log.error(f"TheHive promotion: {e}")
        return None

    def create_case(self, title: str, description: str,
                    severity: Severity, tags: list,
                    observables: list = None, source_ref: str = None) -> Optional[dict]:
        """
        Crée un Case dans TheHive via le workflow standard :
        1. Créer l'Alert (visible dans l'onglet Alerts, dédupliquée)
        2. La promouvoir automatiquement en Case
        Garde la même signature de retour ({_id, number, ...}) que
        l'ancien appel direct à /api/v1/case, pour ne rien casser en aval.
        """
        if not self.api_key:
            log.error("TheHive API non configurée")
            return None

        if not source_ref:
            import time as _t
            source_ref = f"soc-{int(_t.time()*1000)}"

        alert = self.create_alert(
            title=title, description=description, severity=severity,
            tags=tags, source_ref=source_ref, observables=observables
        )
        if not alert:
            return None

        alert_id = alert.get("_id")
        # Attribution automatique à un analyste (round-robin sur la liste .env)
        assignee = self._next_assignee()
        case = self.promote_alert_to_case(alert_id, assignee=assignee)
        if not case:
            log.warning(f"Alert {alert_id} créée mais promotion en Case échouée")
            return None
        return case

    def add_comment(self, case_id: str, message: str) -> bool:
        """Ajoute un commentaire à un Case."""
        try:
            r = requests.post(
                f"{self.url}/api/v1/case/{case_id}/comment",
                headers=self._headers(),
                json={"message": message},
                timeout=10,
                verify=False
            )
            return r.status_code in [200, 201]
        except Exception as e:
            log.error(f"TheHive comment: {e}")
            return False

    def get_cases(self, limit: int = 10) -> list:
        """Récupère les derniers cases."""
        try:
            r = requests.post(
                f"{self.url}/api/v1/query",
                headers=self._headers(),
                json={"query": [
                    {"_name": "listCase"},
                    {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                    {"_name": "limit", "from": 0, "to": limit}
                ]},
                timeout=15,
                verify=False
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log.error(f"TheHive query: {e}")
        return []

    def create_ip_case(self, ip: str, title: str, description: str,
                       severity: Severity, source: str = "Wazuh") -> Optional[dict]:
        """Crée un Case pour une IP OU un domaine, avec le bon dataType."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            data_type = "ip"
        except ValueError:
            # Pas une IP valide → c'est un FQDN/domaine
            data_type = "fqdn" if ip.count(".") >= 1 and not ip.replace(".", "").isdigit() else "ip"

        return self.create_case(
            title=f"[SOC-AUTO] {title} — {ip}",
            description=f"{description}\n\n**Observable:** {ip} ({data_type})\n**Source:** {source}\n**Heure:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            severity=severity,
            tags=["SOC", "automatise", source.lower(), f"ioc:{ip}"],
            observables=[{
                "dataType": data_type,
                "data": ip,
                "message": "IP/domaine source de l'attaque",
                "ioc": True,
                "tlp": self.tlp
            }]
        )

    def create_observable_case(self, value: str, data_type: str, title: str,
                               description: str, severity: Severity,
                               source: str = "Telegram") -> Optional[dict]:
        """Crée un Case pour un observable de type explicite (url, domain, hash, ip...)."""
        return self.create_case(
            title=f"[SOC-AUTO] {title} — {value[:60]}",
            description=f"{description}\n\n**Observable:** {value} ({data_type})\n**Source:** {source}\n**Heure:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            severity=severity,
            tags=["SOC", "automatise", source.lower(), data_type],
            observables=[{
                "dataType": data_type,
                "data": value,
                "message": f"Observable {data_type} soumis pour analyse",
                "ioc": True,
                "tlp": self.tlp
            }]
        )

    def create_malware_case(self, file_path: str, hash_value: str,
                            agent: str, description: str) -> Optional[dict]:
        """Crée un Case pour un malware avec observable hash."""
        return self.create_case(
            title=f"[SOC-MALWARE] {file_path}",
            description=f"{description}\n\n**Fichier:** {file_path}\n**Machine:** {agent}\n**SHA256:** {hash_value}",
            severity=Severity.CRITICAL,
            tags=["SOC", "malware", agent, hash_value[:16]],
            observables=[{
                "dataType": "hash",
                "data": hash_value,
                "message": f"Hash malware — {file_path}",
                "ioc": True,
                "tlp": 3
            }]
        )

    def create_fim_case(self, file_path: str, hash_value: str,
                        agent: str, action: str) -> Optional[dict]:
        """
        Crée un Case pour un fichier créé/modifié détecté par FIM,
        avec observable hash pour analyse automatique via Cortex.
        Sévérité MEDIUM (pas forcément malveillant, juste à analyser).
        """
        return self.create_case(
            title=f"[SOC-FIM] Fichier {action} — {file_path}",
            description=(
                f"**Événement FIM automatique**\n\n"
                f"**Fichier:** {file_path}\n"
                f"**Machine:** {agent}\n"
                f"**Action:** {action}\n"
                f"**SHA256:** {hash_value}\n\n"
                f"Case créé automatiquement pour analyse Cortex (VirusTotal, etc.)"
            ),
            severity=Severity.MEDIUM,
            tags=["SOC", "fim", "auto-analyse", agent],
            observables=[{
                "dataType": "hash",
                "data": hash_value,
                "message": f"Hash FIM ({action}) — {file_path}",
                "ioc": False,
                "tlp": 2
            }]
        )

    def check_connectivity(self) -> bool:
        try:
            r = requests.get(self.url, verify=False, timeout=5)
            return r.status_code < 500
        except Exception:
            return False


# ╔══════════════════════════════════════════════════════════╗
# ║                   CLIENT CORTEX                          ║
# ╚══════════════════════════════════════════════════════════╝

class CortexClient:
    """Client API Cortex pour lancer des analyzers."""

    def __init__(self):
        self.url = Config.CORTEX_URL
        self.api_key = Config.CORTEX_API
        self.timeout = Config.CORTEX_TIMEOUT
        self.poll_interval = Config.CORTEX_POLL
        self.tlp = Config.CORTEX_TLP

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def get_analyzers(self, data_type: str = "ip") -> list:
        """Récupère les analyzers disponibles pour un type de donnée."""
        if not self.api_key:
            return []
        try:
            r = requests.get(
                f"{self.url}/api/analyzer/type/{data_type}",
                headers=self._headers(),
                timeout=15,
                verify=False
            )
            if r.status_code == 200:
                analyzers = r.json()
                log.debug(f"{len(analyzers)} analyzers pour '{data_type}'")
                return analyzers
        except Exception as e:
            log.error(f"Cortex analyzers: {e}")
        return []

    def run_analyzer(self, analyzer_id: str, data: str,
                     data_type: str = "ip") -> Optional[str]:
        """Lance un analyzer et retourne le job_id."""
        try:
            r = requests.post(
                f"{self.url}/api/analyzer/{analyzer_id}/run",
                headers=self._headers(),
                json={"data": data, "dataType": data_type, "tlp": self.tlp},
                timeout=15,
                verify=False
            )
            if r.status_code in [200, 201]:
                return r.json().get("id")
            log.error(f"Cortex run {analyzer_id}: {r.status_code}")
        except Exception as e:
            log.error(f"Cortex run: {e}")
        return None

    def get_job_result(self, job_id: str) -> Optional[dict]:
        """Récupère le résultat d'un job."""
        try:
            r = requests.get(
                f"{self.url}/api/job/{job_id}",
                headers=self._headers(),
                timeout=10,
                verify=False
            )
            if r.status_code == 200:
                return r.json()
        except Exception as e:
            log.error(f"Cortex job {job_id}: {e}")
        return None

    def analyze_observable(self, data: str, data_type: str = "ip") -> list[CortexResult]:
        """
        Lance tous les analyzers disponibles et collecte les résultats.
        
        Args:
            data: La donnée à analyser (IP, hash, domaine, etc.)
            data_type: Type de donnée (ip, hash, domain, url, file)
        
        Returns:
            Liste de CortexResult
        """
        if not self.api_key:
            log.error("Cortex API non configurée")
            return []

        # Récupérer les analyzers
        analyzers = self.get_analyzers(data_type)
        if not analyzers:
            log.warning(f"Aucun analyzer pour type '{data_type}'")
            return []

        # Lancer tous les analyzers
        jobs = {}
        for analyzer in analyzers:
            analyzer_id = analyzer.get("id")
            analyzer_name = analyzer.get("name", analyzer_id)
            job_id = self.run_analyzer(analyzer_id, data, data_type)
            if job_id:
                jobs[job_id] = analyzer_name
                log.info(f"Analyzer lancé: {analyzer_name}")

        if not jobs:
            return []

        # Attendre les résultats
        return self._wait_for_results(jobs, data_type)

    def _wait_for_results(self, jobs: dict, data_type: str) -> list[CortexResult]:
        """Attend et collecte les résultats de tous les jobs."""
        import time
        results = []
        pending = set(jobs.keys())
        start = time.time()

        while pending and (time.time() - start) < self.timeout:
            done = set()
            for job_id in list(pending):
                job = self.get_job_result(job_id)
                if not job:
                    continue
                
                status = job.get("status", "")
                if status in ["Success", "Failure"]:
                    done.add(job_id)
                    results.append(CortexResult(
                        analyzer_name=jobs[job_id],
                        analyzer_id=job_id,
                        status=status,
                        report=job.get("report", {})
                    ))
                elif status == "InProgress":
                    pass  # Continuer d'attendre
                else:
                    done.add(job_id)
            
            pending -= done
            if pending:
                time.sleep(self.poll_interval)

        # Marquer les jobs en timeout
        for job_id in pending:
            results.append(CortexResult(
                analyzer_name=jobs[job_id],
                analyzer_id=job_id,
                status="Timeout",
                report={}
            ))
            log.warning(f"Job {job_id} en timeout")

        return results

    def check_connectivity(self) -> bool:
        try:
            r = requests.get(self.url, verify=False, timeout=5)
            return r.status_code < 500
        except Exception:
            return False


# ╔══════════════════════════════════════════════════════════╗
# ║                   CLIENT GROQ (IA)                      ║
# ╚══════════════════════════════════════════════════════════╝

class GroqClient:
    """Client API Groq pour l'analyse IA."""

    def __init__(self):
        self.api_key = Config.GROQ_API_KEY
        self.model = Config.GROQ_MODEL
        self.max_tokens = Config.GROQ_MAX_TOKENS
        self.temperature = Config.GROQ_TEMPERATURE

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def analyze(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """Envoie une requête à Groq et retourne la réponse."""
        if not self.api_key:
            return "⚠️ Clé API Groq non configurée"

        if system_prompt is None:
            system_prompt = GROQ_SYSTEM_PROMPT

        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=self._headers(),
                json={
                    "model": self.model,
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ]
                },
                timeout=45
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            log.error(f"Groq erreur: {r.status_code} — {r.text[:200]}")
            return f"❌ Erreur Groq ({r.status_code})"
        except requests.exceptions.Timeout:
            return "❌ Groq timeout"
        except Exception as e:
            log.error(f"Groq: {e}")
            return f"❌ Groq indisponible: {e}"

    def analyze_ip(self, ip: str, results: list[CortexResult],
                   alert_desc: str) -> str:
        """Analyse les résultats Cortex pour une IP."""
        results_data = []
        for r in results:
            entry = {
                "analyzer": r.analyzer_name,
                "status": r.status,
                "malicious": r.is_malicious,
                "score": r.score,
                "summary": r.summary[:300]
            }
            results_data.append(entry)

        prompt = f"""Analyse cet incident de sécurité :

IP ANALYSÉE : {ip}
DESCRIPTION ALERTE : {alert_desc}
NOMBRE D'ANALYZERS : {len(results)} (réussis: {sum(1 for r in results if r.status == 'Success')})

RÉSULTATS CORTEX :
{json.dumps(results_data, indent=2, ensure_ascii=False)[:4000]}

Fournis ton analyse structurée."""

        return self.analyze(prompt)

    def analyze_malware(self, file_path: str, hash_value: str,
                        agent: str, results: list[CortexResult]) -> str:
        """Analyse les résultats Cortex pour un malware."""
        results_data = [{"analyzer": r.analyzer_name, "summary": r.summary[:200]} for r in results]
        
        prompt = GROQ_MALWARE_PROMPT.format(
            file=file_path,
            agent=agent,
            hash=hash_value,
            results=json.dumps(results_data, indent=2, ensure_ascii=False)[:3000]
        )
        return self.analyze(prompt)

    def generate_report(self, logs: list, stats: dict) -> str:
        """Génère un rapport d'activité."""
        logs_text = "\n".join([
            f"• {l.get('ts', '')} [{l.get('action', '')}] {l.get('detail', '')[:60]}"
            for l in logs[:25]
        ])
        
        prompt = GROQ_REPORT_PROMPT.format(
            logs=logs_text,
            stats=json.dumps(stats, indent=2)
        )
        return self.analyze(prompt, system_prompt="Tu es un analyste SOC. Génère un rapport concis en français.")


# ╔══════════════════════════════════════════════════════════╗
# ║                   CLIENT MAIL                            ║
# ╚══════════════════════════════════════════════════════════╝

class MailClient:
    """Client d'envoi d'emails (Gmail ou SMTP custom)."""

    def __init__(self):
        self.sender = Config.GMAIL_SENDER
        self.password = Config.GMAIL_PASSWORD
        # Multi-destinataires : GMAIL_RECEIVER peut contenir plusieurs
        # adresses séparées par des virgules. SEUL l'expéditeur (sender)
        # a besoin d'un mot de passe ; les destinataires n'en ont JAMAIS
        # besoin (ils reçoivent, c'est tout — Gmail, Outlook, Yahoo, peu importe).
        self.receivers = [
            r.strip() for r in str(Config.GMAIL_RECEIVER).split(",") if r.strip()
        ]
        self.smtp_host = Config.GMAIL_SMTP_HOST
        self.smtp_port = Config.GMAIL_SMTP_PORT

    def is_configured(self) -> bool:
        return bool(self.sender and self.password and self.receivers)

    def send(self, subject: str, body: str, html: bool = False) -> bool:
        """Envoie un email à TOUS les destinataires configurés."""
        if not self.is_configured():
            log.warning("Mail non configuré")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.receivers)   # affichage (tous visibles)
        msg.attach(MIMEText(body, "html" if html else "plain", "utf-8"))

        try:
            if self.smtp_port == 465:
                with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=30) as smtp:
                    smtp.login(self.sender, self.password)
                    smtp.sendmail(self.sender, self.receivers, msg.as_string())
            else:
                with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30) as smtp:
                    smtp.ehlo()
                    smtp.starttls()
                    smtp.ehlo()
                    smtp.login(self.sender, self.password)
                    smtp.sendmail(self.sender, self.receivers, msg.as_string())
            log.info(f"Email envoyé à {len(self.receivers)} destinataire(s): {subject[:50]}")
            return True
        except smtplib.SMTPAuthenticationError:
            log.error("Mail: erreur d'authentification (vérifie le mot de passe d'APPLICATION de l'expéditeur)")
            return False
        except Exception as e:
            log.error(f"Mail erreur: {e}")
            return False

    def send_block_alert(self, ip: str, reason: str, category: str,
                         duration: str, agent: str = "") -> bool:
        """Envoie une alerte de blocage IP."""
        if not Config.MAIL_ON_BLOCK:
            return False
        
        html = f"""
        <html><body style="font-family:Arial;background:#f4f4f4;padding:20px;">
          <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;
                      border-left:5px solid #e74c3c;padding:20px;">
            <h2 style="color:#e74c3c;">🚨 IP BLOQUÉE — {category}</h2>
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:8px;font-weight:bold;">IP</td>
                  <td style="padding:8px;font-family:monospace;font-size:16px;">{ip}</td></tr>
              <tr style="background:#f9f9f9;"><td style="padding:8px;font-weight:bold;">Raison</td>
                  <td style="padding:8px;">{reason}</td></tr>
              <tr><td style="padding:8px;font-weight:bold;">Durée</td>
                  <td style="padding:8px;">{duration}</td></tr>
              {"<tr style='background:#f9f9f9;'><td style='padding:8px;font-weight:bold;'>Agent</td><td style='padding:8px;'>" + agent + "</td></tr>" if agent else ""}
              <tr><td style="padding:8px;font-weight:bold;">Heure</td>
                  <td style="padding:8px;">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</td></tr>
            </table>
            <p style="color:#aaa;font-size:11px;margin-top:20px;">SOC Automation Pro</p>
          </div>
        </body></html>"""
        
        return self.send(
            f"[SOC] IP BLOQUÉE: {ip} — {category}",
            html, html=True
        )

    def send_case_alert(self, ip: str, case_num: str, title: str,
                        results: list[CortexResult], ia_analysis: str) -> bool:
        """Envoie un rapport de Case complet."""
        if not Config.MAIL_ON_CASE:
            return False

        analyzers_txt = "<br>".join([
            f"• <b>{r.analyzer_name}</b>: {r.status} — Score: {r.score}/100"
            for r in results
        ])

        ia_html = ia_analysis.replace("\n", "<br>")
        
        html = f"""
        <html><body style="font-family:Arial;background:#f4f4f4;padding:20px;">
          <div style="max-width:700px;margin:auto;background:#fff;border-radius:8px;
                      border-left:5px solid #3498db;padding:20px;">
            <h2 style="color:#3498db;">📊 Rapport SOC — Case #{case_num}</h2>
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:8px;font-weight:bold;">IP</td>
                  <td style="padding:8px;font-family:monospace;">{ip}</td></tr>
              <tr style="background:#f9f9f9;"><td style="padding:8px;font-weight:bold;">Titre</td>
                  <td style="padding:8px;">{title}</td></tr>
              <tr><td style="padding:8px;font-weight:bold;">Heure</td>
                  <td style="padding:8px;">{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</td></tr>
            </table>
            <h3 style="margin-top:20px;color:#333;">Analyzers Cortex</h3>
            <p>{analyzers_txt}</p>
            <h3 style="margin-top:20px;color:#333;">Analyse IA</h3>
            <div style="background:#f8f9fa;padding:15px;border-radius:5px;">
              {ia_html}
            </div>
            <p style="color:#aaa;font-size:11px;margin-top:20px;">SOC Automation Pro</p>
          </div>
        </body></html>"""
        
        return self.send(
            f"[SOC] Case #{case_num} — {ip} — Analyse terminée",
            html, html=True
        )

    def send_malware_alert(self, file_path: str, hash_value: str,
                           agent: str, ia_analysis: str) -> bool:
        """Envoie une alerte malware."""
        if not Config.MAIL_ON_MALWARE:
            return False

        html = f"""
        <html><body style="font-family:Arial;background:#f4f4f4;padding:20px;">
          <div style="max-width:600px;margin:auto;background:#fff;border-radius:8px;
                      border-left:5px solid #9b59b6;padding:20px;">
            <h2 style="color:#9b59b6;">🦠 MALWARE DÉTECTÉ</h2>
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:8px;font-weight:bold;">Fichier</td>
                  <td style="padding:8px;font-family:monospace;">{file_path}</td></tr>
              <tr style="background:#f9f9f9;"><td style="padding:8px;font-weight:bold;">Machine</td>
                  <td style="padding:8px;">{agent}</td></tr>
              <tr><td style="padding:8px;font-weight:bold;">SHA256</td>
                  <td style="padding:8px;font-family:monospace;font-size:10px;">{hash_value}</td></tr>
            </table>
            <h3>Analyse IA</h3>
            <div style="background:#f8f9fa;padding:15px;border-radius:5px;">
              {ia_analysis.replace(chr(10), '<br>')}
            </div>
          </div>
        </body></html>"""
        
        return self.send(
            f"[SOC] MALWARE: {file_path} sur {agent}",
            html, html=True
        )


# ╔══════════════════════════════════════════════════════════╗
# ║              INSTANCES GLOBALES                          ║
# ╚══════════════════════════════════════════════════════════╝

wazuh = WazuhClient()
thehive = TheHiveClient()
cortex = CortexClient()
groq = GroqClient()
mail = MailClient()


# ╔══════════════════════════════════════════════════════════╗
# ║              HELPERS EXTRACTION                           ║
# ╚══════════════════════════════════════════════════════════╝

def extract_telegram_version(analysis: str) -> str:
    """Extrait la version Telegram de l'analyse IA."""
    if not analysis:
        return "⚠️ Analyse non disponible"
    
    patterns = [
        r"⚡\s*(?:VERSION\s+)?TELEGRAM\s*[:\-]?\s*\n*(.*?)(?:\n\n|\Z)",
        r"⚡.*?\n(.*?)(?:\n\n|\Z)",
    ]
    
    for pattern in patterns:
        match = re.search(pattern, analysis, re.IGNORECASE | re.DOTALL)
        if match:
            version = match.group(1).strip()
            if version:
                return " ".join(version.split("\n")[:3])[:300]
    
    # Fallback: premières lignes utiles
    for line in analysis.split("\n"):
        line = line.strip()
        if line and not line.startswith(("🎯", "📊", "🔍", "💡", "⚡", "🦠")):
            return line[:300]
    
    return analysis[:300]