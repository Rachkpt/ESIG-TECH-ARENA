#!/usr/bin/env python3
"""
soc_assets.py — Inventaire des équipements & politique de criticité
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Charge assets.yml (inventaire du parc des infrastructures critiques) et
répond à la question centrale du SOC "infrastructures critiques" :

    « L'équipement VISÉ par cette attaque est-il critique ?
      Dois-je bloquer automatiquement, ou demander l'accord d'un humain ? »

Rattachement d'une alerte à un équipement par IP destination OU nom d'agent
Wazuh. Aucune dépendance dure : si PyYAML ou assets.yml manquent, on retombe
proprement sur la politique par défaut (blocage automatique), pour ne jamais
bloquer le fonctionnement historique du SOC.
"""

import os
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

log = logging.getLogger("soc.assets")

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_PATH = os.getenv("ASSETS_FILE", os.path.join(_THIS_DIR, "assets.yml"))


# ╔══════════════════════════════════════════════════════════╗
# ║                    NIVEAUX DE CRITICITÉ                  ║
# ╚══════════════════════════════════════════════════════════╝

class Criticality(Enum):
    """Niveau de criticité d'un équipement → dicte la réponse du SOC."""
    STANDARD = "standard"   # blocage automatique immédiat (comportement legacy)
    SENSIBLE = "sensible"   # blocage auto court + alerte prioritaire
    CRITIQUE = "critique"   # PAS de blocage auto — validation humaine requise

    @classmethod
    def parse(cls, value: str) -> "Criticality":
        v = (value or "").strip().lower()
        for c in cls:
            if c.value == v:
                return c
        return cls.STANDARD

    def emoji(self) -> str:
        return {"standard": "🟢", "sensible": "🟠", "critique": "🔴"}[self.value]

    def label(self) -> str:
        return {"standard": "STANDARD", "sensible": "SENSIBLE", "critique": "CRITIQUE"}[self.value]

    @property
    def requires_human_approval(self) -> bool:
        """True si une attaque sur cet équipement NE doit PAS être bloquée
        automatiquement, mais soumise à validation humaine."""
        return self is Criticality.CRITIQUE


# Métadonnées d'affichage par secteur (emoji + libellé lisible)
SECTOR_META = {
    "sante":    ("🏥", "Santé"),
    "banque":   ("🏦", "Banque"),
    "energie":  ("⚡", "Énergie"),
    "inconnu":  ("❓", "Inconnu"),
}


def sector_emoji(secteur: str) -> str:
    return SECTOR_META.get((secteur or "inconnu").lower(), ("🏢", secteur))[0]


def sector_label(secteur: str) -> str:
    return SECTOR_META.get((secteur or "inconnu").lower(), ("🏢", secteur or "Autre"))[1]


# ╔══════════════════════════════════════════════════════════╗
# ║                       MODÈLE ASSET                       ║
# ╚══════════════════════════════════════════════════════════╝

@dataclass
class Asset:
    """Un équipement de l'inventaire (une CIBLE potentielle d'attaque)."""
    nom: str
    secteur: str
    criticite: Criticality
    ips: tuple = ()
    agent: str = ""
    description: str = ""

    @property
    def is_default(self) -> bool:
        return self.nom == "" and self.agent == "" and not self.ips


# ╔══════════════════════════════════════════════════════════╗
# ║                    CHARGEMENT INVENTAIRE                 ║
# ╚══════════════════════════════════════════════════════════╝

_assets: list = []                 # liste d'Asset
_by_ip: dict = {}                  # ip -> Asset
_by_agent: dict = {}               # agent_name(lower) -> Asset
_default_criticality = Criticality.STANDARD
_default_sector = "inconnu"
_loaded = False


def _reset():
    global _assets, _by_ip, _by_agent, _default_criticality, _default_sector, _loaded
    _assets, _by_ip, _by_agent = [], {}, {}
    _default_criticality, _default_sector = Criticality.STANDARD, "inconnu"
    _loaded = False


def load_assets(force: bool = False) -> bool:
    """
    (Re)charge l'inventaire depuis assets.yml.
    Retourne True si un inventaire a été chargé, False si on utilise la
    politique par défaut (fichier/lib absents ou vides).
    """
    global _loaded, _default_criticality, _default_sector

    if _loaded and not force:
        return bool(_assets)

    _reset()

    try:
        import yaml  # PyYAML — optionnel
    except ImportError:
        log.warning("PyYAML absent — inventaire ignoré, politique par défaut (blocage auto). "
                    "Installer : pip install pyyaml")
        _loaded = True
        return False

    if not os.path.exists(ASSETS_PATH):
        log.info(f"Inventaire {ASSETS_PATH} absent — politique par défaut (blocage auto).")
        _loaded = True
        return False

    try:
        with open(ASSETS_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        log.error(f"Lecture {ASSETS_PATH} impossible ({e}) — politique par défaut.")
        _loaded = True
        return False

    # Politique par défaut (équipement hors inventaire)
    defaut = data.get("defaut", {}) or {}
    _default_criticality = Criticality.parse(defaut.get("criticite", "standard"))
    _default_sector = (defaut.get("secteur", "inconnu") or "inconnu").lower()

    for raw in (data.get("equipements", []) or []):
        try:
            ips = raw.get("ips") or ([raw["ip"]] if raw.get("ip") else [])
            ips = tuple(str(ip).strip() for ip in ips if str(ip).strip())
            asset = Asset(
                nom=str(raw.get("nom", "")).strip(),
                secteur=str(raw.get("secteur", _default_sector)).strip().lower(),
                criticite=Criticality.parse(raw.get("criticite", _default_criticality.value)),
                ips=ips,
                agent=str(raw.get("agent", "")).strip(),
                description=str(raw.get("description", "")).strip(),
            )
        except Exception as e:
            log.warning(f"Équipement ignoré (format invalide) : {e}")
            continue

        _assets.append(asset)
        for ip in asset.ips:
            _by_ip[ip] = asset
        if asset.agent:
            _by_agent[asset.agent.lower()] = asset

    _loaded = True
    log.info(f"Inventaire chargé : {len(_assets)} équipement(s), "
             f"{len(_by_ip)} IP, {len(_by_agent)} agent(s).")
    return bool(_assets)


# ╔══════════════════════════════════════════════════════════╗
# ║                        LOOKUP                            ║
# ╚══════════════════════════════════════════════════════════╝

def _default_asset() -> Asset:
    return Asset(nom="", secteur=_default_sector,
                 criticite=_default_criticality, ips=(), agent="", description="")


def lookup(dst_ip: str = "", agent_name: str = "") -> Asset:
    """
    Retourne l'équipement CIBLE d'une attaque, identifié par son IP
    destination puis par son nom d'agent Wazuh. À défaut, un Asset
    par défaut (secteur inconnu, criticité par défaut) — jamais None.
    """
    if not _loaded:
        load_assets()

    if dst_ip and dst_ip in _by_ip:
        return _by_ip[dst_ip]
    if agent_name and agent_name.lower() in _by_agent:
        return _by_agent[agent_name.lower()]
    return _default_asset()


def all_assets() -> list:
    if not _loaded:
        load_assets()
    return list(_assets)


def sectors() -> list:
    """Liste triée des secteurs présents dans l'inventaire."""
    if not _loaded:
        load_assets()
    return sorted({a.secteur for a in _assets})


def is_inventory_loaded() -> bool:
    if not _loaded:
        load_assets()
    return bool(_assets)
