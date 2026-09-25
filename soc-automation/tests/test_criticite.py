#!/usr/bin/env python3
"""
Tests de la réponse graduée par criticité (infrastructures critiques).
Lancer :  cd soc-automation && python3 -m pytest tests/ -v
"""
import os
import sys
import tempfile

# Isoler l'état et les logs dans des fichiers temporaires AVANT import
_tmp = tempfile.mkdtemp(prefix="soc-test-")
os.environ.setdefault("STATE_FILE", os.path.join(_tmp, "state.json"))
os.environ.setdefault("LOG_FILE", os.path.join(_tmp, "soc.log"))

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_assets as assets
from soc_assets import Criticality
from soc_config import (
    classify_alert, WazuhAlert, AlertCategory,
    get_severity_for_category, Severity, ACTIONABLE_CATEGORIES,
)


def _alert(**kw):
    base = dict(id="x", timestamp="", rule_id=0, rule_description="",
                rule_level=6, rule_groups=[], src_ip="", dst_ip="",
                agent_name="", agent_id="", data={})
    base.update(kw)
    return WazuhAlert(**base)


# ── Inventaire & criticité ────────────────────────────────────────

def test_inventaire_charge():
    assert assets.load_assets(force=True) is True
    assert set(assets.sectors()) == {"sante", "banque", "energie"}


def test_lookup_par_ip_critique():
    assets.load_assets(force=True)
    a = assets.lookup(dst_ip="192.168.10.50")   # automate CEET
    assert a.criticite is Criticality.CRITIQUE
    assert a.secteur == "energie"
    assert a.criticite.requires_human_approval is True


def test_lookup_par_agent_standard():
    assets.load_assets(force=True)
    a = assets.lookup(agent_name="banque-guichet")
    assert a.criticite is Criticality.STANDARD
    assert a.criticite.requires_human_approval is False


def test_lookup_inconnu_retombe_sur_defaut():
    assets.load_assets(force=True)
    a = assets.lookup(dst_ip="8.8.8.8")
    assert a.secteur == "inconnu"
    assert a.criticite is Criticality.STANDARD  # défaut = blocage auto


# ── Classification ICS ────────────────────────────────────────────

def test_classification_ics_modbus():
    a = _alert(rule_description="SCADA MODBUS unauthorized write (coil)",
               rule_level=12, rule_groups=["ics"])
    assert classify_alert(a) is AlertCategory.ICS_ATTACK
    assert AlertCategory.ICS_ATTACK in ACTIONABLE_CATEGORIES


def test_ics_prime_sur_scan():
    # Un message qui contient "scan" ET du contexte modbus reste ICS
    a = _alert(rule_description="modbus port 502 scan reconnaissance",
               rule_level=6, rule_groups=["modbus"])
    assert classify_alert(a) is AlertCategory.ICS_ATTACK


def test_ics_severite_critique():
    sev = get_severity_for_category(AlertCategory.ICS_ATTACK, base_level=6)
    assert sev is Severity.CRITICAL


def test_scan_reste_network_scan():
    a = _alert(rule_description="POSSBL PORT SCAN (NMAP -sS)",
               rule_level=6, rule_groups=["suricata"])
    assert classify_alert(a) is AlertCategory.NETWORK_SCAN
