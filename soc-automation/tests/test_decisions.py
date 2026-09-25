#!/usr/bin/env python3
"""
Tests de la file de décisions en attente + réponse graduée bout-à-bout.
"""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="soc-test-dec-")
os.environ["STATE_FILE"] = os.path.join(_tmp, "state.json")
os.environ["LOG_FILE"] = os.path.join(_tmp, "soc.log")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import soc_assets as assets
import soc_utils as u
import surveillance_soc as s
from soc_config import WazuhAlert


def _reset_state():
    st = u._default_state()
    u.save_state(st)


def _alert(**kw):
    base = dict(id="x", timestamp="", rule_id=0, rule_description="",
                rule_level=6, rule_groups=[], src_ip="", dst_ip="",
                agent_name="", agent_id="", data={})
    base.update(kw)
    return WazuhAlert(**base)


def test_pending_cycle():
    _reset_state()
    dec_id = u.add_pending_decision({
        "ip": "1.2.3.4", "category": "ics_attack", "secteur": "energie",
        "criticite": "critique", "reason": "test",
    })
    assert len(u.get_pending_decisions()) == 1
    d = u.resolve_pending_decision(dec_id, "approved")
    assert d["status"] == "approved"
    # Double résolution refusée
    assert u.resolve_pending_decision(dec_id, "rejected") is None
    assert len(u.get_pending_decisions()) == 0


def test_anti_doublon_pending():
    _reset_state()
    d1 = u.add_pending_decision({"ip": "5.5.5.5", "category": "ics_attack"})
    d2 = u.add_pending_decision({"ip": "5.5.5.5", "category": "ics_attack"})
    assert d1 == d2  # même (ip, catégorie) → une seule décision
    assert len(u.get_pending_decisions()) == 1


def test_cible_critique_ne_bloque_pas_automatiquement():
    _reset_state()
    assets.load_assets(force=True)
    # Attaque Modbus vers l'automate CRITIQUE de la CEET
    a = _alert(rule_description="SCADA MODBUS unauthorized write",
               rule_level=12, rule_groups=["ics"],
               src_ip="192.168.10.99", dst_ip="192.168.10.50",
               agent_name="ceet-plc-lome-nord")
    s.process_network_alert(a)
    pend = u.get_pending_decisions()
    assert len(pend) == 1
    assert pend[0]["secteur"] == "energie"
    # L'attaquant NE doit PAS avoir été bloqué automatiquement
    assert "192.168.10.99" not in u.load_state()["blocked_ips"]


def test_stats_par_secteur():
    _reset_state()
    u.bump_sector_stat("sante", "alerts")
    u.bump_sector_stat("sante", "alerts")
    u.bump_sector_stat("sante", "blocked")
    stats = u.get_sector_stats()
    assert stats["sante"]["alerts"] == 2
    assert stats["sante"]["blocked"] == 1
