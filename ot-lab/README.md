# ⚡ Lab OT / ICS — Automate industriel simulé (CEET)

> Brique **infrastructures critiques énergétiques** du SOC. Simule un
> automate (PLC) d'un poste électrique parlant **Modbus/TCP**, la cible
> à protéger, et fournit un scénario d'attaque pour la démonstration.

## Pourquoi ?

Un réseau électrique (CEET) n'est pas piloté par des PC classiques mais
par des **automates programmables (PLC)** qui parlent des protocoles
industriels comme **Modbus**. Ce protocole, conçu dans les années 1970,
**n'a aucune authentification** : n'importe quel hôte du réseau peut
envoyer « ouvre le disjoncteur » et couper l'alimentation.

Le SOC doit donc :
1. **détecter** une écriture Modbus venant d'un hôte non autorisé ;
2. **ne PAS couper aveuglément** — un automate est un équipement
   `critique` dans [`assets.yml`](../soc-automation/assets.yml), donc le
   SOC demande une **validation humaine** (voir la réponse graduée).

## Fichiers

| Fichier | Rôle |
|---|---|
| [`plc_simulator.py`](plc_simulator.py) | Automate Modbus/TCP simulé (la **cible**). Aucune dépendance. |
| [`attaque_modbus.py`](attaque_modbus.py) | Scénario d'attaque pour la démo (la **menace**). |

Les règles de détection sont dans
[`../docs/04-suricata/rules/soc-ics.rules`](../docs/04-suricata/rules/soc-ics.rules).

## Démonstration (3 machines du lab)

```
┌────────────────┐   trafic Modbus    ┌────────────────┐
│  Kali (attaque)│ ─────────────────► │ Capteur Suricata│──► Wazuh ──► SOC
│ attaque_modbus │      port 502      │ + plc_simulator │      (validation
└────────────────┘                    └────────────────┘       humaine Telegram)
```

### 1. Sur la machine « automate » (cible)

```bash
sudo python3 plc_simulator.py            # écoute sur le port Modbus 502
# ou sans les droits root :
python3 plc_simulator.py --port 1502
```

L'automate affiche l'état des 3 disjoncteurs et journalise chaque
écriture reçue.

### 2. S'assurer que Suricata surveille le port 502

Déposer `soc-ics.rules` est automatique (tout `*.rules` dans `rules/`
est repris). Définir le poste de supervision **autorisé** :

```bash
sudo SCADA_HMI='[192.168.10.10]' bash ../docs/04-suricata/install-suricata-soc.sh
```

> Par défaut `SCADA_HMI` vaut un placeholder improbable : **toute**
> écriture Modbus déclenche une alerte — pratique pour la démo.

### 3. Depuis la machine attaquante

```bash
# Reconnaissance seule (lecture de l'état des disjoncteurs)
python3 attaque_modbus.py --target 192.168.10.50 --scan

# Attaque : ouvrir (couper) le disjoncteur 0
python3 attaque_modbus.py --target 192.168.10.50
```

### 4. Résultat attendu côté SOC

- Suricata lève une alerte `ICS/SCADA MODBUS ecriture ... non autorisee`.
- `surveillance_soc.py` la classe en **`ICS_ATTACK`**.
- L'automate étant `critique`, **aucun blocage automatique** : une
  **décision en attente** est créée et Telegram affiche
  `✅ Bloquer l'attaquant / ❌ Ignorer`.
- L'admin valide → l'IP attaquante est bloquée (local + Wazuh AR).

## ⚠️ Cadre d'usage

`attaque_modbus.py` n'est destiné qu'à ce **lab de démonstration**,
contre `plc_simulator.py`. Ne jamais l'utiliser sur un équipement réel.

## Références

- [Modbus Application Protocol Specification](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [Suricata — Modbus / ICS](https://docs.suricata.io/en/latest/configuration/suricata-yaml.html#modbus)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)
