# 🏛️ Sécurité des infrastructures critiques

> Comment ce SOC garantit la sécurité des systèmes d'information des
> infrastructures critiques — hôpitaux, banques, énergie (CEET) — sans
> jamais sacrifier la **continuité des services vitaux**.

## Le problème

Les infrastructures critiques ne se protègent pas comme une entreprise
ordinaire. Deux exigences s'y opposent :

- **Sécurité** : détecter et stopper une attaque au plus vite.
- **Disponibilité** : un hôpital, une banque ou un réseau électrique ne
  peut **pas** être coupé. Bloquer automatiquement l'IP d'un appareil
  médical, d'un automate électrique ou d'un serveur transactionnel peut
  faire **plus de dégâts que l'attaque elle-même**.

Un SOC classique bloque tout, automatiquement. Ici, la réponse est
**graduée** selon la criticité de l'équipement concerné.

## Les 3 secteurs couverts

| Secteur | Menaces typiques | Ce que fait le SOC |
|---|---|---|
| 🏥 **Santé** | Rançongiciel, vol de dossiers patients | FIM + VirusTotal (Wazuh), équipements médicaux en `critique` |
| 🏦 **Banque** | Brute force, exfiltration, fraude | Détection réseau, cœur transactionnel en `critique` (PCI DSS) |
| ⚡ **Énergie (CEET)** | Attaque SCADA/Modbus sur les automates | [Lab OT](../../ot-lab/README.md) + règles Suricata ICS |

## La réponse graduée par criticité

Chaque équipement est déclaré dans
[`soc-automation/assets.yml`](../../soc-automation/assets.yml) avec un
**secteur** et une **criticité** :

| Criticité | Réponse du SOC en cas d'attaque |
|---|---|
| 🟢 **standard** | Blocage automatique immédiat (poste bureautique, guichet…) |
| 🟠 **sensible** | Blocage automatique **de courte durée** + alerte prioritaire |
| 🔴 **critique** | **Aucun blocage automatique** → **validation humaine** sur Telegram |

Le SOC regarde à la fois la **cible** et la **source** de l'attaque : si
l'une des deux est un équipement critique connu, c'est ce niveau qui
s'applique. Bloquer par erreur (faux positif) l'IP d'un automate ou d'un
appareil médical couperait un service vital — c'est justement ce qu'on
évite.

```
Alerte ──► classification ──► criticité de l'équipement ?
                                     │
        ┌────────────┬──────────────┴───────────────┐
     standard      sensible                       critique
   blocage auto   blocage auto court        PAS de blocage auto
                                            décision en attente
                                            Telegram: ✅ / ❌
```

## La validation humaine (« human in the loop »)

Sur un équipement critique, l'admin reçoit sur Telegram :

```
🏭 [ALERTE ICS/SCADA] ⚡ Énergie
━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Équipement : Automate poste Lomé-Nord (PLC Modbus) (🔴 CRITIQUE)
🌐 Source : 192.168.10.99
📌 Attaque système industriel (ICS/SCADA)
━━━━━━━━━━━━━━━━━━━━━━━━
⛔ Blocage automatique DÉSACTIVÉ sur cet équipement critique
👉 Décision requise :
   [ ✅ Bloquer l'attaquant ]   [ ❌ Ignorer (faux positif) ]
```

- **✅ Bloquer** → l'IP attaquante est bloquée (local + Wazuh Active
  Response), un journal horodaté trace **qui** a décidé et **quand**.
- **❌ Ignorer** → classé faux positif, journalisé, aucune coupure.

Commandes associées : `/attente` (décisions en attente), `/secteurs`
(tableau de bord par secteur).

### Anti-surcharge : récidive silencieuse

Pour ne pas noyer l'admin sous les notifications quand un attaquant
insiste, une seule demande de validation est envoyée par IP :

| Attaque de l'IP X | Telegram |
|---|---|
| 1ère fois | 📩 1 message avec ✅ / ❌ (« tentative n°1 ») |
| 2ème, 3ème… | 🔕 silencieux (le compteur monte en arrière-plan) |
| Seuil atteint (`REPEAT_THRESHOLD`, défaut 3) | 📩 1 message « récidive → **blocage automatique** » |

Le blocage automatique de récidive ne s'applique **jamais** si la
*source* est elle-même un équipement critique/sensible connu (un faux
positif couperait un service vital) — là, on continue de demander à
l'humain. Seuils réglables : `REPEAT_THRESHOLD` / `REPEAT_WINDOW`.

### Déblocage

`/unblock <ip>` (ou le bouton 🔓) lève le blocage local et remet le
compteur de récidive à zéro. Le blocage natif Wazuh sur l'agent expire
seul via son `<timeout>` ; pour un déblocage **immédiat** des agents,
configurer `WAZUH_AR_UNBLOCK_COMMAND` (voir
[active-response.md](../03-wazuh/active-response.md)).

> ⚠️ **Important pour la CEET** : sur un équipement critique, il faut
> aussi **désactiver le blocage natif** de Wazuh Active Response (sinon
> Wazuh bloquerait sans attendre la décision humaine). Le SOC déclenche
> alors lui-même le blocage, mais seulement **après validation**.

## Le volet industriel (OT / SCADA)

Le réseau électrique est piloté par des automates parlant **Modbus**, un
protocole **sans authentification**. Le SOC détecte :

- toute **écriture Modbus** venant d'un hôte non-supervision (ouverture
  de disjoncteur, changement de consigne) ;
- les **diagnostics dangereux** (redémarrage d'automate, mode
  « listen-only ») ;
- la **reconnaissance** (scan du port 502, fingerprinting du PLC).

Voir le [lab OT](../../ot-lab/README.md) (automate simulé + scénario
d'attaque) et les [règles Suricata ICS](../04-suricata/rules/soc-ics.rules).

## Scénario de démonstration (≈ 5 min)

1. **Banque** — scan Nmap vers un poste `standard` → **blocage
   automatique** + alerte Telegram.
2. **Hôpital** — fichier malveillant (EICAR) → détection Wazuh FIM +
   analyse VirusTotal + synthèse IA.
3. **CEET** — `attaque_modbus.py` ouvre un disjoncteur → alerte
   `ICS_ATTACK`, **pas de blocage auto**, Telegram demande la
   validation → l'admin clique **✅ Bloquer**. 🎯 *moment fort.*

## Ce qui reste manuel / perspectives

- Désactivation ciblée de l'Active Response Wazuh sur les hôtes critiques.
- Tableaux de bord Grafana par secteur (les stats `by_sector` sont déjà
  collectées, cf. `/secteurs`).
- Export de rapport d'incident vers un CERT national (ANCy / CERT.tg).

## Fichiers de cette brique

| Fichier | Rôle |
|---|---|
| [`assets.yml`](../../soc-automation/assets.yml) | Inventaire du parc (secteur + criticité) |
| [`soc_assets.py`](../../soc-automation/soc_assets.py) | Chargement + résolution par IP/agent |
| [`ot-lab/`](../../ot-lab/README.md) | Automate Modbus simulé + attaque |
| [`rules/soc-ics.rules`](../04-suricata/rules/soc-ics.rules) | Détection Modbus/SCADA |
| [`tests/`](../../soc-automation/tests/) | Tests de la réponse graduée |
