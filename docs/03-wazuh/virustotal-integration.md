# Intégration VirusTotal dans Wazuh

> ⚠️ Page à compléter — aucun contenu spécifique au projet n'existait encore dans le dépôt sur ce sujet.

## Deux façons d'utiliser VirusTotal dans ce projet — ne pas confondre

| | Intégration native Wazuh | Analyzer Cortex |
|---|---|---|
| Où | Côté Wazuh Manager (`ossec.conf`, bloc `<integration>`) | Côté Cortex (`VirusTotal_GetReport`, voir [cortex-analyzers.md](../06-thehive-cortex/cortex-analyzers.md)) |
| Déclenché par | Wazuh directement, sur événement FIM | `response_soc.py`, sur un observable de case TheHive |
| Doc officielle | [Integrating Wazuh with VirusTotal](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html) | [cortex-analyzers.md](../06-thehive-cortex/cortex-analyzers.md) |

> ⚠️ **À déterminer** : ce projet utilise-t-il l'intégration native, l'analyzer Cortex, ou les deux en parallèle ? D'après le code (`_fim_auto_analyze` dans `surveillance_soc.py` crée un case TheHive puis laisse `response_soc.py` lancer Cortex), c'est le chemin **Cortex** qui est utilisé pour l'analyse déclenchée par le FIM — voir [FIM](fim.md). L'intégration native Wazuh (`<integration>`) n'apparaît pas dans le code du script, donc probablement pas utilisée, à confirmer.

## Plan de la page (à remplir)

- [ ] Confirmer/infirmer le point ci-dessus
- [ ] Si intégration native utilisée : configuration (`ossec.conf`, clé API, seuil de détection) — voir [Integration reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- [ ] Exemple d'alerte générée et son traitement dans `soc_config.py`
- [ ] Dépannage rencontré (le cas échéant)

## Documentation officielle

- [Integrating Wazuh with VirusTotal (intégration native)](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html)
- [Integration — référence de configuration `ossec.conf`](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)
- [VirusTotal — documentation API](https://docs.virustotal.com/reference/overview)
