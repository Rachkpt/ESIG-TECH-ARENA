# Dépannage général

> Le dépannage spécifique à chaque composant est documenté dans sa propre page : [Wazuh](03-wazuh/README.md), [TheHive/Cortex](06-thehive-cortex/README.md). Cette page couvre les problèmes transverses.

## Espace disque

Le manque d'espace disque est la cause la plus fréquente de plantage sur ce type de stack (Elasticsearch, Wazuh Indexer, Cortex jobs). À vérifier en premier réflexe :

```bash
df -h /
sudo du -h /var | sort -hr | head -20
```

## Voir quel service utilise un port

```bash
sudo ss -tulpn | grep :PORT
```

## Vérifier tous les services du SOC en un coup d'œil

📖 Doc officielle systemd : [systemctl(1)](https://www.freedesktop.org/software/systemd/man/systemctl.html) · [journalctl(1)](https://www.freedesktop.org/software/systemd/man/journalctl.html)

```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard suricata fail2ban
docker compose -f ~/soc-project/docker-compose.yml ps
sudo systemctl status soc-script1 soc-script2 soc-telegram   # surveillance / analyse-réponse / bot Telegram
```

## Dépannage Docker

📖 Doc officielle : [Docker — troubleshoot the daemon](https://docs.docker.com/config/daemon/troubleshoot/) · [Docker Compose — CLI reference](https://docs.docker.com/compose/reference/)

```bash
docker compose logs --tail=50 <service>
docker system df        # espace disque utilisé par Docker
docker system prune     # nettoyer images/conteneurs orphelins (⚠️ vérifier avant)
```

## Connectivité réseau entre composants

Le script `soc-automation/` a besoin d'accéder à :

| Service | Port |
|---|---|
| Wazuh Indexer | 9200 |
| TheHive | 9000 |
| Cortex | 9001 |

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://IP_WAZUH:9200
curl -s -o /dev/null -w "%{http_code}\n" http://IP_THEHIVE:9000
curl -s -o /dev/null -w "%{http_code}\n" http://IP_CORTEX:9001
```

---

> Page à compléter au fil des problèmes rencontrés pendant la préparation de la soutenance.
