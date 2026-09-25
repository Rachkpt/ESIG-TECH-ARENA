# 📊 Installation Grafana & Prometheus — Monitoring SOC

> Module SOC — Prometheus collecte les métriques système et Grafana les visualise en temps réel via des dashboards interactifs. Installation native (sans Docker).

---

## 📚 Documentation officielle

| Outil | Documentation |
|---|---|
| Prometheus | https://prometheus.io/docs/introduction/overview/ 👈 |
| Node Exporter | https://prometheus.io/docs/guides/node-exporter/ 👈 |
| Grafana | https://grafana.com/docs/grafana/latest/ 👈 |
| Dashboard Node Exporter Full | https://grafana.com/grafana/dashboards/1860 👈 |

---

## 📋 Prérequis

| Ressource | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS 64-bit |
| RAM | 512 MB (léger, tourne bien avec TheHive) |
| CPU | 1 vCPU |
| Disque | 10 GB |

---

## Architecture

```
Node Exporter (port 9100)
      │
      │  expose métriques CPU/RAM/Disque/Réseau
      ▼
Prometheus (port 9090)
      │
      │  source de données
      ▼
Grafana (port 3000)
      │
      │  dashboards temps réel
      ▼
    Navigateur
```

---

## Étape 1 — Installer Prometheus

### Créer un utilisateur système dédié

```bash
sudo useradd --no-create-home --shell /bin/false prometheus
```

### Créer les répertoires

```bash
sudo mkdir -p /etc/prometheus /var/lib/prometheus
```

### Télécharger et installer Prometheus

```bash
cd /tmp
curl -sLO https://github.com/prometheus/prometheus/releases/download/v2.52.0/prometheus-2.52.0.linux-amd64.tar.gz
tar xzf prometheus-2.52.0.linux-amd64.tar.gz
cd prometheus-2.52.0.linux-amd64
```

### Copier les binaires

```bash
sudo cp prometheus /usr/local/bin/
sudo cp promtool /usr/local/bin/
```

### Copier les fichiers de configuration

```bash
sudo cp -r consoles /etc/prometheus/
sudo cp -r console_libraries /etc/prometheus/
```

### Donner les droits à l'utilisateur prometheus

```bash
sudo chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus
sudo chown prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool
```

---

## Étape 2 — Configurer Prometheus

```bash
sudo nano /etc/prometheus/prometheus.yml
```

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  # Prometheus se monitore lui-même
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Métriques système de la VM
  - job_name: 'node_exporter'
    static_configs:
      - targets: ['localhost:9100']

  # TheHive — ⚠️ non vérifié : TheHive n'expose pas de endpoint /metrics Prometheus
  # nativement sur son port applicatif (9000) sans configuration additionnelle,
  # absente de ce projet. À tester en pratique ; la cible affichera probablement
  # "down" dans Prometheus tant que ce n'est pas confirmé/configuré.
  - job_name: 'thehive'
    static_configs:
      - targets: ['localhost:9000']
```

```bash
sudo chown prometheus:prometheus /etc/prometheus/prometheus.yml
```

---

## Étape 3 — Créer le service systemd Prometheus

```bash
sudo nano /etc/systemd/system/prometheus.service
```

```ini
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/var/lib/prometheus/ \
  --web.console.templates=/etc/prometheus/consoles \
  --web.console.libraries=/etc/prometheus/console_libraries \
  --web.listen-address=0.0.0.0:9090

Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now prometheus
sudo systemctl status prometheus
```

---

## Étape 4 — Installer Node Exporter

> Node Exporter expose les métriques CPU, RAM, disque et réseau de la VM à Prometheus.

```bash
cd /tmp
curl -sLO https://github.com/prometheus/node_exporter/releases/download/v1.8.0/node_exporter-1.8.0.linux-amd64.tar.gz
tar xzf node_exporter-1.8.0.linux-amd64.tar.gz
sudo cp node_exporter-1.8.0.linux-amd64/node_exporter /usr/local/bin/
sudo chown prometheus:prometheus /usr/local/bin/node_exporter
```

### Créer le service systemd Node Exporter

```bash
sudo nano /etc/systemd/system/node_exporter.service
```

```ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/node_exporter

Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter
sudo systemctl status node_exporter
```

---

## Étape 5 — Installer Grafana

```bash
sudo apt install -y apt-transport-https software-properties-common wget
```

### Ajouter le dépôt officiel Grafana

```bash
wget -q -O - https://apt.grafana.com/gpg.key | \
  sudo gpg --dearmor -o /usr/share/keyrings/grafana.gpg

echo "deb [signed-by=/usr/share/keyrings/grafana.gpg] \
  https://apt.grafana.com stable main" | \
  sudo tee /etc/apt/sources.list.d/grafana.list
```

### Installer et démarrer Grafana

```bash
sudo apt update
sudo apt install -y grafana
sudo systemctl daemon-reload
sudo systemctl enable --now grafana-server
sudo systemctl status grafana-server
```

---

## Étape 6 — Connecter Prometheus à Grafana

### Vérifier que les services répondent

```bash
curl http://localhost:9090
curl http://localhost:9100/metrics
```

### Accéder à Grafana

```
http://IP_VM:3000
```

- **Login** : `admin`
- **Password** : `admin` *(Grafana demande de le changer au premier accès)*

### Ajouter Prometheus comme source de données

1. Aller dans **Connections → Data Sources**
2. Cliquer **Add data source**
3. Choisir **Prometheus**
4. URL : `http://localhost:9090`
5. Cliquer **Save & Test**

Tu dois voir ✅ `Data source is working`

---

## Étape 7 — Importer le dashboard Node Exporter

1. Aller dans **Dashboards → Import**
2. Entrer l'ID : **`1860`**
3. Cliquer **Load**
4. Sélectionner la source **Prometheus**
5. Cliquer **Import**

> Le dashboard **1860 — Node Exporter Full** affiche en temps réel : CPU, RAM, disque, réseau, charge système.
> Page du dashboard : https://grafana.com/grafana/dashboards/1860 👈

---

## Étape 8 — Vérifier que tout tourne

```bash
sudo systemctl status prometheus
sudo systemctl status node_exporter
sudo systemctl status grafana-server
```

Les trois services doivent afficher `active (running)`.

---

## Accès rapide

| Service | URL | Identifiants |
|---|---|---|
| Grafana | `http://IP_VM:3000` | `admin` / `admin` |
| Prometheus | `http://IP_VM:9090` | — |
| Node Exporter | `http://IP_VM:9100/metrics` | — |

---

## Commandes utiles

```bash
# Redémarrer un service
sudo systemctl restart prometheus
sudo systemctl restart node_exporter
sudo systemctl restart grafana-server

# Voir les logs Grafana
sudo journalctl -u grafana-server -n 50 --no-pager

# Voir les logs Prometheus
sudo journalctl -u prometheus -n 50 --no-pager

# Vérifier la config Prometheus
promtool check config /etc/prometheus/prometheus.yml
```

---

## Auteur

**12ak_H4ck** — ESIG Tech Arena · Blue Team / SOC
