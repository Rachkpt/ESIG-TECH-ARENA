# Installation Docker

> Nécessaire pour héberger TheHive & Cortex (voir [docs/06](06-thehive-cortex/README.md)).

## 1. Supprimer les anciennes versions

```bash
sudo apt remove docker docker-engine docker.io containerd runc -y
```

## 2. Installer les dépendances

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release
```

## 3. Ajouter la clé GPG officielle Docker

```bash
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
```

## 4. Ajouter le dépôt Docker

```bash
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

## 5. Installer Docker Engine

```bash
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

## 6. Vérifier l'installation

```bash
docker --version
docker compose version
```

## 7. Autoriser l'utilisateur courant (sans sudo)

```bash
sudo usermod -aG docker $USER
newgrp docker
```

## 8. Configuration système obligatoire (Elasticsearch)

> Sans ça, Elasticsearch crashe au démarrage.

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Fichier swap (recommandé)

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

## Documentation officielle

- [Docker Engine — documentation officielle](https://docs.docker.com/engine/)
- [Docker Compose — référence](https://docs.docker.com/compose/)

---

Suite : [Déploiement TheHive & Cortex](06-thehive-cortex/README.md)
