# Organisation TheHive dédiée

## Pourquoi

Le compte TheHive utilisé par le script d'automatisation (`soc-automation/`) doit appartenir à une **organisation dédiée**, et surtout **pas** à l'organisation `admin` par défaut.

> L'organisation `admin` n'a pas les droits de gestion de cas (création/modification d'Alert et de Case) — elle est réservée à l'administration de la plateforme (gestion des organisations, des utilisateurs globaux). Un compte de service qui tente de créer des cas depuis `admin` échoue silencieusement ou renvoie une erreur de permission.

## Mise en place

1. Se connecter à TheHive avec le compte administrateur (`http://IP_VM:9000`).
2. Aller dans **Administration → Organisations** → créer une nouvelle organisation (ex. `SOC`).
3. Dans cette organisation, créer un utilisateur dédié au script (ex. `soc-automation`), de type **service account** si l'option est disponible, sinon un utilisateur standard.
4. Attribuer à cet utilisateur le profil `analyst` ou `org-admin` selon les droits nécessaires (création d'Alert/Case, upload de fichiers).
5. Générer une **clé API** pour cet utilisateur → à placer dans `soc-automation/.env` (`THEHIVE_API_KEY`).
6. Vérifier que le compte a bien accès à l'organisation `SOC` et pas seulement à `admin` (sélecteur d'organisation en haut de l'interface TheHive).

## Rappel — workflow des cas

Les cas ne sont **jamais** créés directement en `Case` : le script crée d'abord une `Alert`, qui est ensuite promue automatiquement en `Case` (workflow standard TheHive). Voir [Automatisation SOC](../08-automatisation-soc/README.md).
