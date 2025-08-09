# Web Security Checker

Un outil simple en ligne de commande pour effectuer des vérifications de sécurité de base sur un site web.

## Description

Ce script Python analyse une URL donnée pour évaluer certains aspects de sa configuration de sécurité. C'est un outil de base destiné à fournir un aperçu rapide de la posture de sécurité d'un serveur web.

## Fonctionnalités

Le script effectue actuellement les vérifications suivantes :

1.  **Vérification de la chaîne de confiance et de l'expiration du certificat SSL/TLS**
    *   C'est le point de départ. Si le certificat est invalide ou expiré, tout le reste est compromis. Un certificat non valide empêche la connexion sécurisée, ce qui expose les données des utilisateurs. Le vérifier en premier garantit que la communication entre le client et le serveur est sécurisée.

2.  **Analyse des En-têtes de Sécurité HTTP**
    *   Détecte la présence des en-têtes de sécurité recommandés suivants :
        *   `Strict-Transport-Security`
        *   `Content-Security-Policy`
        *   `Content-Security-Policy-Report-Only`
        *   `X-Content-Type-Options`
        *   `X-Frame-Options`
        *   `Referrer-Policy`
        *   `Permissions-Policy`

3.  **Redirections HTTP vers HTTPS**
    *   Une fois que vous savez que le certificat est valide, assurez-vous que toutes les requêtes non chiffrées sont automatiquement redirigées vers la version sécurisée du site. Si ce n'est pas le cas, un attaquant peut intercepter les premières requêtes des utilisateurs sur une connexion non chiffrée.

## Installation

1.  Assurez-vous d'avoir Python 3 installé sur votre système.
2.  Clonez ce dépôt ou téléchargez les fichiers `security_checker.py` et `requirements.txt`.
3.  Installez les dépendances nécessaires en utilisant pip :

    ```bash
    pip install -r requirements.txt
    ```

## Utilisation

Pour analyser un site web, exécutez le script depuis votre terminal en lui passant l'URL ou le nom de domaine comme argument.

```bash
python3 security_checker.py google.com
```

### Exemple de sortie

```
Analyse de l'hôte : google.com

--- Analyse du certificat SSL/TLS ---
  Sujet du certificat : *.google.com
  Émetteur : WR2
  Date d'expiration : 2025-09-29
  Le certificat est valide.

--- Analyse des en-têtes de sécurité HTTP ---
  Analyse des en-têtes pour l'URL finale : https://www.google.com/

  En-têtes de sécurité trouvés :
    - Content-Security-Policy-Report-Only: Trouvé
    - X-Frame-Options: Trouvé
```
