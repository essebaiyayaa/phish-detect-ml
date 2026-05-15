# PROJET DE FIN DE MODULE — Machine Learning — Phase 1
## Détection de Sites de Phishing via l'API PhishTank & URLScan.io

**École Nationale des Sciences Appliquées de Tétouan**  
2ème année Cycle d'ingénieurs — GI | 2025-2026

---

## 1. C'est quoi le Phishing ?

Le phishing (ou hameçonnage en français) est une technique d'arnaque sur internet où des cybercriminels créent de faux sites web qui imitent parfaitement des sites légitimes (banques, PayPal, réseaux sociaux...) dans le but de voler les informations personnelles des utilisateurs.

### 1.1 Exemple concret

Tu reçois un email : *"Votre compte PayPal est suspendu, cliquez ici pour le réactiver"* → Le lien t'envoie vers : `paypa1-secure-login.xyz` au lieu de `paypal.com` → Le faux site ressemble exactement au vrai → tu entres ton mot de passe → les pirates le volent.

### 1.2 Pourquoi c'est un vrai problème ?

| Statistique | Valeur |
|---|---|
| Attaques de phishing par jour dans le monde | > 3,4 millions |
| Coût moyen d'une attaque pour une entreprise | ~ 4,9 millions $ |
| Part des cyberattaques qui commencent par du phishing | 90% |
| Taux de clic sur des emails de phishing | ~ 30% |

---

## 2. L'idée du Projet ML

**Objectif :** Entraîner un modèle de Machine Learning qui, en analysant les caractéristiques d'une URL, peut automatiquement dire : "c'est un site légitime ✅" ou "c'est un site de phishing ❌"

### 2.1 Pourquoi c'est un problème de classification ?

Il s'agit d'une **classification binaire supervisée** :

- **Classe 0** (majorité) : Site web légitime
- **Classe 1** (minorité) : Site web de phishing

Le déséquilibre est naturel : environ 10 à 15% des URLs collectées sont du phishing, ce qui correspond exactement aux contraintes imposées par le projet (5% à 25%).

### 2.2 Adéquation avec les contraintes du projet

| Contrainte du prof | Notre projet | Statut |
|---|---|---|
| Classification supervisée | Légitime vs Phishing (binaire) | ✅ OK |
| Dataset ≥ 10 000 lignes | PhishTank contient des millions d'URLs | ✅ OK |
| Classe minoritaire 5%-25% | ~10-15% de phishing naturellement | ✅ OK |
| ≥ 8 features après FE | 25+ features (URL + URLScan.io + WHOIS) | ✅ OK |
| Mix numérique + catégoriel | Longueur (num.) + extension (cat.)... | ✅ OK |
| APIs publiques et gratuites | PhishTank + URLScan.io = 100% gratuits | ✅ OK |

---

## 3. Les Sources de Données

### 3.1 PhishTank API — Labels & URLs de Phishing

PhishTank est une plateforme communautaire gratuite qui collecte, vérifie et partage des URLs de phishing confirmées. Elle est maintenue par OpenDNS (Cisco) et est utilisée par des chercheurs en cybersécurité du monde entier.

| Caractéristique | Détail |
|---|---|
| URL de l'API | https://phishtank.org/developer_info.php |
| Authentification | Clé API gratuite (inscription simple) |
| Format de données | JSON ou CSV direct |
| Nombre d'URLs disponibles | > 1 000 000 d'URLs vérifiées |
| Mise à jour | Toutes les heures |
| Quota | Aucune limite stricte pour la recherche |
| Licence | Gratuite pour usage académique |

### 3.2 Ce que PhishTank fournit directement

- L'URL complète du site de phishing
- Le statut de vérification (confirmé ou non)
- La date de soumission
- Le statut en ligne (site encore actif ou non)
- L'identifiant unique du phish

> **Avantage clé :** La variable cible (phishing = 1 / légitime = 0) est déjà labelisée dans PhishTank. Il n'y a aucun travail manuel de labellisation à faire.

### 3.3 URLScan.io API — Enrichissement des Features

URLScan.io est un service d'analyse de sécurité web qui scanne les URLs et fournit des données techniques détaillées sur le comportement réel des pages : redirections, DOM, certificats SSL, adresses IP, pays d'hébergement, etc.

| Caractéristique | Détail |
|---|---|
| URL de l'API | https://urlscan.io/api/v1/ |
| Authentification | Clé API gratuite (inscription simple) |
| Format de données | JSON |
| Quota (gratuit) | ~1 000 requêtes/jour |
| Endpoints clés | `/scan/` (soumission) + `/result/{uuid}/` (résultats) + `/search/` (recherche) |
| Délai de scan | ~10 secondes par URL scannée |
| Licence | Gratuite pour usage académique |

### 3.4 Ce que URLScan.io fournit pour le ML

URLScan.io fournit des features réseau et comportementales impossibles à extraire syntaxiquement depuis l'URL :

- **page_status_code** — Code HTTP réel observé (200, 301, 404...)
- **nb_redirects_real** — Nombre de redirections réelles (très discriminant)
- **final_url_domain** — URL finale après redirections (révèle le masquage)
- **ip_country** — Pays réel du serveur d'hébergement
- **asn_name** — Fournisseur d'hébergement (AS) — les phishings privilégient certains AS
- **ssl_issuer** — Autorité de certification SSL (Let's Encrypt dominant sur le phishing)
- **dom_size** — Taille du DOM (pages de phishing souvent légères)
- **nb_external_links** — Nombre de liens externes dans la page

### 3.5 Complémentarité des deux APIs

| Aspect | PhishTank | URLScan.io |
|---|---|---|
| Rôle principal | Fournit les labels (phishing=1 / légitime=0) | Fournit les features techniques réelles |
| Type de données | URLs + métadonnées de vérification | Résultats de scan réseau & DOM |
| Quota | Illimité (CSV direct) | ~1 000 req/jour (plan gratuit) |
| Stratégie d'usage | Collecte principale des 10 000+ URLs | Enrichissement via `/search/` (URLs déjà scannées) |

---

## 4. Les Features du Dataset

Les features sont extraites depuis trois sources complémentaires : l'URL elle-même, URLScan.io (enrichissement réseau/comportemental), et WHOIS/DNS.

### 4.1 Features basées sur l'URL (sans requête externe)

| Feature | Type | Description | Exemple |
|---|---|---|---|
| `url_length` | Numérique | Longueur totale de l'URL | 85, 120, 23 |
| `nb_dots` | Numérique | Nombre de points dans l'URL | 3, 7, 1 |
| `nb_hyphens` | Numérique | Nombre de tirets | 0, 2, 5 |
| `nb_at` | Numérique | Présence du symbole @ | 0, 1 |
| `nb_subdomains` | Numérique | Nombre de sous-domaines | 1, 3, 5 |
| `has_ip` | Booléen | URL contient une adresse IP ? | 0, 1 |
| `has_https` | Booléen | Protocole HTTPS présent ? | 0, 1 |
| `domain_length` | Numérique | Longueur du nom de domaine | 6, 25, 40 |
| `tld` | Catégoriel | Extension du domaine | .com, .xyz, .top |
| `nb_suspicious_words` | Numérique | Mots suspects (login, secure...) | 0, 1, 3 |
| `has_port` | Booléen | Port non standard dans l'URL ? | 0, 1 |
| `path_length` | Numérique | Longueur du chemin après / | 12, 45, 0 |
| `nb_redirects` | Numérique | Nombre de redirections HTTP | 0, 1, 3 |

### 4.2 Features enrichies via URLScan.io *(NOUVEAU)*

| Feature | Type | Description |
|---|---|---|
| `page_status_code` | Numérique | Code HTTP réel observé lors du scan (200, 301, 404...) |
| `nb_redirects_real` | Numérique | Nombre de redirections réelles observées par URLScan |
| `final_url_domain` | Catégoriel | Domaine final après toutes les redirections |
| `ip_country` | Catégoriel | Pays réel du serveur d'hébergement |
| `asn_name` | Catégoriel | Fournisseur d'hébergement (Autonomous System) |
| `ssl_issuer` | Catégoriel | Autorité de certification SSL (ex: Let's Encrypt) |
| `dom_size` | Numérique | Taille du DOM en octets (pages phishing souvent légères) |
| `nb_external_links` | Numérique | Nombre de liens externes dans la page |

### 4.3 Features enrichies (WHOIS + DNS)

| Feature | Type | Description |
|---|---|---|
| `domain_age_days` | Numérique | Âge du domaine en jours (WHOIS) |
| `country` | Catégoriel | Pays d'enregistrement du domaine |
| `has_valid_ssl` | Booléen | Certificat SSL valide ? |
| `brand_similarity` | Numérique | Similarité avec un domaine connu (0-1) |

> **Total : 25 features** — largement au-dessus du minimum requis de 8 features.  
> *(13 features URL + 8 features URLScan.io + 4 features WHOIS/DNS)*

---

## 5. Objectifs Métiers et ML

### 5.1 Objectifs métiers

Le projet vise à protéger les utilisateurs du web contre les sites malveillants en automatisant leur détection :

- Détecter au moins **90%** des sites de phishing avant que les utilisateurs les visitent.
- Réduire le taux de faux positifs (sites légitimes bloqués) à moins de **5%**.
- Fonctionner en temps réel avec un délai d'analyse **< 200ms** par URL.

### 5.2 Traduction en objectifs ML

| Objectif métier | Objectif ML | Métrique principale |
|---|---|---|
| Détecter 90% des phishing | Maximiser le rappel sur la classe phishing | Recall ≥ 0.90 |
| Limiter les faux blocages | Maintenir une précision acceptable | Precision ≥ 0.80 |
| Performance globale | Optimiser le compromis Recall/Precision | F1-Score ≥ 0.85 |
| Robustesse au déséquilibre | Évaluer sur courbe PR | PR-AUC ≥ 0.85 |

### 5.3 Analyse du coût asymétrique

**Question clé : Que coûte plus cher, un faux positif ou un faux négatif ?**

| Type d'erreur | Situation | Conséquence | Coût estimé |
|---|---|---|---|
| Faux Négatif (FN) | Un site de phishing passe inaperçu | Utilisateur hacké, vol de données, fraude financière | ⚠️ Très élevé |
| Faux Positif (FP) | Un site légitime est bloqué | Utilisateur redirigé, expérience dégradée | ✅ Faible |

> **Conclusion :** Le faux négatif coûte beaucoup plus cher → on privilégie le **Recall** comme métrique principale. On accepte de bloquer quelques sites légitimes pour ne rater aucun phishing.

### 5.4 Métriques à utiliser

| Métrique | Statut | Justification |
|---|---|---|
| Recall (Rappel) | ✅ Principale | Minimiser les phishings non détectés |
| F1-Score | ✅ Secondaire | Équilibre Recall/Precision |
| PR-AUC | ✅ Secondaire | Robuste au déséquilibre de classes |
| Accuracy | ❌ Refusée | Trompeuse sur données déséquilibrées |
| ROC-AUC seule | ❌ Refusée | Optimiste sur classes déséquilibrées |

---

## 6. Architecture de la Collecte de Données

### 6.1 Vue d'ensemble du pipeline

| Étape | Action | Outil |
|---|---|---|
| 1 | Télécharger la base PhishTank (URLs phishing + labels) | PhishTank API / CSV direct |
| 2 | Collecter des URLs légitimes pour équilibrer | Alexa Top 1M / Common Crawl |
| **3** | **Enrichir chaque URL avec URLScan.io (features réseau, DOM, SSL)** | **URLScan.io API (/search/ + /result/)** |
| 4 | Extraire les features syntaxiques depuis chaque URL | Python (urllib, re, tldextract) |
| 5 | Enrichir avec WHOIS et DNS | Python (whois, dnspython) |
| 6 | Nettoyer et construire le DataFrame final (25+ features) | Pandas |
| 7 | Sauvegarder en CSV/Parquet | Pandas / PyArrow |

### 6.2 Stratégie d'utilisation de URLScan.io

Le quota gratuit de URLScan.io (~1 000 req/jour) impose une stratégie d'usage optimisée :

- Utiliser en priorité l'endpoint `/search/` pour récupérer les résultats d'URLs déjà scannées (pas de délai, pas de quota consommé).
- Utiliser l'endpoint `/scan/` uniquement pour les URLs non encore indexées (délai ~10s obligatoire par scan).
- Sauvegarder les résultats bruts JSON localement pour éviter de re-requêter à chaque exécution.
- Logguer chaque appel API (timestamp, uuid, statut) pour faciliter le debug et le suivi du quota.

### 6.3 Structure du projet Git

```
projet-ml-phishing/
├── src/
│   └── data_collection.py    ← Script principal (PhishTank + URLScan.io + WHOIS)
├── data/
│   ├── raw/                  ← Données brutes JSON (PhishTank + URLScan)
│   ├── dataset.parquet       ← Dataset final (25+ features)
│   └── sample.csv            ← Extrait 100 lignes
├── notebooks/
│   └── 01_discovery.ipynb   ← Exploration initiale
├── cadrage.md               ← Fiche de cadrage
└── DATASET.md               ← Documentation du dataset
```

---

## 7. Livrables de la Phase 1

| N° | Livrable | Contenu | Statut |
|---|---|---|---|
| 1 | `cadrage.md` | Objectifs métiers, tableau ML, métriques | À produire |
| 2 | `src/data_collection.py` | Script reproductible : PhishTank + URLScan.io + WHOIS, avec docstrings | À produire |
| 3 | `data/dataset.parquet` | ≥ 10 000 lignes, 25+ features (URL + URLScan + WHOIS) | À produire |
| 4 | `data/sample.csv` | 100 lignes pour vérification rapide | À produire |
| 5 | `DATASET.md` | Documentation complète du dataset (sources : PhishTank + URLScan.io) | À produire |
| 6 | `notebooks/01_discovery.ipynb` | EDA initial + vérification déséquilibre | À produire |

---

## 8. Planning Recommandé

| Jour | Tâche |
|---|---|
| Jour 1 | Créer compte PhishTank + compte URLScan.io, tester les deux APIs, collecter 100 URLs test |
| Jour 2 | Écrire `data_collection.py` complet intégrant PhishTank + URLScan.io + WHOIS, lancer collecte complète |
| Jour 3 | Extraire toutes les features (25+), nettoyer le dataset, vérifier le déséquilibre |
| Jour 4 | Rédiger `cadrage.md` et `DATASET.md`, créer le notebook `01_discovery.ipynb` |
| Jour 5 | Relecture, commits Git, préparation de la présentation 10 minutes |

> **Conseil final :** Commencez par collecter 100 URLs (50 phishing + 50 légitimes) pour valider votre pipeline avant de lancer la collecte complète. Pour URLScan.io, privilégiez l'endpoint `/search/` pour les URLs déjà indexées afin de ne pas consommer votre quota. Committez sur Git après chaque étape !
