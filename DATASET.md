# Documentation du Dataset — Détection de Phishing

**Projet :** Détection de Phishing par Machine Learning
**Auteur :** Étudiant 3 — Documentation & Exploration
**Version :** 2.0 | Date : 2026-05-15

---

## 1. Identification

| Champ | Valeur |
|---|---|
| **Nom du dataset** | `phishing_detection_dataset` |
| **Fichier principal** | `data/dataset.parquet` |
| **Fichier d'aperçu** | `data/sample.csv` (100 lignes) |
| **Tâche ML** | Classification binaire supervisée |
| **Variable cible** | `is_phishing` (0 = Légitime, 1 = Phishing) |
| **Volume total** | 11 000 lignes |
| **Nombre de features** | 15 features (11 syntaxiques URL + 4 enrichies) |
| **Déséquilibre des classes** | ~18 % de phishing (classe minoritaire naturelle) |
| **Format de stockage** | Apache Parquet (`.parquet`) + CSV d'aperçu |

---

## 2. Source des Données

Le dataset est constitué à partir de sources publiques et gratuites.

### 2.1 URLs Malveillantes (Classe Phishing = 1)

| Source | Description | Endpoint utilisé |
|---|---|---|
| **PhishTank** | Plateforme communautaire de Cisco Talos. Fournit des URLs de phishing vérifiées manuellement par la communauté. | `.json.gz` (téléchargement complet) |

- **URL de base :** `https://data.phishtank.com`
- **Endpoint :** `/data/{key}/online-valid.json.gz`
- **Date d'accès :** 2026-05-15
- **Licence :** Gratuit pour un usage académique / non-commercial.
- **Pourquoi PhishTank ?** Labels vérifiés (gold standard), dataset complet accessible en une seule requête, aucune pagination requise.
- **Alternatives écartées :** OpenPhish (quota limité), VirusTotal (quota trop restrictif pour +10 000 lignes).

### 2.2 URLs Légitimes (Classe Légitime = 0)

| Source | Description | Licence |
|---|---|---|
| **Tranco** | Liste agrégée des domaines les plus populaires (Alexa, Majestic, Umbrella, Chrome UX). | Liste publique en libre accès. |
| **Majestic Million** | Fallback automatique si Tranco est indisponible. | Liste publique en libre accès. |

- **URL de base Tranco :** `https://tranco-list.eu`
- **Endpoint :** `/download_daily/top-1m.csv.zip`
- **Date d'accès :** 2026-05-15
- **Objectif :** Représenter le trafic "sain" avec un déséquilibre naturel.

### 2.3 Enrichissement des Features (Réseau / APIs)

| API / Outil | Features extraites | URL / Source | Quota gratuit |
|---|---|---|---|
| **URLScan.io** | `country` | `https://urlscan.io/api/v1/search/` | 1 000 req/jour |
| **WHOIS** | `domain_age_days` | Lookup DNS standard | Illimité |
| **SSL (Python natif)** | `has_valid_ssl` | Connexion socket port 443 | Illimité |
| **difflib** | `brand_similarity` | Comparaison locale vs marques connues | Illimité |

---

## 3. Description

### 3.1 Objectif Métier

L'objectif de ce dataset est d'entraîner un modèle capable de détecter et de bloquer de manière proactive les URLs de phishing en temps réel (latence inférieure à 200 ms). Le système vise à intercepter au moins 90 % des tentatives de hameçonnage avant que l'utilisateur ne visite la page frauduleuse, tout en minimisant les faux positifs (sites légitimes bloqués à tort).

### 3.2 Statistiques Générales

| Statistique | Valeur |
|---|---|
| Nombre total de lignes | 11 000 |
| Nombre de colonnes | 17 (1 identifiant URL + 1 variable cible + 15 features) |
| Taille du fichier (disque) | ~0.18 MB (Parquet) |
| Taille en mémoire | ~1.8 MB |
| Valeurs manquantes | 0 (aucun NaN) |
| Types de variables | 14 numériques, 1 catégorielle (`country`) |

### 3.3 Schéma des Variables

#### 3.3.1 Features Syntaxiques URL (11 features — extraction locale, sans réseau)

| # | Nom | Type | Description métier | Plage de valeurs | Unité | Rôle |
|---|---|---|---|---|---|---|
| 1 | `url_length` | `int` | Longueur totale de la chaîne de l'URL | 12 à 1 159 | Caractères | feature |
| 2 | `domain_length` | `int` | Longueur du nom de domaine seul | 4 à 84 | Caractères | feature |
| 3 | `num_dots` | `int` | Nombre de points (`.`) dans l'URL complète | 1 à 9 | Unité | feature |
| 4 | `num_subdomains` | `int` | Nombre de sous-domaines présents | 0 à 6 | Unité | feature |
| 5 | `num_hyphens` | `int` | Nombre de tirets (`-`) dans l'URL | 0 à 37 | Unité | feature |
| 6 | `num_underscores` | `int` | Nombre d'underscores (`_`) dans l'URL | 0 à 8 | Unité | feature |
| 7 | `num_at_signs` | `int` | Nombre de symboles `@` (technique d'obfuscation) | 0 à 1 | Unité | feature |
| 8 | `has_port` | `int` | 1 si un port explicite est présent dans l'URL | 0 ou 1 | Booléen | feature |
| 9 | `has_https` | `int` | 1 si l'URL commence par `https://` | 0 ou 1 | Booléen | feature |
| 10 | `has_http_in_domain` | `int` | 1 si la chaîne "http" est insérée dans le nom de domaine | 0 ou 1 | Booléen | feature |
| 11 | `path_length` | `int` | Longueur du chemin d'accès après le domaine | 0 à 215 | Caractères | feature |

#### 3.3.2 Features Enrichies (4 features — via APIs / réseau)

| # | Nom | Type | Source | Description métier | Plage de valeurs | Unité | Rôle |
|---|---|---|---|---|---|---|---|
| 12 | `domain_age_days` | `int` | WHOIS | Âge du nom de domaine depuis sa création. `-1` si WHOIS masqué ou indisponible. | -1 à 15 087 | Jours | feature |
| 13 | `country` | `str` | URLScan.io | Code pays ISO-3166 du serveur hébergeant l'URL. `"UNKNOWN"` si non résolu. | `US`, `FR`, `UNKNOWN`… | Code ISO | feature |
| 14 | `has_valid_ssl` | `int` | SSL natif Python | 1 si le certificat TLS est valide et non expiré. | 0 ou 1 | Booléen | feature |
| 15 | `brand_similarity` | `float` | difflib (local) | Score de similarité entre le domaine et une liste de marques connues (Google, PayPal, Apple…). | 0.0 à 1.0 | Score | feature |

### 3.4 Variable Cible

| Champ | Valeur |
|---|---|
| **Nom** | `is_phishing` |
| **Type** | Binaire |
| **Valeur 1** | Phishing — URL identifiée et vérifiée par la communauté PhishTank |
| **Valeur 0** | Légitime — URL provenant de la liste de confiance Tranco / Majestic |

### 3.5 Distribution des Classes

| Classe | Label | Nombre d'occurrences | Pourcentage |
|---|---|---|---|
| 0 | Légitime | 9 020 | 82.00 % |
| 1 | Phishing | 1 980 | 18.00 % |

**Confirmation :** La classe minoritaire (Phishing) représente **18.00 %** du dataset. Ce ratio se situe bien dans la fourchette requise [5 %, 25 %] et correspond au déséquilibre naturel observé sur le terrain.

> Graphique : voir `figures/class_distribution.png` (généré dans `notebooks/01_discovery.ipynb`)

---

## 4. Objectifs Métiers et ML

### 4.1 Objectifs Métiers Quantifiés

| Objectif métier | Cible chiffrée |
|---|---|
| Détecter les URLs de phishing avant la visite de l'utilisateur | ≥ 90 % des phishings interceptés |
| Maintenir un temps de réponse compatible avec une utilisation en temps réel | Latence ≤ 200 ms par URL |
| Limiter les blocages de sites légitimes (faux positifs) | Taux de FP acceptable pour l'utilisateur |

### 4.2 Tableau de Traduction Métier → ML

| Objectif métier | Objectif ML | Métrique principale | Seuil cible |
|---|---|---|---|
| Détecter 90 % des phishings | Maximiser le rappel sur la classe 1 | Recall | ≥ 0.90 |
| Limiter les faux positifs | Maintenir une précision correcte | Precision | ≥ 0.80 |
| Équilibre global détection / précision | Optimiser le compromis F1 | F1-Score | ≥ 0.85 |
| Robustesse sur données déséquilibrées | Aire sous la courbe Précision-Rappel | PR-AUC | ≥ 0.85 |

### 4.3 Analyse du Coût Asymétrique

| Erreur | Description | Coût estimé |
|---|---|---|
| **Faux Négatif (FN)** | Un phishing non détecté → l'utilisateur visite la page frauduleuse | ~50 000 DH (source : IBM Cost of Data Breach 2024) |
| **Faux Positif (FP)** | Un site légitime bloqué à tort → friction contournable pour l'utilisateur | ~0 DH |

**Conséquence :** Le coût d'un FN est plusieurs milliers de fois supérieur au coût d'un FP. Le seuil de décision sera donc abaissé à **0.3** (au lieu de 0.5 par défaut) en Phase 2 pour maximiser le recall.

### 4.4 Métriques Retenues

- **Métrique principale :** PR-AUC (robuste au déséquilibre)
- **Métriques secondaires :** Recall, F1-Score, Precision
- **Métriques exclues :** Accuracy seule (trompeuse sur données déséquilibrées), ROC-AUC seule (optimiste sur données déséquilibrées)

---

## 5. Qualité des Données

### 5.1 Valeurs Manquantes

Aucune valeur NaN dans le dataset final.

### 5.2 Valeurs Sentinelles

| Feature | Valeur sentinelle | Signification |
|---|---|---|
| `domain_age_days` | `-1` | WHOIS masqué ou indisponible (domain privacy) |
| `country` | `"UNKNOWN"` | Résolution géographique impossible via URLScan.io |

### 5.3 Remarques

- La feature `url` (identifiant brut) est exclue de l'entraînement ML — elle sert uniquement à la traçabilité.
- La feature `country` nécessite un encodage (LabelEncoder ou One-Hot) avant modélisation.
- `domain_age_days = -1` est une information utile en soi (les domaines récents avec WHOIS masqué sont sur-représentés parmi les phishings).

---

## 6. Structure du Dépôt

```
projet-phishing/
├── data/
│   ├── dataset.parquet       # Dataset complet (11 000 lignes)
│   └── sample.csv            # Extrait de 100 lignes pour vérification rapide
├── src/
│   └── data_collection.py    # Script de collecte reproductible
├── notebooks/
│   └── 01_discovery.ipynb    # Exploration initiale et vérification du déséquilibre
├── figures/
│   └── class_distribution.png
└── DATASET.md                # Ce fichier
```

---

## Références

- **IBM Cost of Data Breach 2024 :** https://www.ibm.com/reports/data-breach
- **PhishTank :** https://www.phishtank.com/
- **Tranco List :** https://tranco-list.eu/
- **URLScan.io :** https://urlscan.io/
- **Majestic Million :** https://majestic.com/reports/majestic-million

---

*Projet ML — Détection de Phishing | ENSAT Tétouan | DATASET.md v2.0 — Mai 2026*
