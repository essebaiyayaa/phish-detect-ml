# Tableau de Décisions de Preprocessing

**Projet :** Phish-Detect ML — Détection de Phishing par Machine Learning  
**Phase :** Phase 2 — Nettoyage & Feature Engineering  
**Date :** Mai 2026  
**Dataset source :** `data/dataset.parquet` (~10 000 lignes × 17 colonnes)  
**Dataset produit :** `data/dataset_engineered.parquet`

---

## 1. Résumé Exécutif

| Indicateur | Valeur |
|---|---|
| Lignes initiales | ~10 000 |
| NaN classiques détectés | **0** |
| Doublons détectés | **0** |
| Sentinelles traitées | **2** (`domain_age_days = -1`, `country = UNKNOWN`) |
| Outliers détectés | Oui (IQR + Z-score) |
| Décision outliers | **Conservation** (signal métier, non erreurs) |
| Features encodées | **1** (`country` → One-Hot) |
| Scaler sélectionné | **RobustScaler** (résistant aux outliers URL) |
| Nouvelles features créées | **3** (`url_to_domain_ratio`, `domain_age_category`, `special_char_density`) |

---

## 2. Tableau Complet — Variable → Action → Justification

### 2.1 Variable Identifiant & Cible

| Variable | Type | Action | Justification |
|---|---|---|---|
| `url` | `str` | **Exclue du modèle** | Identifiant brut non utilisable comme feature — source d'où les features numériques ont été extraites |
| `is_phishing` | `int` (0/1) | **Aucune transformation** | Variable cible binaire — utilisée telle quelle pour la classification supervisée |

---

### 2.2 Features Syntaxiques URL — Groupe 1 (11 features numériques)

| Variable | Type | Outliers (IQR) | Action | Justification |
|---|---|---|---|---|
| `url_length` | `int` | Oui — URLs > 200 car. | **RobustScaler** · Outliers **conservés** | Les URLs très longues sont une signature de phishing (masquage du vrai domaine). RobustScaler résistant aux extrêmes par construction (médiane + IQR). |
| `domain_length` | `int` | Oui — domaines > 60 car. | **RobustScaler** · Outliers **conservés** | Domaines très longs = phishings imitant des marques connues. Signal discriminant confirmé. |
| `num_dots` | `int` | Oui — > 5 points | **RobustScaler** · Outliers **conservés** | Plusieurs points = sous-domaines trompeurs (`a.b.bank.com`). Valeurs élevées = réels phishings. |
| `num_subdomains` | `int` | Oui — > 4 sous-domaines | **RobustScaler** · Outliers **conservés** | Multiples sous-domaines = technique de camouflage du vrai domaine. Signal documenté. |
| `num_hyphens` | `int` | Oui — > 6 tirets | **RobustScaler** · Outliers **conservés** | Tirets multiples dans le domaine (`bank-secure-login.phish.com`) = tactique phishing classique et documentée. |
| `num_underscores` | `int` | Oui — > 3 underscores | **RobustScaler** · Outliers **conservés** | Rare dans les domaines légitimes. Valeurs élevées = URLs de phishing réelles collectées depuis PhishTank. |
| `num_at_signs` | `int` | Oui — > 1 @ | **RobustScaler** · Outliers **conservés** | Présence de `@` dans une URL = technique de tromperie classique (RFC 3986 : tout ce qui précède @ est ignoré par le navigateur). |
| `has_port` | `int` (0/1) | Non applicable | **Aucune transformation** | Variable binaire déjà dans {0, 1}. Le scaling d'une variable binaire n'apporte aucun bénéfice. |
| `has_https` | `int` (0/1) | Non applicable | **Aucune transformation** | Variable binaire — idem. À noter : HTTPS ne garantit pas la légitimité (les phishings utilisent aussi HTTPS). |
| `has_http_in_domain` | `int` (0/1) | Non applicable | **Aucune transformation** | Variable binaire. Feature très discriminante (`http` dans le domaine = presque exclusivement phishing). |
| `path_length` | `int` | Oui — > 80 car. | **RobustScaler** · Outliers **conservés** | Chemins longs avec tokens d'authentification = signature de phishing. Outliers porteurs de signal fort. |

---

### 2.3 Features Enrichies — Groupe 2 (4 features via APIs)

| Variable | Type | Valeurs spéciales | Action | Justification |
|---|---|---|---|---|
| `domain_age_days` | `int` | **Sentinelle `-1`** : WHOIS indisponible | **Binning → `domain_age_category`** · Valeurs ≥ 0 : **RobustScaler** via pipeline | La valeur `-1` n'est pas une erreur mais une information métier (domaine sans WHOIS = souvent récent = souvent phishing). Elle est transformée en catégorie `inconnu` dans `domain_age_category`. Les valeurs connues (≥ 0) reçoivent un RobustScaler car elles ont des outliers (domaines légitimes très anciens > 15 000 jours). |
| `country` | `str` (ISO-3166) | **Sentinelle `UNKNOWN`** : domaine non indexé dans URLScan | **Regroupement modalités rares → `OTHER`** puis **One-Hot Encoding** | Variable catégorielle nominale avec cardinalité modérée (< 15 modalités). `UNKNOWN` est conservée comme modalité à part entière car elle est informative (non-indexation corrélée avec le phishing). Les modalités représentant < 1% des observations sont regroupées en `OTHER` pour éviter les colonnes OHE creuses. |
| `has_valid_ssl` | `int` (0/1) | Aucune | **Aucune transformation** | Variable binaire. Un site sans SSL est fortement suspect, avec SSL = neutre (les phishings modernes utilisent aussi SSL). |
| `brand_similarity` | `float` | Outliers proches de 1.0 | **RobustScaler** · Outliers **conservés** | Score [0.0, 1.0] calculé par difflib. Les valeurs proches de 1.0 indiquent une imitation délibérée d'une marque connue (Amazon, PayPal, Google) — c'est précisément le signal qu'on veut capturer. |

---

### 2.4 Nouvelles Features Créées (Feature Engineering)

| Variable | Type | Formule | Action | Justification |
|---|---|---|---|---|
| `url_to_domain_ratio` | `float` | `path_length / (url_length + 1)` | **RobustScaler** (via pipeline Étudiant 3) | Un ratio élevé indique un domaine court avec un chemin long et complexe — signature typique des phishings qui utilisent des tokens d'authentification dans le path. Le `+1` évite la division par zéro. Corrélation positive avec `is_phishing` confirmée. |
| `domain_age_category` | `str` (5 modalités) | Binning de `domain_age_days` : `inconnu` / `nouveau` (≤30j) / `recent` (≤365j) / `etabli` (≤3650j) / `ancien` (>3650j) | **One-Hot Encoding** (via pipeline Étudiant 3) | La relation entre l'âge du domaine et le phishing est non-linéaire : les domaines très récents (< 30 jours) ont un taux de phishing beaucoup plus élevé que les domaines établis. Le binning capture cette discontinuité que le RobustScaler sur la valeur brute atténuerait. La catégorie `inconnu` (sentinelle -1) est informative et conservée. |
| `special_char_density` | `float` | `(num_hyphens + num_underscores + num_at_signs) / (url_length + 1)` | **RobustScaler** (via pipeline Étudiant 3) | Un phishing combine souvent plusieurs types de caractères spéciaux dans la même URL. La densité capture cet effet d'accumulation que chaque feature prise isolément ne révèle pas. Test Mann-Whitney U confirme la significativité statistique (p < 0.05). |

---

## 3. Décisions sur les Outliers (Synthèse IQR)

| Feature | Méthode | Outliers détectés | Décision | Justification |
|---|---|---|---|---|
| `url_length` | IQR + Z-score | Oui | **Conserver** | URLs extrêmement longues = phishings réels PhishTank |
| `domain_length` | IQR + Z-score | Oui | **Conserver** | Domaines très longs = imitation marque connue |
| `num_dots` | IQR | Oui | **Conserver** | Valides métier |
| `num_subdomains` | IQR + Z-score | Oui | **Conserver** | Valides métier |
| `num_hyphens` | IQR + Z-score | Oui | **Conserver** | Tactique phishing documentée |
| `num_underscores` | IQR | Oui | **Conserver** | Valides métier |
| `num_at_signs` | IQR + Z-score | Oui | **Conserver** | RFC 3986 — technique de tromperie réelle |
| `path_length` | IQR + Z-score | Oui | **Conserver** | Chemins longs = tokens phishing |
| `brand_similarity` | IQR | Oui (≈ 1.0) | **Conserver** | Score élevé = imitation marque intentionnelle |
| `domain_age_days` | — | Élevé (≥ 10 000 j) | **Conserver** | Domaines très anciens = Tranco Top Sites légitimes |

> **Principe général :** Dans ce projet, les outliers ne sont PAS des erreurs de collecte — ils correspondent à des URLs réelles de PhishTank ou de Tranco. Leur suppression détruirait des exemples très discriminants pour le modèle. Le **RobustScaler** (médiane + IQR) est précisément conçu pour gérer ces cas.

---

## 4. Récapitulatif du Schéma de Transformation

```
Dataset brut (dataset.parquet)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  ÉTUDIANT 2 — Ce notebook (03_preprocessing.ipynb)      │
│                                                         │
│  1. Audit NaN → 0 NaN confirmé                          │
│  2. Sentinelles → domain_age_category + UNKNOWN conservé│
│  3. Doublons → 0 doublon                                │
│  4. Outliers IQR/Z-score → Conservation (justifiée)     │
│  5. OHE country → country_US, country_FR, ...           │
│  6. Feature Engineering :                               │
│       url_to_domain_ratio                               │
│       domain_age_category                               │
│       special_char_density                              │
└─────────────────────────────────────────────────────────┘
         │
         ▼
Dataset enrichi (dataset_engineered.parquet)
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  ÉTUDIANT 3 — Pipeline + Split (03_preprocessing.ipynb) │
│                                                         │
│  ColumnTransformer :                                    │
│    • num → RobustScaler (fit sur train UNIQUEMENT)      │
│    • cat → OneHotEncoder (domain_age_category)          │
│    • bin → passthrough (has_*, country_* OHE)           │
│  Split stratifié 70/15/15 sur is_phishing               │
│  Sérialisation → models/preprocessor.joblib             │
│  Export → data/processed/ (train/val/test .csv)         │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Note sur le Data Leakage

> ** Important :** Ce notebook effectue les analyses exploratoires (IQR, Z-score, distributions) sur l'ensemble du dataset pour **documenter et justifier** les décisions. Cependant, toutes les **statistiques utilisées pour transformer les données** (médiane pour RobustScaler, fréquences pour le regroupement OHE) devront être **recalculées uniquement sur le jeu d'entraînement** par Étudiant 3 dans le pipeline `ColumnTransformer`. C'est la garantie d'absence de data leakage.

---

*Document généré dans le cadre du Projet ML — Détection de Phishing | ENSATE 2025-2026*
