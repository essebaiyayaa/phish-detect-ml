# Cadrage du Projet - Détection de Phishing par Machine Learning

*2ème année Cycle d'ingénieurs – GI | Machine Learning | 2025-2026*

---

## Introduction

Ce document constitue la fiche de cadrage du projet de fin de module de Machine Learning. Il formalise l'ensemble des choix intellectuels et techniques réalisés en amont de la phase de collecte et de construction du dataset : identification du domaine métier, sélection et justification des sources de données, définition des objectifs métiers et de leurs équivalents ML, analyse du coût asymétrique des erreurs de prédiction, et description du pipeline de collecte de données.

Le domaine retenu est la **cybersécurité**, avec pour objectif la détection automatique d'URLs de phishing. Ce choix répond à une problématique réelle et à fort impact : les attaques par hameçonnage représentent l'un des vecteurs de cybercriminalité les plus actifs, et leur détection préventive constitue un enjeu critique pour la protection des utilisateurs en ligne.

---

## 1. Contexte et Problématique Métier

### 1.1. Domaine métier

Le domaine choisi est la **cybersécurité**, et plus précisément la **détection automatique d'URLs de phishing**. Le phishing est l'une des formes de cybercriminalité les plus répandues : des attaquants créent des pages web frauduleuses imitant des services légitimes (banques, réseaux sociaux, services cloud) afin de voler les identifiants des utilisateurs.

### 1.2. Exploration et sélection des sources de données

Avant de retenir nos sources finales, nous avons exploré et comparé plusieurs APIs candidates en vérifiant leurs quotas gratuits, la nature des données et leur pertinence pour la construction d'un dataset de classification supervisée.

| API / Source | Décision | Usage dans le projet | Justification |
| :--- | :--- | :--- | :--- |
| **OpenPhish** | Écartée | Non utilisée | Feed de phishing limité et non structuré pour un usage dataset à grande échelle ; moins adapté que PhishTank pour une collecte exploitable. |
| **VirusTotal** | Écartée | Non utilisée | API orientée analyse et détection d'URLs, avec quotas limités (500 req/jour) ; non adaptée à la constitution d'un dataset de grande taille. |
| **PhishTank** | **Retenue** | Classe minoritaire — URLs phishing (`is_phishing=1`) | Source publique d'URLs phishing vérifiées communautairement ; label `is_phishing=1` attribué nativement par PhishTank. |
| **Tranco** | **Retenue** | Classe majoritaire — URLs légitimes (`is_phishing=0`) | Liste académique de domaines populaires et légitimes, mise à jour quotidiennement et utilisable sans authentification. |
| **Majestic Million** | **Retenue (fallback)** | Complément des URLs légitimes | Source alternative de domaines populaires utilisée automatiquement si Tranco est indisponible. |
| **URLScan.io** | **Retenue (enrichissement)** | Extraction de features réseau | Utilisé uniquement via l'endpoint `/search/` pour enrichir les URLs avec des métadonnées (ex : pays du serveur). |

### 1.3. Questions métiers explorées

L'exploration des APIs listées en section 1.2 — et notamment la richesse des données proposées par PhishTank (labels binaires natifs) et URLScan.io (métadonnées réseau) — a naturellement conduit à formuler trois questions métiers candidates :

1. *Comment identifier automatiquement si une URL appartient à une campagne de hameçonnage avant que l'utilisateur ne la visite ?*
   → Implique un problème de classification binaire supervisée. Trop large pour définir un objectif opérationnel précis : elle ne fixe ni seuil de performance ni contrainte de délai.

2. *Quelles caractéristiques syntaxiques et réseau d'une URL sont les plus discriminantes pour détecter le phishing ?*
   → Relève davantage d'une étude analytique (sélection de features, interprétabilité) que d'un système déployable. Elle ne débouche pas sur un modèle de décision utilisable en production.

3. *Comment concevoir un système de protection proactive capable de bloquer une URL malveillante en temps réel, avant le chargement de la page ?*
   → Combine à la fois un problème de classification binaire et des contraintes opérationnelles mesurables (délai d'inférence, taux de détection). C'est la seule question qui oriente vers un système réel, évaluable et déployable.

### 1.4. Problématique retenue

Parmi les trois questions formulées, la **Question 3** a été retenue comme problématique centrale du projet, pour les raisons suivantes.

La **Question 1** a été écartée car elle est trop générique : détecter si une URL est malveillante est une reformulation du problème de classification lui-même, sans contrainte opérationnelle mesurable. Elle pourrait s'appliquer à n'importe quel problème de détection de menaces et n'oriente pas vers un design de système concret.

La **Question 2** a été écartée car elle est de nature purement analytique et descriptive. Elle conduit à une étude d'importance des variables — exercice utile en phase d'exploration — mais ne débouche pas sur un système déployable capable de prendre des décisions en production.

La **Question 3** a été retenue car elle est la seule à combiner trois dimensions indissociables d'un système de cybersécurité réel : un **objectif de détection chiffré** (≥ 90 % des phishings interceptés), une **contrainte de latence** imposée par le temps réel (< 200 ms par URL), et une **vision de déploiement** proactive où le blocage intervient avant que l'utilisateur n'atteigne la page frauduleuse. Cette triple contrainte rend le problème à la fois ML et ingénierique, ce qui en fait la question la plus riche et la plus pertinente du point de vue académique.

**Problématique retenue :** *Comment entraîner un modèle de classification supervisée capable d'identifier automatiquement les URLs de phishing avec un taux de détection ≥ 90 %, une latence d'inférence inférieure à 200 ms, en exploitant un déséquilibre de classes naturel et sans labellisation manuelle ?*

### 1.5. Variable cible

**Variable cible :** `is_phishing`

- **`1` (Classe positive)** : URL de phishing. Cette étiquette est attribuée automatiquement aux données extraites de **PhishTank** (validées communautairement par les utilisateurs Cisco Talos).
- **`0` (Classe négative)** : URL légitime. Cette étiquette est attribuée **programmatiquement** (`df['is_phishing'] = 0`) aux domaines issus de **Tranco** et **Majestic Million** lors de l'étape de transformation dans `LegitimateURLCollector`.

---

## 2. Objectifs Métiers Quantifiés

Pour répondre à notre problématique, le système de détection doit atteindre les KPIs métiers suivants :

| # | Objectif Métier | Seuil cible |
|---|---|---|
| 1 | **Efficacité de détection** — Bloquer les sites de phishing avant que l'utilisateur les atteigne | ≥ 90 % des phishings détectés |
| 2 | **Expérience utilisateur** — Limiter les fausses alertes (blocage de sites légitimes) | Taux de faux positifs < 5 % |
| 3 | **Performance système** — Garantir une analyse en temps réel | Latence d'inférence < 200 ms par URL |

---

## 3. Traduction des Objectifs Métiers en Objectifs ML

| Objectif Métier | Objectif Machine Learning | Métrique ML associée |
|:---|:---|:---|
| Détecter 90 % des sites de phishing | Maximiser l'identification de la classe minoritaire « Phishing » (classe 1) | **Recall ≥ 0.90** |
| Limiter les faux blocages (< 5 %) | Maintenir une proportion d'erreurs acceptable sur les prédictions positives | **Precision ≥ 0.80** |
| Équilibrer détection et précision | Optimiser le compromis Recall/Precision globalement | **F1-Score ≥ 0.85** |
| Gérer le déséquilibre naturel (5–25 %) | Évaluer sur une métrique robuste au déséquilibre de classes | **PR-AUC ≥ 0.85** |

---

## 4. Analyse du Coût Asymétrique

Dans ce projet de cybersécurité, le coût des erreurs de prédiction est **fortement asymétrique**.

### 4.1. Faux Négatif (FN) — Le modèle laisse passer un phishing

> Le modèle prédit « Légitime » (0) alors que l'URL est un site de phishing (1).

**Conséquence métier :** L'utilisateur visite le faux site, saisit ses identifiants bancaires ou personnels et se fait pirater. Cela engendre :
- Une fraude financière directe (virement frauduleux, usurpation d'identité)
- Des poursuites judiciaires pour l'entreprise négligente
- Une perte irréversible de confiance des utilisateurs

**Référence :** Selon l'[IBM Cost of a Data Breach Report 2025](https://www.ibm.com/reports/data-breach), 
le coût moyen d'une violation de données est de **4,44 millions USD**, 
ce qui illustre l'impact financier catastrophique d'un seul incident non détecté.

**→ Coût = TRÈS ÉLEVÉ**

### 4.2. Faux Positif (FP) — Le modèle bloque un site légitime

> Le modèle prédit « Phishing » (1) alors que l'URL est légitime (0).

**Conséquence métier :** L'utilisateur voit une page d'avertissement « Site bloqué par sécurité ». Il peut, dans la plupart des cas, contourner le blocage en cliquant sur « Continuer quand même ». Il s'agit d'un simple désagrément passager.

**→ Coût = FAIBLE (friction utilisateur uniquement)**

### 4.3. Chiffrage de l'asymétrie

| Type d'erreur | Coût estimé |
|---|---|
| Faux Négatif (FN) |  4,44 millions USD |
| Faux Positif (FP) | ~0 DH (légère friction, contournable) |
| **Ratio d'asymétrie** | **Un FN coûte infiniment plus cher qu'un FP** |

### 4.4. Conclusion et ajustement du seuil de décision

Puisque le coût d'un Faux Négatif est immensément supérieur à celui d'un Faux Positif, **notre modèle doit absolument éliminer les Faux Négatifs en priorité**. Nous acceptons délibérément de bloquer quelques sites légitimes par excès de prudence.

**Ajustement technique :** Le seuil de décision (`threshold`) sera **abaissé à 0.3** (au lieu de 0.5 par défaut) pour forcer le modèle à déclencher une alerte plus facilement, maximisant le Recall au détriment acceptable de la Precision.

---

## 5. Choix et Justification des Métriques

### 5.1. Métriques retenues

| Métrique | Rôle | Justification |
|---|---|---|
| **Recall** *(métrique principale)* | Mesure la capacité à ne rater aucun phishing | Répond directement à l'objectif de bloquer 90 % des fraudes ; minimise les Faux Négatifs dont le coût est catastrophique |
| **F1-Score** *(métrique secondaire)* | Équilibre Recall et Precision | S'assure que la maximisation du Recall ne détruit pas entièrement la Precision (ce qui générerait trop de Faux Positifs) |
| **PR-AUC** | Évalue le modèle sur l'ensemble du spectre de seuils | Spécialement adapté aux classes déséquilibrées : la courbe PR reste fiable quand la classe négative est surreprésentée |

### 5.2. Métriques refusées

| Métrique | Raison du refus |
|---|---|
| **Accuracy** | **Dangereuse et trompeuse** dans notre contexte : un modèle qui prédirait *toujours* « Légitime » obtiendrait ~88 % d'accuracy tout en laissant passer 100 % des phishings |
| **ROC-AUC** | Donne des scores trop optimistes quand la classe négative est très majoritaire ; lui préférer catégoriquement la PR-AUC sur données déséquilibrées |

---

## 6. Features du Dataset

Le dataset final contient **15 features** réparties en deux groupes, plus la variable cible.

### 6.1. Features syntaxiques URL (11 features — sans appel réseau)

Extraites par `URLFeatureExtractor` directement depuis la chaîne de caractères de l'URL, sans aucun appel réseau.

| # | Feature | Type | Description |
|---|---|---|---|
| 1 | `url_length` | Numérique entier | Nombre total de caractères de l'URL |
| 2 | `domain_length` | Numérique entier | Longueur du domaine (sans port) |
| 3 | `num_dots` | Numérique entier | Nombre de points `.` dans l'URL complète |
| 4 | `num_subdomains` | Numérique entier | Nombre de sous-domaines (points dans le netloc − 1) |
| 5 | `num_hyphens` | Numérique entier | Nombre de tirets `-` dans l'URL |
| 6 | `num_underscores` | Numérique entier | Nombre d'underscores `_` dans l'URL |
| 7 | `num_at_signs` | Numérique entier | Nombre de symboles `@` (technique de tromperie courante) |
| 8 | `has_port` | Binaire (0/1) | 1 si un port explicite est présent dans le netloc |
| 9 | `has_https` | Binaire (0/1) | 1 si l'URL commence par `https://` |
| 10 | `has_http_in_domain` | Binaire (0/1) | 1 si la chaîne `http` apparaît dans le nom de domaine |
| 11 | `path_length` | Numérique entier | Longueur du chemin (`path`) après le domaine |

### 6.2. Features enrichies (4 features — via APIs/réseau)

Extraites par `EnrichedFeatureExtractor` via des appels réseau (WHOIS, URLScan.io, SSL). Activables séparément via le flag `--no-enrich` pour un build rapide (11 features uniquement).

| # | Feature | Type | Source | Description |
|---|---|---|---|---|
| 12 | `domain_age_days` | Numérique entier | WHOIS (python-whois) | Âge du domaine en jours depuis sa création ; −1 si indisponible |
| 13 | `country` | Catégoriel (code ISO) | URLScan.io `/search/` | Code pays ISO-3166 du serveur (ex : `US`, `FR`) ; `UNKNOWN` si absent |
| 14 | `has_valid_ssl` | Binaire (0/1) | SSL Python natif (socket) | 1 si le domaine possède un certificat TLS valide sur le port 443 |
| 15 | `brand_similarity` | Numérique flottant [0,1] | difflib (local) | Similarité maximale du domaine avec une liste de 20 marques connues (PayPal, Amazon, Google…) |

### 6.3. Variable cible

| Variable | Type | Valeurs | Source du label |
|---|---|---|---|
| `is_phishing` | Binaire (0/1) | `1` = phishing | PhishTank — labels natifs vérifiés communautairement |
| `is_phishing` | Binaire (0/1) | `0` = légitime | Attribué programmatiquement (`df['is_phishing'] = 0`) aux domaines Tranco / Majestic Million |

---
## Conclusion

Ce cadrage définit les bases d'un système de détection de phishing par apprentissage supervisé, ancré dans une problématique de cybersécurité à fort impact réel.

Les choix effectués forment un ensemble cohérent : les sources de données (PhishTank, Tranco) garantissent des labels fiables sans annotation manuelle ; les 15 features couvrent à la fois les indices syntaxiques et les métadonnées réseau ; et les métriques retenues — Recall, F1-Score et PR-AUC — sont adaptées au déséquilibre de classes et au coût asymétrique des erreurs.

L'asymétrie fondamentale du problème (un faux négatif coûte infiniment plus qu'un faux positif) justifie l'abaissement du seuil de décision à 0.3 et oriente toute la stratégie de modélisation vers la minimisation des phishings non détectés.

Ce cadrage constitue désormais le socle sur lequel reposera la phase de collecte, de construction du dataset et d'entraînement des modèles.
