# PhishGuard — Détecteur de phishing par Machine Learning

**PhishGuard** est une application de détection automatique de sites de phishing à partir de l'analyse d'URL. Un modèle Random Forest pré-entraîné est exposé via une API REST (FastAPI) et accessible aux utilisateurs via une interface web interactive (Streamlit). Le projet permet des prédictions unitaires ou par lot, avec déploiement reproductible via Docker.

---

## Captures d'écran de l'interface

### Saisie d'une URL à analyser

![Page d'analyse unitaire](figures/ui_1_input.png)

### Résultat : site de phishing détecté

![Résultat phishing](figures/ui_3_phishing.png)

### Analyse par lot (CSV)

![Upload et résultats batch](figures/ui_4_batch_upload.png)

---

## Installation

Le projet est fourni sous forme d'archive **`phishguard.zip`**. Décompressez-la, puis ouvrez un terminal à la racine du dossier `phishguard/` avant de suivre l'une des options ci-dessous.

### Option 1 — Avec Docker (recommandé)

Prérequis : [Docker Desktop](https://www.docker.com/) installé et démarré.

```bash
# 1. Décompresser l'archive phishguard.zip reçue
# 2. Ouvrir un terminal dans le dossier extrait
cd phishguard

# 3. Lancer l'application (API + interface web)
docker compose up -d
```

Une fois démarré :

| Service | URL |
|---|---|
| Interface Streamlit | http://localhost:8501 |
| API FastAPI | http://localhost:8000 |
| Documentation Swagger | http://localhost:8000/docs |

Pour arrêter les services : `docker compose down`

### Option 2 — Sans Docker

Prérequis : Python 3.11+.

```bash
# 1. Décompresser l'archive phishguard.zip reçue
# 2. Ouvrir un terminal dans le dossier extrait
cd phishguard

# Créer et activer un environnement virtuel
python -m venv venv

# Windows (PowerShell)
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

Lancer les deux services dans des terminaux séparés :

```bash
# Terminal 1 — API FastAPI
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2 — Interface Streamlit
streamlit run app/streamlit_ui.py
```

---

## Exemple d'utilisation

### Tester l'API avec curl

Vérifier que l'API est opérationnelle :

```bash
curl http://localhost:8000/health
```

Réponse attendue :

```json
{
  "status": "healthy",
  "timestamp": "2026-06-10T10:00:00.000000",
  "model_loaded": true
}
```

Effectuer une prédiction unitaire :

```bash
curl -X POST "http://localhost:8000/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "url_length": 52,
    "domain_length": 28,
    "num_dots": 3,
    "num_subdomains": 2,
    "num_hyphens": 1,
    "num_underscores": 0,
    "num_at_signs": 0,
    "path_length": 15,
    "brand_similarity": 0.8,
    "domain_age_days": 5,
    "has_port": 0,
    "has_https": 0,
    "has_http_in_domain": 1,
    "has_valid_ssl": 0,
    "country": "UNKNOWN"
  }'
```

Réponse attendue :

```json
{
  "prediction": "phishing",
  "probability": 0.998,
  "threshold": 0.3,
  "confidence": "high"
}
```

> **Windows (PowerShell)** : `curl` est un alias de `Invoke-WebRequest`. Utilisez `curl.exe` pour les commandes ci-dessus, ou remplacez par `Invoke-WebRequest` avec `-Method POST` et `-Body`.

Prédiction par lot (fichier CSV) :

```bash
curl -X POST "http://localhost:8000/predict/batch" \
  -F "file=@data/sample.csv"
```

### Flow utilisateur — Interface web

1. Ouvrir **http://localhost:8501** dans un navigateur.
2. Coller une URL suspecte (ex. `http://paypal-secure-login.verify-account.com/login`).
3. Cliquer sur **Analyser** : le système extrait automatiquement les 15 caractéristiques de l'URL (structure, SSL, âge du domaine, similarité de marque).
4. Consulter le verdict (**Phishing** ou **Légitime**), la probabilité et les facteurs de risque expliqués.

![Flow utilisateur — saisie et résultat](figures/ui_2_legit.png)

---

## Architecture du dépôt

```text
phishguard/
├── app/                            # Application déployée
│   ├── main.py                     # API REST FastAPI (endpoints /health, /predict, /predict/batch, /model/info)
│   └── streamlit_ui.py             # Interface utilisateur Streamlit (analyse unitaire, batch, à propos)
├── data/                           # Données du projet
│   ├── raw/                        # Données brutes collectées (PhishTank, Tranco)
│   │   ├── phishtank_raw.json
│   │   └── legitimate_urls.csv
│   ├── processed/                  # Jeux train / validation / test après prétraitement
│   │   ├── train.csv
│   │   ├── validation.csv
│   │   └── test.csv
│   ├── dataset.parquet             # Dataset complet (11 000 lignes)
│   ├── dataset_engineered.parquet  # Dataset après feature engineering
│   └── sample.csv                  # Exemple de 100 lignes pour /predict/batch
├── figures/                        # Visualisations EDA et captures d'écran de l'UI
│   ├── eda/                        # Graphiques d'analyse exploratoire
│   └── ui_*.png                    # Captures du flux utilisateur Streamlit
├── models/                         # Artefacts ML sérialisés
│   ├── final_model.joblib          # Modèle Random Forest final
│   └── preprocessor.joblib         # Pipeline de prétraitement (RobustScaler + OHE)
├── notebooks/                      # Notebooks Jupyter par phase du projet
│   ├── 01_discovery.ipynb          # Phase 1 — Exploration initiale
│   ├── 02_eda.ipynb                # Phase 1 — Analyse exploratoire
│   ├── 03_preprocessing.ipynb      # Phase 2 — Nettoyage et feature engineering
│   ├── 04_modeling.ipynb           # Phase 3 — Entraînement des modèles
│   ├── 05_tuning.ipynb             # Phase 3 — Optimisation des hyperparamètres
│   └── 06_evaluation.ipynb         # Phase 3 — Évaluation finale
├── src/
│   └── data_collection.py          # Collecte des URLs et extraction des features
├── Dockerfile.api                  # Image Docker de l'API
├── Dockerfile.streamlit            # Image Docker de l'interface
├── docker-compose.yml              # Orchestration des deux services
├── requirements.txt                # Dépendances Python figées
└── README.md                       # Le fichier de documentation principale
```

---

## Documentation Swagger

L'API expose une documentation interactive générée automatiquement par FastAPI (OpenAPI). Une fois l'API démarrée, vous pouvez tester tous les endpoints directement depuis le navigateur :

**[http://localhost:8000/docs](http://localhost:8000/docs)**

---

## Limites connues du modèle

Bien que le modèle atteigne d'excellentes performances (F1 ≈ 0.996, Recall ≈ 0.996), les limites suivantes doivent être prises en compte :

1. **URLs raccourcies** — Les services comme `bit.ly` ou `tinyurl.com` masquent la destination réelle. Le modèle analyse l'URL raccourcie, qui ressemble souvent à une URL légitime courte.
2. **Domaines légitimes compromis** — Un site historiquement fiable piraté conserve des attributs « sûrs » (âge de domaine ancien, SSL valide). Le modèle ne détecte pas ce cas sans analyse du contenu de la page.
3. **Faux positifs sur jeunes domaines** — Les entreprises légitimes avec un domaine récent (< 30 jours) peuvent être classées à tort comme phishing par excès de prudence.
4. **Dépendance réseau** — L'extraction des features enrichies (WHOIS, certificat SSL) nécessite une connexion internet et dépend de la disponibilité de services externes.

---

## Licence

Ce projet est distribué sous la licence **MIT**. Vous êtes libre de l'utiliser, le modifier et le distribuer à des fins éducatives ou commerciales, sous réserve d'inclure la notification de copyright originale.
