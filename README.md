# phish-detect-ml

This project aims to train a **Machine Learning** model capable of automatically detecting **phishing websites** by analyzing only the URL of a website.

The model learns to distinguish legitimate sites from malicious ones based on features extracted from URLs (length, structure, subdomains, suspicious words...) enriched with real network data provided by the **PhishTank** and **URLScan.io** APIs — without ever needing to visit the site.

The ultimate goal is to predict in under 200ms: **"this site is phishing"** or **"this site is legitimate"**.

---

*École Nationale des Sciences Appliquées de Tétouan — 2nd year GI | 2025-2026*

---

## 🚀 Installation et lancement

### 1. Cloner le dépôt et installer les dépendances

```bash
# Cloner le dépôt (si pas déjà fait)
git clone https://github.com/essebaiyayaa/phish-detect-ml.git
cd phish-detect-ml

# Créer un environnement virtuel (optionnel mais recommandé)
python -m venv venv

# Activer l'environnement virtuel
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

### 2. Lancer l'API FastAPI

```bash
# Avec rechargement automatique (pour développement)
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# En production (sans rechargement)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

L'API sera accessible à:
- API: http://localhost:8000
- Documentation Swagger: http://localhost:8000/docs
- Documentation Redoc: http://localhost:8000/redoc

### 3. Lancer l'interface Streamlit

```bash
streamlit run app/streamlit_ui.py
```

L'interface sera accessible à: http://localhost:8501

---

## 📋 Points de terminaison de l'API

| Point de terminaison | Méthode | Description |
|---------------------|---------|-------------|
| `/` | GET | Page d'accueil |
| `/health` | GET | Vérifier l'état de l'API |
| `/model/info` | GET | Informations sur le modèle |
| `/predict` | POST | Prédiction pour une URL unique |
| `/predict/batch` | POST | Prédiction par lot depuis un CSV |
