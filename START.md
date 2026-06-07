
# 🚀 Commandes rapides pour démarrer

## Prérequis
- Python 3.8+ installé

## 1. Installer les dépendances
```bash
pip install -r requirements.txt
```

## 2. Lancer l'API FastAPI
```bash
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
→ Accès: http://localhost:8000/docs

## 3. Lancer l'interface Streamlit (dans un autre terminal)
```bash
streamlit run app/streamlit_ui.py
```
→ Accès: http://localhost:8501

---

C'est tout ! 😊
