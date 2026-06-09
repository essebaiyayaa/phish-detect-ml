
import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
import io
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialiser l'application
app = FastAPI(
    title="Phish-Detect ML API",
    description="API de détection de phishing par analyse de features URL",
    version="1.0.0"
)

# Chemins des modèles
# Lire depuis la variable d'environnement (Docker) ou utiliser le chemin local par défaut
MODEL_PATH = Path(os.environ.get("MODEL_PATH", "models/final_model.joblib"))
THRESHOLD = 0.3  # Seuillage optimal défini en Phase 1

# Variables globales pour le modèle (chargé une seule fois au démarrage)
model = None
model_info = {}


class URLFeatures(BaseModel):
    """Schéma de validation pour les features d'une URL unique (format raw depuis sample.csv)"""
    url_length: int = Field(..., description="Longueur totale de l'URL", ge=0)
    domain_length: int = Field(..., description="Longueur du domaine", ge=0)
    num_dots: int = Field(..., description="Nombre de points dans l'URL", ge=0)
    num_subdomains: int = Field(..., description="Nombre de sous-domaines", ge=0)
    num_hyphens: int = Field(..., description="Nombre de tirets", ge=0)
    num_underscores: int = Field(..., description="Nombre d'underscores", ge=0)
    num_at_signs: int = Field(..., description="Nombre de @", ge=0)
    path_length: int = Field(..., description="Longueur du chemin", ge=0)
    brand_similarity: float = Field(..., description="Similarité avec des marques connues [0,1]", ge=0, le=1)
    domain_age_days: int = Field(..., description="Âge du domaine en jours (-1 si inconnu)")
    has_port: int = Field(..., description="Port explicite (0/1)", ge=0, le=1)
    has_https: int = Field(..., description="HTTPS activé (0/1)", ge=0, le=1)
    has_http_in_domain: int = Field(..., description="HTTP dans le domaine (0/1)", ge=0, le=1)
    has_valid_ssl: int = Field(..., description="Certificat SSL valide (0/1)", ge=0, le=1)
    country: str = Field(..., description="Code pays ISO (US, DE, OTHER, UNKNOWN)")


class PredictionResponse(BaseModel):
    """Schéma de réponse pour une prédiction"""
    prediction: str
    probability: float
    threshold: float
    confidence: str


def categorize_domain_age(age):
    """Binning de domain_age_days en tranches métier."""
    if age == -1:
        return 'inconnu'
    elif age <= 30:
        return 'nouveau'
    elif age <= 365:
        return 'recent'
    elif age <= 3650:
        return 'etabli'
    else:
        return 'ancien'


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Calculer les 3 features d'ingénierie + one-hot encoding pour country à partir des features brutes."""
    # Feature 1: url_to_domain_ratio
    df['url_to_domain_ratio'] = df['path_length'] / (df['url_length'] + 1)
    
    # Feature 2: domain_age_category
    df['domain_age_category'] = df['domain_age_days'].apply(categorize_domain_age)
    
    # Feature 3: special_char_density
    df['special_char_density'] = (
        (df['num_hyphens'] + df['num_underscores'] + df['num_at_signs']) 
        / (df['url_length'] + 1)
    )
    
    # One-hot encoding pour country
    country_cats = ["US", "DE", "OTHER", "UNKNOWN"]
    for cat in country_cats:
        df[f'country_{cat}'] = (df['country'] == cat).astype(int)
    
    return df


@app.on_event("startup")
async def load_model():
    """Charger le modèle au démarrage de l'API"""
    global model, model_info
    
    logger.info("Chargement du modèle...")
    try:
        model = joblib.load(MODEL_PATH)
        model_info = {
            "name": "Random Forest Classifier",
            "version": "1.0.0",
            "training_date": "2025-2026",
            "threshold": THRESHOLD,
            "input_features": [
                "url_length", "domain_length", "num_dots", "num_subdomains",
                "num_hyphens", "num_underscores", "num_at_signs", "path_length",
                "brand_similarity", "domain_age_days", "has_port",
                "has_https", "has_http_in_domain", "has_valid_ssl", "country"
            ],
            "engineered_features": [
                "url_to_domain_ratio", "domain_age_category", "special_char_density",
                "country_DE", "country_OTHER", "country_UNKNOWN", "country_US"
            ],
            "performance": {
                "recall": 0.92,
                "f1_score": 0.85,
                "pr_auc": 0.91
            }
        }
        logger.info("Modèle chargé avec succès !")
    except Exception as e:
        logger.error(f"Erreur lors du chargement du modèle : {e}")
        raise


@app.get("/")
async def root():
    """Page d'accueil avec informations sur l'API"""
    return {
        "message": "Bienvenue sur l'API Phish-Detect ML !",
        "version": "1.0.0",
        "documentation": "/docs",
        "health_check": "/health",
        "model_info": "/model/info"
    }


@app.get("/health")
async def health_check():
    """Vérifier que l'API et le modèle sont opérationnels"""
    if model is None:
        raise HTTPException(status_code=503, detail="Modèle non chargé")
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "model_loaded": True
    }


@app.get("/model/info")
async def get_model_info():
    """Retourner les métadonnées du modèle"""
    if model is None:
        raise HTTPException(status_code=503, detail="Modèle non chargé")
    return model_info


@app.post("/predict", response_model=PredictionResponse)
async def predict(features: URLFeatures):
    """Prédiction unitaire : reçoit les features d'une URL, retourne classe + probabilité"""
    try:
        # Convertir les features en DataFrame
        input_data = features.model_dump()
        df = pd.DataFrame([input_data])
        
        # Feature engineering + one-hot encoding
        df = engineer_features(df)
        
        # Prédire (le pipeline s'occupe du reste du preprocessing)
        proba = model.predict_proba(df)[0, 1]  # Probabilité de la classe positive (phishing)
        prediction = "phishing" if proba >= THRESHOLD else "legitime"
        
        # Déterminer le niveau de confiance
        if abs(proba - 0.5) > 0.4:
            confidence = "high"
        elif abs(proba - 0.5) > 0.2:
            confidence = "medium"
        else:
            confidence = "low"
        
        return PredictionResponse(
            prediction=prediction,
            probability=float(proba),
            threshold=THRESHOLD,
            confidence=confidence
        )
    
    except Exception as e:
        logger.error(f"Erreur lors de la prédiction : {e}")
        raise HTTPException(status_code=500, detail=f"Erreur de prédiction : {str(e)}")


@app.post("/predict/batch")
async def predict_batch(file: UploadFile = File(...)):
    """Prédiction par lot : reçoit un CSV (format sample.csv), retourne un CSV enrichi des prédictions"""
    try:
        # Lire le fichier CSV
        contents = await file.read()
        df = pd.read_csv(io.BytesIO(contents))
        
        # Vérifier les colonnes requises
        required_cols = [
            "url_length", "domain_length", "num_dots", "num_subdomains",
            "num_hyphens", "num_underscores", "num_at_signs", "path_length",
            "brand_similarity", "domain_age_days", "has_port",
            "has_https", "has_http_in_domain", "has_valid_ssl", "country"
        ]
        
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            raise HTTPException(
                status_code=400,
                detail=f"Colonnes manquantes dans le CSV : {', '.join(missing_cols)}"
            )
        
        # Feature engineering + one-hot encoding
        df = engineer_features(df)
        
        # Prédire
        probas = model.predict_proba(df)[:, 1]
        predictions = ["phishing" if p >= THRESHOLD else "legitime" for p in probas]
        
        # Ajouter les résultats au DataFrame
        df["prediction"] = predictions
        df["probability"] = probas
        df["threshold"] = THRESHOLD
        
        # Convertir en CSV
        output = io.StringIO()
        df.to_csv(output, index=False)
        output.seek(0)
        
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=predictions_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Erreur lors de la prédiction par lot : {e}")
        raise HTTPException(status_code=500, detail=f"Erreur de prédiction par lot : {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
