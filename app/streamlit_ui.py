
import streamlit as st
import joblib
import pandas as pd
import numpy as np
from pathlib import Path

# Configuration de la page
st.set_page_config(
    page_title="Phish-Detect ML",
    page_icon="🎣",
    layout="wide"
)

# Charger le modèle
MODEL_PATH = Path("models/final_model.joblib")
THRESHOLD = 0.3

@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)

def categorize_domain_age(age):
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

def engineer_features(df):
    df['url_to_domain_ratio'] = df['path_length'] / (df['url_length'] + 1)
    df['domain_age_category'] = df['domain_age_days'].apply(categorize_domain_age)
    df['special_char_density'] = (
        (df['num_hyphens'] + df['num_underscores'] + df['num_at_signs']) 
        / (df['url_length'] + 1)
    )
    country_cats = ["US", "DE", "OTHER", "UNKNOWN"]
    for cat in country_cats:
        df[f'country_{cat}'] = (df['country'] == cat).astype(int)
    return df

# Titre principal
st.title("🎣 Phish-Detect ML")
st.markdown("### Détecteur de sites de phishing par analyse de caractéristiques")

# Sidebar pour la navigation
page = st.sidebar.radio("Navigation", ["Prédiction unique", "Prédiction par lot", "À propos"])

if page == "Prédiction unique":
    st.header("🔍 Prédiction pour une URL")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Caractéristiques de l'URL")
        url_length = st.number_input("Longueur de l'URL", min_value=0, value=26)
        domain_length = st.number_input("Longueur du domaine", min_value=0, value=19)
        num_dots = st.number_input("Nombre de points", min_value=0, value=2)
        num_subdomains = st.number_input("Nombre de sous-domaines", min_value=0, value=1)
        num_hyphens = st.number_input("Nombre de tirets", min_value=0, value=1)
        num_underscores = st.number_input("Nombre d'underscores", min_value=0, value=0)
        num_at_signs = st.number_input("Nombre de @", min_value=0, value=0)
        path_length = st.number_input("Longueur du chemin", min_value=0, value=0)
    
    with col2:
        st.subheader("Autres caractéristiques")
        brand_similarity = st.slider("Similarité avec une marque connue", 0.0, 1.0, 0.4)
        domain_age_days = st.number_input("Âge du domaine (jours, -1 si inconnu)", min_value=-1, value=0)
        has_port = st.selectbox("Port explicite ?", [0, 1], index=0)
        has_https = st.selectbox("HTTPS activé ?", [0, 1], index=0)
        has_http_in_domain = st.selectbox("HTTP dans le domaine ?", [0, 1], index=0)
        has_valid_ssl = st.selectbox("Certificat SSL valide ?", [0, 1], index=1)
        country = st.selectbox("Pays du serveur", ["US", "DE", "OTHER", "UNKNOWN"], index=3)
    
    # Bouton de prédiction
    if st.button("Prédire 🔮", type="primary"):
        with st.spinner("Analyse en cours..."):
            model = load_model()
            
            input_data = pd.DataFrame([{
                "url_length": url_length,
                "domain_length": domain_length,
                "num_dots": num_dots,
                "num_subdomains": num_subdomains,
                "num_hyphens": num_hyphens,
                "num_underscores": num_underscores,
                "num_at_signs": num_at_signs,
                "path_length": path_length,
                "brand_similarity": brand_similarity,
                "domain_age_days": domain_age_days,
                "has_port": has_port,
                "has_https": has_https,
                "has_http_in_domain": has_http_in_domain,
                "has_valid_ssl": has_valid_ssl,
                "country": country
            }])
            
            input_data = engineer_features(input_data)
            proba = model.predict_proba(input_data)[0, 1]
            prediction = "phishing" if proba >= THRESHOLD else "legitime"
            
            # Afficher le résultat
            st.divider()
            
            if prediction == "phishing":
                st.error(f"⚠️ **Ce site est probablement un PHISHING !**", icon="🚨")
            else:
                st.success(f"✅ **Ce site semble légitime**", icon="✅")
            
            col_res1, col_res2, col_res3 = st.columns(3)
            col_res1.metric("Probabilité de phishing", f"{proba:.2%}")
            col_res2.metric("Seuil de décision", f"{THRESHOLD:.0%}")
            
            if abs(proba - 0.5) > 0.4:
                confidence = "Haute"
            elif abs(proba - 0.5) > 0.2:
                confidence = "Moyenne"
            else:
                confidence = "Basse"
            col_res3.metric("Confiance", confidence)

elif page == "Prédiction par lot":
    st.header("📊 Prédiction par lot (CSV)")
    
    st.markdown("""
    Téléchargez un fichier CSV avec les colonnes suivantes :
    `url_length`, `domain_length`, `num_dots`, `num_subdomains`,
    `num_hyphens`, `num_underscores`, `num_at_signs`, `path_length`,
    `brand_similarity`, `domain_age_days`, `has_port`,
    `has_https`, `has_http_in_domain`, `has_valid_ssl`, `country`
    """)
    
    uploaded_file = st.file_uploader("Choisissez un fichier CSV", type=["csv"])
    
    if uploaded_file is not None:
        with st.spinner("Traitement en cours..."):
            model = load_model()
            
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ Fichier chargé avec succès ! ({len(df)} URLs)")
            
            st.subheader("Aperçu des données")
            st.dataframe(df.head())
            
            # Prédictions
            df = engineer_features(df)
            probas = model.predict_proba(df)[:, 1]
            predictions = ["phishing" if p >= THRESHOLD else "legitime" for p in probas]
            
            df["prediction"] = predictions
            df["probability"] = probas
            df["threshold"] = THRESHOLD
            
            st.divider()
            st.subheader("Résultats")
            
            # Statistiques
            phishing_count = (df["prediction"] == "phishing").sum()
            legit_count = (df["prediction"] == "legitime").sum()
            col_stat1, col_stat2 = st.columns(2)
            col_stat1.metric("Sites de phishing détectés", phishing_count)
            col_stat2.metric("Sites légitimes", legit_count)
            
            st.dataframe(df)
            
            # Télécharger les résultats
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Télécharger les résultats (CSV)",
                data=csv,
                file_name="phish_detect_predictions.csv",
                mime="text/csv"
            )

else:
    st.header("ℹ️ À propos")
    
    st.markdown("""
    ### Phish-Detect ML
    Ce projet est un système de détection de phishing par Machine Learning, développé dans le cadre d'un projet scolaire.
    
    #### Caractéristiques :
    - Modèle : Random Forest
    - Métrique principale : Recall (minimiser les faux négatifs)
    - Seuil de décision : 0.3 (abaissé pour détecter plus de phishing)
    
    #### Avertissement :
    Ce système est à des fins éducatives uniquement. Il ne remplace pas un outil de sécurité professionnel.
    """)
