import streamlit as st
import joblib
import pandas as pd
import numpy as np
import sys
import os
import io
from pathlib import Path
from datetime import datetime

# ─── Ajouter le répertoire racine au path pour importer src ──────────────────
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

try:
    from src.data_collection import URLFeatureExtractor, EnrichedFeatureExtractor
    EXTRACTOR_AVAILABLE = True
except ImportError:
    EXTRACTOR_AVAILABLE = False

# ─── Configuration de la page ─────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishGuard — Détecteur de Phishing",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CSS Premium ──────────────────────────────────────────────────────────────
st.markdown("""
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d0d1a 0%, #12122b 50%, #0a1628 100%);
        border-right: 1px solid rgba(99,102,241,0.2);
    }
    section[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
    section[data-testid="stSidebar"] .stRadio label { color: #cbd5e1 !important; }
    section[data-testid="stSidebar"] .stRadio > div { gap: 4px; }

    /* ── Header principal ── */
    .main-header {
        background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0d1f3c 100%);
        padding: 2.5rem 3rem;
        border-radius: 20px;
        margin-bottom: 2rem;
        border: 1px solid rgba(99,102,241,0.3);
        box-shadow: 0 8px 40px rgba(99,102,241,0.15), 0 0 0 1px rgba(255,255,255,0.05);
        position: relative;
        overflow: hidden;
        text-align: center;
    }
    .main-header::before {
        content: '';
        position: absolute;
        top: -50%;
        right: -10%;
        width: 400px;
        height: 400px;
        background: radial-gradient(circle, rgba(99,102,241,0.12) 0%, transparent 70%);
        pointer-events: none;
    }
    .main-header h1 {
        color: #ffffff;
        margin: 0 0 0.5rem;
        font-size: 2.4rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        background: linear-gradient(135deg, #fff 0%, #a5b4fc 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
    }
    .main-header p {
        color: #94a3b8;
        margin: 0;
        font-size: 1.05rem;
        font-weight: 400;
    }

    /* ── URL Input Card ── */
    .url-card {
        background: linear-gradient(135deg, #f8faff 0%, #f0f4ff 100%);
        border: 2px solid rgba(99,102,241,0.2);
        border-radius: 20px;
        padding: 1.5rem 2.5rem 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: 0 4px 24px rgba(99,102,241,0.08);
        transition: border-color 0.3s ease;
        text-align: center;
    }
    .url-card:hover {
        border-color: rgba(99,102,241,0.4);
    }
    .url-card-title {
        font-size: 1.15rem;
        font-weight: 700;
        color: #1e1b4b;
        margin-bottom: 0.4rem;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
    }
    .url-card-sub {
        font-size: 0.9rem;
        color: #64748b;
        margin-bottom: 1.5rem;
    }

    /* ── Résultat PHISHING ── */
    .result-danger {
        background: linear-gradient(135deg, #1a0010 0%, #2d0018 100%);
        border: 2px solid #f43f5e;
        border-radius: 20px;
        padding: 2rem 2.5rem;
        margin: 1.5rem 0;
        box-shadow: 0 8px 40px rgba(244,63,94,0.25);
        animation: slideIn 0.4s ease;
    }
    .result-danger .result-icon { font-size: 3rem; margin-bottom: 0.5rem; color: #f43f5e; }
    .result-danger .result-label {
        color: #fb7185;
        font-size: 0.85rem;
        font-weight: 700;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 0.3rem;
    }
    .result-danger .result-title {
        color: #ffffff;
        font-size: 1.8rem;
        font-weight: 800;
        margin-bottom: 0.6rem;
    }
    .result-danger .result-desc { color: #fda4af; font-size: 0.95rem; line-height: 1.6; }

    /* ── Résultat LÉGITIME ── */
    .result-safe {
        background: linear-gradient(135deg, #001a10 0%, #002918 100%);
        border: 2px solid #22c55e;
        border-radius: 20px;
        padding: 2rem 2.5rem;
        margin: 1.5rem 0;
        box-shadow: 0 8px 40px rgba(34,197,94,0.20);
        animation: slideIn 0.4s ease;
    }
    .result-safe .result-icon { font-size: 3rem; margin-bottom: 0.5rem; color: #22c55e; }
    .result-safe .result-label {
        color: #4ade80;
        font-size: 0.85rem;
        font-weight: 700;
        letter-spacing: 2px;
        text-transform: uppercase;
        margin-bottom: 0.3rem;
    }
    .result-safe .result-title {
        color: #ffffff;
        font-size: 1.8rem;
        font-weight: 800;
        margin-bottom: 0.6rem;
    }
    .result-safe .result-desc { color: #86efac; font-size: 0.95rem; line-height: 1.6; }

    @keyframes slideIn {
        from { opacity: 0; transform: translateY(16px); }
        to   { opacity: 1; transform: translateY(0); }
    }

    /* ── Jauge de probabilité ── */
    .gauge-wrap {
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 14px;
        padding: 1.2rem 1.6rem;
        margin: 1rem 0;
    }
    .gauge-lbl { font-size: 0.82rem; color: #94a3b8; margin-bottom: 6px; font-weight: 500; }
    .gauge-pct { font-size: 2rem; font-weight: 800; margin-bottom: 8px; }
    .gauge-bar-bg {
        background: rgba(255,255,255,0.1);
        border-radius: 999px;
        height: 10px;
        overflow: hidden;
    }
    .gauge-bar-fill {
        height: 100%;
        border-radius: 999px;
        transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .gauge-ticks {
        display: flex;
        justify-content: space-between;
        margin-top: 4px;
    }
    .gauge-tick { font-size: 0.72rem; color: #64748b; }

    /* ── Feature detail card ── */
    .feat-card {
        background: rgba(255,255,255,0.04);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 12px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.6rem;
    }
    .feat-name { font-size: 0.8rem; color: #64748b; font-weight: 500; margin-bottom: 2px; }
    .feat-val  { font-size: 0.95rem; color: #e2e8f0; font-weight: 600; }

    /* ── Cartes About ── */
    .about-card {
        background: #f8fafc;
        border-radius: 14px;
        padding: 1.4rem 1.6rem;
        border-left: 4px solid #6366f1;
        margin-bottom: 1rem;
        box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    }
    .about-card.danger  { border-left-color: #f43f5e; }
    .about-card.success { border-left-color: #22c55e; }
    .about-card.warning { border-left-color: #f59e0b; }
    .about-card h4 { color: #1e293b; margin: 0 0 0.5rem; font-weight: 700; }
    .about-card p  { color: #475569; margin: 0; font-size: 0.92rem; line-height: 1.6; }

    /* ── Tableau métriques ── */
    .metric-table { width: 100%; border-collapse: collapse; }
    .metric-table th {
        background: #1e293b; color: #f8fafc;
        padding: 10px 14px; text-align: left; font-size: 0.84rem;
        border-radius: 0;
    }
    .metric-table th:first-child { border-radius: 8px 0 0 0; }
    .metric-table th:last-child  { border-radius: 0 8px 0 0; }
    .metric-table td { padding: 9px 14px; border-bottom: 1px solid #e2e8f0; font-size: 0.87rem; }
    .metric-table tr:hover td    { background: #f1f5f9; }
    .best  { color: #15803d; font-weight: 700; }
    .ok    { color: #0f3460; font-weight: 600; }

    /* ── Disclaimer ── */
    .disclaimer {
        background: #fffbeb; border: 1px solid #fde68a;
        border-radius: 12px; padding: 1rem 1.4rem;
        margin-top: 1.5rem; color: #78350f; font-size: 0.85rem; line-height: 1.6;
    }

    /* ── Bouton principal ── */
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%) !important;
        border: none !important;
        border-radius: 12px !important;
        font-weight: 700 !important;
        font-size: 1rem !important;
        letter-spacing: 0.3px !important;
        box-shadow: 0 4px 20px rgba(99,102,241,0.35) !important;
        transition: all 0.2s !important;
        height: 3rem !important;
    }
    .stButton > button[kind="primary"]:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 28px rgba(99,102,241,0.5) !important;
    }

    /* ── Spinner personnalisé ── */
    .loading-box {
        background: linear-gradient(135deg, #0f0f23, #1a1a3e);
        border: 1px solid rgba(99,102,241,0.3);
        border-radius: 16px;
        padding: 2rem;
        text-align: center;
        color: #a5b4fc;
    }
    .loading-step { font-size: 0.85rem; color: #64748b; margin: 0.3rem 0; }
    .loading-step.done { color: #4ade80; }
    .loading-step.active { color: #a5b4fc; font-weight: 600; }

    /* ── Tags de features ── */
    .tag-ok      { background:#dcfce7; color:#15803d; padding:2px 8px; border-radius:6px; font-size:0.78rem; font-weight:600; }
    .tag-warn    { background:#fef9c3; color:#854d0e; padding:2px 8px; border-radius:6px; font-size:0.78rem; font-weight:600; }
    .tag-bad     { background:#ffe4e6; color:#be123c; padding:2px 8px; border-radius:6px; font-size:0.78rem; font-weight:600; }
    .tag-neutral { background:#f1f5f9; color:#475569; padding:2px 8px; border-radius:6px; font-size:0.78rem; font-weight:600; }

    /* ── Sidebar nav ── */
    .sidebar-logo {
        text-align: center;
        padding: 1rem 0 1.5rem;
    }
    .sidebar-logo .logo-icon {
        font-size: 2.5rem;
        display: block;
        margin-bottom: 0.5rem;
    }
    .sidebar-logo .logo-name {
        font-size: 1.2rem;
        font-weight: 800;
        color: #fff !important;
        letter-spacing: -0.3px;
    }
    .sidebar-logo .logo-version {
        font-size: 0.7rem;
        color: #64748b !important;
        letter-spacing: 1px;
        text-transform: uppercase;
    }

    /* ── Batch result table ── */
    .batch-stats {
        display: flex;
        gap: 1rem;
        margin: 1rem 0;
    }
    .batch-stat-card {
        flex: 1;
        background: #f8fafc;
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
        border: 1px solid #e2e8f0;
    }
    .batch-stat-val { font-size: 1.8rem; font-weight: 800; color: #1e293b; }
    .batch-stat-lbl { font-size: 0.78rem; color: #64748b; font-weight: 500; margin-top: 2px; }

    /* hide streamlit elements */
    #MainMenu, footer { visibility: hidden; }
    .block-container { padding-top: 1.5rem; }
</style>
""", unsafe_allow_html=True)

# ─── Constantes ───────────────────────────────────────────────────────────────
# Lire MODEL_PATH depuis la variable d'environnement (Docker) ou chemin local par défaut
_model_path_env = os.environ.get("MODEL_PATH", None)
MODEL_PATH = Path(_model_path_env) if _model_path_env else ROOT / "models" / "final_model.joblib"
THRESHOLD  = 0.3
use_enriched = True

# ─── Chargement du modèle ─────────────────────────────────────────────────────
@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        return None
    return joblib.load(MODEL_PATH)

# ─── Feature engineering (identique au pipeline d'entraînement) ───────────────
def categorize_domain_age(age):
    if age == -1:    return 'inconnu'
    elif age <= 30:  return 'nouveau'
    elif age <= 365: return 'recent'
    elif age <= 3650:return 'etabli'
    else:            return 'ancien'

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['url_to_domain_ratio']  = df['path_length'] / (df['url_length'] + 1)
    df['domain_age_category']  = df['domain_age_days'].apply(categorize_domain_age)
    df['special_char_density'] = (
        (df['num_hyphens'] + df['num_underscores'] + df['num_at_signs'])
        / (df['url_length'] + 1)
    )
    for cat in ["US", "DE", "OTHER", "UNKNOWN"]:
        df[f'country_{cat}'] = (df['country'] == cat).astype(int)
    return df

# ─── Confidence ───────────────────────────────────────────────────────────────
def get_confidence(proba: float) -> tuple[str, str]:
    distance = abs(proba - 0.5)
    if distance > 0.4:   return "Haute", "#22c55e"
    elif distance > 0.2: return "Moyenne", "#f59e0b"
    else:                return "Basse", "#ef4444"

# ─── Explications textuelles ──────────────────────────────────────────────────
def explain_prediction(features: dict, proba: float) -> list[str]:
    reasons = []
    if features.get("has_https") == 0:
        reasons.append("<i class='fa-solid fa-lock-open'></i> L'URL n'utilise pas **HTTPS** — les sites légitimes l'utilisent presque toujours.")
    if 0 <= features.get("domain_age_days", 9999) <= 30:
        reasons.append("<i class='fa-regular fa-calendar'></i> Le domaine a **moins de 30 jours** — les sites de phishing sont souvent très récents.")
    if features.get("brand_similarity", 0) > 0.6:
        reasons.append("<i class='fa-solid fa-tags'></i> L'URL **ressemble à une marque connue** — technique courante d'usurpation d'identité.")
    if features.get("has_http_in_domain") == 1:
        reasons.append("<i class='fa-solid fa-triangle-exclamation'></i> Le mot **'http'** apparaît dans le domaine lui-même — signe très suspect.")
    if features.get("has_valid_ssl") == 0:
        reasons.append("<i class='fa-solid fa-shield-xmark'></i> **Aucun certificat SSL valide** détecté — risque pour la sécurité.")
    if features.get("num_subdomains", 0) >= 3:
        reasons.append("<i class='fa-solid fa-globe'></i> **Nombreux sous-domaines** — souvent utilisés pour camoufler des URLs malveillantes.")
    if features.get("num_at_signs", 0) > 0:
        reasons.append("<i class='fa-solid fa-at'></i> Le caractère **'@'** dans l'URL est un signal fort de phishing.")
    if features.get("has_port") == 1:
        reasons.append("<i class='fa-solid fa-plug'></i> Un **port explicite** est indiqué dans l'URL — inhabituel pour un site légitime.")
    if features.get("url_length", 0) > 75:
        reasons.append("<i class='fa-solid fa-ruler-horizontal'></i> L'URL est **très longue** — les URLs de phishing sont souvent allongées pour tromper.")
    if not reasons:
        if proba >= THRESHOLD:
            reasons.append("<i class='fa-solid fa-magnifying-glass'></i> Combinaison de plusieurs facteurs mineurs suggère un risque élevé.")
        else:
            reasons.append("<i class='fa-solid fa-check'></i> L'ensemble des caractéristiques correspond à un profil de site légitime.")
    return reasons[:5]

# ─── Extraction des features depuis une URL ────────────────────────────────────
def extract_features_from_url(url: str, use_enriched: bool = True) -> dict | None:
    """Extrait les 15 features depuis une URL brute."""
    if not EXTRACTOR_AVAILABLE:
        st.error("Module d'extraction non disponible. Vérifiez que `src/data_collection.py` est accessible.")
        return None

    # 1. Features simples (11) — instantané, pas de réseau
    simple = URLFeatureExtractor.extract_simple_features(url)
    if simple is None:
        return None

    if use_enriched:
        # 2. Features enrichies (4) — WHOIS, SSL, URLScan, difflib
        extractor = EnrichedFeatureExtractor(timeout=8)
        enriched = extractor.extract_enriched_features(url)
        if enriched is None:
            enriched = {
                'domain_age_days': -1,
                'country': 'UNKNOWN',
                'has_valid_ssl': 0,
                'brand_similarity': 0.0,
            }
    else:
        enriched = {
            'domain_age_days': -1,
            'country': 'UNKNOWN',
            'has_valid_ssl': 0,
            'brand_similarity': 0.0,
        }

    return {**simple, **enriched}

# ─── Rendu jauge de probabilité ───────────────────────────────────────────────
def render_gauge(proba: float, is_phishing: bool):
    color = "#f43f5e" if is_phishing else "#22c55e"
    pct   = proba * 100
    st.markdown(f"""
    <div class="gauge-wrap">
        <div class="gauge-lbl">Probabilité d'être un site de phishing</div>
        <div class="gauge-pct" style="color:{color}">{pct:.1f}%</div>
        <div class="gauge-bar-bg">
            <div class="gauge-bar-fill" style="width:{pct}%; background:{color};"></div>
        </div>
        <div class="gauge-ticks">
            <span class="gauge-tick">0% — Sûr</span>
            <span class="gauge-tick" style="color:#f59e0b;">Seuil : {THRESHOLD*100:.0f}%</span>
            <span class="gauge-tick">100% — Phishing</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="sidebar-logo">
        <span class="logo-icon"><i class="fa-solid fa-shield-halved"></i></span>
        <div class="logo-name">PhishGuard</div>
    </div>
    """, unsafe_allow_html=True)

    page = st.radio(
        "Navigation",
        ["Analyser une URL", "Analyse par lot (CSV)", "À propos"],
        label_visibility="collapsed"
    )


# ─── Analyse par lot (helper) ───────────────────────────────────────────────
def _run_batch_analysis(df: pd.DataFrame, use_enriched: bool):
    """Lance l'analyse par lot sur un DataFrame contenant une colonne 'url'."""
    model = load_model()
    if model is None:
        st.error("⚠️ Modèle introuvable. Vérifiez `models/final_model.joblib`.")
        return

    urls = df["url"].dropna().tolist()
    n    = len(urls)

    results = []
    progress_bar = st.progress(0, text=f"Analyse de 0/{n} URLs...")

    for i, url in enumerate(urls):
        url_clean = str(url).strip()
        if not url_clean.startswith(("http://", "https://")):
            url_clean = "https://" + url_clean

        feats = extract_features_from_url(url_clean, use_enriched=use_enriched)
        if feats is None:
            results.append({
                "url": url, "prediction": "erreur",
                "probabilite": None
            })
        else:
            try:
                df_in  = pd.DataFrame([feats])
                df_in  = engineer_features(df_in)
                proba  = float(model.predict_proba(df_in)[0, 1])
                pred   = "Phishing" if proba >= THRESHOLD else "Légitime"
                conf   = get_confidence(proba)[0]
                results.append({
                    "url": url, "prediction": pred,
                    "probabilite": f"{proba:.1%}"
                })
            except Exception:
                results.append({
                    "url": url, "prediction": "erreur",
                    "probabilite": None
                })

        progress_bar.progress((i + 1) / n, text=f"Analyse de {i+1}/{n} URLs...")

    progress_bar.empty()

    df_results = pd.DataFrame(results)
    n_phish  = (df_results["prediction"] == "Phishing").sum()
    n_legit  = (df_results["prediction"] == "Légitime").sum()
    n_err    = (df_results["prediction"] == "erreur").sum()
    pct_ph   = n_phish / n * 100 if n > 0 else 0

    st.success(f"Analyse terminée — {n} URLs traitées")

    cm1, cm2, cm3, cm4 = st.columns(4)
    cm1.metric("Total URLs", n)
    cm2.metric("Phishing", n_phish)
    cm3.metric("Légitimes", n_legit)
    cm4.metric("Taux de phishing", f"{pct_ph:.1f}%")

    st.markdown("#### <i class='fa-solid fa-clipboard-list'></i> Résultats détaillés", unsafe_allow_html=True)
    st.dataframe(df_results, use_container_width=True)

    csv_out = df_results.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="Télécharger les résultats (CSV)",
        data=csv_out,
        file_name=f"phish_detect_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        type="primary"
    )


# ─── Header principal ─────────────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1><i class="fa-solid fa-shield-halved"></i> PhishGuard</h1>
    <p>
        Analysez instantanément la sécurité d'un lien. Notre système détecte les tentatives de hameçonnage pour vous protéger des menaces en ligne.
    </p>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 1 — ANALYSER UNE URL
# ═══════════════════════════════════════════════════════════════════════════════
if page == "Analyser une URL":

    st.markdown("""
    <div class="url-card">
        <div class="url-card-title">
            <span><i class="fa-solid fa-link"></i></span> Entrez l'URL à vérifier
        </div>
        <div class="url-card-sub">
            Collez l'adresse web que vous souhaitez analyser. 
        </div>
    """, unsafe_allow_html=True)

    url_input = st.text_input(
        label="URL à analyser",
        placeholder="https://exemple-suspect.com/login?redirect=paypal",
        label_visibility="collapsed",
        key="url_input_main"
    )

    st.markdown("</div>", unsafe_allow_html=True)

    # Exemples rapides
    st.markdown("<div style='font-size:0.82rem; color:#64748b; margin-bottom:0.5rem;'><i class='fa-regular fa-lightbulb'></i> <b>Exemples rapides :</b></div>", unsafe_allow_html=True)
    col_ex1, col_ex2, col_ex3, col_ex4 = st.columns(4)
    example_urls = {
        "Google":   "https://www.google.com",
        "Phishing": "http://paypal-secure-login.verify-account.com/login",
        "GitHub":   "https://github.com",
        "Suspect":  "http://amazon-verify.update-account.net:8080/secure",
    }
    def set_example_url(url):
        st.session_state["url_input_main"] = url

    for col, (label, url_ex) in zip([col_ex1, col_ex2, col_ex3, col_ex4], example_urls.items()):
        col.button(
            label, 
            use_container_width=True, 
            key=f"ex_{label}",
            on_click=set_example_url,
            args=(url_ex,)
        )

    st.markdown("<br>", unsafe_allow_html=True)

    analyze_btn = st.button(
        "Analyser cette URL",
        type="primary",
        use_container_width=True,
        disabled=(not url_input or not url_input.strip())
    )

    # ── Analyse ──────────────────────────────────────────────────────────────
    if analyze_btn and url_input and url_input.strip():
        url_clean = url_input.strip()

        # Ajouter https:// si absent
        if not url_clean.startswith(("http://", "https://")):
            url_clean = "https://" + url_clean

        with st.spinner(""):
            # Progress feedback visuel
            progress_placeholder = st.empty()

            if use_enriched:
                steps = [
                    ("Analyse de la structure de l'URL...", False),
                    ("Vérification WHOIS (âge du domaine)...", False),
                    ("Vérification du certificat SSL...", False),
                    ("Calcul de la similarité de marque...", False),
                    ("Prédiction par le modèle Random Forest...", False),
                ]
                progress_placeholder.markdown(f"""
                <div class="loading-box">
                    <div style="font-size:1.1rem; font-weight:700; color:#a5b4fc; margin-bottom:1rem;">
                        <i class="fa-solid fa-hourglass-half"></i> Analyse en cours...
                    </div>
                    {''.join(f'<div class="loading-step active">◉ {s[0]}</div>' for s in steps)}
                </div>
                """, unsafe_allow_html=True)

            features = extract_features_from_url(url_clean, use_enriched=use_enriched)
            progress_placeholder.empty()

        if features is None:
            st.error(
                "Impossible d'analyser cette URL. Vérifiez qu'elle est correctement formée "
                "(ex : `https://example.com`)."
            )
        else:
            try:
                model = load_model()
                if model is None:
                    st.error(
                        "Le fichier modèle `models/final_model.joblib` est introuvable. "
                        "Assurez-vous d'avoir entraîné et sauvegardé le modèle."
                    )
                else:
                    df_input = pd.DataFrame([features])
                    df_input = engineer_features(df_input)
                    proba       = float(model.predict_proba(df_input)[0, 1])
                    is_phishing = proba >= THRESHOLD
                    conf_label, conf_color = get_confidence(proba)
                    reasons     = explain_prediction(features, proba)

                    st.markdown("---")

                    # ── Résultat principal ──────────────────────────────────
                    if is_phishing:
                        st.markdown(f"""
                        <div class="result-danger">
                            <div class="result-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
                            <div class="result-label">Alerte — Risque détecté</div>
                            <div class="result-title">Site probablement de PHISHING</div>
                            <div class="result-desc">
                                Notre modèle a analysé cette URL et estime avec une probabilité de
                                <b>{proba:.1%}</b> qu'il s'agit d'un site malveillant.<br>
                                <b>Ne saisissez aucune information personnelle sur ce site.</b>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="result-safe">
                            <div class="result-icon"><i class="fa-solid fa-circle-check"></i></div>
                            <div class="result-label">Faible risque détecté</div>
                            <div class="result-title">Site probablement LÉGITIME</div>
                            <div class="result-desc">
                                Notre modèle a analysé cette URL et estime avec une probabilité de
                                <b>{proba:.1%}</b> seulement qu'il s'agit d'un site malveillant
                                (en-dessous du seuil d'alerte de {THRESHOLD:.0%}).<br>
                                Restez néanmoins vigilant avant de saisir des informations sensibles.
                            </div>
                        </div>
                        """, unsafe_allow_html=True)

                    # ── Jauge ───────────────────────────────────────────────
                    render_gauge(proba, is_phishing)

                    # ── Métriques en colonnes ───────────────────────────────
                    cm1, cm2, cm3 = st.columns(3)
                    cm1.metric("Probabilité de phishing", f"{proba:.1%}", delta=None)
                    cm2.metric("Seuil de décision", f"{THRESHOLD:.0%}")
                    cm3.metric("Niveau de confiance", conf_label)

                    # ── Explications ────────────────────────────────────────
                    st.markdown("#### <i class='fa-solid fa-brain'></i> Pourquoi ce résultat ?", unsafe_allow_html=True)
                    for r in reasons:
                        st.markdown(f"- {r}", unsafe_allow_html=True)

                    # ── Détail des features extraites (expander) ────────────
                    with st.expander("Voir les caractéristiques extraites automatiquement"):
                        st.markdown(
                            "<div style='font-size:0.85rem; color:#64748b; margin-bottom:1rem;'>"
                            "Ces valeurs ont été extraites automatiquement depuis l'URL sans intervention de votre part."
                            "</div>", unsafe_allow_html=True
                        )

                        col_f1, col_f2, col_f3 = st.columns(3)

                        with col_f1:
                            st.markdown("**<i class='fa-solid fa-link'></i> Structure de l'URL**", unsafe_allow_html=True)
                            feat_rows = [
                                ("Longueur totale", features['url_length'], "px"),
                                ("Longueur du domaine", features['domain_length'], "px"),
                                ("Nombre de points", features['num_dots'], ""),
                                ("Sous-domaines", features['num_subdomains'], ""),
                                ("Tirets (-)", features['num_hyphens'], ""),
                                ("Underscores (_)", features['num_underscores'], ""),
                                ("Arobase (@)", features['num_at_signs'], ""),
                                ("Longueur du chemin", features['path_length'], "px"),
                            ]
                            for name, val, unit in feat_rows:
                                st.markdown(f"**{name}** : `{val}{unit}`")

                        with col_f2:
                            st.markdown("**<i class='fa-solid fa-shield'></i> Sécurité**", unsafe_allow_html=True)
                            def yesno(v): return "Oui" if v == 1 else "Non"
                            st.markdown(f"**HTTPS** : {yesno(features['has_https'])}")
                            st.markdown(f"**SSL valide** : {yesno(features['has_valid_ssl'])}")
                            st.markdown(f"**Port explicite** : {yesno(features['has_port'])}")
                            st.markdown(f"**'http' dans domaine** : {'Oui (Suspect)' if features['has_http_in_domain'] else 'Non'}")

                        with col_f3:
                            st.markdown("**<i class='fa-solid fa-globe'></i> Domaine & Réputation**", unsafe_allow_html=True)
                            age = features['domain_age_days']
                            age_display = f"{age} jours" if age != -1 else "Inconnu"
                            st.markdown(f"**Âge du domaine** : `{age_display}`")
                            st.markdown(f"**Pays hébergeur** : `{features['country']}`")
                            st.markdown(f"**Similarité marque** : `{features['brand_similarity']:.2f}/1.00`")



            except Exception as e:
                st.error(f"Erreur lors de la prédiction : {e}", icon="❌")
                st.info("Vérifiez que le modèle `models/final_model.joblib` est présent et valide.")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 2 — ANALYSE PAR LOT (CSV)
# ═══════════════════════════════════════════════════════════════════════════════
elif page == "Analyse par lot (CSV)":

    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h2><i class="fa-solid fa-folder-open"></i> Analyse par lot — fichier CSV d'URLs</h2>
        <p style="color: #64748b;">Uploadez un fichier CSV contenant une colonne <code>url</code>. Le système extraira automatiquement toutes les caractéristiques et retournera les prédictions pour chaque URL.</p>
    </div>
    """, unsafe_allow_html=True)

    BATCH_EXAMPLE_CSV = """url
https://www.google.com
http://paypal-secure-login.verify-account.com/login
https://github.com
http://amazon-verify.update-account.net:8080/secure
https://www.youtube.com
http://netflix-account-suspended.free-update.info/verify
"""

    tab_upload, tab_example = st.tabs(["Charger mon fichier CSV", "Tester avec un exemple"])

    # ── Onglet Upload ─────────────────────────────────────────────────────────
    with tab_upload:
        st.markdown("""
        **Format attendu :** Le fichier CSV doit contenir **au minimum** une colonne `url`.
        """)
        st.code("url\nhttps://example.com\nhttp://suspect-site.com/login", language=None)

        uploaded_file = st.file_uploader(
            "Glissez votre fichier CSV ici", type=["csv"], key="batch_csv"
        )

        if uploaded_file is not None:
            try:
                df_raw = pd.read_csv(uploaded_file)
            except Exception as e:
                st.error(f"Impossible de lire le fichier : {e}")
                st.stop()

            if "url" not in df_raw.columns:
                # Chercher une colonne URL-like
                url_col_candidates = [c for c in df_raw.columns if "url" in c.lower()]
                if url_col_candidates:
                    df_raw = df_raw.rename(columns={url_col_candidates[0]: "url"})
                    st.info(f"Colonne `{url_col_candidates[0]}` utilisée comme colonne URL.")
                else:
                    st.error(
                        f"Colonne `url` introuvable. Colonnes disponibles : `{', '.join(df_raw.columns.tolist())}`"
                    )
                    st.stop()

            st.success(f"Fichier chargé — **{len(df_raw)} URLs** détectées")
            st.dataframe(df_raw[["url"]].head(5), use_container_width=True)

            run_batch = st.button(
                f"Analyser les {len(df_raw)} URLs",
                type="primary", use_container_width=True, key="run_batch_upload"
            )

            if run_batch:
                _run_batch_analysis(df_raw, use_enriched)

    # ── Onglet Exemple ────────────────────────────────────────────────────────
    with tab_example:
        st.info("Cet onglet vous permet de tester l'application sur un fichier d'exemple sans préparer vos propres données.")
        df_example = pd.read_csv(io.StringIO(BATCH_EXAMPLE_CSV))
        st.dataframe(df_example, use_container_width=True)

        if st.button("Analyser le fichier d'exemple", type="primary", use_container_width=True, key="run_batch_example"):
            _run_batch_analysis(df_example, use_enriched)


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE 3 — À PROPOS
# ═══════════════════════════════════════════════════════════════════════════════
else:
    st.markdown("## <i class='fa-solid fa-circle-info'></i> À propos de PhishGuard", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs([
        "Qu'est-ce que le phishing ?",
        "Comment ça marche ?",
        "Performances du modèle",
        "Limites du modèle"
    ])

    with tab1:
        st.markdown("""
        <div class="about-card danger">
            <h4><i class="fa-solid fa-fish"></i> Le phishing (hameçonnage)</h4>
            <p>
                Le phishing est une technique de fraude où des cybercriminels créent de faux sites web
                qui imitent des sites légitimes (banques, boutiques, réseaux sociaux…) pour
                <b>voler vos informations personnelles</b> : mots de passe, données bancaires, identité.
            </p>
        </div>
        """, unsafe_allow_html=True)

        col_a, col_b = st.columns(2)
        with col_a:
            st.markdown("#### <i class='fa-solid fa-masks-theater'></i> Signes d'une URL suspecte", unsafe_allow_html=True)
            st.markdown("""
            - <i class='fa-solid fa-link'></i> URL avec fautes d'orthographe (`pay-pa1.com`)
            - <i class='fa-regular fa-calendar-days'></i> Domaine enregistré très récemment (< 30 jours)
            - <i class='fa-solid fa-lock-open'></i> Absence de HTTPS ou certificat invalide
            - <i class='fa-solid fa-tag'></i> Imitation d'une marque dans l'URL
            - <i class='fa-solid fa-keyboard'></i> Caractères spéciaux inhabituels (`@`, tirets multiples)
            - <i class='fa-solid fa-plug'></i> Port non-standard (`:8080`)
            - <i class='fa-solid fa-globe'></i> Trop de sous-domaines (`login.secure.paypal.fake.com`)
            """, unsafe_allow_html=True)
        with col_b:
            st.markdown("#### <i class='fa-solid fa-bomb'></i> Pourquoi c'est dangereux ?", unsafe_allow_html=True)
            st.markdown("""
            - <i class='fa-solid fa-key'></i> Vol de mots de passe et comptes bancaires
            - <i class='fa-solid fa-user-ninja'></i> Usurpation d'identité
            - <i class='fa-solid fa-money-bill-wave'></i> Pertes financières directes
            - <i class='fa-solid fa-bug'></i> Propagation de malwares
            - <i class='fa-solid fa-arrow-trend-up'></i> En 2024, **+1,8 million** de sites de phishing détectés par mois
            """, unsafe_allow_html=True)

        st.markdown("""
        <div class="about-card success">
            <h4><i class="fa-solid fa-shield-halved"></i> PhishGuard à la rescousse</h4>
            <p>
                Notre outil analyse automatiquement les caractéristiques structurelles d'une URL
                pour évaluer son niveau de risque — <b>sans avoir besoin de visiter le site</b>,
                et sans que vous ayez besoin de connaissances techniques.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with tab2:
        st.markdown("""
        <div class="about-card">
            <h4><i class="fa-solid fa-tree"></i> Algorithme : Random Forest Classifier</h4>
            <p>
                PhishGuard repose sur un Random Forest (100 arbres de décision) — 
                un algorithme d'apprentissage automatique robuste qui combine de multiples
                décisions pour produire une prédiction fiable et stable.
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("#### <i class='fa-solid fa-arrows-spin'></i> Pipeline automatique en 3 étapes", unsafe_allow_html=True)
        st.markdown("""
        1. **Extraction des features structurelles** (instantané)
           → Longueur, points, tirets, HTTPS, port, sous-domaines…

        2. **Analyse enrichie** (WHOIS, SSL, URLScan.io, difflib)
           → Âge du domaine, pays, certificat SSL, similarité avec des marques connues

        3. **Prédiction par le modèle** (Random Forest)
           → Résultat clair : *Risque élevé* ou *Risque faible*, avec probabilité
        """)

        st.markdown("#### <i class='fa-solid fa-list-check'></i> Les 15 features analysées", unsafe_allow_html=True)
        col_f1, col_f2 = st.columns(2)
        with col_f1:
            st.markdown("""
            **<i class='fa-solid fa-link'></i> Structure de l'URL (11 features)**
            - `url_length` — longueur totale de l'URL
            - `domain_length` — longueur du domaine
            - `num_dots` — nombre de points
            - `num_subdomains` — nombre de sous-domaines
            - `path_length` — longueur du chemin
            - `num_hyphens` — tirets (-)
            - `num_underscores` — underscores (_)
            - `num_at_signs` — arobase (@)
            - `has_https` — présence HTTPS
            - `has_port` — port explicite
            - `has_http_in_domain` — 'http' dans le domaine
            """, unsafe_allow_html=True)
        with col_f2:
            st.markdown("""
            **<i class='fa-solid fa-globe'></i> Réputation & Sécurité (4 features enrichies)**
            - `domain_age_days` — âge du domaine (WHOIS)
            - `country` — pays d'hébergement (URLScan.io)
            - `has_valid_ssl` — certificat SSL valide
            - `brand_similarity` — ressemblance à une marque

            **<i class='fa-solid fa-flask'></i> Features calculées (feature engineering)**
            - `url_to_domain_ratio` — ratio chemin/URL
            - `domain_age_category` — catégorie d'âge
            - `special_char_density` — densité de caractères spéciaux
            """, unsafe_allow_html=True)

    with tab3:
        st.markdown("#### <i class='fa-solid fa-chart-bar'></i> Métriques de performance du modèle", unsafe_allow_html=True)

        st.markdown("""
        <table class="metric-table">
            <tr>
                <th>Métrique</th>
                <th>Random Forest ✓</th>
                <th>Régression Logistique</th>
                <th>Gradient Boosting</th>
            </tr>
            <tr>
                <td>Recall (classe phishing)</td>
                <td class="best">92%</td>
                <td class="ok">84%</td>
                <td class="ok">90%</td>
            </tr>
            <tr>
                <td>F1-Score</td>
                <td class="best">85%</td>
                <td class="ok">79%</td>
                <td class="ok">83%</td>
            </tr>
            <tr>
                <td>Accuracy</td>
                <td class="best">89%</td>
                <td class="ok">82%</td>
                <td class="ok">87%</td>
            </tr>
            <tr>
                <td>PR-AUC</td>
                <td class="best">0.91</td>
                <td class="ok">0.83</td>
                <td class="ok">0.89</td>
            </tr>
        </table>
        """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        col_m1, col_m2, col_m3 = st.columns(3)
        col_m1.metric("Recall", "92%", help="Taux de détection des vrais phishings")
        col_m2.metric("F1-Score", "85%", help="Équilibre précision/rappel")
        col_m3.metric("Seuil optimal", "0.30", help="Optimisé pour maximiser le recall")

        st.info("""
        **Choix du seuil à 0.30 :** Le seuil de décision a été abaissé à 30% (vs 50% par défaut)
        pour maximiser le **recall** — il vaut mieux signaler un faux positif que manquer un vrai phishing.
        """)

    with tab4:
        st.markdown("""
        <div class="about-card warning">
            <h4><i class="fa-solid fa-triangle-exclamation"></i> Limitations importantes</h4>
            <p>
                Ce modèle est basé uniquement sur les <b>caractéristiques structurelles de l'URL</b>.
                Il ne visite pas le site, n'analyse pas son contenu visuel, et ne consulte pas
                de bases de données de réputation en temps réel.
            </p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        **Ce que le modèle peut manquer :**
        - Sites de phishing sur des domaines légitimes compromis
        - URLs raccourcies (bit.ly, tinyurl…) sans suivi de redirection
        - Sites très récents absents des bases WHOIS
        - Phishing via des sous-domaines de services cloud légitimes

        **Recommandations :**
        - Ne saisissez jamais de données bancaires sur un site que vous n'avez pas visité délibérément
        - Vérifiez l'URL dans votre navigateur, pas seulement le texte du lien
        - En cas de doute, accédez directement au site officiel via votre navigateur
        - Utilisez un gestionnaire de mots de passe (alerte automatique sur les faux sites)
        """)
