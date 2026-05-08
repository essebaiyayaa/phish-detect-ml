"""
Script de collecte de données brutes — Projet Détection de Phishing.

"""

import os
import time
import json
import logging
import argparse
import gzip
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("collecte.log"),
        logging.StreamHandler()
    ]
)



class PhishTankCollector:
    """
    Classe responsable de la collecte des URLs de phishing depuis PhishTank.

    Gère l'authentification, le téléchargement du dataset brut,
    le rate limiting, les erreurs réseau et la sauvegarde JSON.
    """

    def __init__(self):
        """Initialise le collecteur avec la clé API depuis le fichier .env."""
        load_dotenv()
        self.api_key = os.getenv('PHISHTANK_API_KEY')

        if self.api_key:
            self.url = f"https://data.phishtank.com/data/{self.api_key}/online-valid.json.gz"
            logging.info("PhishTank : clé API trouvée — utilisation de l'URL authentifiée (.gz).")
        else:
            self.url = "https://data.phishtank.com/data/online-valid.json.gz"
            logging.warning("PHISHTANK_API_KEY absente — utilisation de l'URL publique anonyme (.gz).")

        self.headers = {
            'User-Agent': 'phishtank-student-project/1.0'
        }

    def _fetch_with_retry(self, url: str, max_retries: int = 3) -> Optional[requests.Response]:
        delays = [1, 2, 4]  

        for attempt in range(max_retries):
            try:
                logging.info(f"Tentative {attempt + 1}/{max_retries} → GET {url}")

                response = requests.get(url, headers=self.headers, timeout=60)

                if response.status_code >= 500:
                    logging.warning(f"Erreur serveur {response.status_code} — retry dans {delays[attempt]}s...")
                    time.sleep(delays[attempt])
                    continue

                response.raise_for_status()
                logging.info(f"Requête réussie — statut HTTP : {response.status_code}")
                return response

            except requests.exceptions.ConnectionError as e:
                logging.warning(f"Erreur de connexion (tentative {attempt + 1}) : {e}")
            except requests.exceptions.Timeout as e:
                logging.warning(f"Timeout (tentative {attempt + 1}) : {e}")
            except requests.exceptions.RequestException as e:
                logging.warning(f"Erreur requête (tentative {attempt + 1}) : {e}")

            if attempt < max_retries - 1:
                logging.info(f"Nouvelle tentative dans {delays[attempt]}s...")
                time.sleep(delays[attempt])

        logging.error(f"Toutes les tentatives ont échoué pour : {url}")
        return None

    def fetch_raw_data(self, limit: int = None) -> Optional[list]:
        """Télécharge le dataset brut depuis PhishTank.

        Récupère toutes les URLs de phishing actives et vérifiées
        par la communauté PhishTank (Cisco Talos).
        Note : L'API PhishTank fournit le dataset complet en un seul fichier JSON,
        la pagination classique n'est donc pas requise pour cette source.

        Args:
            limit (int, optional): Nombre max d'URLs à retourner.
                                   None = toutes les URLs disponibles.

        Returns:
            Optional[list]: Liste de dicts phishing ou None si erreur.
        """
        logging.info("Démarrage du téléchargement depuis PhishTank...")

        response = self._fetch_with_retry(self.url)

        if response is None:
            logging.error("Échec du téléchargement PhishTank après tous les retries.")
            return None

        try:
            decompressed_content = gzip.decompress(response.content)
            data = json.loads(decompressed_content)
            logging.info(f"Téléchargement réussi : {len(data)} URLs récupérées de PhishTank.")

            if limit is not None:
                data = data[:limit]
                logging.info(f"Limite appliquée : {len(data)} URLs conservées.")

            return data

        except ValueError as e:
            logging.error(f"Erreur de parsing : contenu non JSON valide : {e}")
            return None

    def save_raw_json(self, data: list, filepath: str = "data/raw/phishtank_raw.json") -> bool:
        """Sauvegarde les données brutes au format JSON dans data/raw/.

        Args:
            data (list): Données à sauvegarder.
            filepath (str): Chemin du fichier de sortie.

        Returns:
            bool: True si sauvegarde réussie, False sinon.
        """
        if not data:
            logging.warning("Aucune donnée à sauvegarder.")
            return False

        try:
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)

            logging.info(f"Données brutes sauvegardées dans : {filepath} ({len(data)} entrées)")
            return True

        except IOError as e:
            logging.error(f"Erreur d'écriture du fichier JSON : {e}")
            return False



def main():
    """Orchestre la collecte brute des données PhishTank."""

    parser = argparse.ArgumentParser(
        description='Collecte brute PhishTank — Phase 1 Étudiant 1'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=None,
        help='Nombre max d\'URLs à conserver. Ex: --limit 100 pour tester, omettre pour tout télécharger.'
    )
    args = parser.parse_args()

    logging.info("=== Lancement du pipeline de collecte brute (Phase 1 — Étudiant 1) ===")

    collector = PhishTankCollector()
    raw_path = Path("data/raw/phishtank_raw.json")
    
    logging.info("PhishTank fournit un dump complet — pagination non requise pour cette source.")

    if raw_path.exists():
        logging.info("Fichier déjà présent — chargement local pour éviter de re-requêter.")
        if args.limit is not None:
            logging.warning("Fichier en cache trouvé — l'argument --limit est ignoré.")
        with open(raw_path, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
    else:
        raw_data = collector.fetch_raw_data(limit=args.limit)
        
        if not raw_data:
            logging.error("Échec critique de la collecte. Pipeline arrêté.")
            return

        success = collector.save_raw_json(raw_data, filepath=str(raw_path))
        if not success:
            logging.error("Échec de la sauvegarde.")
            return

    logging.info("=== Collecte terminée. Fichier data/raw/phishtank_raw.json prêt. ===")


# ===========================================================================
# Extraction des Features URL Simples
# ===========================================================================
"""
Classe URLFeatureExtractor : extrait les 11 features statiques directement
depuis l'URL (sans appel API externe).

Features extraites :
    1.  url_length          — Nombre total de caractères de l'URL
    2.  domain_length       — Nombre de caractères du domaine (netloc)
    3.  num_dots            — Nombre de points dans l'URL complète
    4.  num_subdomains      — Nombre de sous-domaines (nombre de points dans netloc)
    5.  num_hyphens         — Nombre de tirets (-) dans l'URL
    6.  num_underscores     — Nombre de underscores (_) dans l'URL
    7.  num_at_signs        — Nombre de symboles @ dans l'URL
    8.  has_port            — 1 si un port explicite est présent dans le netloc
    9.  has_https           — 1 si l'URL commence par https
    10. has_http_in_domain  — 1 si la chaîne "http" apparaît dans le domaine
    11. path_length         — Longueur du chemin (path) après le domaine

Utilisation :
    from src.data_collection import URLFeatureExtractor

    features = URLFeatureExtractor.extract_simple_features("https://example.com/page")
    # → dict avec 11 clés

    # Ou sur un DataFrame complet :
    df_features = URLFeatureExtractor.extract_from_dataframe(df, url_column='url')
"""

import re
from urllib.parse import urlparse
from typing import Optional

import pandas as pd


logger = logging.getLogger(__name__)


class URLFeatureExtractor:
    """Extrait les 11 features simples d'une URL.

    Toutes les méthodes sont statiques : pas besoin d'instancier la classe.

    Example:
        >>> feats = URLFeatureExtractor.extract_simple_features("https://google.com")
        >>> feats['has_https']
        1
    """

    # Regex pour détecter un port dans le netloc (ex: "example.com:8080")
    _PORT_PATTERN = re.compile(r':\d+$')

    @staticmethod
    def _safe_parse(url: str):
        """Parse l'URL de façon sécurisée et retourne l'objet ParseResult ou None."""
        try:
            parsed = urlparse(url)
            # urlparse ne lève pas d'exception sur les URLs invalides,
            # on vérifie a minima que le scheme existe.
            if not parsed.scheme:
                logger.warning(f"URL sans scheme ignorée : '{url}'")
                return None
            return parsed
        except Exception as exc:
            logger.error(f"Impossible de parser l'URL '{url}' : {exc}")
            return None

    @classmethod
    def extract_simple_features(cls, url: str) -> Optional[dict]:
        """Extrait les 11 features simples depuis une URL.

        Args:
            url (str): URL complète à analyser.

        Returns:
            dict: Dictionnaire de 11 features, ou None si l'URL est invalide.

        Example:
            >>> URLFeatureExtractor.extract_simple_features(
            ...     "https://amazon-verify.phishing.com/login?session=abc123"
            ... )
            {
                'url_length': 57, 'domain_length': 30, 'num_dots': 4,
                'num_subdomains': 1, 'num_hyphens': 1, 'num_underscores': 0,
                'num_at_signs': 0, 'has_port': 0, 'has_https': 1,
                'has_http_in_domain': 0, 'path_length': 19
            }
        """
        if not isinstance(url, str) or not url.strip():
            logger.warning("URL vide ou non-string reçue.")
            return None

        url = url.strip()
        parsed = cls._safe_parse(url)
        if parsed is None:
            return None

        try:
            netloc = parsed.netloc  # ex: "sub.example.com:8080"

            # --- Feature 8 : présence d'un port explicite ---
            # On retire le port du netloc avant de calculer domain_length
            domain_clean = cls._PORT_PATTERN.sub('', netloc)  # "example.com" sans ":8080"

            # --- Feature 4 : num_subdomains ---
            # Nombre de points dans le domaine pur = nombre de sous-domaines
            # "a.b.example.com" → 3 points → 2 sous-domaines (a, b)
            # "example.com"     → 1 point  → 0 sous-domaine
            # On soustrait 1 car le dernier point sépare SLD et TLD
            dots_in_domain = domain_clean.count('.')
            num_subdomains = max(0, dots_in_domain - 1)

            features = {
                # 1. Longueur totale de l'URL
                'url_length': len(url),

                # 2. Longueur du domaine (sans port)
                'domain_length': len(domain_clean),

                # 3. Nombre de points dans toute l'URL
                'num_dots': url.count('.'),

                # 4. Nombre de sous-domaines
                'num_subdomains': num_subdomains,

                # 5. Nombre de tirets
                'num_hyphens': url.count('-'),

                # 6. Nombre d'underscores
                'num_underscores': url.count('_'),

                # 7. Nombre de symboles @  (tromperie courante dans les URLs de phishing)
                'num_at_signs': url.count('@'),

                # 8. Port explicite dans le netloc ? (ex: ":8080")
                'has_port': 1 if cls._PORT_PATTERN.search(netloc) else 0,

                # 9. Protocole HTTPS ?
                'has_https': 1 if url.lower().startswith('https') else 0,

                # 10. La chaîne "http" apparaît-elle dans le DOMAINE ? (signe de tromperie)
                'has_http_in_domain': 1 if 'http' in domain_clean.lower() else 0,

                # 11. Longueur du chemin après le domaine
                'path_length': len(parsed.path),
            }

            assert len(features) == 11, "ERREUR INTERNE : nombre de features != 11"
            return features

        except Exception as exc:
            logger.error(f"Erreur lors de l'extraction des features de '{url}' : {exc}")
            return None

    @classmethod
    def extract_from_dataframe(
        cls,
        df: pd.DataFrame,
        url_column: str = 'url',
    ) -> pd.DataFrame:
        """Applique extract_simple_features à toutes les URLs d'un DataFrame.

        Les lignes dont l'extraction échoue sont remplies de NaN (elles
        seront ensuite supprimées lors du nettoyage E2-04).

        Args:
            df          (pd.DataFrame): DataFrame contenant au moins une colonne d'URLs.
            url_column  (str):          Nom de la colonne URL (défaut : 'url').

        Returns:
            pd.DataFrame: DataFrame original + 11 colonnes de features ajoutées.
        """
        if url_column not in df.columns:
            raise ValueError(f"Colonne '{url_column}' introuvable dans le DataFrame.")

        logger.info(f"Extraction des features pour {len(df)} URLs...")

        features_list = df[url_column].apply(cls.extract_simple_features)

        # Convertir la série de dicts en DataFrame (None → ligne de NaN)
        features_df = pd.DataFrame(features_list.tolist(), index=df.index)

        result = pd.concat([df, features_df], axis=1)

        total = len(result)
        failed = result['url_length'].isna().sum()
        logger.info(
            f"Extraction terminée — {total - failed}/{total} URLs traitées avec succès "
            f"({failed} échecs → NaN)."
        )
        return result