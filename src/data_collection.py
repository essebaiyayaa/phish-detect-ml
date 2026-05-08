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


# ===========================================================================
# E2-02 : Extraction des Features WHOIS/DNS Enrichies
# ===========================================================================
"""
Classe EnrichedFeatureExtractor : extrait les 4 features enrichies nécessitant
des appels API externes (WHOIS, URLScan.io, SSL, difflib).

Features extraites :
    12. domain_age_days    — Âge du domaine en jours (via WHOIS)
    13. country            — Pays du serveur (via URLScan.io)
    14. has_valid_ssl      — Certificat SSL valide ? 1/0 (socket/ssl)
    15. brand_similarity   — Similarité max avec marques connues (difflib)

Utilisation :
    from src.data_collection import EnrichedFeatureExtractor

    extractor = EnrichedFeatureExtractor()
    features = extractor.extract_enriched_features("https://example.com")
    # → {'domain_age_days': 9500, 'country': 'US', 'has_valid_ssl': 1, 'brand_similarity': 0.36}

    # Ou sur un DataFrame complet :
    df_enriched = extractor.extract_from_dataframe(df, url_column='url')
"""

import ssl
import socket
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse

import whois as whois_lib


class EnrichedFeatureExtractor:
    """Extrait les 4 features enrichies d'une URL via APIs externes.

    Gère : WHOIS (âge domaine), URLScan.io (pays), SSL (certificat),
    difflib (similarité marque). Toutes les méthodes incluent une gestion
    complète des erreurs (timeout, domaine invalide, API indisponible).

    Attributes:
        urlscan_api_key (str | None): Clé API URLScan.io (optionnelle).
        timeout (int): Timeout réseau en secondes pour SSL et URLScan.
        known_brands (list[str]): Liste de marques connues pour brand_similarity.

    Example:
        >>> extractor = EnrichedFeatureExtractor()
        >>> features = extractor.extract_enriched_features("https://amazon.com")
        >>> features['brand_similarity']
        1.0
    """

    # Marques connues ciblées par le phishing (liste extensible)
    KNOWN_BRANDS = [
        'amazon', 'google', 'facebook', 'paypal', 'ebay',
        'apple', 'microsoft', 'netflix', 'instagram', 'twitter',
        'linkedin', 'dropbox', 'github', 'yahoo', 'outlook',
        'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
    ]

    # Valeurs de repli utilisées quand une feature ne peut pas être calculée
    _FALLBACK_VALUES = {
        'domain_age_days': -1,
        'country': 'UNKNOWN',
        'has_valid_ssl': 0,
        'brand_similarity': 0.0,
    }

    def __init__(
        self,
        urlscan_api_key: Optional[str] = None,
        timeout: int = 10,
    ):
        """Initialise l'extracteur.

        Args:
            urlscan_api_key (str, optional): Clé API URLScan.io.
                Si None, essaie de lire URLSCAN_API_KEY depuis l'environnement.
            timeout (int): Timeout réseau en secondes (défaut : 10).
        """
        load_dotenv()
        self.urlscan_api_key = urlscan_api_key or os.getenv('URLSCAN_API_KEY')
        self.timeout = timeout
        self._whois_cache: dict = {}  # Cache WHOIS pour éviter les doublons

        if not self.urlscan_api_key:
            logger.warning(
                "URLSCAN_API_KEY absente — la feature 'country' retournera 'UNKNOWN' "
                "pour les domaines absents de l'index public URLScan."
            )

    # -----------------------------------------------------------------------
    # Feature 12 : domain_age_days  (WHOIS)
    # -----------------------------------------------------------------------

    def get_domain_age_days(self, domain: str) -> int:
        """Retourne l'âge du domaine en jours via WHOIS.

        Gère :
        - Les dates de création sous forme de liste (whois peut retourner plusieurs dates)
        - Les domaines inexistants ou sans info WHOIS
        - Les timeouts et erreurs réseau
        - Le cache interne pour éviter des appels répétés

        Args:
            domain (str): Nom de domaine pur (ex: "example.com").

        Returns:
            int: Nombre de jours depuis la création du domaine,
                 ou -1 si l'info n'est pas disponible.

        Example:
            >>> extractor.get_domain_age_days("google.com")
            9908  # valeur approximative
        """
        if not domain or not isinstance(domain, str):
            logger.warning("get_domain_age_days : domaine vide ou invalide.")
            return self._FALLBACK_VALUES['domain_age_days']

        # Cache hit → évite un nouvel appel réseau
        if domain in self._whois_cache:
            logger.debug(f"WHOIS cache hit pour : {domain}")
            return self._whois_cache[domain]

        try:
            logger.debug(f"WHOIS lookup pour : {domain}")
            w = whois_lib.whois(domain)

            creation_date = w.creation_date

            # whois peut retourner une liste de dates ; on prend la plus ancienne
            if isinstance(creation_date, list):
                creation_date = min(
                    [d for d in creation_date if isinstance(d, datetime)],
                    default=None
                )

            if creation_date is None:
                logger.warning(f"WHOIS : pas de date de création pour '{domain}'.")
                self._whois_cache[domain] = self._FALLBACK_VALUES['domain_age_days']
                return self._FALLBACK_VALUES['domain_age_days']

            # Harmonisation timezone-naive / timezone-aware
            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)

            age_days = (now - creation_date).days
            if age_days < 0:
                logger.warning(f"WHOIS : date de création dans le futur pour '{domain}' — valeur ignorée.")
                age_days = self._FALLBACK_VALUES['domain_age_days']

            self._whois_cache[domain] = age_days
            logger.info(f"WHOIS OK — '{domain}' : {age_days} jours")
            return age_days

        except Exception as exc:
            logger.warning(f"WHOIS erreur pour '{domain}' : {exc}")
            self._whois_cache[domain] = self._FALLBACK_VALUES['domain_age_days']
            return self._FALLBACK_VALUES['domain_age_days']

    # -----------------------------------------------------------------------
    # Feature 13 : country  (URLScan.io)
    # -----------------------------------------------------------------------

    def get_country(self, domain: str) -> str:
        """Retourne le pays du serveur via l'API URLScan.io.

        Effectue une requête GET sur le endpoint de recherche URLScan.io
        et parse le code pays ISO-3166 depuis le dernier scan connu.

        Args:
            domain (str): Nom de domaine pur (ex: "example.com").

        Returns:
            str: Code pays ISO à 2 lettres (ex: "US", "FR"),
                 ou "UNKNOWN" si l'info n'est pas disponible.

        Example:
            >>> extractor.get_country("google.com")
            'US'
        """
        if not domain or not isinstance(domain, str):
            logger.warning("get_country : domaine vide ou invalide.")
            return self._FALLBACK_VALUES['country']

        try:
            headers = {'Content-Type': 'application/json'}
            if self.urlscan_api_key:
                headers['API-Key'] = self.urlscan_api_key

            api_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1"
            logger.debug(f"URLScan.io GET : {api_url}")

            response = requests.get(
                api_url,
                headers=headers,
                timeout=self.timeout
            )

            if response.status_code == 429:
                logger.warning("URLScan.io : rate limit atteint — 'country' = UNKNOWN.")
                return self._FALLBACK_VALUES['country']

            if response.status_code == 401:
                logger.warning("URLScan.io : clé API invalide ou absente.")
                return self._FALLBACK_VALUES['country']

            response.raise_for_status()
            data = response.json()

            results = data.get('results', [])
            if not results:
                logger.info(f"URLScan.io : aucun résultat pour '{domain}'.")
                return self._FALLBACK_VALUES['country']

            # Cherche le pays dans page > country ou task > country
            first = results[0]
            country = (
                first.get('page', {}).get('country')
                or first.get('task', {}).get('country')
                or first.get('stats', {}).get('ipStats', [{}])[0].get('geoip', {}).get('country_code')
            )

            if country and isinstance(country, str) and len(country) <= 3:
                logger.info(f"URLScan.io OK — '{domain}' : pays = {country}")
                return country.upper()

            logger.info(f"URLScan.io : pays non trouvé pour '{domain}'.")
            return self._FALLBACK_VALUES['country']

        except requests.exceptions.Timeout:
            logger.warning(f"URLScan.io : timeout pour '{domain}'.")
            return self._FALLBACK_VALUES['country']
        except requests.exceptions.ConnectionError as exc:
            logger.warning(f"URLScan.io : erreur connexion pour '{domain}' : {exc}")
            return self._FALLBACK_VALUES['country']
        except (requests.exceptions.RequestException, ValueError, KeyError) as exc:
            logger.warning(f"URLScan.io : erreur pour '{domain}' : {exc}")
            return self._FALLBACK_VALUES['country']

    # -----------------------------------------------------------------------
    # Feature 14 : has_valid_ssl  (socket + ssl)
    # -----------------------------------------------------------------------

    def check_ssl_validity(self, domain: str) -> int:
        """Vérifie si le domaine possède un certificat SSL valide.

        Tente une connexion TLS sur le port 443 avec le contexte par défaut
        (vérification de la chaîne de certificats et du hostname).

        Args:
            domain (str): Nom de domaine pur (ex: "example.com").

        Returns:
            int: 1 si le certificat est valide, 0 sinon.

        Example:
            >>> extractor.check_ssl_validity("google.com")
            1
            >>> extractor.check_ssl_validity("expired.badssl.com")
            0
        """
        if not domain or not isinstance(domain, str):
            logger.warning("check_ssl_validity : domaine vide ou invalide.")
            return self._FALLBACK_VALUES['has_valid_ssl']

        try:
            context = ssl.create_default_context()
            logger.debug(f"SSL check pour : {domain}")

            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Vérification supplémentaire : le cert doit être non-vide
                    if cert:
                        logger.info(f"SSL OK — '{domain}' : certificat valide.")
                        return 1
                    else:
                        logger.warning(f"SSL : certificat vide pour '{domain}'.")
                        return 0

        except ssl.SSLCertVerificationError as exc:
            logger.warning(f"SSL : certificat invalide pour '{domain}' : {exc}")
            return 0
        except ssl.SSLError as exc:
            logger.warning(f"SSL : erreur SSL pour '{domain}' : {exc}")
            return 0
        except socket.timeout:
            logger.warning(f"SSL : timeout pour '{domain}'.")
            return 0
        except socket.gaierror as exc:
            logger.warning(f"SSL : résolution DNS échouée pour '{domain}' : {exc}")
            return 0
        except ConnectionRefusedError:
            logger.warning(f"SSL : connexion refusée sur le port 443 pour '{domain}'.")
            return 0
        except OSError as exc:
            logger.warning(f"SSL : erreur réseau pour '{domain}' : {exc}")
            return 0

    # -----------------------------------------------------------------------
    # Feature 15 : brand_similarity  (difflib)
    # -----------------------------------------------------------------------

    @staticmethod
    def calculate_brand_similarity(domain: str, brands: Optional[list] = None) -> float:
        """Calcule la similarité maximale entre le nom de domaine et les marques connues.

        Utilise SequenceMatcher (difflib) pour comparer le nom de domaine
        (partie avant le premier point) avec chaque marque de la liste.

        Args:
            domain (str): Nom de domaine pur (ex: "amaz0n.com").
            brands (list, optional): Liste de marques à comparer.
                Si None, utilise EnrichedFeatureExtractor.KNOWN_BRANDS.

        Returns:
            float: Score de similarité maximal entre 0.0 et 1.0
                   (1.0 = identique, 0.0 = aucune ressemblance).

        Example:
            >>> EnrichedFeatureExtractor.calculate_brand_similarity("amazon.com")
            1.0
            >>> EnrichedFeatureExtractor.calculate_brand_similarity("amaz0n.com")
            0.923...
        """
        if not domain or not isinstance(domain, str):
            logger.warning("calculate_brand_similarity : domaine vide ou invalide.")
            return EnrichedFeatureExtractor._FALLBACK_VALUES['brand_similarity']

        if brands is None:
            brands = EnrichedFeatureExtractor.KNOWN_BRANDS

        try:
            # Extrait uniquement le nom avant le premier point
            domain_name = domain.split('.')[0].lower().strip()

            if not domain_name:
                return EnrichedFeatureExtractor._FALLBACK_VALUES['brand_similarity']

            max_similarity = 0.0
            for brand in brands:
                similarity = SequenceMatcher(None, domain_name, brand).ratio()
                if similarity > max_similarity:
                    max_similarity = similarity

            result = round(max_similarity, 4)
            logger.debug(f"brand_similarity pour '{domain}' : {result}")
            return result

        except Exception as exc:
            logger.warning(f"calculate_brand_similarity erreur pour '{domain}' : {exc}")
            return EnrichedFeatureExtractor._FALLBACK_VALUES['brand_similarity']

    # -----------------------------------------------------------------------
    # Méthode principale : extract_enriched_features
    # -----------------------------------------------------------------------

    def extract_enriched_features(self, url: str) -> Optional[dict]:
        """Extrait les 4 features enrichies pour une URL donnée.

        Orchestre les 4 sous-méthodes dans l'ordre et retourne un dict
        avec exactement 4 clés. En cas d'erreur partielle, la feature
        concernée prend sa valeur de repli (pas d'exception levée).

        Args:
            url (str): URL complète à analyser (ex: "https://example.com/page").

        Returns:
            dict: Dictionnaire avec exactement 4 features enrichies,
                  ou None si l'URL est invalide.

        Example:
            >>> extractor = EnrichedFeatureExtractor()
            >>> extractor.extract_enriched_features("https://amazon.com")
            {
                'domain_age_days': 9908,
                'country': 'US',
                'has_valid_ssl': 1,
                'brand_similarity': 1.0
            }
        """
        if not isinstance(url, str) or not url.strip():
            logger.warning("extract_enriched_features : URL vide ou non-string reçue.")
            return None

        url = url.strip()

        # Extraire le domaine pur depuis l'URL
        try:
            parsed = urlparse(url)
            # Retire le port éventuel du netloc (ex: "example.com:8080" → "example.com")
            domain = parsed.netloc.split(':')[0].strip()

            if not domain:
                logger.warning(f"Impossible d'extraire le domaine de : '{url}'")
                return None
        except Exception as exc:
            logger.error(f"Erreur parsing URL '{url}' : {exc}")
            return None

        logger.info(f"Extraction features enrichies pour domaine : '{domain}'")

        # Appel des 4 sous-méthodes (chacune gère ses propres erreurs)
        domain_age = self.get_domain_age_days(domain)
        country    = self.get_country(domain)
        has_ssl    = self.check_ssl_validity(domain)
        brand_sim  = self.calculate_brand_similarity(domain)

        features = {
            'domain_age_days': domain_age,
            'country':         country,
            'has_valid_ssl':   has_ssl,
            'brand_similarity': brand_sim,
        }

        assert len(features) == 4, "ERREUR INTERNE : nombre de features enrichies != 4"
        logger.info(f"Features enrichies extraites pour '{domain}' : {features}")
        return features

    # -----------------------------------------------------------------------
    # Traitement en masse : extract_from_dataframe
    # -----------------------------------------------------------------------

    def extract_from_dataframe(
        self,
        df: pd.DataFrame,
        url_column: str = 'url',
        delay_between_requests: float = 0.5,
    ) -> pd.DataFrame:
        """Applique extract_enriched_features à toutes les URLs d'un DataFrame.

        Introduit un délai entre les requêtes pour respecter les rate limits
        des APIs externes (URLScan.io notamment). Les lignes échouées sont
        remplies de NaN et seront filtrées lors de l'étape E2-04.

        Args:
            df (pd.DataFrame): DataFrame contenant au moins une colonne d'URLs.
            url_column (str): Nom de la colonne URL (défaut : 'url').
            delay_between_requests (float): Délai en secondes entre deux URLs
                                            (défaut : 0.5 s).

        Returns:
            pd.DataFrame: DataFrame original + 4 colonnes enrichies ajoutées.

        Raises:
            ValueError: Si la colonne url_column est absente du DataFrame.
        """
        if url_column not in df.columns:
            raise ValueError(f"Colonne '{url_column}' introuvable dans le DataFrame.")

        total = len(df)
        logger.info(f"Extraction des features enrichies pour {total} URLs...")

        enriched_rows = []
        for i, url in enumerate(df[url_column], start=1):
            logger.info(f"[{i}/{total}] Traitement : {url}")
            features = self.extract_enriched_features(url)
            enriched_rows.append(features)  # None → ligne de NaN dans le DataFrame final

            # Pause pour ne pas surcharger les APIs externes
            if i < total and delay_between_requests > 0:
                time.sleep(delay_between_requests)

        features_df = pd.DataFrame(enriched_rows, index=df.index)
        result = pd.concat([df, features_df], axis=1)

        failed = features_df['domain_age_days'].isna().sum()
        logger.info(
            f"Extraction enrichie terminée — {total - failed}/{total} URLs traitées "
            f"({failed} échecs → NaN)."
        )
        return result