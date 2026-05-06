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


if __name__ == "__main__":
    main()