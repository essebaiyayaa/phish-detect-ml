"""
Script principal de collecte de données pour le projet de détection de phishing.

"""

import os
import requests
import json
import logging
from dotenv import load_dotenv

# Configuration du logging pour avoir des messages propres dans la console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    load_dotenv() # Chargement des variables d'environnement (ex: clés API) depuis le fichier .env
    logging.info("Démarrage du processus de collecte de données...")
    
    # TODO : Implémenter la collecte depuis l'API PhishTank
    # TODO : Intégrer l'extraction des features URL et URLScan.io

if __name__ == "__main__":
    main()
