# Cadrage du Projet - Détection de Phishing par Machine Learning

## 1. Contexte et Problématique Métier

### A. Exploration et sélection des sources de données
Avant de retenir nos sources finales, nous avons exploré et comparé plusieurs APIs candidates pour s'assurer du respect des quotas gratuits et de la qualité des données :
* **OpenPhish** → *Écartée* : Quota gratuit trop limité et moins de labels manuellement vérifiés.
* **VirusTotal** → *Écartée* : Quota de 4 requêtes/minute insuffisant pour collecter 10 000 lignes dans le temps imparti, et la licence commerciale interdit l'usage académique sans accord préalable.
* **PhishTank** → ** Retenue** : Plateforme communautaire de Cisco offrant des labels vérifiés (sites légitimes vs phishing), accès gratuit sans limite stricte pour un usage académique.
* **URLScan.io** → ** Retenue** : API permettant d'enrichir les URLs avec des données réseau (taille du DOM, ASN, redirections réelles). Concernant la contrainte de quota URLScan.io (1 000 req/jour) : pour un dataset de 10 000 URLs, nous utiliserons en priorité l'endpoint `/search/` qui retourne les résultats d'URLs déjà scannées et indexées — sans consommer de quota. L'endpoint `/scan/` (quota consommé) ne sera utilisé qu'en dernier recours pour les URLs non encore indexées.

Pour constituer notre dataset d'entraînement, notre système combinera ces sources principales : **PhishTank** (pour identifier les URLs malveillantes), des listes publiques comme **Alexa Top 1M** (pour collecter les URLs légitimes), ainsi que **URLScan.io** et **WHOIS** pour extraire les caractéristiques techniques et réseau (features) de chaque lien.
*(Note : L'extraction via URLScan.io et WHOIS sera réalisée dans la phase secondaire d'enrichissement du pipeline de collecte).*

### B. Questions Métiers
Lors de notre phase d'idéation, nous avons formulé trois questions métiers principales :
1. *Comment identifier automatiquement si une URL appartient à une campagne de hameçonnage ?*
2. *Quelles sont les caractéristiques réseau et syntaxiques les plus discriminantes d'un site frauduleux ?*
3. *Comment concevoir un système automatisé capable de bloquer une URL malveillante avant le chargement de la page pour l'utilisateur ?*

**Problématique retenue :**
Nous avons choisi de nous concentrer sur la **Question 3**. Alors que la Question 1 est trop basique et la Question 2 purement analytique, la Question 3 est la seule qui intègre la notion de "protection proactive" et de "temps réel". Elle répond directement au besoin critique de cybersécurité moderne : empêcher l'utilisateur d'atteindre le site malveillant avant que les dommages ne se produisent.

### C. Variable cible
**Variable cible :** `is_phishing` (0 = site légitime, 1 = site de phishing). Elle est naturellement présente dans les données PhishTank — aucune labellisation manuelle n'est requise. Le déséquilibre est naturel (~10-15% de phishing) et non forcé artificiellement.

---

## 2. Objectifs Métiers Quantifiés

Pour répondre à cette problématique, notre système de détection doit atteindre les Key Performance Indicators (KPI) métiers suivants :

1. **Efficacité de détection :** Détecter et bloquer au moins **90%** des sites de phishing avant que l'utilisateur n'y accède.
2. **Expérience utilisateur :** Réduire le taux de fausses alertes (blocage de sites légitimes) à moins de **5%** pour ne pas frustrer les utilisateurs.
3. **Performance système :** Assurer un fonctionnement en temps réel avec un délai d'analyse technique **inférieur à 200 ms** par URL.

---

## 3. Traduction des Objectifs Métiers en Objectifs ML

Pour que le modèle de Machine Learning réponde aux exigences métiers, nous traduisons ces KPI en métriques d'évaluation techniques :

| Objectif Métier | Objectif Machine Learning | Métrique ML associée |
| :--- | :--- | :--- |
| **Détecter 90% des fraudes** | Maximiser l'identification de la classe minoritaire "Phishing" (Classe 1). | **Recall ≥ 0.90** |
| **Limiter les faux blocages (< 5%)**| Maintenir une proportion d'erreurs acceptable sur les prédictions positives. | **Precision ≥ 0.80** |
| **Performance globale** | Optimiser le compromis entre détecter la fraude et ne pas bloquer les sites sains. | **F1-Score ≥ 0.85** |
| **Gérer le déséquilibre (10-15%)**| Évaluer le modèle sur une métrique robuste au déséquilibre. | **PR-AUC ≥ 0.85** |

---

## 4. Analyse du Coût Asymétrique

Dans ce projet de cybersécurité, le coût des erreurs de prédiction n'est pas symétrique. Il est crucial d'analyser la matrice de confusion sous un angle purement "business" :

* **Faux Négatif (FN) :** Le modèle prédit que le site est "Légitime" (0) alors qu'il s'agit d'un "Phishing" (1).
  * *Conséquence métier :* Catastrophique. L'utilisateur visite le faux site, saisit ses identifiants bancaires et se fait pirater. Cela entraîne une fraude financière, des poursuites judiciaires et une perte totale de confiance.
  * **Coût financier = TRÈS ÉLEVÉ.**

* **Faux Positif (FP) :** Le modèle prédit "Phishing" (1) alors que c'est un site "Légitime" (0).
  * *Conséquence métier :* Léger désagrément. L'utilisateur voit un écran rouge "Site bloqué par sécurité", mais il a généralement la possibilité de cliquer sur "Continuer quand même".
  * **Coût financier = FAIBLE.**

**Chiffrage estimé de l'asymétrie :**
Selon l'[IBM Cost of a Data Breach Report 2024](https://www.ibm.com/reports/data-breach), le coût moyen d'une violation de données est de 4,88 millions USD. En ramenant à une victime individuelle (fraude bancaire + frais juridiques), on estime un coût de Faux Négatif à ~50 000 DH minimum. Le coût d'un Faux Positif reste nul (simple redirection).

| Type d'erreur     | Coût estimé                                      |
|-------------------|--------------------------------------------------|
| Faux Négatif (FN) | ~50 000 DH minimum                               |
| Faux Positif (FP) | ~0 DH                                            |
| **Ratio**         | **Un FN coûte infiniment plus cher qu'un FP**    |

**Conclusion de l'analyse et Seuil de Décision :**
Puisque le coût d'un Faux Négatif est immensément plus destructeur qu'un Faux Positif, **notre modèle doit absolument privilégier l'élimination des Faux Négatifs**. Nous acceptons de bloquer quelques sites légitimes par précaution, afin de garantir qu'aucun site de phishing ne passe entre les mailles du filet.

→ **Ajustement technique :** Le seuil de décision (threshold) sera abaissé à 0.3 (au lieu de 0.5 par défaut) pour forcer le modèle à déclencher une alerte plus facilement, maximisant ainsi le Recall au détriment de la Precision.

---

## 5. Choix et Justification des Métriques

En accord avec l'analyse du coût asymétrique et la nature de nos données (classe "Phishing" représentant seulement 10 à 15% du dataset), nous justifions nos choix de métriques d'évaluation :

### Métriques retenues :
* **Recall (Rappel) - *Métrique Principale* :** C'est la métrique reine de notre projet. Elle mesure notre capacité à ne rater aucun Faux Négatif. Maximiser le Recall répond directement à notre objectif de bloquer 90% des fraudes.
* **F1-Score - *Métrique Secondaire* :** Moyenne harmonique de la Précision et du Recall. Il nous assure que notre volonté absolue d'augmenter le Recall ne détruit pas complètement notre Précision (ce qui générerait trop de Faux Positifs).
* **PR-AUC (Precision-Recall Area Under Curve) :** Contrairement à la courbe ROC, la courbe PR est spécialement conçue pour évaluer les performances d'un modèle sur des classes fortement déséquilibrées.

### Métriques refusées :
* **Accuracy (Exactitude) :** Elle est **dangereuse et trompeuse** dans notre contexte. Puisque 85 à 90% des URLs sont légitimes, un modèle "idiot" qui prédirait *toujours* qu'un site est légitime obtiendrait 90% d'Accuracy, mais laisserait passer 100% des phishings. Elle est donc totalement inadaptée.
* **ROC-AUC :** Bien que populaire, la courbe ROC a tendance à donner des scores trop optimistes lorsque la classe négative (sites légitimes) est surreprésentée. Nous lui préférons catégoriquement la PR-AUC.

---

## 6. Conformité aux contraintes du sujet

| Contrainte | Valeur prévue | Statut |
|---|---|---|
| Type de tâche | Classification binaire supervisée | ✅ |
| Taille totale | ~10 000 lignes (8 500 légitimes + 1 500 phishing) | ✅ |
| Nombre de features | 25 features (13 URL + 8 URLScan + 4 WHOIS) | ✅ |
| Classe minoritaire | ~15% (naturel, non forcé) | ✅ |
| Types de variables | Numérique (`url_length`, `dom_size`...) + Catégoriel (`tld`, `ip_country`...) | ✅ |
