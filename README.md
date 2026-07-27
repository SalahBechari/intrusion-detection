# Intrusion Detection System

Ce projet est une application web de détection d’intrusions réseau basée sur le Machine Learning.

L’objectif est de proposer une plateforme capable d’analyser plusieurs types de données réseau :

- une connexion saisie manuellement ;
- un fichier CSV contenant plusieurs connexions ;
- une capture réseau au format PCAP ou PCAPNG.

L’application utilise deux modèles de Machine Learning :

- un modèle entraîné avec le dataset NSL-KDD pour les prédictions individuelles et les fichiers CSV ;
- un modèle entraîné avec le dataset CICIDS2017 pour l’analyse des flux extraits depuis les captures réseau.

Le projet comprend également :

- une API FastAPI ;
- une interface web en HTML, CSS et JavaScript ;
- une analyse descriptive avec TShark ;
- une extraction des flux avec CICFlowMeter ;
- une classification `Normal / Attaque` ;
- une configuration Docker et Docker Compose.

## Objectif du projet

L’objectif principal est de construire une chaîne complète de détection d’intrusions réseau.

Le projet ne se limite pas à entraîner un modèle dans un notebook. Il permet de passer d’une donnée réseau réelle jusqu’à une prédiction affichée dans une interface web.

La chaîne principale de l’analyse PCAP est la suivante :

```text
Capture PCAP ou PCAPNG
        ↓
TShark
        ↓
Analyse descriptive
        ↓
CICFlowMeter
        ↓
Extraction des flux réseau
        ↓
Modèle CICIDS2017 Random Forest
        ↓
Classification Normal / Attaque
        ↓
Affichage des résultats dans l’interface
```

## Fonctionnalités

### Prédiction individuelle

L’utilisateur peut saisir les principales caractéristiques d’une connexion réseau et lancer une prédiction.

Le système retourne :

- la classe prédite ;
- la probabilité d’attaque ;
- le niveau de risque.

Les classes possibles sont :

```text
Normal
Attaque
```

Deux exemples sont disponibles dans l’interface :

- un exemple normal ;
- un exemple d’attaque.

### Analyse d’un fichier CSV

L’application permet d’importer un fichier CSV contenant les caractéristiques attendues par le modèle NSL-KDD.

Le système affiche :

- le nombre total de connexions ;
- le nombre de connexions normales ;
- le nombre d’attaques détectées ;
- le taux d’attaque ;
- les prédictions ligne par ligne ;
- les probabilités d’attaque ;
- les niveaux de risque.

Les résultats peuvent être recherchés dans un tableau puis exportés au format CSV.

### Analyse descriptive d’une capture réseau

L’application accepte les formats suivants :

```text
.pcap
.pcapng
```

L’analyse descriptive est réalisée avec TShark.

Elle fournit :

- le nom du fichier ;
- le nombre total de paquets ;
- le volume total du trafic ;
- les protocoles détectés ;
- les ports les plus utilisés ;
- les principales adresses IP sources ;
- les principales adresses IP destinations ;
- le nombre de paquets SYN ;
- le nombre de paquets ACK ;
- le nombre de paquets RST ;
- la répartition graphique des protocoles ;
- la répartition graphique des ports ;
- un résumé descriptif de sécurité.

### Analyse Machine Learning d’une capture réseau

La capture est également analysée avec CICFlowMeter.

CICFlowMeter transforme la capture PCAP en flux réseau contenant les caractéristiques nécessaires pour le modèle CICIDS2017.

Le modèle retourne :

- le nombre total de flux ;
- le nombre de flux normaux ;
- le nombre de flux classés comme attaques ;
- le pourcentage de flux suspects ;
- la probabilité maximale d’attaque ;
- la probabilité moyenne d’attaque ;
- le résultat global ;
- les flux ayant les probabilités les plus élevées.

Pour chaque flux affiché, l’application indique :

- l’adresse IP source ;
- le port source ;
- l’adresse IP destination ;
- le port destination ;
- le protocole ;
- la prédiction ;
- la probabilité d’attaque.

Un flux peut être classé comme normal tout en ayant une probabilité d’attaque supérieure à zéro. Cela signifie que le score n’est pas suffisamment élevé pour que le modèle le classe comme une attaque.

## Résumé descriptif de sécurité

Le résumé de sécurité de l’analyse PCAP affiche :

- le niveau d’attention ;
- le score d’attention ;
- le protocole dominant ;
- l’adresse IP source la plus active ;
- le port le plus utilisé ;
- le pourcentage de trafic identifié comme chiffré ;
- le pourcentage de trafic identifié comme non chiffré ;
- le nombre de paquets SYN ;
- le nombre de paquets ACK ;
- le nombre de paquets RST ;
- les indicateurs descriptifs détectés.

Le niveau d’attention peut être :

```text
Faible
Modéré
Élevé
```

Ce niveau est descriptif. Il ne correspond pas directement à une prédiction du modèle de Machine Learning.

## Différence entre les analyses

### Analyse NSL-KDD

Le modèle NSL-KDD est utilisé pour :

- les prédictions individuelles ;
- les fichiers CSV.

Il fonctionne à partir de 41 caractéristiques décrivant une connexion réseau.

Il fournit :

- une prédiction ;
- une probabilité d’attaque ;
- un niveau de risque.

### Analyse descriptive PCAP

L’analyse descriptive utilise TShark.

Elle fournit :

- des statistiques sur les paquets ;
- les protocoles ;
- les ports ;
- les adresses IP ;
- les indicateurs descriptifs ;
- les graphiques.

Cette analyse ne constitue pas à elle seule une classification Machine Learning.

### Analyse Machine Learning PCAP

L’analyse Machine Learning PCAP utilise :

- TShark pour convertir les fichiers PCAPNG en PCAP si nécessaire ;
- CICFlowMeter pour extraire les flux ;
- un modèle Random Forest entraîné avec CICIDS2017.

Elle fournit une classification :

```text
Normal
Attaque
```

Cette analyse est différente de l’analyse NSL-KDD, car elle utilise un modèle et des caractéristiques adaptés aux flux extraits depuis des captures réseau.

## Technologies utilisées

### Backend

- Python 3.12
- FastAPI
- Uvicorn
- Pandas
- NumPy
- Scikit-learn
- SciPy
- Joblib
- Pydantic
- Jinja2

### Frontend

- HTML
- CSS
- JavaScript
- Chart.js

### Machine Learning

- Random Forest
- NSL-KDD
- CICIDS2017
- Scikit-learn
- Joblib

### Analyse réseau

- Wireshark
- TShark
- CICFlowMeter
- jNetPcap
- Npcap
- PCAP
- PCAPNG

### Conteneurisation

- Docker
- Docker Compose

### Outils de développement

- Visual Studio Code
- PowerShell
- Jupyter Notebook
- Git
- GitHub

## Structure du projet

```text
intrusion-detection/
│
├── data/
│   ├── captures/
│   │   └── test_capture.pcapng
│   ├── cicids2017/
│   ├── flows/
│   ├── attack_sample.csv
│   ├── batch_connections.csv
│   ├── batch_connections_v2.csv
│   ├── examples.json
│   ├── KDDTest+.txt
│   ├── KDDTrain+.txt
│   ├── normal_sample.csv
│   └── sample_connection.csv
│
├── models/
│   ├── intrusion_detector.joblib
│   └── cicids_intrusion_detector.joblib
│
├── notebooks/
│   └── 01_data_exploration.ipynb
│
├── reports/
│   ├── final_metrics.json
│   └── cicids_metrics.json
│
├── src/
│   ├── __init__.py
│   ├── api.py
│   ├── data_preprocessing.py
│   ├── pcap_analyzer.py
│   ├── pcap_ml_analyzer.py
│   ├── predict.py
│   ├── predict_cicids_flow.py
│   ├── train_cicids_model.py
│   └── train_model.py
│
├── static/
│   ├── app.js
│   └── styles.css
│
├── templates/
│   └── index.html
│
├── .dockerignore
├── .gitignore
├── Dockerfile
├── docker-compose.yml
├── README.md
└── requirements.txt
```

Les dossiers volumineux comme `data/cicids2017` et `data/flows` sont ignorés par Git.

## Datasets utilisés

### NSL-KDD

Le premier modèle est entraîné avec le dataset NSL-KDD.

Les fichiers utilisés sont :

```text
data/KDDTrain+.txt
data/KDDTest+.txt
```

Le dataset contient 41 caractéristiques décrivant une connexion réseau.

Certaines caractéristiques sont numériques et d’autres sont catégorielles, notamment :

```text
protocol_type
service
flag
```

Toutes les classes différentes de `normal` sont regroupées dans la classe :

```text
Attaque
```

### CICIDS2017

Le deuxième modèle est entraîné avec le dataset CICIDS2017.

Les fichiers CSV utilisés se trouvent localement dans :

```text
data/cicids2017/extracted/MachineLearningCVE/
```

Le modèle effectue une classification binaire :

```text
Normal
Attaque
```

Le modèle final est enregistré dans :

```text
models/cicids_intrusion_detector.joblib
```

Les métriques sont enregistrées dans :

```text
reports/cicids_metrics.json
```

Le modèle CICIDS2017 est utilisé pour analyser les flux générés depuis les captures PCAP.

## Modèle NSL-KDD

L’entraînement du modèle NSL-KDD est défini dans :

```text
src/train_model.py
```

Le pipeline contient :

- un `ColumnTransformer` ;
- un `OneHotEncoder` pour les colonnes catégorielles ;
- un `RandomForestClassifier`.

La configuration principale est :

```text
Nombre d’arbres : 100
Random state : 42
Seuil de décision : 0.10
```

Le modèle final est enregistré dans :

```text
models/intrusion_detector.joblib
```

## Modèle CICIDS2017

L’entraînement du modèle CICIDS2017 est défini dans :

```text
src/train_cicids_model.py
```

Le modèle utilisé est un Random Forest.

Le modèle est chargé depuis :

```text
models/cicids_intrusion_detector.joblib
```

Le fichier contient notamment :

- le modèle entraîné ;
- la liste des caractéristiques ;
- les alias des colonnes ;
- les colonnes à exclure.

La prédiction sur un fichier de flux est réalisée dans :

```text
src/predict_cicids_flow.py
```

L’analyse complète d’une capture PCAP est réalisée dans :

```text
src/pcap_ml_analyzer.py
```

## Résultats du modèle CICIDS2017

Lors de l’entraînement réalisé sur le dataset CICIDS2017, les résultats obtenus étaient proches de :

```text
Accuracy : 99,81 %
Précision attaque : 99,65 %
Rappel attaque : 99,76 %
F1-score attaque : 99,70 %
```

Ces résultats doivent être interprétés avec prudence, car ils dépendent de la méthode utilisée pour séparer les données d’entraînement et de test.

Une bonne performance sur le dataset ne garantit pas une détection parfaite sur tous les trafics réseau réels.

## Analyse PCAP avec TShark

Le fichier principal de l’analyse descriptive est :

```text
src/pcap_analyzer.py
```

Les données extraites comprennent :

- le numéro du paquet ;
- la taille du paquet ;
- le protocole ;
- les adresses IP sources et destinations ;
- les ports TCP ;
- les ports UDP ;
- le drapeau TCP SYN ;
- le drapeau TCP ACK ;
- le drapeau TCP RST.

Les informations sont ensuite regroupées afin d’obtenir :

- les protocoles les plus utilisés ;
- les IP sources les plus actives ;
- les IP destinations les plus sollicitées ;
- les ports les plus utilisés ;
- le volume total de la capture.

Le champ TShark utilisé pour récupérer le protocole est :

```text
_ws.col.Protocol
```

## Analyse PCAP avec CICFlowMeter

Le fichier principal est :

```text
src/pcap_ml_analyzer.py
```

Son fonctionnement est le suivant :

1. vérification du format du fichier ;
2. conversion du PCAPNG en PCAP avec TShark si nécessaire ;
3. création d’un dossier temporaire ;
4. exécution de CICFlowMeter ;
5. génération d’un fichier CSV contenant les flux ;
6. préparation des caractéristiques ;
7. prédiction avec le modèle CICIDS2017 ;
8. génération du résumé ;
9. retour des résultats à l’API.

Les fichiers temporaires sont supprimés après l’analyse.

## Prérequis pour un lancement local sous Windows

Pour lancer le projet sans Docker, il faut installer :

- Python 3.12 ;
- Wireshark ;
- TShark ;
- Java 8 ;
- CICFlowMeter ;
- Npcap ;
- un navigateur web.

Les chemins par défaut utilisés sous Windows sont :

```text
C:\Program Files\Wireshark\tshark.exe
C:\Users\salah\Desktop\CICFlowMeter
C:\Windows\System32\Npcap
```

Ces chemins peuvent être remplacés avec des variables d’environnement.

## Variables d’environnement

L’application utilise plusieurs variables d’environnement pour fonctionner sous Windows et dans Docker :

```text
TSHARK_PATH
CICFLOWMETER_DIRECTORY
CICIDS_MODEL_PATH
JNETPCAP_DIRECTORY
NPCAP_DIRECTORY
```

Exemple sous Docker :

```text
TSHARK_PATH=/usr/bin/tshark
CICFLOWMETER_DIRECTORY=/opt/CICFlowMeter
CICIDS_MODEL_PATH=/app/models/cicids_intrusion_detector.joblib
JNETPCAP_DIRECTORY=/opt/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425
```

## Installation locale

Se placer dans le dossier du projet :

```powershell
cd C:\Users\salah\Desktop\intrusion-detection
```

Créer un environnement virtuel :

```powershell
python -m venv venv
```

Activer l’environnement virtuel :

```powershell
.\venv\Scripts\Activate.ps1
```

Installer les dépendances :

```powershell
pip install -r requirements.txt
```

Lancer l’application :

```powershell
python -m uvicorn src.api:app --reload
```

L’application est accessible à l’adresse :

```text
http://127.0.0.1:8000
```

La documentation Swagger est accessible à l’adresse :

```text
http://127.0.0.1:8000/docs
```

## Lancement avec Docker

Docker permet de lancer l’application avec ses principales dépendances dans un conteneur.

La configuration contient :

- Python 3.12 ;
- Java 8 ;
- TShark ;
- CICFlowMeter ;
- jNetPcap ;
- les dépendances Python ;
- les modèles Machine Learning ;
- l’API FastAPI ;
- l’interface web.

### Construire l’image

```powershell
docker compose build
```

Pour reconstruire complètement l’image sans cache :

```powershell
docker compose build --no-cache --progress=plain
```

### Démarrer l’application

```powershell
docker compose up -d
```

### Vérifier le conteneur

```powershell
docker compose ps
```

### Consulter les logs

```powershell
docker compose logs -f
```

### Arrêter le conteneur

```powershell
docker compose down
```

L’application est accessible à l’adresse :

```text
http://127.0.0.1:8000
```

## Fichiers Docker

### Dockerfile

Le `Dockerfile` :

- utilise Python 3.12 ;
- ajoute Java 8 ;
- installe TShark ;
- installe les bibliothèques réseau ;
- clone CICFlowMeter ;
- prépare jNetPcap ;
- compile CICFlowMeter ;
- installe les dépendances Python ;
- copie l’application ;
- lance Uvicorn.

Java 8 est utilisé car la version Gradle de CICFlowMeter n’est pas compatible avec Java 17.

### docker-compose.yml

Le fichier `docker-compose.yml` :

- construit l’image ;
- démarre le service FastAPI ;
- expose le port `8000` ;
- définit les variables d’environnement ;
- redémarre automatiquement le conteneur si nécessaire.

### .dockerignore

Le fichier `.dockerignore` évite d’envoyer dans l’image Docker des fichiers inutiles comme :

- l’environnement virtuel ;
- les caches Python ;
- les datasets volumineux ;
- les captures locales ;
- les fichiers temporaires ;
- les sauvegardes locales ;
- le dossier Git.

## Routes de l’API

### Accueil

```text
GET /
```

Affiche l’interface web.

### Vérification de l’API

```text
GET /health
```

Vérifie que l’API et le modèle sont disponibles.

### Exemple normal

```text
GET /examples/normal
```

### Exemple d’attaque

```text
GET /examples/attack
```

### Prédiction individuelle

```text
POST /predict
```

Reçoit les caractéristiques d’une connexion au format JSON.

### Analyse CSV

```text
POST /predict-csv
```

Reçoit un fichier CSV contenant les caractéristiques NSL-KDD.

### Analyse PCAP

```text
POST /analyze-pcap
```

Reçoit un fichier PCAP ou PCAPNG.

Cette route lance :

- l’analyse descriptive avec TShark ;
- l’analyse Machine Learning avec CICFlowMeter et CICIDS2017.

## Interface utilisateur

L’interface permet :

- de charger un exemple normal ;
- de charger un exemple d’attaque ;
- de saisir les caractéristiques d’une connexion ;
- d’importer un fichier CSV ;
- d’afficher les résultats CSV juste après la partie CSV ;
- d’importer une capture PCAP ou PCAPNG ;
- d’afficher les résultats PCAP après la partie PCAP ;
- de visualiser les statistiques ;
- de consulter les graphiques ;
- de consulter les flux les plus suspects ;
- de rechercher dans les prédictions ;
- d’exporter les résultats.

L’ordre principal de l’interface est :

```text
Prédiction individuelle
Analyse CSV
Résultats CSV
Analyse PCAP
Résultats PCAP
```

## Exportation des résultats

### Export CSV des prédictions NSL-KDD

Le fichier contient :

- le numéro de ligne ;
- la prédiction ;
- la probabilité d’attaque ;
- le pourcentage ;
- le niveau de risque.

### Export de l’analyse PCAP

Le fichier contient notamment :

- le nom de la capture ;
- le nombre total de paquets ;
- le volume total ;
- les protocoles ;
- les ports ;
- les IP sources ;
- les IP destinations ;
- le niveau d’attention ;
- les indicateurs descriptifs ;
- les résultats Machine Learning ;
- le nombre total de flux ;
- les flux normaux ;
- les flux suspects ;
- les probabilités ;
- les flux ayant les scores les plus élevés.

## Dépendances Python

Le fichier `requirements.txt` contient :

```text
fastapi==0.139.0
uvicorn==0.51.0
pandas==3.0.3
numpy==2.5.1
scikit-learn==1.9.0
scipy==1.18.0
joblib==1.5.3
pydantic==2.13.4
python-multipart==0.0.32
Jinja2==3.1.6
```

TShark, Java et CICFlowMeter ne sont pas installés avec `pip`.

Ils sont installés séparément en local ou directement dans l’image Docker.

## Commandes utiles

### Activer l’environnement virtuel

```powershell
.\venv\Scripts\Activate.ps1
```

### Installer les dépendances

```powershell
pip install -r requirements.txt
```

### Vérifier la syntaxe de l’API

```powershell
python -m py_compile src\api.py
```

### Vérifier l’analyseur PCAP descriptif

```powershell
python -m py_compile src\pcap_analyzer.py
```

### Vérifier l’analyseur PCAP Machine Learning

```powershell
python -m py_compile src\pcap_ml_analyzer.py
```

### Réentraîner le modèle NSL-KDD

```powershell
python -m src.train_model
```

### Réentraîner le modèle CICIDS2017

```powershell
python -m src.train_cicids_model
```

### Tester une prédiction CICIDS2017

```powershell
python src\predict_cicids_flow.py
```

### Lancer localement

```powershell
python -m uvicorn src.api:app --reload
```

### Construire avec Docker

```powershell
docker compose build
```

### Démarrer avec Docker

```powershell
docker compose up -d
```

### Voir les logs Docker

```powershell
docker compose logs -f
```

### Arrêter Docker

```powershell
docker compose down
```

## Git

Le projet utilise `.gitignore` afin de ne pas envoyer sur GitHub les fichiers inutiles ou volumineux.

Les éléments ignorés comprennent notamment :

- l’environnement virtuel ;
- les caches Python ;
- les datasets CICIDS2017 ;
- les fichiers de flux générés ;
- les résultats temporaires ;
- les fichiers de sauvegarde ;
- certaines captures locales.

Le modèle CICIDS2017 reste enregistré dans le projet :

```text
models/cicids_intrusion_detector.joblib
```

## Auteur

Projet réalisé par **Salah-Eddine Bechari**.

Étudiant en **Data Science and Cloud Computing**.