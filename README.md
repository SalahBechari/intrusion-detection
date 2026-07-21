# Intrusion Detection System

Application web de détection d’intrusions réseau basée sur le dataset NSL-KDD et sur l’analyse descriptive de captures Wireshark.

Le projet combine :

- un modèle de machine learning pour classifier des connexions réseau ;
- une API FastAPI ;
- une interface web en HTML, CSS et JavaScript ;
- l’analyse de fichiers CSV ;
- l’analyse descriptive de fichiers PCAP et PCAPNG avec TShark ;
- l’export des résultats au format CSV ;
- un système de résumé descriptif de sécurité.

## Fonctionnalités

### Prédiction individuelle

L’utilisateur peut saisir les principales caractéristiques d’une connexion réseau puis lancer une prédiction.

Le système retourne :

- la classe prédite : `Normal` ou `Attaque` ;
- la probabilité d’attaque ;
- le niveau de risque.

Deux exemples peuvent être chargés automatiquement :

- un exemple normal ;
- un exemple d’attaque.

### Analyse d’un fichier CSV

L’application permet d’importer un fichier CSV contenant les 41 caractéristiques attendues par le modèle NSL-KDD.

Le système affiche :

- le nombre total de connexions ;
- le nombre de connexions normales ;
- le nombre d’attaques détectées ;
- le taux d’attaque ;
- les prédictions ligne par ligne ;
- les probabilités d’attaque ;
- les niveaux de risque.

Les résultats peuvent être exportés au format CSV.

### Analyse d’une capture Wireshark

L’application accepte les formats suivants :

- `.pcap`
- `.pcapng`

L’analyse est réalisée avec TShark.

Elle fournit :

- le nom du fichier importé ;
- le nombre total de paquets ;
- le volume total du trafic ;
- les protocoles détectés ;
- les ports les plus utilisés ;
- les principales adresses IP sources ;
- les principales adresses IP destinations ;
- la répartition graphique des protocoles ;
- la répartition graphique des ports ;
- un résumé descriptif de sécurité.

### Résumé descriptif de sécurité

Le résumé PCAP contient :

- le niveau d’attention ;
- le score d’attention ;
- le protocole dominant ;
- l’adresse IP source la plus active ;
- le port le plus utilisé ;
- le pourcentage de trafic identifié comme chiffré ;
- le volume de trafic identifié comme non chiffré ;
- le nombre de paquets SYN ;
- le nombre de paquets ACK ;
- le nombre de paquets RST ;
- les indicateurs descriptifs détectés ;
- un avertissement expliquant la nature descriptive de l’analyse.

Le niveau d’attention peut être :

- faible ;
- modéré ;
- élevé.

Ce niveau est descriptif. Il ne constitue pas une prédiction du modèle NSL-KDD.

## Technologies utilisées

### Backend

- Python
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

### Analyse réseau

- Wireshark
- TShark
- PCAP
- PCAPNG

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
│   └── intrusion_detector.joblib
│
├── notebooks/
│   └── 01_data_exploration.ipynb
│
├── reports/
│   └── final_metrics.json
│
├── src/
│   ├── __init__.py
│   ├── api.py
│   ├── data_preprocessing.py
│   ├── pcap_analyzer.py
│   ├── predict.py
│   └── train_model.py
│
├── static/
│   ├── app.js
│   └── styles.css
│
├── templates/
│   └── index.html
│
├── .gitignore
├── README.md
└── requirements.txt
```

## Prérequis

Avant de lancer le projet, il faut installer :

- Python 3.12 ;
- Wireshark ;
- TShark ;
- un navigateur web.

Le chemin actuellement utilisé pour TShark est :

```text
C:\Program Files\Wireshark\tshark.exe
```

Ce chemin est défini dans :

```text
src/pcap_analyzer.py
```

## Installation

Ouvrir PowerShell puis se placer dans le dossier du projet :

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

## Lancement de l’application

Depuis la racine du projet, lancer :

```powershell
uvicorn src.api:app --reload
```

L’application est accessible à l’adresse :

```text
http://127.0.0.1:8000
```

La documentation Swagger est accessible à l’adresse :

```text
http://127.0.0.1:8000/docs
```

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

Vérifie que le modèle est bien chargé.

### Chargement d’un exemple normal

```text
GET /examples/normal
```

### Chargement d’un exemple d’attaque

```text
GET /examples/attack
```

### Prédiction individuelle

```text
POST /predict
```

Reçoit les caractéristiques d’une connexion réseau au format JSON.

### Analyse d’un fichier CSV

```text
POST /predict-csv
```

Reçoit un fichier CSV contenant les caractéristiques NSL-KDD.

### Analyse d’une capture Wireshark

```text
POST /analyze-pcap
```

Reçoit un fichier PCAP ou PCAPNG.

## Dataset NSL-KDD

Le modèle est entraîné à partir du dataset NSL-KDD.

Les fichiers utilisés sont :

```text
data/KDDTrain+.txt
data/KDDTest+.txt
```

Le dataset contient 41 caractéristiques décrivant une connexion réseau.

Les fichiers contiennent également :

- la classe d’origine ;
- le niveau de difficulté.

Certaines caractéristiques sont numériques, tandis que d’autres sont catégorielles, notamment :

- `protocol_type`
- `service`
- `flag`

Le modèle effectue une classification binaire :

- `Normal`
- `Attaque`

Toutes les classes différentes de `normal` sont regroupées dans la classe `Attaque`.

## Prétraitement des données

Le prétraitement est défini dans :

```text
src/data_preprocessing.py
```

Ce fichier assure :

- le chargement de `KDDTrain+.txt` ;
- le chargement de `KDDTest+.txt` ;
- l’attribution des noms de colonnes ;
- la vérification de l’existence des fichiers ;
- la vérification que les fichiers ne sont pas vides ;
- la transformation des étiquettes en classification binaire ;
- la séparation entre les caractéristiques et la cible ;
- la suppression des colonnes `label` et `difficulty`.

Les colonnes catégorielles utilisées sont :

```text
protocol_type
service
flag
```

## Modèle de machine learning

L’entraînement est défini dans :

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

Le modèle utilise `predict_proba` pour calculer la probabilité d’attaque.

Une connexion est classée comme attaque lorsque :

```text
probabilité d’attaque >= 0.10
```

Le modèle final est enregistré dans :

```text
models/intrusion_detector.joblib
```

Le fichier contient :

- le pipeline de prétraitement ;
- le modèle entraîné ;
- le seuil de décision ;
- la liste des caractéristiques attendues.

## Reproduction du modèle

Le projet contient les scripts nécessaires pour reconstruire le modèle à partir des fichiers NSL-KDD.

Tester le prétraitement :

```powershell
python src\data_preprocessing.py
```

Réentraîner complètement le modèle :

```powershell
python -m src.train_model
```

Cette commande :

- charge les données d’entraînement et de test ;
- prépare les caractéristiques ;
- transforme les étiquettes ;
- encode les colonnes catégorielles ;
- entraîne le modèle Random Forest ;
- calcule les probabilités ;
- applique le seuil de décision ;
- calcule les métriques ;
- sauvegarde le modèle ;
- sauvegarde les métriques.

Le modèle est sauvegardé dans :

```text
models/intrusion_detector.joblib
```

Les métriques sont sauvegardées dans :

```text
reports/final_metrics.json
```

Attention : cette commande remplace le modèle précédemment enregistré.

## Métriques calculées

Le script d’entraînement calcule notamment :

- l’accuracy ;
- la précision de la classe attaque ;
- le rappel de la classe attaque ;
- le F1-score de la classe attaque ;
- la matrice de confusion ;
- la durée d’entraînement ;
- le seuil de décision ;
- le nombre d’arbres ;
- le random state.

Les résultats sont enregistrés dans :

```text
reports/final_metrics.json
```

## Analyse PCAP

L’analyse des captures réseau est réalisée avec TShark.

Le fichier principal est :

```text
src/pcap_analyzer.py
```

Les données extraites comprennent notamment :

- le numéro du paquet ;
- la taille du paquet ;
- le protocole ;
- l’adresse IP source IPv4 ;
- l’adresse IP destination IPv4 ;
- l’adresse IP source IPv6 ;
- l’adresse IP destination IPv6 ;
- les ports TCP sources et destinations ;
- les ports UDP sources et destinations ;
- le drapeau TCP SYN ;
- le drapeau TCP ACK ;
- le drapeau TCP RST.

Les informations sont ensuite regroupées avec des compteurs afin d’obtenir :

- les protocoles les plus utilisés ;
- les IP sources les plus actives ;
- les IP destinations les plus sollicitées ;
- les ports les plus utilisés ;
- le volume total de la capture.

## Indicateurs descriptifs de sécurité

L’analyse PCAP calcule plusieurs indicateurs descriptifs, notamment :

- présence de protocoles non chiffrés ;
- proportion de trafic non chiffré ;
- proportion de trafic DNS ;
- proportion de paquets SYN ;
- comparaison entre SYN et ACK ;
- proportion de paquets RST ;
- proportion de trafic identifié comme chiffré.

Un score descriptif est calculé afin de produire un niveau d’attention :

```text
Faible
Modéré
Élevé
```

Ce niveau ne constitue pas une détection certaine d’attaque.

## Trafic chiffré

Les protocoles actuellement considérés comme chiffrés comprennent notamment :

- TLSv1
- TLSv1.1
- TLSv1.2
- TLSv1.3
- SSL
- QUIC

Les protocoles actuellement considérés comme non chiffrés comprennent notamment :

- HTTP
- FTP
- FTP-DATA
- TELNET

Le pourcentage de trafic chiffré peut être sous-estimé, car certains paquets appartenant à une connexion HTTPS peuvent être affichés simplement comme `TCP` par TShark.

## Différence entre les deux analyses

### Analyse NSL-KDD

L’analyse NSL-KDD utilise un modèle de machine learning.

Elle fournit :

- une prédiction ;
- une probabilité d’attaque ;
- un niveau de risque.

### Analyse PCAP

L’analyse PCAP utilise TShark et des règles descriptives.

Elle fournit :

- des statistiques réseau ;
- des protocoles ;
- des ports ;
- des adresses IP ;
- des graphiques ;
- des indicateurs d’attention.

Le niveau d’attention PCAP ne doit pas être présenté comme une détection certaine d’attaque.

Les 41 caractéristiques NSL-KDD ne peuvent pas toutes être extraites directement à partir d’une capture PCAP brute. Pour cette raison, la capture PCAP n’est pas envoyée directement au modèle NSL-KDD.

## Exportation

### Export des prédictions CSV

Le fichier exporté contient :

- le numéro de ligne ;
- la prédiction ;
- la probabilité d’attaque ;
- le pourcentage de probabilité ;
- le niveau de risque.

### Export de l’analyse PCAP

Le fichier exporté contient :

- le nom de la capture ;
- le nombre total de paquets ;
- le volume total en octets ;
- le volume total en mégaoctets ;
- le nombre de protocoles ;
- le nombre de ports principaux ;
- le niveau d’attention ;
- le score d’attention ;
- le protocole dominant ;
- le nombre de paquets du protocole dominant ;
- le pourcentage du protocole dominant ;
- l’IP source la plus active ;
- le nombre de paquets de cette IP ;
- le pourcentage de cette IP ;
- le port le plus utilisé ;
- le nombre d’occurrences du port ;
- le trafic chiffré ;
- le trafic non chiffré ;
- les paquets SYN ;
- les paquets ACK ;
- les paquets RST ;
- les pourcentages SYN et RST ;
- les indicateurs descriptifs ;
- l’avertissement de sécurité ;
- les protocoles ;
- les ports ;
- les IP sources ;
- les IP destinations.

## Interface utilisateur

L’interface permet :

- de charger un exemple normal ;
- de charger un exemple d’attaque ;
- de modifier les principales caractéristiques d’une connexion ;
- d’importer un fichier CSV par sélection ou glisser-déposer ;
- d’afficher le nom du fichier CSV directement dans la zone d’import ;
- d’importer une capture PCAP ou PCAPNG ;
- d’afficher le nom de la capture directement dans la zone d’import ;
- de visualiser les résultats ;
- de rechercher une ligne dans les prédictions ;
- de télécharger les résultats ;
- de consulter les graphiques de protocoles et de ports.

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

Wireshark et TShark ne sont pas installés avec `pip`. Ils doivent être installés séparément sur le système.

## Commandes utiles

Activer l’environnement virtuel :

```powershell
.\venv\Scripts\Activate.ps1
```

Installer les dépendances :

```powershell
pip install -r requirements.txt
```

Tester le prétraitement :

```powershell
python src\data_preprocessing.py
```

Réentraîner le modèle :

```powershell
python -m src.train_model
```

Tester une prédiction :

```powershell
python src\predict.py
```

Tester l’analyse PCAP :

```powershell
python src\pcap_analyzer.py
```

Vérifier la syntaxe de l’API :

```powershell
python -m py_compile src\api.py
```

Vérifier la syntaxe du prétraitement :

```powershell
python -m py_compile src\data_preprocessing.py
```

Vérifier la syntaxe du script d’entraînement :

```powershell
python -m py_compile src\train_model.py
```

Vérifier la syntaxe de l’analyseur PCAP :

```powershell
python -m py_compile src\pcap_analyzer.py
```

Lancer l’application :

```powershell
uvicorn src.api:app --reload
```

Arrêter l’application :

```text
Ctrl + C
```

## Git

Le projet utilise un fichier `.gitignore` afin de ne pas envoyer sur GitHub les fichiers inutiles ou locaux.

Les éléments ignorés comprennent notamment :

- l’environnement virtuel `venv` ;
- les dossiers `__pycache__` ;
- les fichiers Python compilés ;
- les checkpoints Jupyter ;
- les fichiers `.env` ;
- les fichiers de configuration de certains éditeurs ;
- les captures PCAP non prévues pour être partagées.

Le fichier d’exemple suivant reste autorisé :

```text
data/captures/test_capture.pcapng
```

## Limites actuelles

- Le dataset NSL-KDD est ancien.
- Les attaques récentes ne sont pas nécessairement bien représentées.
- Le modèle effectue une classification binaire et ne distingue pas les différentes familles d’attaques.
- Le seuil de décision fixé à `0.10` favorise la détection des attaques, mais peut augmenter le nombre de faux positifs.
- L’analyse PCAP est descriptive et ne constitue pas une classification par machine learning.
- Le chemin de TShark est actuellement configuré pour Windows.
- L’analyse PCAP dépend de l’installation de Wireshark et TShark.
- Les fichiers PCAP volumineux peuvent nécessiter davantage de mémoire et de temps.
- Le contenu complet du fichier uploadé est actuellement lu en mémoire par l’API.
- L’application fonctionne actuellement en environnement local.
- Aucune authentification n’est encore intégrée.
- Aucun historique des analyses n’est conservé.
- Le modèle n’est pas automatiquement réentraîné.
- Le projet n’est pas encore conteneurisé avec Docker.
- Le projet n’est pas encore déployé dans le cloud.
- Les indicateurs PCAP ne remplacent pas un système de détection d’intrusions professionnel.

## Améliorations possibles

- utiliser un dataset réseau plus récent ;
- utiliser CIC-IDS2017 ou CIC-IDS2018 ;
- extraire des flux réseau avec CICFlowMeter ;
- entraîner un modèle compatible avec des captures réelles ;
- distinguer plusieurs catégories d’attaques ;
- comparer plusieurs algorithmes de machine learning ;
- optimiser le seuil de décision ;
- ajouter une courbe ROC ;
- ajouter une courbe précision-rappel ;
- effectuer une validation croisée ;
- ajouter des tests automatisés ;
- ajouter une base de données ;
- enregistrer l’historique des analyses ;
- ajouter une authentification ;
- ajouter une gestion des utilisateurs ;
- ajouter une limite de taille pour les fichiers importés ;
- traiter les fichiers volumineux progressivement ;
- détecter automatiquement le chemin de TShark ;
- rendre l’analyse PCAP compatible avec Linux ;
- ajouter une analyse en temps réel ;
- ajouter des graphiques supplémentaires ;
- générer un rapport PDF ;
- conteneuriser l’application avec Docker ;
- automatiser l’entraînement avec un pipeline MLOps ;
- déployer l’application dans le cloud.

## Avertissement

Les résultats produits par cette application sont destinés à un usage pédagogique et expérimental.

Une prédiction d’attaque ou un niveau d’attention ne constitue pas une preuve définitive d’activité malveillante.

Les résultats doivent être interprétés avec d’autres informations réseau et par une personne compétente en cybersécurité.

## Auteur

Projet réalisé par **Salah-Eddine Bechari**.

Étudiant en **Data Science and Cloud Computing**.