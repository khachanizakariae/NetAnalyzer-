
# NetAnalyzer – Application Web d’Analyse du Trafic Réseau

## Présentation

**NetAnalyzer** est une application web développée avec Python et Flask permettant d’importer et d’analyser des fichiers de capture réseau au format PCAP ou PCAPNG.

L’objectif du projet est de faciliter l’analyse du trafic réseau en présentant les principales informations des paquets dans une interface web claire et interactive.

## Fonctionnalités

- Importation de fichiers PCAP et PCAPNG.
- Extraction des adresses IP sources et destinations (IPv4).
- Identification de plusieurs protocoles réseau : TCP, UDP, DNS, ICMP et ARP.
- Calcul des statistiques du trafic réseau :
  - Nombre total de paquets.
  - Volume total de données.
  - Taille moyenne des paquets.
  - Taille minimale et maximale.
- Visualisation graphique de la répartition des protocoles.
- Détection de certaines anomalies à l'aide de règles simples.
- Historique des analyses avec stockage dans une base de données SQLite.

## Technologies utilisées

- **Python** : langage de programmation.
- **Flask** : framework web.
- **Scapy** : lecture et analyse des paquets réseau.
- **SQLite** : stockage de l'historique.
- **HTML / CSS / Bootstrap** : interface utilisateur.
- **JavaScript / Chart.js** : visualisation des données.
- **Git / GitHub** : gestion du code source.

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/khachanizakariae/NetAnalyzer-.git
cd NetAnalyzer-
```

### 2. Créer un environnement virtuel

```bash
python -m venv venv
```

### 3. Activer l'environnement virtuel

Sous Windows PowerShell :

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 5. Lancer l'application

```bash
python app.py
```

Ouvrir ensuite cette adresse dans le navigateur :

```text
http://127.0.0.1:5000
```

## Utilisation

1. Accéder à l'application depuis le navigateur.
2. Sélectionner un fichier PCAP ou PCAPNG.
3. Lancer l'analyse.
4. Consulter les statistiques, les adresses IP et les protocoles détectés.
5. Examiner les alertes et consulter l'historique des analyses.

## Structure du projet

```text
NetAnalyzer/
│
├── app.py
├── analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   ├── index.html
│   └── history.html
│
├── uploads/
└── netanalyzer.db
```

## Détection des anomalies

L'application utilise actuellement des règles heuristiques simples, notamment :

- Signalement des paquets dont la taille dépasse 1500 octets.
- Signalement des adresses IP sources générant plus de 100 paquets.

Ces alertes indiquent des comportements à examiner. Elles ne constituent pas, à elles seules, une preuve d'attaque ou d'activité malveillante.

## Limites actuelles

- L'extraction des adresses IP est actuellement basée sur IPv4.
- La classification des protocoles reste limitée aux protocoles pris en charge par l'analyseur actuel.
- Les seuils de détection sont fixes et peuvent nécessiter une adaptation selon le réseau analysé.

## Améliorations futures

- Ajouter la prise en charge d'IPv6.
- Enrichir l'identification des protocoles réseau.
- Améliorer les règles de détection des anomalies.
- Ajouter des filtres et une recherche avancée.
- Ajouter l'exportation des résultats d'analyse.
- Mettre en place des tests automatisés.

## Auteur

Projet académique réalisé dans le cadre de l'apprentissage de l'analyse réseau et de la cybersécurité.
