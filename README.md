# Simulation et préparation de traces d’un réseau domestique pour un dataset Machine Learning

## 1. Contexte du projet

Ce projet s’inscrit dans le cadre du sujet **« Simulation et préparation de traces d’un réseau domestique »**.  
L’objectif est de simuler une maison connectée composée de plusieurs types d’équipements IoT connectés à un point d’accès Wi-Fi (standard 802.11ac), de générer des traces d'exécution des équipements, puis de préparer un **jeu de données (dataset)** utilisable pour entraîner un modèle de **Machine Learning** destiné à la **classification des flux réseau par type d’appareil et type de trafic**.

Le projet comporte deux grandes étapes :

1. **Simulation du réseau domestique dans ns-3**
2. **Traitement des traces PCAP pour créer un dataset ML-ready avec Python3**

## 2. Environnement de travail

Le projet a été entièrement réalisé sous **Kali Linux 2025**, choisi pour :
- la présence native d’outils réseau (Wireshark, tcpdump)
- la facilité d’installation des dépendances de ns-3 et Scapy
- un environnement adapté aux travaux de cybersécurité et de réseaux

### Outils utilisés

| Outil | Version / Rôle |
|------|------|
| **Kali Linux** | Version 2025 |
| **ns-3** | 3.46.1 (simulation réseau) |
| **NetAnim** | Visualisation graphique de la topologie |
| **Python** | 3.11 |
| **VS Code** | Éditeur de code |
| **Scapy** | Analyse PCAP |
| **Pandas / Numpy / Matplotlib** | Traitement et analyse du dataset |


## 3. Topologie simulée

Le scénario simulé correspond à une **maison connectée** composée de :

- 1 point d’accès Wi-Fi (Access Point)
- 25 types d’équipements IoT répartis en plusieurs catégories :
  - Multimédia (TV, caméra, console…)
  - Domotique (ampoule, thermostat, serrure…)
  - Capteurs (température, mouvement…)
  - Électroménager (frigo, robot, machine à laver…)
  - Bureautique (PC, smartphone, imprimante…)
- 15 équipements par type  
- Soit **N = 375 équipements au total**

Tous les équipements sont connectés au point d’accès en **WiFi 802.11ac**.  
Chaque type d’appareil possède son propre **profil de trafic (DeviceProfile)** défini selon :

- Type de protocole : TCP ou UDP
- Débit (DataRate)
- Taille des paquets (PacketSize)
- Durée d’activité (OnTime)
- Durée d’inactivité (OffTime)
- Port utilisé
- Type de trafic simulé (HTTP, IoT, IPTV, CoAP, etc.)

Les applications sont générées à l’aide de **OnOffApplication** avec une loi exponentielle pour les phases ON/OFF afin d’augmenter la variabilité.

L’instant de démarrage de chaque équipement est volontairement aléatoire dans un intervalle compris entre **0 et 5 secondes**, conformément aux consignes du travail pratique.


## 4. Fichiers générés par la simulation

Après l’exécution du fichier `final_home_simulation_tp_fixed.cc`, plusieurs fichiers sont produits :

| Fichier | Description |
|------|------|
| `output/smart_home_simulation_capture-....pcap` | Trace brute de tous les paquets au niveau du point d'accès |
| `output/ground_truth.csv` | Table des équipements et leurs caractéristiques (DeviceID, IP, Type, Protocole, Port…) |
| `output/smart_home_simulation.xml` | Fichier NetAnim pour visualisation |
| `traces/*.xml` | Traces supplémentaires de la simulation |

Le fichier `ground_truth.csv` contient **exactement 375 lignes**, une par équipement simulé.


## 5. Préparation du dataset

Le traitement des traces est effectué avec le script Python : processing_dataset_fixed.py

Ce script utilise **Scapy + Pandas** pour :

1. Lire le PCAP généré par ns-3
2. Identifier automatiquement l’adresse IP du point d’accès
3. Filtrer les paquets liés aux devices enregistrés dans `ground_truth.csv`
4. Extraire des **features par paquet**, notamment :
   - Taille du paquet
   - Entropie du payload
   - Direction (UPLINK / DOWNLINK)
   - Protocole (TCP / UDP)
   - Flags TCP
   - Fenêtre TCP
   - Timestamp
   - IP source/destination
   - Port source/destination

5. Regrouper les paquets par :
   - Adresse IP de l’équipement (DeviceIP)
   - Fenêtre temporelle fixe (1 seconde : `WINDOW_SIZE_SECONDS = 1`)

Cette fenêtre temporelle est volontairement conservée car :
- Elle est essentielle pour capturer la **périodicité**
- Elle permet d’observer l’évolution du trafic dans le temps
- Elle correspond à la logique de classification par “morceaux de trafic”

## 6. Dataset final 

Le script génère deux fichiers principaux :

### 1. Le dataset basé sur les paquets

Le premier fichier est : output/final_iot_dataset_packet_based.csv, il contient un enregistrement de toutes les traces d'exécution par paquet.

### 2. Le dataset basé sur les équipements

Le second fichier est : output/final_iot_dataset_bidirectional_full.csv, il contient un enregistrement de toutes les traces d'exécution **par fenêtre temporelle et par équipement** avec plus de 35 features :

- TotalPacketCount
- MeanIAT
- VarIAT
- Uplink_Count
- Downlink_Count
- Uplink/Downlink Bytes
- Entropie moyenne et variance
- Ratio TCP/UDP
- Ratio Uplink/Downlink
- Débit estimé en bps et pps
- WindowDuration
- Labels

#### Labels contenus :

- `Label` → Type d’appareil (ex : Camera, Smartphone, Fridge...)
- `Label_ID` → Version codée numérique
- `DeviceIP`
- `Port` 
- `TrafficType` (HTTP, IPTV, IoT, CoAP, Video, etc.)

## 7. Lancement du projet

Cette section décrit, étape par étape, la procédure complète pour exécuter la simulation ns-3, générer les fichiers de traces (PCAP / XML) et produire le dataset final.

### 7.1 Lancer la simulation réseau avec ns-3

Copiez d’abord votre fichier C++ dans le dossier `scratch` de ns-3 avec les commandes :  cp final_home_simulation_tp_fixed.cc ~/workspace/ns-3-dev/scratch/
Ensuite, placez-vous dans le répertoire racine de ns-3, puis compilez et exécutez la simulation :
cd ~/workspace/ns-3-dev
./ns3 configure
./ns3 build
./ns3 run scratch/final_home_simulation_tp_fixed

Si l’exécution est correcte, plusieurs fichiers seront générés automatiquement dans le dossier output/ :
- smart_home_simulation_capture-*.pcap : capture du trafic réseau
- smart_home_simulation.xml : fichier de visualisation pour NetAnim
- ground_truth.csv : vérité terrain (IP, type d’appareil, protocole, etc.)

###7.2 Visualisation de la simulation avec NetAnim

Pour ouvrir et visualiser le réseau simulé, il faut ouvrir ce fichier dans NetAnim, netanim output/smart_home_simulation.xml

Vous pourrez observer :
- Le point d’accès (Access Point – AP)
- Les différents équipements connectés
- L’échange de paquets entre les nœuds


### 7.3 Génération du dataset pour le Machine Learning

Une fois la simulation terminée, exécutez le script Python qui transforme la capture réseau en jeu de données structuré. Placez-vous dans le dossier output  et lancer le fichier python3 processing_dataset_fixed.py

Les fichiers générés sont notamment :
- final_iot_dataset_packet_based.csv
- final_iot_dataset_bidirectional_full.csv
- correlation_matrix.png
- distribution_labels.png

### 7.4 Résultat attendu dans le terminal

À la fin du traitement, le terminal doit afficher un message similaire à celui-ci :

Les équipements chargés : 375 équipements à mapper.
Trace PCAP chargée : XXXXX paquets.
Extraction métadonnées : XXXXX paquets retenus.
Dataset temporel final généré : XXXX échantillons.
Processus terminé en XX.XX secondes.
Ces informations confirment que : Les 375 équipements ont bien été détectés


la détection d’anomalies

l’apprentissage supervisé et non supervisé

Ce jeu de données constitue la base principale pour tous les travaux d’analyse et de Machine Learning du projet.

Copy code

