# import pandas as pd
# from scapy.all import rdpcap, IP, TCP, UDP
# import numpy as np
# from scipy.stats import entropy
# import matplotlib.pyplot as plt
# import seaborn as sns
# import time

# # --- Configuration ---
# WINDOW_SIZE_SECONDS = 1.0  # Taille de la fenêtre temporelle pour l'agrégation
# AP_IP = "192.168.0.1" # IP du point d'accès (déduit du script C++)

# # --- Fonctions d'extraction et d'agrégation ---

# def calculate_entropy(payload):
#     """Calcule l'entropie de Shannon du payload (bits)."""
#     if not payload:
#         return 0.0
#     value, counts = np.unique(list(payload), return_counts=True)
#     probabilities = counts / len(payload)
#     return entropy(probabilities, base=2)

# def extract_features_from_packet(pkt, device_ip, direction):
#     """Extrait toutes les métadonnées pour l'agrégation."""
#     features = {
#         'Timestamp': float(pkt.time),
#         'PacketSize': len(pkt),
#         'PayloadSize': 0,
#         'Protocol': pkt[IP].proto if IP in pkt else 0, # 6=TCP, 17=UDP
#         'PayloadEntropy': 0.0,
#         'Direction': direction,
#         'DeviceIP': device_ip,
#         'IsTCP': 1 if TCP in pkt else 0, # Pour le ratio TCP
        
#         # Flags TCP (compteurs à sommer sur la fenêtre)
#         'SYN_Flag': 0, 'ACK_Flag': 0, 'FIN_Flag': 0, 'RST_Flag': 0,
#         'WindowSize': 0,
#     }

#     if IP in pkt and pkt[IP].proto in [6, 17]:
#         if pkt.haslayer('Raw'):
#             payload = pkt['Raw'].load
#             features['PayloadSize'] = len(payload)
#             features['PayloadEntropy'] = calculate_entropy(payload)

#         if TCP in pkt:
#             tcp_layer = pkt[TCP]
#             features['WindowSize'] = tcp_layer.window

#             flags = str(tcp_layer.flags)
#             if 'S' in flags: features['SYN_Flag'] = 1
#             if 'A' in flags: features['ACK_Flag'] = 1
#             if 'F' in flags: features['FIN_Flag'] = 1
#             if 'R' in flags: features['RST_Flag'] = 1
            
#     return features


# def aggregate_to_window(group):
#     """Calcule les features agrégées, bidirectionnelles et les ratios."""
    
#     # Séparation du trafic
#     uplink_group = group[group['Direction'] == 'UPLINK']
#     downlink_group = group[group['Direction'] == 'DOWNLINK']

#     # Calcul des temps
#     duration = group['Timestamp'].max() - group['Timestamp'].min()
#     duration = duration if duration > 0 else 0.000001 
    
#     total_count = len(group)
#     tcp_count = group['IsTCP'].sum()

#     # IAT (Inter-Arrival Time) - total pour la variance globale
#     iat = group['Timestamp'].diff().dropna()
#     mean_iat = iat.mean() if len(iat) > 0 else 0.0
#     var_iat = iat.var() if len(iat) > 1 else 0.0
    
#     # IAT séparé pour UPLINK et DOWNLINK (pour plus de discrimination)
#     uplink_iat = uplink_group['Timestamp'].diff().dropna()
#     downlink_iat = downlink_group['Timestamp'].diff().dropna()

#     uplink_count = len(uplink_group)
#     downlink_count = len(downlink_group)
#     uplink_total_bytes = uplink_group['PacketSize'].sum()
#     downlink_total_bytes = downlink_group['PacketSize'].sum()
    
#     features = {
#         # --- Métriques Générales (Global) ---
#         'WindowDuration': duration,
#         'TotalPacketCount': total_count,
#         'MeanIAT': mean_iat,
#         'VarIAT': var_iat,
#         'TCP_Ratio': tcp_count / total_count, # Nouveau : Ratio de paquets TCP dans la fenêtre
        
#         # --- UPLINK (Trafic envoyé par le Device) ---
#         'Uplink_Count': uplink_count,
#         'Uplink_TotalBytes': uplink_total_bytes,
#         'Uplink_MeanPacketSize': uplink_group['PacketSize'].mean() if uplink_count > 0 else 0,
#         'Uplink_VarPacketSize': uplink_group['PacketSize'].var() if uplink_count > 1 else 0,
#         'Uplink_MeanEntropy': uplink_group['PayloadEntropy'].mean() if uplink_count > 0 else 0,
#         'Uplink_VarEntropy': uplink_group['PayloadEntropy'].var() if uplink_count > 1 else 0, # Nouveau : Variance Entropie
#         'Uplink_MeanIAT': uplink_iat.mean() if len(uplink_iat) > 0 else 0.0, # Nouveau : IAT moyen UPLINK
#         'Uplink_SumSYN': uplink_group['SYN_Flag'].sum(),
#         'Uplink_SumACK': uplink_group['ACK_Flag'].sum(),
#         'Uplink_SumRST': uplink_group['RST_Flag'].sum(),
        
#         # --- DOWNLINK (Trafic reçu par le Device) ---
#         'Downlink_Count': downlink_count,
#         'Downlink_TotalBytes': downlink_total_bytes,
#         'Downlink_MeanPacketSize': downlink_group['PacketSize'].mean() if downlink_count > 0 else 0,
#         'Downlink_VarPacketSize': downlink_group['PacketSize'].var() if downlink_count > 1 else 0,
#         'Downlink_MeanEntropy': downlink_group['PayloadEntropy'].mean() if downlink_count > 0 else 0,
#         'Downlink_VarEntropy': downlink_group['PayloadEntropy'].var() if downlink_count > 1 else 0, # Nouveau : Variance Entropie
#         'Downlink_MeanIAT': downlink_iat.mean() if len(downlink_iat) > 0 else 0.0, # Nouveau : IAT moyen DOWNLINK
#         'Downlink_SumSYN': downlink_group['SYN_Flag'].sum(),
#         'Downlink_SumACK': downlink_group['ACK_Flag'].sum(),
#         'Downlink_SumRST': downlink_group['RST_Flag'].sum(),
        
#         # --- Métriques de Taux et Ratios ---
#         'Rate_pps': total_count / duration,
#         'Rate_bps': ((uplink_total_bytes + downlink_total_bytes) * 8) / duration,
#         'Uplink_Ratio_Count': uplink_count / total_count if total_count > 0 else 0,
#         'Uplink_Ratio_Bytes': uplink_total_bytes / (uplink_total_bytes + downlink_total_bytes) if (uplink_total_bytes + downlink_total_bytes) > 0 else 0,
        
#         # Nouvelle Feature: Ratio de paquets (Count) vs Ratio d'octets (Bytes)
#         # Ceci distingue les petits paquets fréquents vs. les gros paquets rares
#         'Ratio_Count_vs_Bytes': (uplink_count / total_count) / (uplink_total_bytes / (uplink_total_bytes + downlink_total_bytes)) if (uplink_total_bytes + downlink_total_bytes) > 0 and total_count > 0 else 0,
#     }

#     return pd.Series(features)


# def generate_and_analyze_dataset():
#     # ... (les étapes 1, 2, 3 sont inchangées)

#     # 1. Charger la vérité terrain
#     try:
#         labels_df = pd.read_csv("output/ground_truth.csv")
#         device_ips = set(labels_df['IP'])
#         ip_to_type = dict(zip(labels_df['IP'], labels_df['DeviceType']))
#         print(f"Vérité terrain chargée : {len(device_ips)} équipements à mapper.")
#     except FileNotFoundError:
#         print("Erreur : Le fichier output/ground_truth.csv est introuvable. Assurez-vous d'avoir lancé le script ns-3.")
#         return

#     # 2. Lire le PCAP
#     try:
#         packets = rdpcap("output/ap_capture-375-0.pcap")
#         print(f"Trace PCAP chargée : {len(packets)} paquets.")
#     except FileNotFoundError:
#         print("Erreur : Le fichier output/ap_capture-0-0.pcap est introuvable.")
#         return

#     # 3. Extraction de features paquet par paquet avec classification UP/DOWN
#     raw_data = []
    
#     for pkt in packets:
#         if IP in pkt and (pkt[IP].src in device_ips or pkt[IP].dst in device_ips):
#             src_ip = pkt[IP].src
#             dst_ip = pkt[IP].dst
            
#             direction = None
#             device_ip = None

#             if src_ip in device_ips and dst_ip == AP_IP:
#                 direction = 'UPLINK'
#                 device_ip = src_ip
#             elif dst_ip in device_ips and src_ip == AP_IP:
#                 direction = 'DOWNLINK'
#                 device_ip = dst_ip
#             else:
#                 continue 

#             if device_ip:
#                 features = extract_features_from_packet(pkt, device_ip, direction)
#                 raw_data.append(features)

#     df_raw = pd.DataFrame(raw_data)
#     print(f"Extraction des métadonnées terminée : {len(df_raw)} paquets conservés.")

#     # 4. Création du Dataset Temporel (Fenêtrage basé sur le temps)
    
#     df_raw['DateTime'] = pd.to_datetime(df_raw['Timestamp'], unit='s')
    
#     grouped = df_raw.groupby(['DeviceIP', pd.Grouper(key='DateTime', freq=f'{int(WINDOW_SIZE_SECONDS)}S')])
    
#     df_final = grouped.apply(aggregate_to_window).reset_index()
    
#     df_final = df_final.rename(columns={'DateTime': 'WindowStart'})

#     df_final['Label'] = df_final['DeviceIP'].map(ip_to_type)
#     df_final['Label_ID'] = df_final['Label'].astype('category').cat.codes

#     df_final = df_final[df_final['TotalPacketCount'] > 0].reset_index(drop=True)
    
#     print(f"Dataset Temporel Final généré : {len(df_final)} échantillons de fenêtre.")

#     # Sauvegarde
#     output_filename = "output/final_iot_dataset_bidirectional_full.csv"
#     df_final.to_csv(output_filename, index=False)
#     print(f"Fichier '{output_filename}' créé avec {len(df_final.columns)} features.")

#     # 5. Analyse Statistique et Visualisation (Inchangée)
#     # ... (Graphiques de distribution, Boxplot, Scatterplot) ...
#     print("\n--- Analyse Statistique du Dataset (output/) ---")
#     sns.set_style("whitegrid")
    
#     # ... (génération des graphiques countplot, boxplot, scatterplot) ...
#     # a) Distribution des échantillons par type
#     plt.figure(figsize=(12, 6))
#     sns.countplot(y='Label', data=df_final, order=df_final['Label'].value_counts().index, palette='viridis')
#     plt.title('Distribution des échantillons (Fenêtres de 1s) par Type d\'Appareil')
#     plt.xlabel('Nombre d\'Échantillons')
#     plt.ylabel('Type d\'Appareil')
#     plt.tight_layout()
#     plt.savefig('output/distribution_labels.png')
#     plt.close()
    
#     # b) Ratio de trafic : Bidirectionalité clé
#     plt.figure(figsize=(12, 6))
#     sns.boxplot(x='Uplink_Ratio_Count', y='Label', data=df_final, order=df_final['Label'].value_counts().index, palette='coolwarm')
#     plt.title('Ratio UPLINK (Paquets Envoyés / Total) - Caractéristique de Signature')
#     plt.xlabel('Ratio UPLINK (0.0 = Tout reçu, 1.0 = Tout envoyé)')
#     plt.ylabel('Type d\'Appareil')
#     plt.tight_layout()
#     plt.savefig('output/boxplot_uplink_ratio.png')
#     plt.close()
    
#     # c) Scatterplot Entropie UPLINK vs DOWNLINK
#     df_sample = df_final.sample(n=min(5000, len(df_final)), random_state=42)
#     plt.figure(figsize=(10, 8))
#     sns.scatterplot(x='Uplink_MeanEntropy', y='Downlink_MeanEntropy', hue='Label', 
#                     data=df_sample, size='TotalPacketCount', sizes=(20, 200), alpha=0.6, palette='tab20')
#     plt.title('Entropie du Payload : UPLINK vs DOWNLINK (Feature Space)')
#     plt.xlabel('Entropie Moyenne UPLINK')
#     plt.ylabel('Entropie Moyenne DOWNLINK')
#     plt.legend(bbox_to_anchor=(1.05, 1), loc=2, borderaxespad=0.)
#     plt.grid(True)
#     plt.tight_layout()
#     plt.savefig('output/scatterplot_bidirectional_entropy.png')
#     plt.close()
    
#     # 6. Analyse de Corrélation (Nouveau)
#     print("\n--- Calcul et Visualisation de la Matrice de Corrélation ---")
    
#     # Sélectionner uniquement les colonnes numériques pour la corrélation
#     numeric_df = df_final.select_dtypes(include=[np.number]).drop(columns=['Label_ID'])
    
#     # Calcul de la matrice de corrélation
#     correlation_matrix = numeric_df.corr()
    
#     # Filtrer les features trop corrélées avec la durée (si la simulation est longue, c'est normal)
#     # et se concentrer sur les relations entre les features de trafic.
    
#     # Visualisation
#     plt.figure(figsize=(16, 14))
#     # Utilisation d'un masque pour ne pas répéter les valeurs (matrice symétrique)
#     mask = np.triu(correlation_matrix)
#     sns.heatmap(correlation_matrix, annot=False, cmap='coolwarm', fmt=".2f", linewidths=.5, mask=mask, cbar_kws={"shrink": .75})
#     plt.title('Matrice de Corrélation des Features Agrégées (Évitement de Redondance)')
#     plt.tight_layout()
#     plt.savefig('output/correlation_matrix.png')
#     plt.close()
#     print("Graphique de la Matrice de Corrélation (output/correlation_matrix.png) généré.")
    
#     end_time = time.time()
#     print(f"\n--- Processus terminé en {end_time - start_time:.2f} secondes. ---")

# if __name__ == "__main__":
#     generate_and_analyze_dataset()


import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP
import numpy as np
from scipy.stats import entropy
import matplotlib.pyplot as plt
import seaborn as sns
import time

# --- Configuration ---
AP_IP = "192.168.0.1" # IP du point d'accès (déduit du script C++)

# --- Fonctions d'extraction ---

def calculate_entropy(payload):
    """Calcule l'entropie de Shannon du payload (bits)."""
    if not payload:
        return 0.0
    value, counts = np.unique(list(payload), return_counts=True)
    probabilities = counts / len(payload)
    return entropy(probabilities, base=2)

def extract_features_from_packet(pkt, device_ip, direction):
    """Extrait les métadonnées de chaque paquet."""
    features = {
        'Timestamp': float(pkt.time),
        'PacketSize': len(pkt),
        'PayloadSize': 0,
        'Protocol': pkt[IP].proto if IP in pkt else 0, # 6=TCP, 17=UDP
        'PayloadEntropy': 0.0,
        'Direction': direction,
        'DeviceIP': device_ip,
        'IsTCP': 1 if TCP in pkt else 0,
        
        # Flags TCP (valeur binaire: 1 si flag présent, 0 sinon)
        'SYN_Flag': 0, 'ACK_Flag': 0, 'FIN_Flag': 0, 'RST_Flag': 0,
        'PSH_Flag': 0, 'URG_Flag': 0,
        'WindowSize': 0,
    }

    if IP in pkt and pkt[IP].proto in [6, 17]:
        if pkt.haslayer('Raw'):
            payload = pkt['Raw'].load
            features['PayloadSize'] = len(payload)
            features['PayloadEntropy'] = calculate_entropy(payload)

        if TCP in pkt:
            tcp_layer = pkt[TCP]
            features['WindowSize'] = tcp_layer.window

            flags = str(tcp_layer.flags)
            if 'S' in flags: features['SYN_Flag'] = 1
            if 'A' in flags: features['ACK_Flag'] = 1
            if 'F' in flags: features['FIN_Flag'] = 1
            if 'R' in flags: features['RST_Flag'] = 1
            if 'P' in flags: features['PSH_Flag'] = 1
            if 'U' in flags: features['URG_Flag'] = 1
            
    return features


def generate_and_analyze_dataset():
    try:
        labels_df = pd.read_csv("output/ground_truth.csv")
        device_ips = set(labels_df['IP'])
        ip_to_type = dict(zip(labels_df['IP'], labels_df['DeviceType']))
        print(f"Vérité terrain chargée : {len(device_ips)} équipements à mapper.")
    except FileNotFoundError:
        print("Erreur : Le fichier output/ground_truth.csv est introuvable. Assurez-vous d'avoir lancé le script ns-3.")
        return

    # 2. Lire le PCAP
    try:
        packets = rdpcap("output/ap_capture-375-0.pcap")
        print(f"Trace PCAP chargée : {len(packets)} paquets.")
    except FileNotFoundError:
        print("Erreur : Le fichier output/ap_capture-0-0.pcap est introuvable.")
        return

    # 3. Extraction de features paquet par paquet avec classification UP/DOWN
    raw_data = []
    
    for pkt in packets:
        # On ne s'intéresse qu'aux paquets qui ont une couche IP (L3)
        if IP in pkt: 
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            direction = None
            device_ip = None

            # Classification Corrigée : Si la source est un Device, c'est UPLINK. Si la destination est un Device, c'est DOWNLINK.
            if src_ip in device_ips:
                direction = 'UPLINK'  # Le paquet vient de l'équipement
                device_ip = src_ip
            elif dst_ip in device_ips:
                direction = 'DOWNLINK' # Le paquet va vers l'équipement
                device_ip = dst_ip
            else:
                # On ignore le trafic qui ne concerne pas les équipements (e.g., entre serveurs externes)
                continue 

            if device_ip:
                features = extract_features_from_packet(pkt, device_ip, direction)
                raw_data.append(features)

    df_final = pd.DataFrame(raw_data)
    print(f"Extraction des métadonnées terminée : {len(df_final)} paquets conservés.")

    # **GESTION DE L'ABSENCE DE DONNÉES (POUR ÉVITER LE KEYERROR) :**
    if df_final.empty:
        print("\n--- ATTENTION ---")
        print("Le DataFrame est VIDE. Cela signifie que la simulation n'a généré aucun paquet pertinent.")
        print("Veuillez OBLIGATOIREMENT augmenter la durée de simulation C++ (Simulator::Stop(Seconds(...))).")
        return # Arrêt propre du script

    # 4. Ajout des métriques temporelles clés (IAT)
    df_final['IAT'] = df_final.groupby('DeviceIP')['Timestamp'].diff().fillna(0)

    # Ajout du Label (DeviceType)
    df_final['Label'] = df_final['DeviceIP'].map(ip_to_type)
    df_final['Label_ID'] = df_final['Label'].astype('category').cat.codes
    
    # Suppression des paquets de contrôle/faible valeur si la taille est trop petite
    df_final = df_final[df_final['PacketSize'] >= 40].reset_index(drop=True)
    
    print(f"Dataset final (Packet-based) généré : {len(df_final)} échantillons.")

    # Sauvegarde
    output_filename = "output/final_iot_dataset_packet_based.csv"
    df_final.to_csv(output_filename, index=False)
    print(f"Fichier '{output_filename}' créé avec {len(df_final.columns)} features.")

    # 5. Analyse de Corrélation
    print("\n--- Analyse de Corrélation des Features (output/correlation_matrix_packet.png) ---")
    
    # Suppression des colonnes non numériques ou non pertinentes pour la corrélation
    numeric_df = df_final.select_dtypes(include=[np.number]).drop(columns=['Label_ID', 'Timestamp'])
    
    correlation_matrix = numeric_df.corr()
    
    plt.figure(figsize=(14, 12))
    mask = np.triu(correlation_matrix)
    sns.heatmap(correlation_matrix, annot=False, cmap='coolwarm', fmt=".2f", linewidths=.5, mask=mask, cbar_kws={"shrink": .75})
    plt.title('Matrice de Corrélation des Features par Paquet')
    plt.tight_layout()
    plt.savefig('output/correlation_matrix_packet.png')
    plt.close()
    print("Graphique de la Matrice de Corrélation généré.")
    
    end_time = time.time()
    print(f"\n--- Processus terminé en {end_time - start_time:.2f} secondes. ---")

if __name__ == "__main__":
    generate_and_analyze_dataset()