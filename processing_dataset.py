#!/usr/bin/env python3

import glob
import time
import os
import pandas as pd
import numpy as np
from scapy.all import rdpcap, PcapReader, IP, TCP, UDP, Raw
from scipy.stats import entropy
import matplotlib.pyplot as plt
import seaborn as sns

WINDOW_SIZE_SECONDS = 1.0
PCAP_GLOB_PATTERN = "output/*.pcap"
GROUND_TRUTH_CSV = "output/ground_truth.csv"
OUTPUT_WINDOWED_CSV = "output/final_iot_dataset_bidirectional_full.csv"
OUTPUT_PACKET_CSV = "output/final_iot_dataset_packet_based.csv"
OUTPUT_DEVICE_SUMMARY = "output/device_summary.csv"
PLOT_DIR = "output"
USE_PCAP_READER = False
MAX_SAMPLE_FOR_PLOTS = 5000

os.makedirs(PLOT_DIR, exist_ok=True)

def calculate_entropy(payload_bytes):
    if not payload_bytes:
        return 0.0
    arr = np.frombuffer(payload_bytes, dtype=np.uint8)
    vals, counts = np.unique(arr, return_counts=True)
    probs = counts / counts.sum()
    return float(entropy(probs, base=2))

def extract_features_from_packet(pkt, device_ip, direction):
    features = {
        'Timestamp': float(pkt.time),
        'PacketSize': int(len(pkt)),
        'PayloadSize': 0,
        'Protocol': int(pkt[IP].proto) if IP in pkt else 0,
        'PayloadEntropy': 0.0,
        'Direction': direction,
        'DeviceIP': device_ip,
        'IsTCP': 1 if TCP in pkt else 0,
        'SYN_Flag': 0, 'ACK_Flag': 0, 'FIN_Flag': 0, 'RST_Flag': 0,
        'PSH_Flag': 0, 'URG_Flag': 0,
        'WindowSize': 0,
    }

    if IP in pkt:
        if pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw].load)
                features['PayloadSize'] = len(payload)
                features['PayloadEntropy'] = calculate_entropy(payload)
            except Exception:
                features['PayloadSize'] = 0
                features['PayloadEntropy'] = 0.0
        if TCP in pkt:
            tcp_layer = pkt[TCP]
            try:
                features['WindowSize'] = int(tcp_layer.window)
            except Exception:
                features['WindowSize'] = 0
            flags = str(tcp_layer.flags)
            if 'S' in flags: features['SYN_Flag'] = 1
            if 'A' in flags: features['ACK_Flag'] = 1
            if 'F' in flags: features['FIN_Flag'] = 1
            if 'R' in flags: features['RST_Flag'] = 1
            if 'P' in flags: features['PSH_Flag'] = 1
            if 'U' in flags: features['URG_Flag'] = 1

    return features

def find_first_pcap(pattern=PCAP_GLOB_PATTERN):
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None

def determine_ap_ip(packets, device_ips):
    counter = {}
    for pkt in packets:
        if IP in pkt:
            s = str(pkt[IP].src)
            d = str(pkt[IP].dst)
            if s in device_ips and d not in device_ips:
                counter[d] = counter.get(d, 0) + 1
            elif d in device_ips and s not in device_ips:
                counter[s] = counter.get(s, 0) + 1
    return max(counter.items(), key=lambda x: x[1])[0] if counter else None

def generate_device_summary(df_packets, device_ips, ip_to_type):
    rows = []
    grouped = df_packets.groupby('DeviceIP') if not df_packets.empty else {}
    for dev in sorted(device_ips):
        if not df_packets.empty and dev in grouped.groups:
            g = grouped.get_group(dev)
            total_packets = len(g)
            total_bytes = int(g['PacketSize'].sum())
            uplink = g[g['Direction'] == 'UPLINK']
            downlink = g[g['Direction'] == 'DOWNLINK']
            uplink_count = len(uplink)
            downlink_count = len(downlink)
            tcp_ratio = float(g['IsTCP'].sum()) / total_packets if total_packets > 0 else 0.0
            mean_entropy = float(g['PayloadEntropy'].mean()) if total_packets > 0 else 0.0
            mean_pkt_size = float(g['PacketSize'].mean()) if total_packets > 0 else 0.0
            mean_iat = float(g['Timestamp'].diff().mean()) if total_packets > 1 else 0.0
        else:
            total_packets = 0
            total_bytes = 0
            uplink_count = 0
            downlink_count = 0
            tcp_ratio = 0.0
            mean_entropy = 0.0
            mean_pkt_size = 0.0
            mean_iat = 0.0

        rows.append({
            'DeviceIP': dev,
            'DeviceType': ip_to_type.get(dev, 'Unknown'),
            'TotalPackets': total_packets,
            'TotalBytes': total_bytes,
            'Uplink_Count': uplink_count,
            'Downlink_Count': downlink_count,
            'TCP_Ratio': tcp_ratio,
            'MeanEntropy': mean_entropy,
            'MeanPacketSize': mean_pkt_size,
            'MeanIAT': mean_iat
        })

    return pd.DataFrame(rows)

def read_pcap_streaming(pcap_file):
    raw_data = []
    with PcapReader(pcap_file) as pcap:
        for pkt in pcap:
            raw_data.append(pkt)
    return raw_data

def aggregate_to_window(group):
    uplink = group[group['Direction'] == 'UPLINK']
    downlink = group[group['Direction'] == 'DOWNLINK']

    duration = group['Timestamp'].max() - group['Timestamp'].min()
    duration = duration if duration > 0 else 1e-6

    total_count = len(group)
    tcp_count = int(group['IsTCP'].sum())

    iat = group['Timestamp'].diff().dropna()
    mean_iat = float(iat.mean()) if len(iat) > 0 else 0.0
    var_iat = float(iat.var()) if len(iat) > 1 else 0.0

    uplink_count = len(uplink)
    downlink_count = len(downlink)

    uplink_bytes = int(uplink['PacketSize'].sum()) if uplink_count > 0 else 0
    downlink_bytes = int(downlink['PacketSize'].sum()) if downlink_count > 0 else 0

    def safe_mean(series):
        return float(series.mean()) if len(series) > 0 else 0.0

    def safe_var(series):
        return float(series.var()) if len(series) > 1 else 0.0

    total_bytes = uplink_bytes + downlink_bytes
    uplink_ratio_bytes = (uplink_bytes / total_bytes) if total_bytes > 0 else 0.0
    uplink_ratio_count = (uplink_count / total_count) if total_count > 0 else 0.0
    ratio_count_vs_bytes = (uplink_ratio_count / uplink_ratio_bytes) if uplink_ratio_bytes > 0 else 0.0

    uplink_iat = uplink['Timestamp'].diff().dropna()
    downlink_iat = downlink['Timestamp'].diff().dropna()

    features = {
        'WindowDuration': float(duration),
        'TotalPacketCount': int(total_count),
        'MeanIAT': mean_iat,
        'VarIAT': var_iat,
        'TCP_Ratio': (tcp_count / total_count) if total_count > 0 else 0.0,
        'Uplink_Count': int(uplink_count),
        'Uplink_TotalBytes': int(uplink_bytes),
        'Uplink_MeanPacketSize': safe_mean(uplink['PacketSize']),
        'Uplink_VarPacketSize': safe_var(uplink['PacketSize']),
        'Uplink_MeanEntropy': safe_mean(uplink['PayloadEntropy']),
        'Uplink_VarEntropy': safe_var(uplink['PayloadEntropy']),
        'Uplink_MeanIAT': float(uplink_iat.mean()) if len(uplink_iat) > 0 else 0.0,
        'Uplink_SumSYN': int(uplink['SYN_Flag'].sum()),
        'Uplink_SumACK': int(uplink['ACK_Flag'].sum()),
        'Uplink_SumRST': int(uplink['RST_Flag'].sum()),
        'Downlink_Count': int(downlink_count),
        'Downlink_TotalBytes': int(downlink_bytes),
        'Downlink_MeanPacketSize': safe_mean(downlink['PacketSize']),
        'Downlink_VarPacketSize': safe_var(downlink['PacketSize']),
        'Downlink_MeanEntropy': safe_mean(downlink['PayloadEntropy']),
        'Downlink_VarEntropy': safe_var(downlink['PayloadEntropy']),
        'Downlink_MeanIAT': float(downlink_iat.mean()) if len(downlink_iat) > 0 else 0.0,
        'Downlink_SumSYN': int(downlink['SYN_Flag'].sum()),
        'Downlink_SumACK': int(downlink['ACK_Flag'].sum()),
        'Downlink_SumRST': int(downlink['RST_Flag'].sum()),
        'Rate_pps': (total_count / duration) if duration > 0 else 0.0,
        'Rate_bps': ((total_bytes) * 8 / duration) if duration > 0 else 0.0,
        'Uplink_Ratio_Count': uplink_ratio_count,
        'Uplink_Ratio_Bytes': uplink_ratio_bytes,
        'Ratio_Count_vs_Bytes': ratio_count_vs_bytes
    }

    return pd.Series(features)

def generate_and_analyze_dataset():
    start_time = time.time()

    try:
        labels_df = pd.read_csv(GROUND_TRUTH_CSV, dtype=str)
        device_ips = set(labels_df['IP'].astype(str))
        ip_to_type = dict(zip(labels_df['IP'].astype(str), labels_df['DeviceType'].astype(str)))
        print(f"Nombres d'équipement mapper: {len(device_ips)} équipements à mapper.")
    except Exception as e:
        print("Erreur: impossible de charger ground_truth.csv ->", e)
        return

    pcap_file = find_first_pcap()
    if pcap_file is None:
        print("Aucun pcap trouvé dans output/. Génère la simulation ns-3 d'abord.")
        return
    print("PCAP détecté :", pcap_file)

    try:
        if USE_PCAP_READER:
            print("Lecture en streaming (PcapReader)...")
            packets = read_pcap_streaming(pcap_file)
        else:
            print("Chargement complet du PCAP en mémoire...")
            packets = rdpcap(pcap_file)
        print(f"Trace PCAP chargée : {len(packets)} paquets.")
    except Exception as e:
        print("Erreur lecture pcap :", e)
        return

    ap_ip_guess = determine_ap_ip(packets, device_ips)
    if ap_ip_guess:
        print("IP du point d'accès devinée :", ap_ip_guess)
    else:
        print("AP non deviné automatiquement. OK si ground_truth contient l'IP de l'AP.")

    raw_features = []
    for pkt in packets:
        if IP not in pkt:
            continue
        s = str(pkt[IP].src)
        d = str(pkt[IP].dst)
        if s in device_ips and d != s:
            direction = 'UPLINK'
            device_ip = s
        elif d in device_ips and s != d:
            direction = 'DOWNLINK'
            device_ip = d
        else:
            continue
        feats = extract_features_from_packet(pkt, device_ip, direction)
        raw_features.append(feats)

    df_packets = pd.DataFrame(raw_features)
    print(f"Extraction métadonnées : {len(df_packets)} paquets retenus.")

    if df_packets.empty:
        print("Aucun paquet utile extrait -> sortie.")
        summary_df = generate_device_summary(df_packets, device_ips, ip_to_type)
        summary_df.to_csv(OUTPUT_DEVICE_SUMMARY, index=False)
        print(f"Device summary (zeros) créé: {OUTPUT_DEVICE_SUMMARY}")
        return

    df_packets['DateTime'] = pd.to_datetime(df_packets['Timestamp'], unit='s')
    df_packets['Label'] = df_packets['DeviceIP'].map(ip_to_type)
    df_packets['Label_ID'] = df_packets['Label'].astype('category').cat.codes

    df_packets.to_csv(OUTPUT_PACKET_CSV, index=False)
    print(f"Packet-based sauvegardé: {OUTPUT_PACKET_CSV}")

    freq_str = f"{int(WINDOW_SIZE_SECONDS)}s"
    grouped = df_packets.groupby(['DeviceIP', pd.Grouper(key='DateTime', freq=freq_str)])
    agg = grouped.apply(aggregate_to_window).reset_index()
    agg = agg.rename(columns={'DateTime': 'WindowStart'})

    agg['Label'] = agg['DeviceIP'].map(ip_to_type)
    agg['Label_ID'] = agg['Label'].astype('category').cat.codes

    numeric_cols = agg.select_dtypes(include=[np.number]).columns.tolist()
    agg[numeric_cols] = agg[numeric_cols].fillna(0)

    if 'TotalPacketCount' in agg.columns:
        agg = agg[agg['TotalPacketCount'] > 0].reset_index(drop=True)

    agg.to_csv(OUTPUT_WINDOWED_CSV, index=False)
    print(f"Windowed dataset sauvegardé: {OUTPUT_WINDOWED_CSV} ({len(agg)} échantillons).")

    summary_df = generate_device_summary(df_packets, device_ips, ip_to_type)
    summary_df.to_csv(OUTPUT_DEVICE_SUMMARY, index=False)
    print(f"Device summary sauvegardé: {OUTPUT_DEVICE_SUMMARY} ({len(summary_df)} devices).")

    if not agg.empty:
        numeric_df = agg.select_dtypes(include=[np.number])
        if numeric_df.shape[0] > 0 and numeric_df.shape[1] > 1:
            corr = numeric_df.corr()
            plt.figure(figsize=(14,12))
            mask = np.triu(corr)
            sns.heatmap(corr, annot=False, cmap='coolwarm', mask=mask)
            plt.title('Matrice de corrélation')
            plt.tight_layout()
            plt.savefig(os.path.join(PLOT_DIR, 'correlation_matrix.png'))
            plt.close()
            print("Corrélation sauvegardée.")

        if 'Label' in agg.columns and not agg['Label'].isnull().all():
            plt.figure(figsize=(10,6))
            order = agg['Label'].value_counts().index
            sns.countplot(y='Label', data=agg, order=order)
            plt.title('Distribution par type')
            plt.tight_layout()
            plt.savefig(os.path.join(PLOT_DIR, 'distribution_labels.png'))
            plt.close()
            print("Distribution labels sauvegardée.")

    end_time = time.time()
    print(f"\n--- Processus terminé en {end_time - start_time:.2f} secondes. ---")

if __name__ == "__main__":
    generate_and_analyze_dataset()

