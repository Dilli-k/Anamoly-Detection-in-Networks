# Define the feature sets for each category
features = {
    'PortScan': ['Total Length of Fwd Packets', 'Flow Bytes/s', 'Subflow Fwd Bytes', 'PSH Flag Count', 'Bwd Packets/s'],
    'SSH-Patator': ['Init_Win_bytes_backward', 'Bwd Header Length', 'Bwd Packets/s', 'min_seg_size_forward', 'Fwd Packet Length Max'],
    'Infiltration': ['Subflow Fwd Bytes', 'Total Length of Fwd Packets', 'Avg Fwd Segment Size', 'Fwd Packet Length Mean', 'Fwd IAT Min'],
    'FTP-Patator': ['Average Packet Size', 'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Packet Length Variance', 'Fwd Packet Length Std'],
    'WebAttack': ['Init_Win_bytes_backward', 'Subflow Fwd Bytes', 'min_seg_size_forward', 'Total Length of Fwd Packets', 'Init_Win_bytes_forward'],
    'Heartbleed': ['Total Length of Bwd Packets', 'Packet Length Variance', 'Avg Bwd Segment Size', 'Bwd Packet Length Max', 'Fwd Packet Length Max'],
    'Bot': ['Bwd Packet Length Mean', 'Avg Bwd Segment Size', 'Init_Win_bytes_forward', 'Bwd IAT Min', 'Fwd Header Length'],
    'DoS Slowhttptest': ['Flow Packets/s', 'Flow IAT Mean', 'Fwd Packet Length Min', 'Init_Win_bytes_backward', 'Bwd Packet Length Mean'],
    'DoS slowloris': ['Flow IAT Mean', 'Bwd Packet Length Mean', 'Avg Bwd Segment Size', 'min_seg_size_forward', 'SYN Flag Count'],
    'DoS Hulk': ['Bwd Packet Length Std', 'Average Packet Size', 'Bwd Packets/s', 'Init_Win_bytes_forward', 'Fwd Packet Length Std'],
    'DoS GoldenEye': ['Flow IAT Max', 'min_seg_size_forward', 'Bwd Packet Length Std', 'Flow IAT Min', 'Init_Win_bytes_backward'],
    'DDoS': ['Bwd Packet Length Std', 'act_data_pkt_fwd', 'Subflow Bwd Packets', 'Total Backward Packets', 'Fwd IAT Total'],
}

# Count the frequency of each feature
feature_counts = {}
for feature_list in features.values():
    for feature in feature_list:
        if feature in feature_counts:
            feature_counts[feature] += 1
        else:
            feature_counts[feature] = 1

# Sort features by frequency in decreasing order
sorted_features = sorted(feature_counts.items(), key=lambda x: x[1], reverse=True)

# Print the number of unique features
print(f"Number of unique features: {len(feature_counts)}")

lis = []
# Print the union of all features sorted by frequency
print("Union of all features (sorted by frequency):")
for feature, count in sorted_features:
    if(count>1):
        lis.append(feature)
print(len(lis))
print(lis)
