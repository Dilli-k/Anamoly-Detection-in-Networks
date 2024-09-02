import random
import pandas as pd
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to create folder if it doesn't exist
def create_folder(folder_name): 
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        logging.info(f'Created directory: {folder_name}')

# Create attacks folder
create_folder("./attacks/")

# List of attack types and benign count
attacks = ["Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator", "WebAttack"]
benign_count = 2359289

# Dictionary containing attack counts
attack_counts = {
    "Bot": 1966,
    "DDoS": 41835,
    "DoS GoldenEye": 10293,
    "DoS Hulk": 231073,
    "DoS Slowhttptest": 5499,
    "DoS slowloris": 5796,
    "FTP-Patator": 7938,
    "Heartbleed": 11,
    "Infiltration": 36,
    "PortScan": 158930,
    "SSH-Patator": 5897,
    "WebAttack": 2180,
}

# Read the entire CSV file into a DataFrame
csv_file = "./CSVs/all_data.csv"
df = pd.read_csv(csv_file)
logging.info(f'{df.shape} rows read from {csv_file}')

# Remove leading/trailing whitespaces from columns
df.columns = df.columns.str.strip()

# Iterate over each attack type
for attack in attacks:
    attack_df = df[df['Label'] == attack]
    benign_ratio = int( (attack_counts[attack] * 7)/3)
    benign_df = df[df['Label'] == 'BENIGN'].sample(n=benign_ratio, random_state=1)

    # Combine benign and attack DataFrames
    combined_df = pd.concat([benign_df, attack_df])

    # Save to CSV
    attack_file = f'./attacks/{attack}.csv'
    combined_df.to_csv(attack_file, index=False)
    logging.info(f"File {attack} is done with {len(attack_df)} attacks and {len(benign_df)} benign samples.")
