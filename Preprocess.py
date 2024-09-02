import pandas as pd
import os
import logging
from sklearn.preprocessing import LabelEncoder

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List all CSV files in the 'CSVs' folder
csv_folder = './CSVs'
csv_files = [file for file in os.listdir(csv_folder) if file.endswith('.csv')]

# Initialize an empty list to store DataFrames
dfs = []

# Set to store all unique columns
all_columns = set()

# First pass: Determine the union of all columns
for i, file in enumerate(csv_files):
    #logging.info(f"Reading columns of file {i+1}/{len(csv_files)}: {file}")
    try:
        df = pd.read_csv(os.path.join(csv_folder, file), encoding='latin1', low_memory=False, nrows=0)
        all_columns.update(df.columns.str.strip())
    except Exception as e:
        logging.error(f"Error reading file {file}: {e}")
        continue

all_columns = list(all_columns)
logging.info(f"shape of all columns: {len(all_columns)}")

# Second pass: Read the files again and align columns
for i, file in enumerate(csv_files):
    #logging.info(f"Processing file {i+1}/{len(csv_files)}: {file}")
    try:
        df = pd.read_csv(os.path.join(csv_folder, file), encoding='latin1', low_memory=False)
        df.columns = df.columns.str.strip()
        
        # Add missing columns with NaN values
        missing_cols = set(all_columns) - set(df.columns)
        for col in missing_cols:
            df[col] = pd.NA

        # Reorder columns to match the union of all columns
        df = df[all_columns]
        
        dfs.append(df)
        logging.info(f"DataFrame shape of {file}: {df.shape}")
    except Exception as e:
        logging.error(f"Error processing file {file}: {e}")
        continue

# Concatenate all DataFrames along rows (axis=0)
df = pd.concat(dfs, axis=0).reset_index(drop=True)

# Display the shape of the concatenated DataFrame
logging.info(f"Concatenated DataFrame shape: {df.shape}")

# Drop unnecessary column if it exists
if 'Fwd Header Length.1' in df.columns:
    df.drop(columns=['Fwd Header Length.1'], inplace=True)

# Identify categorical columns
categorical = df.select_dtypes(include=['object']).columns.tolist()
logging.info("Categorical variables:")
logging.info(categorical)

# Encode categorical variables except 'Label'
label_encoder = LabelEncoder()
for col in categorical:
    if col != 'Label':
        df[col] = df[col].astype(str)
        try:
            df[col] = label_encoder.fit_transform(df[col])
        except Exception as e:
            logging.error(f"Error encoding column {col}: {e}")

# Handle special values in 'Flow Bytes/s' and 'Flow Packets/s'
df["Flow Bytes/s"] = df["Flow Bytes/s"].replace({"Infinity": -1, "NaN": 0})
df["Flow Packets/s"] = df["Flow Packets/s"].replace({"Infinity": -1, "NaN": 0})

# Drop rows where 'Label' is NaN
df.dropna(subset=['Label'], inplace=True)
logging.info(f"Dropped rows with NaN in 'Label' column: {df.shape}")
# Normalize 'Label' values starting with 'W' to 'WebAttack'
df.loc[df['Label'].str.startswith('W'), 'Label'] = 'WebAttack'

# Save the cleaned DataFrame to a CSV file
output_file = os.path.join(csv_folder, 'all_data.csv')
df.to_csv(output_file, index=False)
logging.info(f"Cleaned data saved to {output_file}")
