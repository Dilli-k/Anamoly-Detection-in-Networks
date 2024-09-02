import pandas as pd
import os
import logging
import matplotlib.pyplot as plt
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def bar_graph(x_values, y_values, x_label, y_label, title='', file_name=''):
    plt.figure(figsize=(10, 5))
    plt.bar(x_values, y_values)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    if title:
        plt.title(title)
    if file_name:
        plt.savefig(file_name)
    plt.show()

# Load the data
csv_folder = './CSVs'
file_path = os.path.join(csv_folder, 'all_data.csv')

try:
    df = pd.read_csv(file_path, usecols=['Label'])
    logging.info(f"Data loaded successfully from {file_path}")
except Exception as e:
    logging.error(f"Error loading data from {file_path}: {e}")
    raise

# Get value counts of the 'Label' column
label_counts = df['Label'].value_counts()
logging.info(f"Label counts:\n{label_counts}")

# Separate labels into categories based on counts
small_labels = label_counts[label_counts < 1000]
medium_labels = label_counts[(label_counts >= 1000) & (label_counts < 10000)]
large_labels = label_counts[label_counts >= 10000]

# Plot and save the graphs
output_folder = './graphs'
os.makedirs(output_folder, exist_ok=True)

bar_graph(small_labels.index, small_labels.values, 'Label', 'Count', 'Small Labels', os.path.join(output_folder, 'small_labels.png'))
bar_graph(medium_labels.index, medium_labels.values, 'Label', 'Count', 'Medium Labels', os.path.join(output_folder, 'medium_labels.png'))
bar_graph(large_labels.index, large_labels.values, 'Label', 'Count', 'Large Labels', os.path.join(output_folder, 'large_labels.png'))
