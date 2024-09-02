from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, AdaBoostClassifier
from sklearn.discriminant_analysis import QuadraticDiscriminantAnalysis as QDA
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, average_precision_score

import pandas as pd
import numpy as np
import os
import logging
import time
import matplotlib.pyplot as plt
import csv
from statsmodels.stats.outliers_influence import variance_inflation_factor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

csv_files = ['all_data.csv']

def create_folder(folder_name):
    try:
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
    except OSError as e:
        logging.error(f"Error: Failed to create the directory {folder_name}. Exception: {e}")

# Create necessary folders
create_folder('./results/')
folder_name = './results/result_graph_2/'
create_folder(folder_name)

def calculate_vif(X, thresh=5.0, max_iter=10):
    """
    Calculate the Variance Inflation Factor (VIF) for each feature and return
    the features with VIF below the threshold. Limit the number of iterations
    to avoid excessive computation time.
    """
    variables = X.columns
    iteration = 0

    while iteration < max_iter:
        vif = pd.DataFrame()
        vif["VIF"] = [variance_inflation_factor(X[variables].values, i) for i in range(len(variables))]
        vif["variable"] = variables

        # Check for infinite VIF values and handle them
        if any(vif["VIF"] == np.inf):
            drop_variables = vif[vif["VIF"] == np.inf]["variable"].values
            variables = variables.drop(drop_variables)
            logging.info(f"Dropping {drop_variables} with VIF=inf due to perfect collinearity")
        else:
            max_vif = vif["VIF"].max()
            if max_vif > thresh:
                drop_variable = vif.sort_values("VIF", ascending=False)["variable"].values[0]
                variables = variables.drop(drop_variable)
                logging.info(f"Dropping {drop_variable} with VIF={max_vif}")
            else:
                break

        iteration += 1

    if iteration >= max_iter:
        logging.warning("Max iterations reached. Some features might still have high VIF.")

    return X[variables]

# The ml attacks need to perform
ml_list = {
    "Naive Bayes": GaussianNB(),
    "QDA": QDA(),
    "Random Forest": RandomForestClassifier(max_depth=5, n_estimators=10, max_features=1),
    "ID3": DecisionTreeClassifier(max_depth=5, criterion="entropy"),
    "AdaBoost": AdaBoostClassifier(algorithm='SAMME'),
    "MLP": MLPClassifier(hidden_layer_sizes=(13, 13, 13), max_iter=500),
    "Nearest Neighbors": KNeighborsClassifier(3)
}

features = ['Bwd IAT Min', 'Fwd IAT Min', 'Fwd Packet Length Mean', 'PSH Flag Count', 'Fwd Packet Length Std', 'Fwd IAT Total', 'Total Backward Packets', 'Bwd Packet Length Mean', 'Packet Length Variance', 'Fwd Packet Length Min', 'Flow IAT Max', 'Bwd Header Length', 'Flow Bytes/s', 'Avg Bwd Segment Size', 'Bwd Packets/s', 'Fwd Packet Length Max', 
'Bwd Packet Length Std', 'Init_Win_bytes_forward', 'Flow Packets/s', 'Total Length of Fwd Packets', 'Init_Win_bytes_backward', 'min_seg_size_forward', 'SYN Flag Count', 'Subflow Fwd Bytes', 'Total Length of Bwd Packets', 'Fwd Header Length', 'Subflow Bwd Packets', 'act_data_pkt_fwd', 'Avg Fwd Segment Size', 'Bwd Packet Length Max', 'Flow IAT Mean'
, 'Flow IAT Min', 'Average Packet Size','Label']

result_path = './results/result_graph_2/results.csv'
repetition = 10

start_time = time.time()

with open(result_path, "w", newline="", encoding="utf-8") as result_file:
    writer = csv.writer(result_file)
    writer.writerow(["File", "ML algorithm", "Avg Accuracy", "Avg Precision", "Avg Recall", "Avg F1-score", "Avg Time"])

    for j in csv_files:
        logging.info(f"Processing file: {j}")
        print('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % ("File", "ML algorithm", "Avg Accuracy", "Avg Precision", "Avg Recall", "Avg F1-score", "Avg Time"))
        
        
        df = pd.read_csv(f'./CSVs/{j}', usecols=features)
        df = df.fillna(0)
        
        # Replace infinities and large values with finite values
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        df[numeric_columns] = df[numeric_columns].replace([np.inf, -np.inf], np.nan)
        df.fillna(df[numeric_columns].max().max(), inplace=True)
        
        df["Label"] = df["Label"].apply(lambda x: 1 if x == "BENIGN" else 0)
        y = df["Label"]
        X = df.drop("Label", axis=1)
        
        # Remove collinear features
        X = calculate_vif(X)
        
        for algo_name, algo in ml_list.items():
            logging.info(f"Running {algo_name} on {j}")
            
            precision_scores = []
            recall_scores = []
            f1_scores = []
            accuracy_scores = []
            times = []
            
            for _ in range(repetition):
                split_start_time = time.time()
                
                X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=repetition)
                
                algo.fit(X_train, y_train)
                predictions = algo.predict(X_test)
                
                accuracy_scores.append(accuracy_score(y_test, predictions))
                precision_scores.append(precision_score(y_test, predictions, average='macro', zero_division=0))
                recall_scores.append(recall_score(y_test, predictions, average='macro', zero_division=0))
                f1_scores.append(f1_score(y_test, predictions, average='macro', zero_division=0))
                times.append(time.time() - split_start_time)
            
            avg_accuracy = np.mean(accuracy_scores)
            avg_precision = np.mean(precision_scores)
            avg_recall = np.mean(recall_scores)
            avg_f1 = np.mean(f1_scores)
            avg_time = np.mean(times)
            
            
            print('%-17s %-17s  %-15s %-15s %-15s %-15s %-15s' % (
                j[:-4], algo_name, round(avg_accuracy, 2), round(avg_precision, 2),
                round(avg_recall, 2), round(avg_f1, 2),
                round(avg_time, 4)
            ))
            
            writer.writerow([j[:-4], algo_name, avg_accuracy, avg_precision, avg_recall, avg_f1, avg_time])
        
        # Plotting the box plots
        fig, axes = plt.subplots(nrows=2, ncols=4, figsize=(12, 6), sharey=True)
        for idx, algo_name in enumerate(ml_list.keys()):
            row, col = divmod(idx, 4)
            axes[row, col].boxplot(f1_scores)
            axes[row, col].set_title(f"{j[:-4]} - {algo_name}", fontsize=7)
            axes[row, col].set_ylabel("F measure")
        
        plt.savefig(f'{folder_name}/{j[:-4]}.pdf', bbox_inches='tight', format='pdf')

        plt.close()
        
        logging.info(f"Completed processing of {j}")
        print("\n------------------------------------------------------------------------------------------------------\n\n")
    
logging.info(f"Mission accomplished! Total operation time: {time.time() - start_time} seconds")
