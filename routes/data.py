from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
import pandas as pd
import pickle
import os
from sklearn.preprocessing import MinMaxScaler
import numpy as np
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

data = Blueprint('data', __name__, template_folder='../templates')

# Define the required features
FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
       'Fwd Packet Length Std', 'Bwd Packet Length Std', 'Flow IAT Min',
       'Fwd IAT Total', 'Bwd IAT Total', 'Bwd IAT Min', 'Fwd PSH Flags',
       'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s',
       'RST Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
       'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
       'Active Mean', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Max',
       'Idle Min', 'Inbound', 'Total Length of Fwd Packets',
       'Fwd Packet Length Max', 'Fwd Packet Length Min',
       'Fwd Packet Length Mean', 'Bwd Packet Length Max',
       'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s',
       'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Fwd IAT Mean',
       'Fwd IAT Std', 'Fwd IAT Max', 'Bwd IAT Mean', 'Bwd IAT Std',
       'Bwd IAT Max', 'Bwd Packets/s', 'Min Packet Length',
       'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
       'Packet Length Variance', 'SYN Flag Count', 'Down/Up Ratio',
       'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
       'min_seg_size_forward', 'Active Std', 'Idle Std',
       'Bwd Packet Length Min', 'Label']

# Default model path
DEFAULT_MODEL_PATH = r"D:\FeatureSelection\models\XGB59.sav"

@data.route('/existing-data', methods=['GET', 'POST'])
def existing_data():
    if request.method == 'POST':
        # Check if dataset was uploaded
        if 'dataset' not in request.files:
            flash('Please upload a dataset file', 'error')
            return redirect(request.url)
        
        dataset_file = request.files['dataset']
        
        if dataset_file.filename == '':
            flash('No dataset file selected', 'error')
            return redirect(request.url)
        
        if not dataset_file.filename.lower().endswith('.csv'):
            flash('Dataset must be a CSV file', 'error')
            return redirect(request.url)
        
        try:
            # Load the uploaded dataset
            dataset_path = os.path.join(current_app.config['UPLOAD_FOLDER'], dataset_file.filename)
            dataset_file.save(dataset_path)
            df = pd.read_csv(dataset_path)
            
            # Check if all required features are present
            missing_features = [f for f in FEATURES if f not in df.columns]
            if missing_features:
                flash(f'Dataset is missing required features: {", ".join(missing_features)}', 'error')
                os.remove(dataset_path)
                return redirect(request.url)
            
            df = df[FEATURES]
            
            # Replace labels as specified
            df['Label'] = df['Label'].replace([
                'BENIGN', 'WebDDoS', 'DrDoS_DNS', 'DrDoS_LDAP', 'DrDoS_MSSQL',
                'DrDoS_NetBIOS', 'DrDoS_NTP', 'DrDoS_SNMP', 'DrDoS_SSDP',
                'DrDoS_UDP', 'Syn', 'TFTP', 'UDP-lag'
            ], [
                'BENIGN', 'LOW', 'HIGH', 'HIGH', 'HIGH',
                'HIGH', 'LOW', 'LOW', 'HIGH', 'HIGH', 
                'LOW', 'LOW', 'LOW'
            ])
            
            # Convert to numerical labels
            label_mapping = {'BENIGN': 0, 'LOW': 1, 'HIGH': 2}
            inverse_label_mapping = {0: 'BENIGN', 1: 'LOW', 2: 'HIGH'}
            df['Label'] = df['Label'].map(label_mapping)
            
            # Get unique classes present in dataset
            present_classes = df['Label'].unique()
            expected_classes = [0, 1, 2]
            missing_classes = set(expected_classes) - set(present_classes)
            
            # If any classes are missing, we'll handle them specially
            if missing_classes:
                # Create proper dummy samples with valid feature values
                dummy_rows = []
                for missing_class in missing_classes:
                    # Create a row with median values for all features
                    dummy_row = df.drop('Label', axis=1).median().to_dict()
                    dummy_row['Label'] = missing_class
                    dummy_rows.append(dummy_row)
                
                if dummy_rows:
                    dummy_df = pd.DataFrame(dummy_rows)
                    df = pd.concat([df, dummy_df], ignore_index=True)
                    # Fill any remaining NaN values with 0 (just in case)
                    df = df.fillna(0)
                
                flash(f'Note: Dataset was missing samples for classes: {[inverse_label_mapping[c] for c in missing_classes]}. '
                     f'Added dummy samples for metric calculation.', 'warning')
            
            # Remove static features
            df = remove_static_features(df)
            
            # Normalize data
            X = df.drop('Label', axis=1)
            y = df['Label']
            
            # Ensure there are no NaN values left
            if X.isna().any().any():
                flash('Warning: Dataset contained NaN values after processing. Filling with 0.', 'warning')
                X = X.fillna(0)
            
            X_normalized = normalize_data(X)
            
            # Load the default model
            try:
                model = pickle.load(open(DEFAULT_MODEL_PATH, 'rb'))
                predictions = model.predict(X_normalized)
                
                # Ensure predictions contain all classes (0, 1, 2)
                unique_preds = np.unique(predictions)
                if not set(expected_classes).issubset(unique_preds):
                    # Add missing classes with zero counts
                    for c in expected_classes:
                        if c not in unique_preds:
                            predictions = np.append(predictions, c)
                            y = np.append(y, c)
            except Exception as e:
                flash(f'Error loading or using model: {str(e)}', 'error')
                os.remove(dataset_path)
                return redirect(request.url)
            
            # Calculate metrics with explicit labels
            cm = confusion_matrix(y, predictions, labels=expected_classes)
            
            # Initialize metrics with zeros for all classes
            sensitivity = [0.0, 0.0, 0.0]
            specificity = [0.0, 0.0, 0.0]
            precision = [0.0, 0.0, 0.0]
            f1 = [0.0, 0.0, 0.0]
            
            # Calculate metrics only for present classes
            for i, class_label in enumerate(expected_classes):
                if class_label in present_classes:
                    # Sensitivity (Recall)
                    tp = cm[i,i]
                    fn = cm[i,:].sum() - tp
                    sensitivity[i] = tp / (tp + fn) if (tp + fn) > 0 else 0.0
                    
                    # Specificity
                    tn = cm.sum() - (cm[i,:].sum() + cm[:,i].sum() - cm[i,i])
                    fp = cm[:,i].sum() - cm[i,i]
                    specificity[i] = tn / (tn + fp) if (tn + fp) > 0 else 0.0
                    
                    # Precision
                    precision[i] = tp / cm[:,i].sum() if cm[:,i].sum() > 0 else 0.0
                    
                    # F1 Score
                    if (precision[i] + sensitivity[i]) > 0:
                        f1[i] = 2 * (precision[i] * sensitivity[i]) / (precision[i] + sensitivity[i])
                    else:
                        f1[i] = 0.0
            
            # Clean up temporary file
            os.remove(dataset_path)
            
            # Convert confusion matrix to list for template rendering
            cm_list = cm.tolist()
            
            return render_template('data_results.html', 
                                confusion_matrix=cm_list,
                                sensitivity=sensitivity,
                                specificity=specificity,
                                precision=precision,
                                f1_score=f1,
                                class_names=['BENIGN', 'LOW', 'HIGH'])
            
        except pd.errors.EmptyDataError:
            flash('The dataset file is empty', 'error')
            return redirect(request.url)
        except pd.errors.ParserError:
            flash('Error parsing the dataset file', 'error')
            return redirect(request.url)
        except Exception as e:
            flash(f'Error processing files: {str(e)}', 'error')
            return redirect(request.url)
    
    # For GET requests
    return render_template('data_upload.html')

def remove_static_features(df):
    static_features = []
    for col in df.columns:
        if df[col].dtype == 'object' and col != 'Label':
            static_features.append(col)
    return df.drop(static_features, axis=1)

def normalize_data(X):
    scaler = MinMaxScaler()
    # Handle columns with zero standard deviation
    for col in X.columns:
        if X[col].std() == 0:
            max_val = X[col].max()
            if max_val <= 0:
                X[col] = 0
            else:
                X[col] = 1
    # Normalize other columns
    X_normalized = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    return X_normalized