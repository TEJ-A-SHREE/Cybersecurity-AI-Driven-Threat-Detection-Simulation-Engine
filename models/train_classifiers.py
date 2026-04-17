import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
from sklearn.metrics import classification_report

def main():
    # File paths
    input_data_path = 'data/processed_data.csv'
    iso_forest_path = 'models/weights/iso_forest.joblib'
    xgboost_path = 'models/weights/xgboost_model.json'
    label_encoder_path = 'models/weights/label_encoder.joblib'
    
    # Ensure models/weights exists
    os.makedirs(os.path.dirname(iso_forest_path), exist_ok=True)

    # Load Data: Load the processed CSV
    print(f"Loading processed data from {input_data_path}...")
    try:
        df = pd.read_csv(input_data_path)
    except FileNotFoundError:
        print(f"Error: Could not find {input_data_path}. Please run preprocess.py first.")
        return

    # Separate features and label
    if 'Label' not in df.columns:
        print("Error: 'Label' column not found in processed data.")
        return
        
    X = df.drop(columns=['Label'])
    y = df['Label']

    # LabelEncoder: Convert the 'Label' column (threat names) into numbers
    print("Encoding labels...")
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # Save the label encoder for inference
    joblib.dump(le, label_encoder_path)
    print(f"Label encoder saved to {label_encoder_path}")
    print(f"Classes found: {le.classes_.tolist()}")

    # Isolation Forest: Train an IsolationForest for general anomaly detection
    print("Training Isolation Forest for anomaly detection...")
    # Using default parameters suitable for network traffic (contamination can be tuned)
    iso_forest = IsolationForest(n_estimators=100, contamination='auto', random_state=42, n_jobs=-1)
    iso_forest.fit(X)
    
    # Save the Isolation Forest model
    print(f"Saving Isolation Forest to {iso_forest_path}...")
    joblib.dump(iso_forest, iso_forest_path)

    # XGBoost: Split the data (80% train, 20% test)
    print("Splitting data into training (80%) and testing (20%) sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded)

    # Train an XGBClassifier to identify specific attacks
    print("Training XGBoost Classifier...")
    # tree_method='hist' is faster for large datasets, especially on CPU.
    xgb_clf = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        objective='multi:softprob',
        random_state=42,
        tree_method='hist',
        n_jobs=-1
    )
    xgb_clf.fit(X_train, y_train)

    # Metrics: Print a classification_report
    print("\nModel Evaluation - Classification Report (Test Set):")
    y_pred = xgb_clf.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=le.classes_)
    print(report)

    # Export: Save the XGBoost model to JSON
    print(f"Saving XGBoost model to {xgboost_path}...")
    xgb_clf.save_model(xgboost_path)

    print("\nTraining completed successfully!")

if __name__ == "__main__":
    main()
