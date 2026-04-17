import pandas as pd
import numpy as np
import os
import joblib
from sklearn.preprocessing import RobustScaler

def main():
    # Input/Output paths
    input_data_path = 'data/cicids_real.csv'
    output_data_path = 'data/processed_data.csv'
    scaler_path = 'models/weights/scaler.joblib'
    
    print(f"Loading data from {input_data_path}...")
    try:
        df = pd.read_csv(input_data_path)
    except FileNotFoundError:
        print(f"Error: Could not find {input_data_path}. Please ensure the file exists.")
        return

    # Load & Clean: Strip whitespace from column names
    print("Cleaning column names...")
    df.columns = df.columns.str.strip()

    # Handle NaN and Inf values
    print("Handling NaN and inf values...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    
    # Identify the 'Label' column
    label_col = 'Label'
    if label_col not in df.columns:
        print(f"Warning: '{label_col}' column not found in the dataset. Available columns: {df.columns.tolist()}")
        # You may need to handle this differently if your label column has a different name
        features = df
        labels = None
    else:
        # Separate features from labels
        labels = df[[label_col]].copy()
        features = df.drop(columns=[label_col])

    # Select only numeric columns for transformations
    numeric_cols = features.select_dtypes(include=[np.number]).columns
    
    print(f"Found {len(numeric_cols)} numeric columns to transform.")

    # Math - Log1p: Apply np.log1p() to all numeric features
    print("Applying Log1p transformation to numeric features...")
    # Using np.clip to prevent negative values from resulting in NaN (since log(-x) is undefined)
    # cicids data might have some negative values depending on prior handling, 
    # but normally log1p is applied to x >= -1.
    features[numeric_cols] = np.log1p(np.clip(features[numeric_cols], a_min=0, a_max=None))

    # Math - RobustScaler: Fit and transform
    print("Applying RobustScaler...")
    scaler = RobustScaler()
    features_scaled = scaler.fit_transform(features[numeric_cols])
    
    # Replace numeric columns with scaled versions and DROP non-numeric features
    # This ensures columns like 'Timestamp' are removed
    features = pd.DataFrame(features_scaled, columns=numeric_cols, index=features.index)

    # Recombine features with the label column
    if labels is not None:
        processed_df = pd.concat([features, labels], axis=1)
    else:
        processed_df = features

    # Ensure output directories exist
    os.makedirs(os.path.dirname(output_data_path), exist_ok=True)
    os.makedirs(os.path.dirname(scaler_path), exist_ok=True)

    # Export Scaler: Save fitted scaler to joblib
    print(f"Saving scaler to {scaler_path}...")
    joblib.dump(scaler, scaler_path)

    # Output Data: Save processed features to CSV
    print(f"Saving processed data to {output_data_path}...")
    processed_df.to_csv(output_data_path, index=False)
    
    print("Preprocessing completed successfully!")

if __name__ == "__main__":
    main()
