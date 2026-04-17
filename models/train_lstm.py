import torch
import torch.nn as nn
import pandas as pd
import numpy as np
import os
from torch.utils.data import DataLoader, Dataset
from tqdm import tqdm

# --- 1. Dataset & Sequencing ---

class SequenceDataset(Dataset):
    def __init__(self, data, window_size=10):
        self.data = torch.tensor(data.values, dtype=torch.float32)
        self.window_size = window_size

    def __len__(self):
        return len(self.data) - self.window_size + 1

    def __getitem__(self, idx):
        return self.data[idx : idx + self.window_size]

def create_sequences(df, window_size=10):
    """
    Filter for Benign traffic and create sliding window sequences.
    """
    print("Filtering for Benign traffic...")
    benign_df = df[df['Label'] == 'Benign'].drop(columns=['Label'])
    
    print(f"Creating sequences of length {window_size}...")
    dataset = SequenceDataset(benign_df, window_size)
    return dataset

# --- 2. Architecture: LSTM Autoencoder ---

class Encoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, latent_dim):
        super(Encoder, self).__init__()
        self.lstm1 = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.lstm2 = nn.LSTM(hidden_dim, latent_dim, batch_first=True)

    def forward(self, x):
        x, _ = self.lstm1(x)
        # We only need the last hidden state for the bottleneck
        _, (last_hidden, _) = self.lstm2(x)
        return last_hidden.squeeze(0)

class Decoder(nn.Module):
    def __init__(self, latent_dim, hidden_dim, output_dim, window_size):
        super(Decoder, self).__init__()
        self.window_size = window_size
        self.lstm1 = nn.LSTM(latent_dim, hidden_dim, batch_first=True)
        self.lstm2 = nn.LSTM(hidden_dim, output_dim, batch_first=True)

    def forward(self, x):
        # Repeat the latent vector for each time step in the window
        x = x.unsqueeze(1).repeat(1, self.window_size, 1)
        x, _ = self.lstm1(x)
        x, _ = self.lstm2(x)
        return x

class LSTMAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, latent_dim=32, window_size=10):
        super(LSTMAutoencoder, self).__init__()
        self.encoder = Encoder(input_dim, hidden_dim, latent_dim)
        self.decoder = Decoder(latent_dim, hidden_dim, input_dim, window_size)

    def forward(self, x):
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction

# --- 3. Inference Logic: Reconstruction Error ---

def calculate_reconstruction_error(model, sequence_tensor):
    """
    Calculates MSE for a single sequence or batch of sequences.
    Flag as anomaly if error > threshold.
    """
    model.eval()
    with torch.no_grad():
        reconstruction = model(sequence_tensor)
        mse = torch.mean((sequence_tensor - reconstruction) ** 2, dim=(1, 2))
    return mse.cpu().numpy()

# --- 4. Training Loop ---

def train_model(model, dataloader, num_epochs=10, learning_rate=1e-3, device='cpu'):
    model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()
    
    print(f"Starting training on {device}...")
    model.train()
    
    for epoch in range(num_epochs):
        total_loss = 0
        loop = tqdm(dataloader, leave=True)
        for batch in loop:
            batch = batch.to(device)
            
            # Forward pass
            output = model(batch)
            loss = criterion(output, batch)
            
            # Backward pass
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            loop.set_description(f"Epoch [{epoch+1}/{num_epochs}]")
            loop.set_postfix(loss=loss.item())
            
        avg_loss = total_loss / len(dataloader)
        print(f"Epoch {epoch+1} completed. Average Loss: {avg_loss:.6f}")

def main():
    # Paths
    data_path = 'data/processed_data.csv'
    model_save_path = 'models/weights/lstm_v1.pth'
    os.makedirs(os.path.dirname(model_save_path), exist_ok=True)

    # Load Data
    print(f"Loading data from {data_path}...")
    df = pd.read_csv(data_path)
    
    # Prepare Sequences
    window_size = 10
    dataset = create_sequences(df, window_size)
    
    # Check if we have enough data
    if len(dataset) == 0:
        print("Error: No benign traffic found or dataset too small for window size.")
        return

    dataloader = DataLoader(dataset, batch_size=128, shuffle=True)
    
    # Initialize Model
    input_dim = df.shape[1] - 1 # Excluding Label
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = LSTMAutoencoder(input_dim=input_dim, window_size=window_size)
    
    # Train
    train_model(model, dataloader, num_epochs=5, device=device) # Reduced epochs for speed, increase if needed
    
    # Save Model
    print(f"Saving LSTM Autoencoder weights to {model_save_path}...")
    torch.save(model.state_dict(), model_save_path)
    
    print("LSTM Training Pipeline Completed!")

if __name__ == "__main__":
    main()
