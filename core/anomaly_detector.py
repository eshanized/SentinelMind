import os
import numpy as np
import pandas as pd
import joblib
from typing import Dict, List, Any, Optional, Tuple, Union
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPRegressor
from sklearn.model_selection import train_test_split

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger()
config = get_config()


class AnomalyDetector:
    """Detects anomalies in security log data using ML techniques."""
    
    def __init__(self, model_type: str = "isolation_forest", load_model: bool = True):
        """Initialize the anomaly detector.
        
        Args:
            model_type: Type of model to use ('isolation_forest' or 'autoencoder')
            load_model: Whether to load a pre-existing model
        """
        self.model_type = model_type
        self.model = None
        self.scaler = None
        self.threshold = config.get("anomaly_threshold", 0.8)
        
        # Define model paths
        self.model_dir = config.get("models_dir", "models")
        os.makedirs(self.model_dir, exist_ok=True)
        
        self.model_path = os.path.join(self.model_dir, f"{model_type}_model.pkl")
        self.scaler_path = os.path.join(self.model_dir, f"{model_type}_scaler.pkl")
        
        # Try to load pre-existing model if requested
        if load_model:
            self.load_model()
    
    def load_model(self) -> bool:
        """Load a pre-trained model from disk.
        
        Returns:
            True if model loaded successfully, False otherwise
        """
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                logger.info(f"Loaded pre-trained {self.model_type} model from {self.model_path}")
                return True
            else:
                logger.warning(f"No pre-trained {self.model_type} model found at {self.model_path}")
                return False
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            return False
    
    def save_model(self) -> bool:
        """Save the trained model to disk.
        
        Returns:
            True if model saved successfully, False otherwise
        """
        try:
            if self.model is not None and self.scaler is not None:
                joblib.dump(self.model, self.model_path)
                joblib.dump(self.scaler, self.scaler_path)
                logger.info(f"Saved {self.model_type} model to {self.model_path}")
                return True
            else:
                logger.warning("No model to save")
                return False
        except Exception as e:
            logger.error(f"Error saving model: {str(e)}")
            return False
    
    def train(self, features: pd.DataFrame) -> None:
        """Train the anomaly detection model.
        
        Args:
            features: DataFrame of extracted features
            
        Raises:
            ValueError: If features DataFrame is empty
        """
        if features.empty:
            raise ValueError("Cannot train on empty feature set")
            
        try:
            # Initialize scaler and transform data
            self.scaler = StandardScaler()
            scaled_features = self.scaler.fit_transform(features)
            
            # Train based on model type
            if self.model_type == "isolation_forest":
                self._train_isolation_forest(scaled_features)
            elif self.model_type == "autoencoder":
                self._train_autoencoder(scaled_features)
            else:
                raise ValueError(f"Unsupported model type: {self.model_type}")
                
            # Save the trained model
            self.save_model()
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            raise
    
    def _train_isolation_forest(self, scaled_features: np.ndarray) -> None:
        """Train an Isolation Forest model.
        
        Args:
            scaled_features: Scaled feature array
        """
        logger.info("Training Isolation Forest model")
        
        # Configure model
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=0.1,  # Assume 10% of data is anomalous
            random_state=42,
            n_jobs=-1  # Use all available cores
        )
        
        # Train model
        self.model.fit(scaled_features)
        logger.info("Isolation Forest model training complete")
    
    def _train_autoencoder(self, scaled_features: np.ndarray) -> None:
        """Train an Autoencoder model (using MLP as approximation).
        
        Args:
            scaled_features: Scaled feature array
        """
        logger.info("Training Autoencoder model")
        
        # Split data for training and validation
        X_train, X_val = train_test_split(
            scaled_features, test_size=0.2, random_state=42
        )
        
        # Configure model
        # Using MLPRegressor as a simple autoencoder
        # In a real implementation, consider using PyTorch or TensorFlow
        input_dim = scaled_features.shape[1]
        hidden_dim = max(int(input_dim / 2), 1)  # At least 1 hidden unit
        
        self.model = MLPRegressor(
            hidden_layer_sizes=(hidden_dim,),
            activation='tanh',
            solver='adam',
            random_state=42,
            max_iter=1000,
            verbose=0
        )
        
        # Train to reconstruct the input
        self.model.fit(X_train, X_train)
        
        # Compute reconstruction errors on validation set to set threshold
        val_pred = self.model.predict(X_val)
        errors = np.mean(np.power(X_val - val_pred, 2), axis=1)
        
        # Set threshold at the 95th percentile of errors
        threshold_percentile = 95
        self.threshold = np.percentile(errors, threshold_percentile) if len(errors) > 0 else 0.5
        
        logger.info(f"Autoencoder model training complete, threshold set to {self.threshold}")
    
    def predict(self, features: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies in a set of log entries.
        
        Args:
            features: DataFrame of extracted features
            
        Returns:
            Tuple of (anomaly predictions, anomaly scores)
            
        Raises:
            ValueError: If model is not trained
        """
        if self.model is None or self.scaler is None:
            raise ValueError("Model not trained yet. Call train() first or load a pre-trained model.")
            
        if features.empty:
            return np.array([]), np.array([])
            
        try:
            # Scale features
            scaled_features = self.scaler.transform(features)
            
            # Predict based on model type
            if self.model_type == "isolation_forest":
                return self._predict_isolation_forest(scaled_features)
            elif self.model_type == "autoencoder":
                return self._predict_autoencoder(scaled_features)
            else:
                raise ValueError(f"Unsupported model type: {self.model_type}")
                
        except Exception as e:
            logger.error(f"Error predicting anomalies: {str(e)}")
            raise
    
    def _predict_isolation_forest(self, scaled_features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies using Isolation Forest.
        
        Args:
            scaled_features: Scaled feature array
            
        Returns:
            Tuple of (anomaly predictions, anomaly scores)
        """
        # Get raw anomaly scores (-1 to 1, with -1 being most anomalous)
        raw_scores = self.model.decision_function(scaled_features)
        
        # Convert to anomaly scores (0 to 1, with 1 being most anomalous)
        # Normalize scores to 0-1 range with 1 being most anomalous
        anomaly_scores = 1 - ((raw_scores + 1) / 2)
        
        # Classify based on threshold
        predictions = (anomaly_scores >= self.threshold).astype(int)
        
        return predictions, anomaly_scores
    
    def _predict_autoencoder(self, scaled_features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies using Autoencoder.
        
        Args:
            scaled_features: Scaled feature array
            
        Returns:
            Tuple of (anomaly predictions, anomaly scores)
        """
        # Get reconstructions
        reconstructions = self.model.predict(scaled_features)
        
        # Compute mean squared error for each sample
        mse = np.mean(np.power(scaled_features - reconstructions, 2), axis=1)
        
        # Normalize scores to 0-1 range with 1 being most anomalous
        # Use min-max scaling
        if len(mse) > 1:
            mse_min, mse_max = np.min(mse), np.max(mse)
            if mse_max > mse_min:
                anomaly_scores = (mse - mse_min) / (mse_max - mse_min)
            else:
                anomaly_scores = np.zeros_like(mse)
        else:
            # Single sample case
            anomaly_scores = np.array([0.5]) if len(mse) > 0 else np.array([])
            
        # Classify based on threshold
        predictions = (anomaly_scores >= self.threshold).astype(int)
        
        return predictions, anomaly_scores
    
    def predict_single(self, features: Dict[str, float]) -> Tuple[int, float]:
        """Predict anomaly for a single log entry.
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            Tuple of (anomaly prediction (0 or 1), anomaly score)
        """
        # Convert to DataFrame
        features_df = pd.DataFrame([features])
        
        # Fill missing values
        features_df = features_df.fillna(0)
        
        # Ensure all required columns are present
        if self.scaler is not None:
            feature_names = self.scaler.feature_names_in_
            for col in feature_names:
                if col not in features_df.columns:
                    features_df[col] = 0
            
            # Ensure columns are in the right order
            features_df = features_df[feature_names]
        
        # Make prediction
        predictions, scores = self.predict(features_df)
        
        # Return first (and only) prediction
        if len(predictions) > 0 and len(scores) > 0:
            return int(predictions[0]), float(scores[0])
        else:
            return 0, 0.0 