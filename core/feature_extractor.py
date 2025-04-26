import re
import ipaddress
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timedelta
from collections import Counter, defaultdict

from ..utils.logger import get_logger

logger = get_logger()


class FeatureExtractor:
    """Extracts features from normalized log data for ML processing."""
    
    def __init__(self):
        """Initialize the feature extractor."""
        self.numerical_features = [
            'hour_of_day',
            'is_weekend',
            'resource_access_count',
            'ip_activity_count',
            'user_activity_count',
            'status_is_error',
            'ip_entropy',
            'username_entropy'
        ]
        
        self.categorical_features = [
            'event_type',
            'action',
            'status'
        ]
        
        # Pre-compiled patterns
        self.ip_octet_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        
    def extract_features(self, logs: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Extract features from normalized logs.
        
        Args:
            logs: List of normalized log dictionaries
            
        Returns:
            Tuple of (DataFrame of extracted features, metadata dictionary)
        """
        if not logs:
            logger.warning("No logs provided for feature extraction")
            return pd.DataFrame(), {}
            
        # Create a DataFrame from the logs for easier processing
        df = pd.DataFrame(logs)
        
        # Initialize feature DataFrame
        features_df = pd.DataFrame()
        
        # Extract temporal features
        features_df = self._extract_temporal_features(df, features_df)
        
        # Extract IP-based features
        features_df = self._extract_ip_features(df, features_df)
        
        # Extract user-based features
        features_df = self._extract_user_features(df, features_df)
        
        # Extract resource-based features
        features_df = self._extract_resource_features(df, features_df)
        
        # Extract action and status features
        features_df = self._extract_action_status_features(df, features_df)
        
        # Extract text-based features
        features_df = self._extract_text_features(df, features_df)
        
        # Handle categorical features
        features_df = self._encode_categorical_features(df, features_df)
        
        # Fill NaN values
        features_df = features_df.fillna(0)
        
        # Collect metadata about the feature extraction
        metadata = {
            'feature_count': len(features_df.columns),
            'numerical_features': [col for col in features_df.columns if col in self.numerical_features],
            'categorical_features': [col for col in features_df.columns if col.startswith('categorical_')],
            'log_count': len(df),
            'extracted_at': datetime.now().isoformat()
        }
        
        logger.info(f"Extracted {len(features_df.columns)} features from {len(df)} logs")
        return features_df, metadata
    
    def _extract_temporal_features(self, logs_df: pd.DataFrame, features_df: pd.DataFrame) -> pd.DataFrame:
        """Extract time-based features.
        
        Args:
            logs_df: DataFrame of normalized logs
            features_df: Existing features DataFrame
            
        Returns:
            Updated features DataFrame
        """
        # Check if timestamp column exists and has data
        if 'timestamp' not in logs_df.columns or logs_df['timestamp'].isna().all():
            # Add empty columns for temporal features
            features_df['hour_of_day'] = 0
            features_df['is_weekend'] = 0
            logger.warning("No timestamp data available for temporal feature extraction")
            return features_df
            
        # Convert timestamp strings to datetime objects
        # Filter out None values first
        valid_timestamps = logs_df['timestamp'].dropna()
        if len(valid_timestamps) == 0:
            features_df['hour_of_day'] = 0
            features_df['is_weekend'] = 0
            return features_df
            
        try:
            # Parse timestamps
            timestamps = pd.to_datetime(valid_timestamps)
            
            # Extract hour of day (0-23)
            hour_of_day = timestamps.dt.hour.fillna(0).astype(int)
            features_df['hour_of_day'] = hour_of_day.reindex_like(logs_df['timestamp']).fillna(0).astype(int)
            
            # Is weekend (0 or 1)
            is_weekend = (timestamps.dt.dayofweek >= 5).astype(int)
            features_df['is_weekend'] = is_weekend.reindex_like(logs_df['timestamp']).fillna(0).astype(int)
            
            # Could add more temporal features here if needed
            
        except Exception as e:
            logger.error(f"Error extracting temporal features: {str(e)}")
            features_df['hour_of_day'] = 0
            features_df['is_weekend'] = 0
            
        return features_df
    
    def calculate_entropy(self, values: List[str]) -> float:
        """Calculate Shannon entropy for a list of values.
        
        Args:
            values: List of string values
            
        Returns:
            Shannon entropy as a float
        """
        if not values:
            return 0.0
            
        # Count occurrences of each value
        value_counts = Counter(values)
        
        # Calculate probabilities
        total = sum(value_counts.values())
        probabilities = [count / total for count in value_counts.values()]
        
        # Calculate entropy
        entropy = -sum(p * np.log2(p) for p in probabilities if p > 0)
        
        return entropy
    
    def _extract_ip_features(self, logs_df: pd.DataFrame, features_df: pd.DataFrame) -> pd.DataFrame:
        """Extract IP-based features.
        
        Args:
            logs_df: DataFrame of normalized logs
            features_df: Existing features DataFrame
            
        Returns:
            Updated features DataFrame
        """
        # Check if IP column exists
        if 'source_ip' not in logs_df.columns or logs_df['source_ip'].isna().all():
            features_df['ip_activity_count'] = 0
            features_df['ip_entropy'] = 0
            logger.warning("No source IP data available for IP feature extraction")
            return features_df
            
        try:
            # Count occurrences of each source IP
            ip_counts = logs_df['source_ip'].value_counts().to_dict()
            
            # Map each log entry to its source IP count
            features_df['ip_activity_count'] = logs_df['source_ip'].map(ip_counts).fillna(0)
            
            # Calculate entropy of source IPs
            ip_entropy = self.calculate_entropy(logs_df['source_ip'].dropna().tolist())
            features_df['ip_entropy'] = ip_entropy
            
            # Add more IP-based features here if needed
            
        except Exception as e:
            logger.error(f"Error extracting IP features: {str(e)}")
            features_df['ip_activity_count'] = 0
            features_df['ip_entropy'] = 0
            
        return features_df
    
    def _extract_user_features(self, logs_df: pd.DataFrame, features_df: pd.DataFrame) -> pd.DataFrame:
        """Extract user-based features.
        
        Args:
            logs_df: DataFrame of normalized logs
            features_df: Existing features DataFrame
            
        Returns:
            Updated features DataFrame
        """
        # Check if username column exists
        if 'username' not in logs_df.columns or logs_df['username'].isna().all():
            features_df['user_activity_count'] = 0
            features_df['username_entropy'] = 0
            logger.warning("No username data available for user feature extraction")
            return features_df
            
        try:
            # Count occurrences of each username
            user_counts = logs_df['username'].value_counts().to_dict()
            
            # Map each log entry to its username count
            features_df['user_activity_count'] = logs_df['username'].map(user_counts).fillna(0)
            
            # Calculate entropy of usernames
            username_entropy = self.calculate_entropy(logs_df['username'].dropna().tolist())
            features_df['username_entropy'] = username_entropy
            
            # Add more user-based features here if needed
            
        except Exception as e:
            logger.error(f"Error extracting user features: {str(e)}")
            features_df['user_activity_count'] = 0
            features_df['username_entropy'] = 0
            
        return features_df
    
    def _extract_resource_features(self, logs_df: pd.DataFrame, features_df: pd.DataFrame) -> pd.DataFrame:
        """Extract resource-based features.
        
        Args:
            logs_df: DataFrame of normalized logs
            features_df: Existing features DataFrame
            
        Returns:
            Updated features DataFrame
        """
        # Check if resource column exists
        if 'resource' not in logs_df.columns or logs_df['resource'].isna().all():
            features_df['resource_access_count'] = 0
            logger.warning("No resource data available for resource feature extraction")
            return features_df
            
        try:
            # Count occurrences of each resource
            resource_counts = logs_df['resource'].value_counts().to_dict()
            
            # Map each log entry to its resource count
            features_df['resource_access_count'] = logs_df['resource'].map(resource_counts).fillna(0)
            
            # Add more resource-based features here if needed
            
        except Exception as e:
            logger.error(f"Error extracting resource features: {str(e)}")
            features_df['resource_access_count'] = 0
            
        return features_df
    
    def _extract_action_status_features(self, logs_df: pd.DataFrame, features_df: pd.DataFrame) -> pd.DataFrame:
        """Extract action and status features.
        
        Args:
            logs_df: DataFrame of normalized logs
            features_df: Existing features DataFrame
            
        Returns:
            Updated features DataFrame
        """
        # Check for status column
        if 'status' in logs_df.columns and not logs_df['status'].isna().all():
            try:
                # Check if status indicates an error
                # Common error indicators: 'error', 'fail', 'failed', numeric codes >= 400
                def is_error_status(status):
                    if pd.isna(status):
                        return 0
                    status_str = str(status).lower()
                    
                    # Check for error keywords
                    if any(err in status_str for err in ['error', 'fail', 'failed', 'denied', 'reject']):
                        return 1
                        
                    # Check for numeric error codes (e.g., HTTP status codes)
                    if status_str.isdigit() and int(status_str) >= 400:
                        return 1
                        
                    return 0
                    
                features_df['status_is_error'] = logs_df['status'].apply(is_error_status)
                
            except Exception as e:
                logger.error(f"Error extracting status features: {str(e)}")
                features_df['status_is_error'] = 0
        else:
            features_df['status_is_error'] = 0
            
        return features_df
    
    def _extract_text_features(self, logs_df: pd.DataFrame, features_df: pd.DataFrame) -> pd.DataFrame:
        """Extract features from text fields.
        
        Args:
            logs_df: DataFrame of normalized logs
            features_df: Existing features DataFrame
            
        Returns:
            Updated features DataFrame
        """
        # This could include more advanced NLP features in a future version
        # For now, we'll keep it simple
        
        # Placeholder for future text-based features
        return features_df
    
    def _encode_categorical_features(self, logs_df: pd.DataFrame, features_df: pd.DataFrame) -> pd.DataFrame:
        """One-hot encode categorical features.
        
        Args:
            logs_df: DataFrame of normalized logs
            features_df: Existing features DataFrame
            
        Returns:
            Updated features DataFrame
        """
        for feature in self.categorical_features:
            if feature in logs_df.columns and not logs_df[feature].isna().all():
                try:
                    # Get top 10 most common values to avoid too many columns
                    top_values = logs_df[feature].value_counts().nlargest(10).index.tolist()
                    
                    # One-hot encode
                    for value in top_values:
                        col_name = f"categorical_{feature}_{value}"
                        features_df[col_name] = (logs_df[feature] == value).astype(int)
                        
                except Exception as e:
                    logger.error(f"Error encoding feature {feature}: {str(e)}")
                    
        return features_df
    
    def extract_from_single_log(self, log: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from a single log entry.
        
        Args:
            log: Single normalized log dictionary
            
        Returns:
            Dictionary of extracted features
        """
        # Create a single-row DataFrame
        df = pd.DataFrame([log])
        
        # Extract features
        features_df, _ = self.extract_features([log])
        
        # Convert to dictionary
        if len(features_df) == 0:
            return {}
            
        return features_df.iloc[0].to_dict()
    
    def combine_features(self, log_features: List[Dict[str, float]]) -> np.ndarray:
        """Combine features from multiple logs into a feature matrix.
        
        Args:
            log_features: List of feature dictionaries
            
        Returns:
            NumPy array of combined features
        """
        if not log_features:
            return np.array([])
            
        # Create a DataFrame from the list of feature dictionaries
        features_df = pd.DataFrame(log_features)
        
        # Fill missing values
        features_df = features_df.fillna(0)
        
        # Convert to numpy array
        return features_df.values 