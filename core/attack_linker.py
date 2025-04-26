import json
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger()
config = get_config()


class AttackLinker:
    """Links detected anomalies into potential attack chains."""
    
    # MITRE ATT&CK techniques and patterns
    MITRE_TECHNIQUES = {
        "initial_access": {
            "id": "TA0001",
            "patterns": [
                {"event_type": "authentication", "status": "fail"},
                {"action": "login", "status": "fail"}
            ]
        },
        "execution": {
            "id": "TA0002",
            "patterns": [
                {"event_type": "process_execution"},
                {"action": "execute"},
                {"action": "run"}
            ]
        },
        "persistence": {
            "id": "TA0003",
            "patterns": [
                {"action": "create", "resource": "service"},
                {"action": "create", "resource": "scheduled_task"},
                {"action": "modify", "resource": "registry"}
            ]
        },
        "privilege_escalation": {
            "id": "TA0004",
            "patterns": [
                {"action": "sudo"},
                {"action": "su"},
                {"event_type": "admin_login"}
            ]
        },
        "defense_evasion": {
            "id": "TA0005",
            "patterns": [
                {"action": "delete", "resource": "log"},
                {"action": "disable", "resource": "security"},
                {"action": "uninstall", "resource": "antivirus"}
            ]
        },
        "credential_access": {
            "id": "TA0006",
            "patterns": [
                {"action": "dump"},
                {"action": "access", "resource": "password"},
                {"resource": "credential"}
            ]
        },
        "discovery": {
            "id": "TA0007",
            "patterns": [
                {"action": "scan"},
                {"action": "list"},
                {"action": "enumerate"}
            ]
        },
        "lateral_movement": {
            "id": "TA0008",
            "patterns": [
                {"action": "ssh"},
                {"action": "connect", "resource": "remote"},
                {"action": "rdp"}
            ]
        },
        "collection": {
            "id": "TA0009",
            "patterns": [
                {"action": "download"},
                {"action": "copy"},
                {"action": "archive"}
            ]
        },
        "exfiltration": {
            "id": "TA0010",
            "patterns": [
                {"action": "upload"},
                {"action": "transfer"},
                {"action": "ftp"}
            ]
        }
    }
    
    def __init__(self, time_window: Optional[int] = None):
        """Initialize the attack linker.
        
        Args:
            time_window: Time window in seconds for correlating events (default from config)
        """
        self.time_window = time_window or config.get("attack_chain_time_window", 3600)
        
    def _match_mitre_technique(self, anomaly: Dict[str, Any]) -> List[str]:
        """Match an anomaly against MITRE ATT&CK techniques.
        
        Args:
            anomaly: Anomaly dictionary
            
        Returns:
            List of matching MITRE technique IDs
        """
        matching_techniques = []
        
        # Extract relevant fields
        event_type = anomaly.get('event_type')
        action = anomaly.get('action')
        resource = anomaly.get('resource')
        status = anomaly.get('status')
        
        # Check each technique
        for technique_name, technique_info in self.MITRE_TECHNIQUES.items():
            technique_id = technique_info['id']
            
            # Check each pattern for the technique
            for pattern in technique_info['patterns']:
                match = True
                
                # Check if all fields in the pattern match the anomaly
                for field, value in pattern.items():
                    if field not in anomaly or anomaly[field] != value:
                        match = False
                        break
                
                # If all fields match, add the technique
                if match:
                    matching_techniques.append(technique_id)
                    break  # Only add each technique once
        
        return matching_techniques
    
    def cluster_anomalies(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Cluster anomalies into potential attack chains.
        
        Args:
            anomalies: List of anomaly dictionaries with timestamps
            
        Returns:
            List of attack chain dictionaries
        """
        if not anomalies:
            return []
            
        # Sort anomalies by timestamp
        try:
            sorted_anomalies = sorted(
                anomalies, 
                key=lambda x: datetime.fromisoformat(x['timestamp']) if x.get('timestamp') else datetime.min
            )
        except (ValueError, TypeError) as e:
            logger.error(f"Error sorting anomalies by timestamp: {str(e)}")
            # If sorting fails, use the original order
            sorted_anomalies = anomalies
        
        # Group anomalies by source IP or username
        ip_groups = defaultdict(list)
        username_groups = defaultdict(list)
        
        for anomaly in sorted_anomalies:
            if anomaly.get('source_ip'):
                ip_groups[anomaly['source_ip']].append(anomaly)
            if anomaly.get('username'):
                username_groups[anomaly['username']].append(anomaly)
        
        # Create attack chains from IP groups
        ip_chains = self._create_chains_from_groups(ip_groups, "IP")
        
        # Create attack chains from username groups
        username_chains = self._create_chains_from_groups(username_groups, "Username")
        
        # Combine and deduplicate chains
        all_chains = ip_chains + username_chains
        
        # Sort chains by severity and confidence
        sorted_chains = sorted(
            all_chains, 
            key=lambda x: (x['severity'], x['confidence']), 
            reverse=True
        )
        
        return sorted_chains
    
    def _create_chains_from_groups(self, groups: Dict[str, List[Dict[str, Any]]], group_type: str) -> List[Dict[str, Any]]:
        """Create attack chains from grouped anomalies.
        
        Args:
            groups: Dictionary of anomaly groups (key: IP or username, value: list of anomalies)
            group_type: Type of grouping ("IP" or "Username")
            
        Returns:
            List of attack chain dictionaries
        """
        chains = []
        
        for group_key, group_anomalies in groups.items():
            # Skip groups with only one anomaly (need at least 2 to form a chain)
            if len(group_anomalies) < 2:
                continue
                
            # Find time-correlated chains within the group
            window_chains = self._find_time_windows(group_anomalies)
            
            # Create a chain for each window
            for window_index, window_anomalies in enumerate(window_chains):
                if not window_anomalies:
                    continue
                    
                # Get anomaly IDs
                anomaly_ids = [a.get('id') for a in window_anomalies if a.get('id')]
                
                # Skip if no valid IDs
                if not anomaly_ids:
                    continue
                
                # Get timestamps for chain range
                start_time = min(
                    datetime.fromisoformat(a['timestamp']) 
                    for a in window_anomalies 
                    if a.get('timestamp')
                )
                end_time = max(
                    datetime.fromisoformat(a['timestamp']) 
                    for a in window_anomalies 
                    if a.get('timestamp')
                )
                
                # Calculate severity and confidence
                # Severity = max anomaly severity, confidence based on techniques
                severity = max(a.get('severity', 0) for a in window_anomalies)
                
                # Identify MITRE techniques
                mitre_techniques = set()
                for anomaly in window_anomalies:
                    mitre_techniques.update(self._match_mitre_technique(anomaly))
                
                # Calculate confidence based on number of techniques and anomalies
                confidence = min(0.3 + (len(mitre_techniques) * 0.2) + (len(window_anomalies) * 0.05), 1.0)
                
                # Create chain name
                if group_type == "IP":
                    entity = f"IP {group_key}"
                else:
                    entity = f"user {group_key}"
                
                chain_name = f"Potential attack chain by {entity}"
                if mitre_techniques:
                    techniques_str = ", ".join(sorted(mitre_techniques))
                    chain_name += f" ({techniques_str})"
                
                # Create chain record
                chain = {
                    'name': chain_name,
                    'anomaly_ids': anomaly_ids,
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat(),
                    'entity_type': group_type,
                    'entity_value': group_key,
                    'severity': severity,
                    'confidence': confidence,
                    'mitre_techniques': sorted(mitre_techniques),
                    'anomaly_count': len(window_anomalies)
                }
                
                chains.append(chain)
        
        return chains
    
    def _find_time_windows(self, anomalies: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Find time-correlated windows of anomalies.
        
        Args:
            anomalies: List of anomalies
            
        Returns:
            List of lists of anomalies within time windows
        """
        result = []
        
        # Sort anomalies by timestamp
        sorted_anomalies = sorted(
            [a for a in anomalies if a.get('timestamp')],
            key=lambda x: datetime.fromisoformat(x['timestamp'])
        )
        
        if not sorted_anomalies:
            return result
        
        current_window = [sorted_anomalies[0]]
        current_end = datetime.fromisoformat(sorted_anomalies[0]['timestamp'])
        
        for anomaly in sorted_anomalies[1:]:
            # Parse timestamp
            timestamp = datetime.fromisoformat(anomaly['timestamp'])
            
            # Check if within time window
            if (timestamp - current_end).total_seconds() <= self.time_window:
                # Add to current window
                current_window.append(anomaly)
                current_end = max(current_end, timestamp)
            else:
                # Save current window and start a new one
                if len(current_window) >= 2:  # Only keep windows with at least 2 anomalies
                    result.append(current_window)
                current_window = [anomaly]
                current_end = timestamp
        
        # Add the last window if it has at least 2 anomalies
        if len(current_window) >= 2:
            result.append(current_window)
        
        return result
    
    def evaluate_chain_risk(self, chain: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate the risk level of an attack chain.
        
        Args:
            chain: Attack chain dictionary
            
        Returns:
            Dictionary with updated risk assessment
        """
        # Start with the base values
        updated_chain = chain.copy()
        
        # Adjust severity based on MITRE techniques
        technique_count = len(chain.get('mitre_techniques', []))
        
        # Higher risk for more techniques (indicates a more complex attack)
        if technique_count >= 3:
            # Multiple techniques indicate a sophisticated attack
            updated_chain['severity'] = min(updated_chain['severity'] + 0.1, 1.0)
            updated_chain['risk_level'] = 'critical' if updated_chain['severity'] > 0.8 else 'high'
        elif technique_count >= 1:
            updated_chain['risk_level'] = 'high' if updated_chain['severity'] > 0.7 else 'medium'
        else:
            updated_chain['risk_level'] = 'medium' if updated_chain['severity'] > 0.6 else 'low'
        
        # Add risk factors list
        risk_factors = []
        
        # Check for specific high-risk techniques
        high_risk_tactics = {'TA0006', 'TA0008', 'TA0010'}  # credential access, lateral movement, exfiltration
        if any(tech in high_risk_tactics for tech in chain.get('mitre_techniques', [])):
            risk_factors.append("High-risk MITRE ATT&CK techniques detected")
        
        # Check time span - quick attacks may be more automated/dangerous
        if 'start_time' in chain and 'end_time' in chain:
            try:
                start = datetime.fromisoformat(chain['start_time'])
                end = datetime.fromisoformat(chain['end_time'])
                duration_seconds = (end - start).total_seconds()
                
                if duration_seconds < 60:  # Less than a minute
                    risk_factors.append("Very rapid attack progression (< 1 minute)")
                    updated_chain['severity'] = min(updated_chain['severity'] + 0.05, 1.0)
                elif duration_seconds < 300:  # Less than 5 minutes
                    risk_factors.append("Rapid attack progression (< 5 minutes)")
            except (ValueError, TypeError):
                pass
        
        # Add anomaly count factor
        anomaly_count = chain.get('anomaly_count', 0)
        if anomaly_count > 10:
            risk_factors.append(f"Large number of related anomalies ({anomaly_count})")
            updated_chain['severity'] = min(updated_chain['severity'] + 0.05, 1.0)
        
        # Update chain with risk factors
        updated_chain['risk_factors'] = risk_factors
        
        return updated_chain 