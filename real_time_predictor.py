import pandas as pd
import numpy as np
import re
import time
import json
import requests
import joblib
from datetime import datetime
import subprocess
import os
import sys
from collections import defaultdict, deque

class SSHFeatureExtractor:
    def __init__(self):
        self.session_data = defaultdict(lambda: {
            'start_time': None, 'end_time': None, 'usernames': set(), 'passwords': set(),
            'failed_attempts': 0, 'success_attempts': 0,
        })
        self.ip_data = defaultdict(lambda: {
            'total_sessions': 0, 'failed_sessions': 0, 'success_sessions': 0,
            'unique_usernames': set(), 'unique_passwords': set(),
        })
        self.recent_events = deque(maxlen=1000)
        
        # All 38 expected features from your model
        self.expected_features = [
            'total_attempts', 'success_count', 'failed_count', 'success_rate', 'failure_rate',
            'unique_ports', 'port_sequence_count', 'avg_port', 'port_entropy', 'unique_usernames',
            'unique_passwords', 'failed_unique_usernames', 'failed_unique_passwords', 'username_password_ratio',
            'common_password_attempts', 'common_username_attempts', 'consecutive_failures', 'requests_per_minute',
            'session_duration_seconds', 'avg_request_interval', 'request_interval_std', 'ssh_version_diversity',
            'auth_method_diversity', 'kex_algorithm_quality', 'unique_countries_in_group', 'unique_asns_in_group',
            'unique_ips_in_window', 'concurrent_sessions', 'ip_diversity', 'server_key_changes',
            'weak_cipher_detected', 'host_key_mismatches', 'suspicious_process_patterns', 'mining_pool_connections',
            'binary_download_attempts', 'lateral_movement_attempts', 'country', 'is_suspicious_country'
        ]
    
    def create_numeric_features(self, log_line):
        """Create all expected features including the missing ones"""
        # Initialize all features to 0
        features = {feature: 0.0 for feature in self.expected_features}
        current_time = time.time()
        
        # Extract IP and session info
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
        ip = ip_match.group(1) if ip_match else 'unknown'
        
        session_match = re.search(r'session: ([a-f0-9]+)', log_line)
        session_id = session_match.group(1) if session_match else 'unknown'
        
        # Update session tracking
        session = self.session_data[session_id]
        ip_info = self.ip_data[ip]
        
        if session['start_time'] is None:
            session['start_time'] = current_time
            ip_info['total_sessions'] += 1
        
        session['end_time'] = current_time
        
        # Extract username from login attempts
        if 'login attempt' in log_line:
            user_match = re.search(r"\[b'([^']+)'", log_line)
            username = user_match.group(1) if user_match else 'unknown'
            if username != 'unknown':
                session['usernames'].add(username)
                ip_info['unique_usernames'].add(username)
        
        # Track password attempts
        if 'login attempt' in log_line and 'b\'' in log_line:
            parts = log_line.split("b'")
            if len(parts) > 2:
                password = parts[2].split("'")[0] if "'" in parts[2] else 'unknown'
                if password != 'unknown':
                    session['passwords'].add(password)
                    ip_info['unique_passwords'].add(password)
        
        # Track success/failure
        is_failed = 'failed' in log_line.lower()
        if is_failed:
            session['failed_attempts'] += 1
            ip_info['failed_sessions'] += 1
        elif 'success' in log_line.lower():
            session['success_attempts'] += 1
            ip_info['success_sessions'] += 1
        
        # Add to recent events for aggregation
        self.recent_events.append({
            'timestamp': current_time,
            'ip': ip,
            'session_id': session_id,
            'success': not is_failed
        })
        
        # Calculate aggregated features
        recent_events_for_ip = [e for e in self.recent_events if e['ip'] == ip]
        
        # Basic counts
        features['total_attempts'] = len(recent_events_for_ip)
        features['failed_count'] = len([e for e in recent_events_for_ip if not e['success']])
        features['success_count'] = len([e for e in recent_events_for_ip if e['success']])
        
        # Rates
        if features['total_attempts'] > 0:
            features['failure_rate'] = features['failed_count'] / features['total_attempts']
            features['success_rate'] = features['success_count'] / features['total_attempts']
        
        # Username/password statistics
        features['unique_usernames'] = len(ip_info['unique_usernames'])
        features['unique_passwords'] = len(ip_info['unique_passwords'])
        features['failed_unique_usernames'] = features['unique_usernames']
        features['failed_unique_passwords'] = features['unique_passwords']
        
        # Ratios
        if features['unique_passwords'] > 0:
            features['username_password_ratio'] = features['unique_usernames'] / features['unique_passwords']
        
        # Common attempts detection
        common_users = {'root', 'admin', 'test', 'user', 'ubuntu'}
        common_attempts = len([u for u in ip_info['unique_usernames'] if u in common_users])
        features['common_username_attempts'] = common_attempts
        features['common_password_attempts'] = common_attempts
        
        # Session duration
        if session['start_time'] and session['end_time']:
            features['session_duration_seconds'] = float(session['end_time'] - session['start_time'])
        
        # Time-based features
        if len(recent_events_for_ip) > 1:
            timestamps = [e['timestamp'] for e in recent_events_for_ip]
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            features['avg_request_interval'] = float(np.mean(intervals)) if intervals else 0.0
            features['request_interval_std'] = float(np.std(intervals)) if len(intervals) > 1 else 0.0
            
            # Requests per minute
            time_span = timestamps[-1] - timestamps[0]
            if time_span > 0:
                features['requests_per_minute'] = float((len(recent_events_for_ip) / time_span) * 60)
        
        # Port information
        port_match = re.search(r':(\d+)\]', log_line)
        if port_match:
            port = int(port_match.group(1))
            features['unique_ports'] = 1
            features['avg_port'] = float(port)
        
        # Consecutive failures
        consecutive_failures = 0
        for event in reversed(recent_events_for_ip):
            if not event['success']:
                consecutive_failures += 1
            else:
                break
        features['consecutive_failures'] = consecutive_failures
        
        # Add the missing features with default values
        features['country'] = 0.0
        features['is_suspicious_country'] = 0.0
        
        # Convert all to float to ensure numeric types
        for key in features:
            features[key] = float(features[key])
        
        return features

class HoneypotPredictor:
    def __init__(self, model_path):
        self.model_path = model_path
        # Use localhost since we're not in Docker container
        self.loki_url = "http://localhost:3101/loki/api/v1/push"
        self.feature_extractor = SSHFeatureExtractor()
        
        print(f"Loading model from: {model_path}")
        
        try:
            self.pipeline = joblib.load(model_path)
            print("Model loaded successfully")
            print(f"Model classes: {self.pipeline.classes_}")
            
        except Exception as e:
            print(f"Error loading model: {e}")
            raise
    
    def send_to_loki(self, prediction, confidence, features, original_log):
        labels = {
            "job": "ml-honeypot",
            "attack_type": str(prediction),
            "confidence": f"{confidence:.2f}",
            "method": "rule_based"
        }
        
        log_message = f"attack_type={prediction} confidence={confidence} source_ip={features.get('source_ip', 'unknown')} total_attempts={features.get('total_attempts', 0)} failed_count={features.get('failed_count', 0)}"
        
        payload = {
            "streams": [{
                "stream": labels,
                "values": [
                    [str(int(time.time() * 1000000000)), log_message]
                ]
            }]
        }
        
        try:
            response = requests.post(
                self.loki_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            if response.status_code == 204:
                print(f"Sent to Loki: {prediction} (Confidence: {confidence:.2f})")
            else:
                print(f"Loki error: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Failed to send to Loki: {e}")
    
    def predict_attack_simple(self, log_line):
        """Simple rule-based prediction as fallback"""
        features = self.feature_extractor.create_numeric_features(log_line)
        
        # Simple rule-based classification
        if features['failed_count'] > 3:
            prediction = 'bruteforce'
            confidence = 0.8
        elif features['unique_usernames'] > 5:
            prediction = 'credential_stuffing' 
            confidence = 0.7
        elif features['requests_per_minute'] > 10:
            prediction = 'resource_exhaustion_ddos'
            confidence = 0.6
        else:
            prediction = 'normal'
            confidence = 0.5
            
        return {
            'prediction': prediction,
            'confidence': confidence,
            'features': features,
            'success': True,
            'method': 'rule_based'
        }
    
    def predict_attack(self, log_line):
        try:
            # Extract numeric features only
            features = self.feature_extractor.create_numeric_features(log_line)
            
            # Create DataFrame with all 38 features
            features_df = pd.DataFrame([features])
            
            print(f"Features shape: {features_df.shape}")
            print(f"All features are numeric: {all(features_df.dtypes != 'object')}")
            print(f"Total features: {len(features_df.columns)}")
            
            # Try to use the full pipeline first
            try:
                prediction = self.pipeline.predict(features_df)[0]
                probabilities = self.pipeline.predict_proba(features_df)[0]
                confidence = probabilities.max()
                
                return {
                    'prediction': prediction,
                    'confidence': confidence,
                    'features': features,
                    'success': True,
                    'method': 'pipeline'
                }
                
            except Exception as pipeline_error:
                print(f"Pipeline prediction failed: {pipeline_error}")
                print("Falling back to rule-based prediction")
                
                # Fall back to rule-based prediction
                return self.predict_attack_simple(log_line)
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                'prediction': 'error',
                'confidence': 0.0,
                'features': {},
                'success': False,
                'error': str(e)
            }
    
    def monitor_docker_logs(self):
        print("Starting Docker logs monitoring...")
        print("ML Classifier Active - Waiting for attacks...")
        print("Generate test attacks with: ssh -p 2222 test@localhost")
        
        processed_lines = set()
        
        try:
            while True:
                try:
                    result = subprocess.run(
                        ['docker', 'logs', 'nimz-cowrie-1', '--tail', '20'],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        
                        for line in lines:
                            if line and line not in processed_lines:
                                processed_lines.add(line)
                                
                                if line.strip() and ('login attempt' in line or 'New connection' in line):
                                    print(f"New log: {line.strip()}")
                                    
                                    result = self.predict_attack(line)
                                    
                                    if result['success']:
                                        self.send_to_loki(
                                            result['prediction'],
                                            result['confidence'],
                                            result['features'],
                                            line
                                        )
                                        print(f"Prediction: {result['prediction']} (Confidence: {result['confidence']:.2f}) [Method: {result.get('method', 'unknown')}]")
                                    else:
                                        print(f"Prediction failed: {result.get('error', 'Unknown error')}")
                except Exception as e:
                    print(f"Error reading logs: {e}")
                
                time.sleep(2)
                        
        except KeyboardInterrupt:
            print("Stopping monitor...")
        except Exception as e:
            print(f"Monitor error: {e}")

def main():
    MODEL_PATH = "/home/nimz/data_processor.joblib"
    
    print("Starting ML Honeypot Predictor - LOKI FIXED VERSION")
    print(f"Model path: {MODEL_PATH}")
    
    # Check if Docker container is running
    try:
        result = subprocess.run(
            ['docker', 'ps', '--filter', 'name=nimz-cowrie-1', '--format', '{{.Names}}'],
            capture_output=True, text=True
        )
        if 'nimz-cowrie-1' not in result.stdout:
            print("Cowrie container 'nimz-cowrie-1' is not running")
            print("Start it with: docker start nimz-cowrie-1")
            return
        else:
            print("Cowrie container is running")
    except Exception as e:
        print(f"Error checking Docker: {e}")
        return
    
    # Start the predictor
    predictor = HoneypotPredictor(MODEL_PATH)
    predictor.monitor_docker_logs()

if __name__ == "__main__":
    main()
