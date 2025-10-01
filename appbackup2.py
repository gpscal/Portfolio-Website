#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import os
from datetime import datetime, timedelta
from uuid import uuid4
from werkzeug.utils import secure_filename
import jwt
import requests
from collections import Counter
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestRegressor
import pickle

app = Flask(__name__)
app.secret_key = 'tesxt7a48b78aa545337760f9fd'

# Optional: app-level upload size limit (match or be lower than Nginx)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB

# RouteLLM/OpenAI-compatible settings (provide via environment)
ROUTELLM_BASE_URL = os.environ.get('ROUTELLM_BASE_URL')
ROUTELLM_API_KEY = os.environ.get('ROUTELLM_API_KEY')
ROUTELLM_MODEL = os.environ.get('ROUTELLM_MODEL')

# Demo users
USERS = {
    'admin': 'password123',
    'user': 'demo123',
    'caleb': 'portfolio2024'
}

# File paths for data storage
DATA_DIR = 'data'
CATEGORIES_FILE = os.path.join(DATA_DIR, 'categories.json')
COMMANDS_FILE = os.path.join(DATA_DIR, 'commands.json')
PCAP_DIR = os.path.join(DATA_DIR, 'pcaps')
PCAP_METADATA_DIR = os.path.join(DATA_DIR, 'pcap_metadata')

# ML Models directory - THIS IS WHERE LEARNING IS STORED
ML_MODELS_DIR = os.path.join(DATA_DIR, 'ml_models')
ML_TRAINING_DATA_DIR = os.path.join(DATA_DIR, 'ml_training_data')

# Ensure data directories exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(PCAP_METADATA_DIR, exist_ok=True)
os.makedirs(ML_MODELS_DIR, exist_ok=True)
os.makedirs(ML_TRAINING_DATA_DIR, exist_ok=True)

# Allowed file extensions for PCAP uploads
ALLOWED_PCAP_EXTS = {'pcap', 'pcapng'}


def allowed_file(filename: str) -> bool:
    """Check if file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_PCAP_EXTS


def load_data(filename, default=None):
    """Load data from JSON file"""
    if default is None:
        default = []
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        return default


def save_data(filename, data):
    """Save data to JSON file"""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)


# ============================================================================
# PCAP PARSING FUNCTIONS (SIP/RTP SUPPORT)
# ============================================================================

def parse_sip_packet(pkt):
    """Extract SIP information from packet"""
    try:
        if hasattr(pkt, 'load'):
            payload = pkt.load.decode('utf-8', errors='ignore')

            # Check if it's a SIP packet
            sip_methods = ['INVITE', 'ACK', 'BYE', 'CANCEL', 'REGISTER', 'OPTIONS',
                          'PRACK', 'SUBSCRIBE', 'NOTIFY', 'PUBLISH', 'INFO', 'REFER',
                          'MESSAGE', 'UPDATE']
            sip_responses = ['SIP/2.0']

            is_sip = False
            sip_type = None

            for method in sip_methods:
                if payload.startswith(method):
                    is_sip = True
                    sip_type = method
                    break

            if not is_sip:
                for response in sip_responses:
                    if payload.startswith(response):
                        is_sip = True
                        # Extract response code
                        parts = payload.split('\r\n')[0].split(' ')
                        if len(parts) >= 2:
                            sip_type = f"Response {parts[1]}"
                        break

            if is_sip:
                sip_info = {
                    'type': sip_type,
                    'call_id': None,
                    'from': None,
                    'to': None,
                    'cseq': None,
                    'user_agent': None,
                    'content_type': None
                }

                # Parse SIP headers
                lines = payload.split('\r\n')
                for line in lines:
                    if line.startswith('Call-ID:'):
                        sip_info['call_id'] = line.split(':', 1)[1].strip()
                    elif line.startswith('From:'):
                        sip_info['from'] = line.split(':', 1)[1].strip()
                    elif line.startswith('To:'):
                        sip_info['to'] = line.split(':', 1)[1].strip()
                    elif line.startswith('CSeq:'):
                        sip_info['cseq'] = line.split(':', 1)[1].strip()
                    elif line.startswith('User-Agent:'):
                        sip_info['user_agent'] = line.split(':', 1)[1].strip()
                    elif line.startswith('Content-Type:'):
                        sip_info['content_type'] = line.split(':', 1)[1].strip()

                return sip_info
    except Exception:
        pass

    return None


def parse_rtp_packet(pkt):
    """Extract RTP information from packet"""
    try:
        from scapy.all import UDP

        if UDP in pkt:
            # RTP typically uses UDP ports in range 16384-32767 (dynamic range)
            # Common VoIP ports: 5004, 5060-5061 (SIP), 10000-20000 (RTP)
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

            # Check if it's likely an RTP packet (common RTP port ranges)
            if (10000 <= src_port <= 20000) or (10000 <= dst_port <= 20000) or \
               (16384 <= src_port <= 32767) or (16384 <= dst_port <= 32767):

                if hasattr(pkt[UDP], 'load') and len(pkt[UDP].load) >= 12:
                    payload = pkt[UDP].load

                    # RTP header structure (first 12 bytes minimum)
                    # Byte 0: V(2), P(1), X(1), CC(4)
                    # Byte 1: M(1), PT(7)
                    byte0 = payload[0]
                    byte1 = payload[1]

                    version = (byte0 >> 6) & 0x03
                    payload_type = byte1 & 0x7F

                    # RTP version should be 2
                    if version == 2:
                        # Extract sequence number (bytes 2-3)
                        seq_num = (payload[2] << 8) | payload[3]

                        # Extract timestamp (bytes 4-7)
                        timestamp = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]

                        # Extract SSRC (bytes 8-11)
                        ssrc = (payload[8] << 24) | (payload[9] << 16) | (payload[10] << 8) | payload[11]

                        return {
                            'version': version,
                            'payload_type': payload_type,
                            'sequence': seq_num,
                            'timestamp': timestamp,
                            'ssrc': hex(ssrc),
                            'payload_size': len(payload) - 12
                        }
    except Exception:
        pass

    return None


def parse_pcap_file(filepath: str) -> dict:
    """
    Parse PCAP file and extract detailed network information including SIP and RTP.
    Returns a dictionary with comprehensive packet analysis.
    """
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR
    except ImportError:
        return {
            'error': 'scapy not installed. Run: pip install scapy',
            'packet_count': 0,
            'total_bytes': 0
        }

    try:
        packets = rdpcap(filepath)

        if not packets:
            return {
                'packet_count': 0,
                'total_bytes': 0,
                'error': 'No packets found in file'
            }

        # Initialize data structures
        data = {
            'packet_count': len(packets),
            'total_bytes': 0,
            'duration_seconds': 0,
            'packets': [],
            'protocols': Counter(),
            'src_ips': Counter(),
            'dst_ips': Counter(),
            'src_ports': Counter(),
            'dst_ports': Counter(),
            'conversations': Counter(),
            'dns_queries': [],
            'dns_responses': [],
            'tcp_flags': Counter(),
            'packet_sizes': [],
            'timestamps': [],
            # VoIP-specific data
            'sip_packets': [],
            'rtp_packets': [],
            'sip_calls': {},
            'rtp_streams': {}
        }

        # Track timing
        first_time = None
        last_time = None

        # Parse each packet (limit to first 10000 for performance)
        for i, pkt in enumerate(packets[:10000]):
            pkt_time = float(pkt.time)

            if first_time is None:
                first_time = pkt_time
            last_time = pkt_time

            pkt_len = len(pkt)
            data['total_bytes'] += pkt_len
            data['packet_sizes'].append(pkt_len)
            data['timestamps'].append(pkt_time)

            # Basic packet info
            pkt_info = {
                'num': i + 1,
                'time': pkt_time,
                'length': pkt_len,
                'protocol': None,
                'src': None,
                'dst': None,
                'src_port': None,
                'dst_port': None,
                'info': ''
            }

            # IP layer analysis
            if IP in pkt:
                pkt_info['src'] = pkt[IP].src
                pkt_info['dst'] = pkt[IP].dst
                pkt_info['protocol'] = pkt[IP].proto

                data['src_ips'][pkt[IP].src] += 1
                data['dst_ips'][pkt[IP].dst] += 1

                # Conversation tracking
                conv = f"{pkt[IP].src} <-> {pkt[IP].dst}"
                data['conversations'][conv] += 1

                # TCP analysis
                if TCP in pkt:
                    data['protocols']['TCP'] += 1
                    pkt_info['src_port'] = pkt[TCP].sport
                    pkt_info['dst_port'] = pkt[TCP].dport
                    pkt_info['info'] = f"TCP {pkt[TCP].sport} → {pkt[TCP].dport}"

                    data['src_ports'][pkt[TCP].sport] += 1
                    data['dst_ports'][pkt[TCP].dport] += 1

                    # TCP flags
                    flags = pkt[TCP].flags
                    if flags:
                        data['tcp_flags'][str(flags)] += 1

                # UDP analysis
                elif UDP in pkt:
                    data['protocols']['UDP'] += 1
                    pkt_info['src_port'] = pkt[UDP].sport
                    pkt_info['dst_port'] = pkt[UDP].dport
                    pkt_info['info'] = f"UDP {pkt[UDP].sport} → {pkt[UDP].dport}"

                    data['src_ports'][pkt[UDP].sport] += 1
                    data['dst_ports'][pkt[UDP].dport] += 1

                    # Check for SIP (port 5060, 5061)
                    if pkt[UDP].sport == 5060 or pkt[UDP].dport == 5060 or \
                       pkt[UDP].sport == 5061 or pkt[UDP].dport == 5061:
                        sip_info = parse_sip_packet(pkt)
                        if sip_info:
                            data['protocols']['SIP'] += 1
                            sip_pkt = {
                                'packet_num': i + 1,
                                'time': pkt_time,
                                'src': pkt[IP].src,
                                'dst': pkt[IP].dst,
                                **sip_info
                            }
                            data['sip_packets'].append(sip_pkt)
                            pkt_info['info'] += f" [SIP {sip_info['type']}]"

                            # Track SIP calls by Call-ID
                            if sip_info['call_id']:
                                if sip_info['call_id'] not in data['sip_calls']:
                                    data['sip_calls'][sip_info['call_id']] = []
                                data['sip_calls'][sip_info['call_id']].append(sip_pkt)

                    # Check for RTP
                    rtp_info = parse_rtp_packet(pkt)
                    if rtp_info:
                        data['protocols']['RTP'] += 1
                        rtp_pkt = {
                            'packet_num': i + 1,
                            'time': pkt_time,
                            'src': pkt[IP].src,
                            'dst': pkt[IP].dst,
                            'src_port': pkt[UDP].sport,
                            'dst_port': pkt[UDP].dport,
                            **rtp_info
                        }
                        data['rtp_packets'].append(rtp_pkt)
                        pkt_info['info'] += f" [RTP PT={rtp_info['payload_type']}]"

                        # Track RTP streams by SSRC
                        ssrc = rtp_info['ssrc']
                        if ssrc not in data['rtp_streams']:
                            data['rtp_streams'][ssrc] = {
                                'packets': 0,
                                'bytes': 0,
                                'src': pkt[IP].src,
                                'dst': pkt[IP].dst,
                                'src_port': pkt[UDP].sport,
                                'dst_port': pkt[UDP].dport
                            }
                        data['rtp_streams'][ssrc]['packets'] += 1
                        data['rtp_streams'][ssrc]['bytes'] += rtp_info['payload_size']

                # ICMP analysis
                elif ICMP in pkt:
                    data['protocols']['ICMP'] += 1
                    pkt_info['info'] = f"ICMP type={pkt[ICMP].type}"

            # ARP analysis
            elif ARP in pkt:
                data['protocols']['ARP'] += 1
                pkt_info['src'] = pkt[ARP].psrc
                pkt_info['dst'] = pkt[ARP].pdst
                pkt_info['info'] = f"ARP {pkt[ARP].op}"

            # DNS analysis
            if DNS in pkt:
                if DNSQR in pkt:
                    query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                    data['dns_queries'].append(query)
                    pkt_info['info'] += f" DNS Query: {query}"

                if DNSRR in pkt:
                    response = pkt[DNSRR].rrname.decode('utf-8', errors='ignore')
                    data['dns_responses'].append(response)
                    pkt_info['info'] += f" DNS Response: {response}"

            # Store packet info (only first 500 for JSON size)
            if i < 500:
                data['packets'].append(pkt_info)

        # Calculate duration
        if first_time and last_time:
            data['duration_seconds'] = round(last_time - first_time, 2)

        # Convert Counters to sorted lists for JSON serialization
        data['protocols'] = dict(data['protocols'])
        data['top_src_ips'] = [{'ip': ip, 'count': count} for ip, count in data['src_ips'].most_common(10)]
        data['top_dst_ips'] = [{'ip': ip, 'count': count} for ip, count in data['dst_ips'].most_common(10)]
        data['top_src_ports'] = [{'port': port, 'count': count} for port, count in data['src_ports'].most_common(10)]
        data['top_dst_ports'] = [{'port': port, 'count': count} for port, count in data['dst_ports'].most_common(10)]
        data['top_conversations'] = [{'conv': conv, 'count': count} for conv, count in data['conversations'].most_common(10)]
        data['tcp_flags_dist'] = dict(data['tcp_flags'])

        # Remove raw counters (too large for JSON)
        del data['src_ips']
        del data['dst_ips']
        del data['src_ports']
        del data['dst_ports']
        del data['conversations']
        del data['tcp_flags']

        # Packet size statistics
        if data['packet_sizes']:
            data['avg_packet_size'] = round(sum(data['packet_sizes']) / len(data['packet_sizes']), 2)
            data['min_packet_size'] = min(data['packet_sizes'])
            data['max_packet_size'] = max(data['packet_sizes'])

        del data['packet_sizes']
        del data['timestamps']

        # VoIP statistics
        data['sip_packet_count'] = len(data['sip_packets'])
        data['rtp_packet_count'] = len(data['rtp_packets'])
        data['sip_call_count'] = len(data['sip_calls'])
        data['rtp_stream_count'] = len(data['rtp_streams'])

        # Limit stored SIP/RTP packets for JSON size
        if len(data['sip_packets']) > 100:
            data['sip_packets'] = data['sip_packets'][:100]
        if len(data['rtp_packets']) > 100:
            data['rtp_packets'] = data['rtp_packets'][:100]

        return data

    except Exception as e:
        return {
            'error': f'Failed to parse PCAP: {str(e)}',
            'packet_count': 0,
            'total_bytes': 0
        }


# ============================================================================
# MACHINE LEARNING FUNCTIONS
# ============================================================================

def extract_ml_features(parsed_data):
    """Extract features for ML models from parsed PCAP data"""
    features = {}

    # Basic statistics
    features['packet_count'] = parsed_data.get('packet_count', 0)
    features['total_bytes'] = parsed_data.get('total_bytes', 0)
    features['duration'] = parsed_data.get('duration_seconds', 0)
    features['avg_packet_size'] = parsed_data.get('avg_packet_size', 0)

    # VoIP-specific features
    features['sip_packet_ratio'] = (
        parsed_data.get('sip_packet_count', 0) / max(features['packet_count'], 1)
    )
    features['rtp_packet_ratio'] = (
        parsed_data.get('rtp_packet_count', 0) / max(features['packet_count'], 1)
    )

    # Calculate jitter (simplified - variance in packet timing)
    if 'rtp_packets' in parsed_data and len(parsed_data['rtp_packets']) > 1:
        timestamps = [p['time'] for p in parsed_data['rtp_packets'][:100]]
        if len(timestamps) > 1:
            deltas = np.diff(timestamps)
            features['jitter'] = float(np.std(deltas) * 1000)  # ms
            features['avg_interarrival'] = float(np.mean(deltas) * 1000)
        else:
            features['jitter'] = 0
            features['avg_interarrival'] = 0
    else:
        features['jitter'] = 0
        features['avg_interarrival'] = 0

    # Packet loss estimation (missing sequence numbers)
    if 'rtp_packets' in parsed_data and len(parsed_data['rtp_packets']) > 1:
        sequences = [p['sequence'] for p in parsed_data['rtp_packets'][:100]]
        expected_packets = max(sequences) - min(sequences) + 1
        actual_packets = len(sequences)
        features['packet_loss_ratio'] = (expected_packets - actual_packets) / max(expected_packets, 1)
    else:
        features['packet_loss_ratio'] = 0

    # Protocol diversity
    protocols = parsed_data.get('protocols', {})
    features['protocol_count'] = len(protocols)
    features['tcp_ratio'] = protocols.get('TCP', 0) / max(features['packet_count'], 1)
    features['udp_ratio'] = protocols.get('UDP', 0) / max(features['packet_count'], 1)

    # Conversation patterns
    features['unique_conversations'] = len(parsed_data.get('top_conversations', []))

    return features


def predict_call_quality(features):
    """Predict MOS score based on network metrics using E-Model"""
    jitter = features.get('jitter', 0)
    packet_loss = features.get('packet_loss_ratio', 0) * 100

    # Base R-factor (E-Model)
    r_factor = 93.2

    # Degrade based on packet loss
    r_factor -= packet_loss * 2.5

    # Degrade based on jitter
    if jitter > 20:
        r_factor -= (jitter - 20) * 0.5

    # Convert R-factor to MOS (1-5 scale)
    if r_factor < 0:
        mos = 1.0
    elif r_factor > 100:
        mos = 4.5
    else:
        mos = 1 + 0.035 * r_factor + 7e-6 * r_factor * (r_factor - 60) * (100 - r_factor)

    return round(max(1.0, min(5.0, mos)), 2)


def detect_anomalies(features, model_path=None):
    """
    Detect anomalies in VoIP traffic using Isolation Forest

    LEARNING STORAGE: Model is saved as a pickle file at:
    data/ml_models/anomaly_detector.pkl
    """
    if model_path is None:
        model_path = os.path.join(ML_MODELS_DIR, 'anomaly_detector.pkl')

    # Feature vector for anomaly detection
    feature_vector = [
        features.get('packet_count', 0),
        features.get('jitter', 0),
        features.get('packet_loss_ratio', 0),
        features.get('rtp_packet_ratio', 0),
        features.get('avg_interarrival', 0),
        features.get('protocol_count', 0)
    ]

    # Load or create model
    if os.path.exists(model_path):
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        model_trained = True
    else:
        # Create new model with default parameters
        model = IsolationForest(contamination=0.1, random_state=42)
        model_trained = False

    try:
        if model_trained:
            # Predict (-1 for anomaly, 1 for normal)
            prediction = model.predict([feature_vector])[0]
            score = model.score_samples([feature_vector])[0]

            is_anomaly = prediction == -1
            confidence = abs(score)

            return {
                'is_anomaly': bool(is_anomaly),
                'confidence': float(confidence),
                'anomaly_score': float(score),
                'model_trained': True
            }
        else:
            return {
                'is_anomaly': False,
                'confidence': 0.0,
                'anomaly_score': 0.0,
                'model_trained': False,
                'note': 'Model not trained - need baseline data. Use /api/ml/train endpoint.'
            }
    except Exception as e:
        return {
            'is_anomaly': False,
            'confidence': 0.0,
            'anomaly_score': 0.0,
            'error': str(e)
        }


def analyze_with_ml(parsed_data):
    """Run comprehensive ML analysis on parsed PCAP data"""
    features = extract_ml_features(parsed_data)

    analysis = {
        'features': features,
        'call_quality': {},
        'anomaly_detection': {},
        'recommendations': []
    }

    # Call quality prediction
    if features['rtp_packet_ratio'] > 0:
        mos_score = predict_call_quality(features)
        analysis['call_quality'] = {
            'mos_score': mos_score,
            'quality_rating': (
                'Excellent' if mos_score >= 4.3 else
                'Good' if mos_score >= 4.0 else
                'Fair' if mos_score >= 3.6 else
                'Poor' if mos_score >= 3.1 else
                'Bad'
            ),
            'jitter_ms': features['jitter'],
            'packet_loss_percent': round(features['packet_loss_ratio'] * 100, 2)
        }

        # Recommendations based on quality
        if mos_score < 4.0:
            if features['jitter'] > 30:
                analysis['recommendations'].append('High jitter detected - consider QoS prioritization')
            if features['packet_loss_ratio'] > 0.01:
                analysis['recommendations'].append('Packet loss detected - check network capacity')

    # Anomaly detection
    anomaly_result = detect_anomalies(features)
    analysis['anomaly_detection'] = anomaly_result

    if anomaly_result.get('is_anomaly'):
        analysis['recommendations'].append('Anomalous traffic pattern detected - investigate further')

    # Additional recommendations
    if features['sip_packet_ratio'] == 0 and features['rtp_packet_ratio'] > 0:
        analysis['recommendations'].append('RTP without SIP - possible mid-call capture or SIP on different port')

    if features['packet_count'] > 5000 and features['rtp_packet_ratio'] == 0:
        analysis['recommendations'].append('Large capture with no RTP - verify VoIP traffic is present')

    return analysis


def save_training_sample(features, label='normal'):
    """
    Save feature vector for future model training

    LEARNING STORAGE: Training samples are saved as JSON files in:
    data/ml_training_data/sample_<timestamp>.json
    """
    timestamp = datetime.utcnow().isoformat().replace(':', '-')
    sample_file = os.path.join(ML_TRAINING_DATA_DIR, f'sample_{timestamp}.json')

    sample = {
        'timestamp': datetime.utcnow().isoformat(),
        'features': features,
        'label': label
    }

    save_data(sample_file, sample)
    return sample_file


def train_anomaly_model():
    """
    Train anomaly detection model on collected samples

    LEARNING STORAGE: Trained model is saved to:
    data/ml_models/anomaly_detector.pkl (binary pickle file)

    This file contains the complete trained Isolation Forest model
    including all learned parameters and decision boundaries.
    """
    # Load all training samples
    training_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if f.endswith('.json')]

    if len(training_files) < 10:
        return {
            'success': False,
            'error': f'Need at least 10 samples to train. Currently have {len(training_files)}.'
        }

    # Extract features from samples
    feature_vectors = []
    for filename in training_files:
        filepath = os.path.join(ML_TRAINING_DATA_DIR, filename)
        sample = load_data(filepath, default={})
        if 'features' in sample:
            feature_vector = [
                sample['features'].get('packet_count', 0),
                sample['features'].get('jitter', 0),
                sample['features'].get('packet_loss_ratio', 0),
                sample['features'].get('rtp_packet_ratio', 0),
                sample['features'].get('avg_interarrival', 0),
                sample['features'].get('protocol_count', 0)
            ]
            feature_vectors.append(feature_vector)

    if len(feature_vectors) < 10:
        return {
            'success': False,
            'error': 'Not enough valid feature vectors extracted.'
        }

    # Train Isolation Forest
    model = IsolationForest(
        contamination=0.1,  # Expect 10% anomalies
        random_state=42,
        n_estimators=100
    )

    model.fit(feature_vectors)

    # Save trained model
    model_path = os.path.join(ML_MODELS_DIR, 'anomaly_detector.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)

    return {
        'success': True,
        'model_path': model_path,
        'training_samples': len(feature_vectors),
        'message': f'Model trained on {len(feature_vectors)} samples and saved to {model_path}'
    }


# ============================================================================
# ROUTELLM INTEGRATION
# ============================================================================

def ask_routellm(question: str, context: dict | None = None) -> dict:
    """
    Calls a RouteLLM/OpenAI-compatible chat endpoint.
    Expects ROUTELLM_BASE_URL and ROUTELLM_API_KEY in the environment.
    Returns {'answer': '...'} or {'error': '...'}.
    """
    if not ROUTELLM_BASE_URL or not ROUTELLM_API_KEY:
        return {'error': 'RouteLLM not configured. Set ROUTELLM_BASE_URL and ROUTELLM_API_KEY.'}

    system_prompt = """You are a VoIP and network security expert specializing in SIP and RTP analysis.
Analyze PCAP data with focus on:
- VoIP call quality and issues
- SIP signaling (INVITE, BYE, ACK, etc.)
- RTP streams and media quality
- Network traffic patterns
- Security concerns and anomalies
- Machine learning insights (MOS scores, anomaly detection)

Be clear, concise, and actionable in your responses."""

    # Build context string from PCAP data
    ctx = ""
    if context:
        try:
            ctx_parts = ["\n=== PCAP Analysis Data ==="]

            if 'packet_count' in context:
                ctx_parts.append(f"Total Packets: {context['packet_count']}")
            if 'total_bytes' in context:
                ctx_parts.append(f"Total Bytes: {context['total_bytes']}")
            if 'duration_seconds' in context:
                ctx_parts.append(f"Duration: {context['duration_seconds']} seconds")

            if 'protocols' in context:
                ctx_parts.append(f"\nProtocol Distribution: {json.dumps(context['protocols'])}")

            # VoIP-specific context
            if 'sip_packet_count' in context and context['sip_packet_count'] > 0:
                ctx_parts.append(f"\n=== VoIP/SIP Analysis ===")
                ctx_parts.append(f"SIP Packets: {context['sip_packet_count']}")
                ctx_parts.append(f"SIP Calls: {context['sip_call_count']}")
                if context.get('sip_packets'):
                    ctx_parts.append(f"SIP Packets Sample: {json.dumps(context['sip_packets'][:10])}")

            if 'rtp_packet_count' in context and context['rtp_packet_count'] > 0:
                ctx_parts.append(f"\nRTP Packets: {context['rtp_packet_count']}")
                ctx_parts.append(f"RTP Streams: {context['rtp_stream_count']}")
                if context.get('rtp_streams'):
                    ctx_parts.append(f"RTP Streams: {json.dumps(context['rtp_streams'])}")
                if context.get('rtp_packets'):
                    ctx_parts.append(f"RTP Packets Sample: {json.dumps(context['rtp_packets'][:10])}")

            # ML Analysis context
            if 'ml_analysis' in context:
                ml = context['ml_analysis']
                ctx_parts.append(f"\n=== ML Analysis ===")
                if 'call_quality' in ml and ml['call_quality']:
                    ctx_parts.append(f"MOS Score: {ml['call_quality'].get('mos_score')} ({ml['call_quality'].get('quality_rating')})")
                    ctx_parts.append(f"Jitter: {ml['call_quality'].get('jitter_ms')} ms")
                    ctx_parts.append(f"Packet Loss: {ml['call_quality'].get('packet_loss_percent')}%")
                if 'anomaly_detection' in ml and ml['anomaly_detection'].get('model_trained'):
                    ctx_parts.append(f"Anomaly Detected: {ml['anomaly_detection'].get('is_anomaly')}")
                    ctx_parts.append(f"Anomaly Score: {ml['anomaly_detection'].get('anomaly_score')}")
                if 'recommendations' in ml and ml['recommendations']:
                    ctx_parts.append(f"ML Recommendations: {', '.join(ml['recommendations'])}")

            if 'top_src_ips' in context:
                ctx_parts.append(f"\nTop Source IPs: {json.dumps(context['top_src_ips'][:5])}")

            if 'top_dst_ips' in context:
                ctx_parts.append(f"Top Destination IPs: {json.dumps(context['top_dst_ips'][:5])}")

            if 'top_conversations' in context:
                ctx_parts.append(f"Top Conversations: {json.dumps(context['top_conversations'][:5])}")

            if 'top_src_ports' in context:
                ctx_parts.append(f"Top Source Ports: {json.dumps(context['top_src_ports'][:5])}")

            if 'top_dst_ports' in context:
                ctx_parts.append(f"Top Destination Ports: {json.dumps(context['top_dst_ports'][:5])}")

            if 'dns_queries' in context and context['dns_queries']:
                ctx_parts.append(f"\nDNS Queries (sample): {json.dumps(context['dns_queries'][:10])}")

            if 'packets' in context and context['packets']:
                ctx_parts.append(f"\nSample Packets (first 20): {json.dumps(context['packets'][:20])}")

            ctx = "\n".join(ctx_parts)

            # Limit context size to avoid token limits
            if len(ctx) > 12000:
                ctx = ctx[:12000] + "\n... (truncated)"

        except Exception as e:
            ctx = f"\nContext parsing error: {str(e)}"

    payload = {
        "model": ROUTELLM_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"{ctx}\n\nUser Question: {question}"}
        ]
    }

    try:
        resp = requests.post(
            f"{ROUTELLM_BASE_URL.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {ROUTELLM_API_KEY}",
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=60
        )
        if resp.status_code >= 400:
            return {"error": f"RouteLLM error {resp.status_code}: {resp.text[:400]}"}
        data = resp.json()

        answer = None
        if isinstance(data, dict):
            try:
                answer = data.get("choices", [{}])[0].get("message", {}).get("content")
            except Exception:
                answer = None
            if not answer:
                try:
                    answer = data.get("choices", [{}])[0].get("text")
                except Exception:
                    pass

        return {"answer": answer or "No answer returned from RouteLLM."}
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# WEB ROUTES
# ============================================================================

@app.route('/')
def index():
    """Main portfolio page"""
    return render_template('index.html')


@app.route('/pcap')
def pcap_page():
    """VoIP LLM page"""
    return render_template('pcap.html')


@app.route('/api/debug/env', methods=['GET'])
def debug_env():
    """Debug endpoint to check environment variables"""
    return jsonify({
        'ROUTELLM_BASE_URL': os.environ.get('ROUTELLM_BASE_URL'),
        'ROUTELLM_API_KEY': os.environ.get('ROUTELLM_API_KEY')[:10] + '...' if os.environ.get('ROUTELLM_API_KEY') else None,
        'ROUTELLM_MODEL': os.environ.get('ROUTELLM_MODEL')
    })


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.route('/api/login', methods=['POST'])
def api_login():
    """Login endpoint"""
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if username in USERS and USERS[username] == password:
        payload = {
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        token = jwt.encode(payload, app.secret_key, algorithm='HS256')
        return jsonify({
            'success': True,
            'token': token,
            'user': {'username': username}
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid username or password'
        }), 401


# ============================================================================
# CATEGORY ROUTES
# ============================================================================

@app.route('/api/categories', methods=['GET'])
def get_categories():
    """Get all categories"""
    categories = load_data(CATEGORIES_FILE)
    return jsonify(categories)


@app.route('/api/categories', methods=['POST'])
def create_category():
    """Create a new category"""
    data = request.get_json() or {}
    categories = load_data(CATEGORIES_FILE)

    new_category = {
        'id': str(len(categories) + 1),
        'name': data.get('name', ''),
        'description': data.get('description', ''),
        'parentId': data.get('parentId'),
        'created_at': datetime.utcnow().isoformat()
    }

    categories.append(new_category)
    save_data(CATEGORIES_FILE, categories)

    return jsonify(new_category), 201


@app.route('/api/categories/<category_id>', methods=['PUT'])
def update_category(category_id):
    """Update a category"""
    data = request.get_json() or {}
    categories = load_data(CATEGORIES_FILE)

    for category in categories:
        if category['id'] == category_id:
            category.update({
                'name': data.get('name', category.get('name', '')),
                'description': data.get('description', category.get('description', '')),
                'parentId': data.get('parentId', category.get('parentId')),
                'updated_at': datetime.utcnow().isoformat()
            })
            break

    save_data(CATEGORIES_FILE, categories)
    return jsonify({'success': True})


@app.route('/api/categories/<category_id>', methods=['DELETE'])
def delete_category(category_id):
    """Delete a category"""
    categories = load_data(CATEGORIES_FILE)
    commands = load_data(COMMANDS_FILE)

    categories = [cat for cat in categories if cat['id'] != category_id and cat.get('parentId') != category_id]
    commands = [cmd for cmd in commands if cmd.get('categoryId') != category_id]

    save_data(CATEGORIES_FILE, categories)
    save_data(COMMANDS_FILE, commands)

    return jsonify({'success': True})


# ============================================================================
# COMMAND ROUTES
# ============================================================================

@app.route('/api/commands', methods=['GET'])
def get_commands():
    """Get all commands"""
    commands = load_data(COMMANDS_FILE)
    return jsonify(commands)


@app.route('/api/commands', methods=['POST'])
def create_command():
    """Create a new command"""
    data = request.get_json() or {}
    commands = load_data(COMMANDS_FILE)

    new_command = {
        'id': str(len(commands) + 1),
        'categoryId': data.get('categoryId'),
        'name': data.get('name', ''),
        'syntax': data.get('syntax', ''),
        'description': data.get('description', ''),
        'examples': data.get('examples', ''),
        'tags': data.get('tags', ''),
        'created_at': datetime.utcnow().isoformat()
    }

    commands.append(new_command)
    save_data(COMMANDS_FILE, commands)

    return jsonify(new_command), 201


@app.route('/api/commands/<command_id>', methods=['PUT'])
def update_command(command_id):
    """Update a command"""
    data = request.get_json() or {}
    commands = load_data(COMMANDS_FILE)

    for command in commands:
        if command['id'] == command_id:
            command.update({
                'categoryId': data.get('categoryId', command.get('categoryId')),
                'name': data.get('name', command.get('name', '')),
                'syntax': data.get('syntax', command.get('syntax', '')),
                'description': data.get('description', command.get('description', '')),
                'examples': data.get('examples', command.get('examples', '')),
                'tags': data.get('tags', command.get('tags', '')),
                'updated_at': datetime.utcnow().isoformat()
            })
            break

    save_data(COMMANDS_FILE, commands)
    return jsonify({'success': True})


@app.route('/api/commands/<command_id>', methods=['DELETE'])
def delete_command(command_id):
    """Delete a command"""
    commands = load_data(COMMANDS_FILE)
    commands = [cmd for cmd in commands if cmd['id'] != command_id]

    save_data(COMMANDS_FILE, commands)
    return jsonify({'success': True})


# ============================================================================
# PCAP ROUTES
# ============================================================================

@app.route('/api/pcap/upload', methods=['POST'])
@app.route('/api/pcap/upload/', methods=['POST'])
def upload_pcap():
    """
    Accepts multipart/form-data with field 'file' containing a .pcap or .pcapng.
    Saves the file, parses it with scapy including SIP/RTP, and returns comprehensive metadata.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'Bad Request', 'detail': "Form field 'file' is required"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Bad Request', 'detail': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': 'Unsupported Media Type',
                        'detail': 'Only .pcap or .pcapng files are allowed'}), 415

    original_name = secure_filename(file.filename)
    pcap_id = str(uuid4())
    stored_name = f"{pcap_id}__{original_name}"
    save_path = os.path.join(PCAP_DIR, stored_name)

    try:
        file.save(save_path)
        file_size = os.path.getsize(save_path)
    except Exception as e:
        return jsonify({'error': 'Internal Server Error', 'detail': str(e)}), 500

    # Parse the PCAP file with SIP/RTP support
    parsed_data = parse_pcap_file(save_path)

    # Save parsed metadata to JSON file for later retrieval
    metadata_path = os.path.join(PCAP_METADATA_DIR, f"{pcap_id}.json")
    save_data(metadata_path, parsed_data)

    # Build stats for response
    stats = {
        "format": "pcap/pcapng",
        "packet_count": parsed_data.get('packet_count', 0),
        "total_bytes": parsed_data.get('total_bytes', 0),
        "duration_seconds": parsed_data.get('duration_seconds', 0),
        "protocols": parsed_data.get('protocols', {}),
        "sip_packets": parsed_data.get('sip_packet_count', 0),
        "rtp_packets": parsed_data.get('rtp_packet_count', 0),
        "sip_calls": parsed_data.get('sip_call_count', 0),
        "rtp_streams": parsed_data.get('rtp_stream_count', 0),
        "note": "Parsed with scapy (SIP/RTP support)" if 'error' not in parsed_data else parsed_data.get('error')
    }

    return jsonify({
        'success': True,
        'pcap_id': pcap_id,
        'filename': original_name,
        'stored_filename': stored_name,
        'size_bytes': file_size,
        'uploaded_at': datetime.utcnow().isoformat() + 'Z',
        'stats': stats
    }), 201


@app.route('/api/pcap/<pcap_id>/route-llm', methods=['POST'])
def pcap_route_llm(pcap_id):
    """
    Accepts JSON: { "question": "..." }
    Loads parsed PCAP data (including SIP/RTP) and calls RouteLLM with full context including ML analysis.
    """
    body = request.get_json() or {}
    question = (body.get('question') or '').strip()
    if not question:
        return jsonify({"error": "Missing 'question'"}), 400

    # Load parsed PCAP metadata
    metadata_path = os.path.join(PCAP_METADATA_DIR, f"{pcap_id}.json")

    if not os.path.exists(metadata_path):
        return jsonify({"error": "PCAP not found or not yet parsed"}), 404

    parsed_data = load_data(metadata_path, default={})

    if 'error' in parsed_data:
        return jsonify({"error": f"PCAP parsing failed: {parsed_data['error']}"}), 500

    # Run ML analysis
    ml_analysis = analyze_with_ml(parsed_data)

    # Add ML analysis to context
    context = parsed_data.copy()
    context['ml_analysis'] = ml_analysis

    # Call RouteLLM with full parsed context including SIP/RTP and ML analysis
    result = ask_routellm(question, context=context)

    if 'error' in result:
        return jsonify(result), 502

    # Return answer with VoIP stats and ML insights
    return jsonify({
        "answer": result['answer'],
        "stats": {
            "packet_count": parsed_data.get('packet_count', 0),
            "total_bytes": parsed_data.get('total_bytes', 0),
            "duration_seconds": parsed_data.get('duration_seconds', 0),
            "protocols": parsed_data.get('protocols', {}),
            "sip_packets": parsed_data.get('sip_packet_count', 0),
            "rtp_packets": parsed_data.get('rtp_packet_count', 0),
            "sip_calls": parsed_data.get('sip_call_count', 0),
            "rtp_streams": parsed_data.get('rtp_stream_count', 0)
        },
        "ml_analysis": ml_analysis
    })

# Add after the existing ML routes

@app.route('/api/ml/samples', methods=['GET'])
def list_ml_samples():
    """
    List all training samples with metadata
    Returns list of samples with timestamps and labels
    """
    training_files = sorted([f for f in os.listdir(ML_TRAINING_DATA_DIR) if f.endswith('.json')])
    
    samples = []
    for filename in training_files:
        filepath = os.path.join(ML_TRAINING_DATA_DIR, filename)
        sample = load_data(filepath, default={})
        
        if sample:
            samples.append({
                'id': filename.replace('.json', ''),
                'filename': filename,
                'timestamp': sample.get('timestamp'),
                'label': sample.get('label'),
                'feature_count': len(sample.get('features', {})),
                'size_bytes': os.path.getsize(filepath)
            })
    
    return jsonify({
        'total_samples': len(samples),
        'samples': samples,
        'storage_path': ML_TRAINING_DATA_DIR
    })


@app.route('/api/ml/samples/<sample_id>', methods=['GET'])
def get_ml_sample(sample_id):
    """
    Get detailed information about a specific training sample
    """
    sample_file = os.path.join(ML_TRAINING_DATA_DIR, f'{sample_id}.json')
    
    if not os.path.exists(sample_file):
        return jsonify({'error': 'Sample not found'}), 404
    
    sample = load_data(sample_file, default={})
    
    return jsonify({
        'id': sample_id,
        'data': sample,
        'file_path': sample_file,
        'size_bytes': os.path.getsize(sample_file)
    })


@app.route('/api/ml/samples/<sample_id>', methods=['DELETE'])
def delete_ml_sample(sample_id):
    """
    Delete a training sample (useful for cleaning bad data)
    """
    sample_file = os.path.join(ML_TRAINING_DATA_DIR, f'{sample_id}.json')
    
    if not os.path.exists(sample_file):
        return jsonify({'error': 'Sample not found'}), 404
    
    try:
        os.remove(sample_file)
        return jsonify({
            'success': True,
            'message': f'Sample {sample_id} deleted'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/model-info', methods=['GET'])
def get_model_info():
    """
    Get detailed information about the trained model
    """
    model_path = os.path.join(ML_MODELS_DIR, 'anomaly_detector.pkl')
    
    if not os.path.exists(model_path):
        return jsonify({
            'trained': False,
            'message': 'Model not trained yet'
        }), 404
    
    # Load model to get details
    try:
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        model_info = {
            'trained': True,
            'model_type': type(model).__name__,
            'n_estimators': model.n_estimators if hasattr(model, 'n_estimators') else None,
            'contamination': model.contamination if hasattr(model, 'contamination') else None,
            'max_samples': model.max_samples if hasattr(model, 'max_samples') else None,
            'file_path': model_path,
            'size_bytes': os.path.getsize(model_path),
            'last_modified': datetime.fromtimestamp(os.path.getmtime(model_path)).isoformat(),
            'features_used': [
                'packet_count',
                'jitter',
                'packet_loss_ratio',
                'rtp_packet_ratio',
                'avg_interarrival',
                'protocol_count'
            ]
        }
        
        return jsonify(model_info)
    except Exception as e:
        return jsonify({'error': f'Failed to load model: {str(e)}'}), 500


@app.route('/api/ml/statistics', methods=['GET'])
def get_ml_statistics():
    """
    Get overall ML system statistics
    """
    # Count samples by label
    training_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if f.endswith('.json')]
    
    label_counts = {'normal': 0, 'anomaly': 0, 'other': 0}
    feature_stats = {
        'jitter': [],
        'packet_loss_ratio': [],
        'packet_count': []
    }
    
    for filename in training_files:
        filepath = os.path.join(ML_TRAINING_DATA_DIR, filename)
        sample = load_data(filepath, default={})
        
        label = sample.get('label', 'other')
        if label in label_counts:
            label_counts[label] += 1
        else:
            label_counts['other'] += 1
        
        # Collect feature statistics
        features = sample.get('features', {})
        if 'jitter' in features:
            feature_stats['jitter'].append(features['jitter'])
        if 'packet_loss_ratio' in features:
            feature_stats['packet_loss_ratio'].append(features['packet_loss_ratio'])
        if 'packet_count' in features:
            feature_stats['packet_count'].append(features['packet_count'])
    
    # Calculate averages
    stats_summary = {}
    for key, values in feature_stats.items():
        if values:
            stats_summary[key] = {
                'avg': round(sum(values) / len(values), 2),
                'min': round(min(values), 2),
                'max': round(max(values), 2),
                'count': len(values)
            }
    
    model_path = os.path.join(ML_MODELS_DIR, 'anomaly_detector.pkl')
    model_exists = os.path.exists(model_path)
    
    return jsonify({
        'total_samples': len(training_files),
        'label_distribution': label_counts,
        'feature_statistics': stats_summary,
        'model_trained': model_exists,
        'storage_paths': {
            'training_data': ML_TRAINING_DATA_DIR,
            'models': ML_MODELS_DIR
        }
    })


@app.route('/api/ml/retrain', methods=['POST'])
def retrain_model():
    """
    Retrain the model (same as train but explicitly for retraining)
    """
    result = train_anomaly_model()
    
    if result['success']:
        return jsonify({
            **result,
            'message': 'Model retrained successfully'
        }), 200
    else:
        return jsonify(result), 400


@app.route('/api/ml/export', methods=['GET'])
def export_ml_data():
    """
    Export all training data as a single JSON file for backup
    """
    training_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if f.endswith('.json')]
    
    all_samples = []
    for filename in training_files:
        filepath = os.path.join(ML_TRAINING_DATA_DIR, filename)
        sample = load_data(filepath, default={})
        if sample:
            sample['filename'] = filename
            all_samples.append(sample)
    
    export_data = {
        'export_date': datetime.utcnow().isoformat(),
        'total_samples': len(all_samples),
        'samples': all_samples
    }
    
    return jsonify(export_data)
# ============================================================================
# MACHINE LEARNING API ROUTES
# ============================================================================

@app.route('/api/pcap/<pcap_id>/ml-analysis', methods=['GET'])
def pcap_ml_analysis(pcap_id):
    """
    Run ML analysis on uploaded PCAP
    Returns call quality prediction, anomaly detection, and recommendations
    """
    metadata_path = os.path.join(PCAP_METADATA_DIR, f"{pcap_id}.json")

    if not os.path.exists(metadata_path):
        return jsonify({"error": "PCAP not found"}), 404

    parsed_data = load_data(metadata_path, default={})

    if 'error' in parsed_data:
        return jsonify({"error": f"PCAP parsing failed: {parsed_data['error']}"}), 500

    # Run ML analysis
    ml_results = analyze_with_ml(parsed_data)

    return jsonify(ml_results)


@app.route('/api/ml/save-sample', methods=['POST'])
def save_ml_sample():
    """
    Save a training sample for future model training
    Body: { "pcap_id": "...", "label": "normal" or "anomaly" }

    LEARNING STORAGE: Saves to data/ml_training_data/sample_<timestamp>.json
    """
    body = request.get_json() or {}
    pcap_id = body.get('pcap_id')
    label = body.get('label', 'normal')

    if not pcap_id:
        return jsonify({"error": "Missing pcap_id"}), 400

    metadata_path = os.path.join(PCAP_METADATA_DIR, f"{pcap_id}.json")

    if not os.path.exists(metadata_path):
        return jsonify({"error": "PCAP not found"}), 404

    parsed_data = load_data(metadata_path, default={})
    features = extract_ml_features(parsed_data)

    sample_file = save_training_sample(features, label)

    return jsonify({
        "success": True,
        "sample_file": sample_file,
        "message": f"Training sample saved with label '{label}'"
    })


@app.route('/api/ml/train', methods=['POST'])
def train_ml_model():
    """
    Train the anomaly detection model on collected samples

    LEARNING STORAGE: Saves trained model to data/ml_models/anomaly_detector.pkl
    """
    result = train_anomaly_model()

    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@app.route('/api/ml/status', methods=['GET'])
def ml_status():
    """
    Get ML system status - model training status and sample count
    """
    model_path = os.path.join(ML_MODELS_DIR, 'anomaly_detector.pkl')
    model_exists = os.path.exists(model_path)

    training_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if f.endswith('.json')]
    sample_count = len(training_files)

    model_info = {}
    if model_exists:
        model_info['trained'] = True
        model_info['path'] = model_path
        model_info['size_bytes'] = os.path.getsize(model_path)
        model_info['last_modified'] = datetime.fromtimestamp(
            os.path.getmtime(model_path)
        ).isoformat()
    else:
        model_info['trained'] = False
        model_info['message'] = 'Model not trained yet. Collect samples and use /api/ml/train'

    return jsonify({
        'model': model_info,
        'training_samples': sample_count,
        'min_samples_required': 10,
        'ready_to_train': sample_count >= 10
    })


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
