
from flask import Flask, request, Response, jsonify, render_template, stream_with_context, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import logging
import requests
import os
import json
import uuid
from datetime import datetime
import pickle
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from scapy.layers.inet import ICMP
import numpy as np
from sklearn.ensemble import IsolationForest
app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_DIR = 'data/uploads'
METADATA_DIR = 'data/metadata'
ML_TRAINING_DATA_DIR = 'data/ml_training_data'
ML_MODELS_DIR = 'data/ml_models'
PCAP_METADATA_DIR = os.path.join(os.path.dirname(__file__), "data", "pcap_metadata")  
os.makedirs(PCAP_METADATA_DIR, exist_ok=True)

# Ensure directories exist
for directory in [UPLOAD_DIR, METADATA_DIR, ML_TRAINING_DATA_DIR, ML_MODELS_DIR]:
    os.makedirs(directory, exist_ok=True)

# RouteLLM Configuration (update with your actual keys)
ROUTELLM_API_KEY = os.getenv('ROUTELLM_API_KEY')
ROUTELLM_MODEL = os.getenv('ROUTELLM_MODEL')
ROUTELLM_ENDPOINT = os.getenv('ROUTELLM_ENDPOINT')


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def save_data(filepath, data):
    """Save data to JSON file"""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def load_data(filepath, default=None):
    """Load data from JSON file"""
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return default


# ============================================================================
# PCAP PARSING FUNCTIONS
# ============================================================================

def parse_pcap_file(filepath):
    """
    Parse a PCAP file and extract detailed information including SIP and RTP packets
    """
    try:
        packets = rdpcap(filepath)
        
        parsed_packets = []
        total_bytes = 0
        sip_packets = 0
        rtp_packets = 0
        
        # Get timing info
        if len(packets) > 0:
            start_time = float(packets[0].time)
            end_time = float(packets[-1].time)
            duration = end_time - start_time
        else:
            duration = 0
        
        for i, pkt in enumerate(packets):
            total_bytes += len(pkt)
            
            packet_info = {
                'index': i,
                'timestamp': float(pkt.time),
                'length': len(pkt),
                'protocol': 'Unknown'
            }
            
            # IP layer
            if IP in pkt:
                packet_info['src_ip'] = pkt[IP].src
                packet_info['dst_ip'] = pkt[IP].dst
                packet_info['protocol'] = pkt[IP].proto
                
                # TCP
                if TCP in pkt:
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = pkt[TCP].sport
                    packet_info['dst_port'] = pkt[TCP].dport
                    
                    # Check for SIP (typically on port 5060)
                    if pkt[TCP].sport == 5060 or pkt[TCP].dport == 5060:
                        if Raw in pkt:
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            if 'SIP' in payload or 'INVITE' in payload or 'REGISTER' in payload:
                                packet_info['protocol'] = 'SIP'
                                packet_info['sip_method'] = extract_sip_method(payload)
                                sip_packets += 1
                
                # UDP
                elif UDP in pkt:
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = pkt[UDP].sport
                    packet_info['dst_port'] = pkt[UDP].dport
                    
                    # Check for SIP over UDP
                    if pkt[UDP].sport == 5060 or pkt[UDP].dport == 5060:
                        if Raw in pkt:
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                            if 'SIP' in payload or 'INVITE' in payload or 'REGISTER' in payload:
                                packet_info['protocol'] = 'SIP'
                                packet_info['sip_method'] = extract_sip_method(payload)
                                sip_packets += 1
                    
                    # Check for RTP (typically on even ports > 1024)
                    elif is_rtp_packet(pkt):
                        packet_info['protocol'] = 'RTP'
                        rtp_info = parse_rtp_packet(pkt)
                        packet_info.update(rtp_info)
                        rtp_packets += 1
                
                # ICMP
                elif ICMP in pkt:
                    packet_info['protocol'] = 'ICMP'
            
            parsed_packets.append(packet_info)
        
        stats = {
            'format': 'pcap',
            'packet_count': len(packets),
            'total_bytes': total_bytes,
            'duration_seconds': round(duration, 2),
            'sip_packets': sip_packets,
            'rtp_packets': rtp_packets,
            'note': f'SIP: {sip_packets}, RTP: {rtp_packets}'
        }
        
        return {
            'stats': stats,
            'packets': parsed_packets
        }
    
    except Exception as e:
        return {
            'stats': {
                'format': 'unknown',
                'packet_count': 0,
                'total_bytes': 0,
                'duration_seconds': 0,
                'sip_packets': 0,
                'rtp_packets': 0,
                'note': f'Error parsing: {str(e)}'
            },
            'packets': []
        }


def extract_sip_method(payload):
    """Extract SIP method from payload"""
    lines = payload.split('\r\n')
    if lines:
        first_line = lines[0]
        if ' ' in first_line:
            parts = first_line.split(' ')
            return parts[0]
    return 'UNKNOWN'


def is_rtp_packet(pkt):
    """
    Heuristic to detect RTP packets
    RTP typically uses UDP with even ports > 1024
    """
    if UDP not in pkt or Raw not in pkt:
        return False
    
    # Check port range (RTP typically uses ports 16384-32767)
    src_port = pkt[UDP].sport
    dst_port = pkt[UDP].dport
    
    if not ((10000 <= src_port <= 65535) or (10000 <= dst_port <= 65535)):
        return False
    
    # Check if payload looks like RTP
    payload = pkt[Raw].load
    if len(payload) < 12:  # RTP header is 12 bytes minimum
        return False
    
    # Check RTP version (should be 2)
    version = (payload[0] >> 6) & 0x03
    if version != 2:
        return False
    
    return True


def parse_rtp_packet(pkt):
    """
    Parse RTP packet header
    """
    if Raw not in pkt:
        return {}
    
    payload = pkt[Raw].load
    if len(payload) < 12:
        return {}
    
    try:
        # RTP Header format (RFC 3550)
        # Byte 0: V(2), P(1), X(1), CC(4)
        # Byte 1: M(1), PT(7)
        # Bytes 2-3: Sequence number
        # Bytes 4-7: Timestamp
        # Bytes 8-11: SSRC
        
        version = (payload[0] >> 6) & 0x03
        padding = (payload[0] >> 5) & 0x01
        extension = (payload[0] >> 4) & 0x01
        csrc_count = payload[0] & 0x0F
        
        marker = (payload[1] >> 7) & 0x01
        payload_type = payload[1] & 0x7F
        
        sequence = (payload[2] << 8) | payload[3]
        timestamp = (payload[4] << 24) | (payload[5] << 16) | (payload[6] << 8) | payload[7]
        ssrc = (payload[8] << 24) | (payload[9] << 16) | (payload[10] << 8) | payload[11]
        
        return {
            'rtp_version': version,
            'rtp_payload_type': payload_type,
            'rtp_seq': sequence,
            'rtp_timestamp': timestamp,
            'rtp_ssrc': ssrc,
            'rtp_marker': marker
        }
    except Exception as e:
        return {'rtp_parse_error': str(e)}


# ============================================================================
# MACHINE LEARNING FUNCTIONS
# ============================================================================

def extract_features_from_pcap(stats, packets):
    """
    Extract ML features from PCAP statistics and packets
    
    Returns a feature dictionary suitable for anomaly detection
    """
    # Basic stats features
    packet_count = stats.get('packet_count', 0)
    total_bytes = stats.get('total_bytes', 0)
    duration = stats.get('duration_seconds', 1)
    
    # VoIP-specific features
    sip_packets = stats.get('sip_packets', 0)
    rtp_packets = stats.get('rtp_packets', 0)
    
    # Calculate ratios
    sip_ratio = sip_packets / packet_count if packet_count > 0 else 0
    rtp_ratio = rtp_packets / packet_count if packet_count > 0 else 0
    
    # Packet timing analysis
    interarrival_times = []
    if len(packets) > 1:
        for i in range(1, min(len(packets), 1000)):  # Sample first 1000 packets
            if 'timestamp' in packets[i] and 'timestamp' in packets[i-1]:
                try:
                    delta = float(packets[i]['timestamp']) - float(packets[i-1]['timestamp'])
                    if delta > 0:
                        interarrival_times.append(delta)
                except (ValueError, TypeError):
                    continue
    
    avg_interarrival = sum(interarrival_times) / len(interarrival_times) if interarrival_times else 0
    
    # Calculate jitter (variation in interarrival times)
    jitter = 0
    if len(interarrival_times) > 1:
        mean_time = avg_interarrival
        variance = sum((t - mean_time) ** 2 for t in interarrival_times) / len(interarrival_times)
        jitter = variance ** 0.5
    
    # Protocol distribution
    protocol_counts = {}
    for pkt in packets[:1000]:  # Sample first 1000 packets
        proto = pkt.get('protocol', 'unknown')
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    
    # Packet size statistics
    packet_sizes = [pkt.get('length', 0) for pkt in packets[:1000]]
    avg_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
    
    # Calculate packet loss (for RTP)
    packet_loss_ratio = 0
    if rtp_packets > 0:
        # Estimate packet loss from sequence number gaps
        rtp_seq_numbers = []
        for pkt in packets:
            if pkt.get('protocol') == 'RTP' and 'rtp_seq' in pkt:
                rtp_seq_numbers.append(pkt['rtp_seq'])
        
        if len(rtp_seq_numbers) > 1:
            expected_packets = max(rtp_seq_numbers) - min(rtp_seq_numbers) + 1
            actual_packets = len(rtp_seq_numbers)
            packet_loss_ratio = (expected_packets - actual_packets) / expected_packets if expected_packets > 0 else 0
    
    # Compile features
    features = {
        'packet_count': packet_count,
        'total_bytes': total_bytes,
        'duration_seconds': duration,
        'packets_per_second': packet_count / duration if duration > 0 else 0,
        'bytes_per_second': total_bytes / duration if duration > 0 else 0,
        'avg_packet_size': avg_packet_size,
        'sip_packets': sip_packets,
        'rtp_packets': rtp_packets,
        'sip_ratio': sip_ratio,
        'rtp_ratio': rtp_ratio,
        'avg_interarrival': avg_interarrival,
        'jitter': jitter,
        'packet_loss_ratio': packet_loss_ratio,
        'protocol_count': len(protocol_counts),
        'unique_protocols': list(protocol_counts.keys())
    }
    
    return features


def create_training_sample_from_pcap(pcap_id, parsed_data, label='normal'):
    """
    Create a training sample from parsed PCAP data
    
    Args:
        pcap_id: Unique identifier for the PCAP
        parsed_data: Parsed PCAP data dictionary
        label: 'normal' or 'anomaly' (default: 'normal', can be updated later)
    """
    stats = parsed_data.get('stats', {})
    packets = parsed_data.get('packets', [])
    
    # Extract features for ML
    features = extract_features_from_pcap(stats, packets)
    
    # Create training sample
    sample = {
        'pcap_id': pcap_id,
        'timestamp': datetime.utcnow().isoformat(),
        'label': label,  # Default to 'normal', user can change later
        'features': features,
        'stats': stats
    }
    
    # Save to training data directory
    sample_file = os.path.join(
        ML_TRAINING_DATA_DIR, 
        f'sample_{pcap_id}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
    )
    save_data(sample_file, sample)
    
    print(f"✅ Created training sample: {sample_file}")
    return sample


def train_anomaly_model():
    """
    Train an Isolation Forest model for anomaly detection
    Uses all training samples in ML_TRAINING_DATA_DIR
    """
    # Load all training samples
    training_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if f.endswith('.json')]
    
    if len(training_files) < 10:
        return {
            'success': False,
            'error': f'Need at least 10 training samples, found {len(training_files)}'
        }
    
    # Extract features and labels
    X = []
    y = []
    
    feature_keys = [
        'packet_count', 'total_bytes', 'duration_seconds',
        'packets_per_second', 'bytes_per_second', 'avg_packet_size',
        'sip_packets', 'rtp_packets', 'sip_ratio', 'rtp_ratio',
        'avg_interarrival', 'jitter', 'packet_loss_ratio', 'protocol_count'
    ]
    
    for filename in training_files:
        filepath = os.path.join(ML_TRAINING_DATA_DIR, filename)
        sample = load_data(filepath, default={})
        
        if not sample or 'features' not in sample:
            continue
        
        features = sample['features']
        label = sample.get('label', 'normal')
        
        # Extract feature vector
        feature_vector = []
        for key in feature_keys:
            value = features.get(key, 0)
            # Handle non-numeric values
            if isinstance(value, (int, float)):
                feature_vector.append(value)
            else:
                feature_vector.append(0)
        
        X.append(feature_vector)
        y.append(1 if label == 'normal' else -1)
    
    if len(X) < 10:
        return {
            'success': False,
            'error': f'Not enough valid samples, found {len(X)}'
        }
    
    # Train Isolation Forest
    X_array = np.array(X)
    
    # Calculate contamination (proportion of anomalies)
    contamination = max(0.01, min(0.5, y.count(-1) / len(y)))
    
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42
    )
    
    model.fit(X_array)
    
    # Save model
    model_path = os.path.join(ML_MODELS_DIR, 'anomaly_detector.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump({
            'model': model,
            'feature_keys': feature_keys,
            'trained_at': datetime.utcnow().isoformat(),
            'training_samples': len(X)
        }, f)
    
    return {
        'success': True,
        'message': 'Model trained successfully',
        'training_samples': len(X),
        'model_path': model_path
    }


def predict_anomaly(features):
    """
    Predict if a PCAP is anomalous using the trained model
    
    Returns:
        dict with 'is_anomaly' (bool) and 'anomaly_score' (float)
    """
    model_path = os.path.join(ML_MODELS_DIR, 'anomaly_detector.pkl')
    
    if not os.path.exists(model_path):
        return {
            'is_anomaly': False,
            'anomaly_score': 0,
            'error': 'Model not trained yet'
        }
    
    try:
        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)
        
        model = model_data['model']
        feature_keys = model_data['feature_keys']
        
        # Extract feature vector
        feature_vector = []
        for key in feature_keys:
            value = features.get(key, 0)
            if isinstance(value, (int, float)):
                feature_vector.append(value)
            else:
                feature_vector.append(0)
        
        X = np.array([feature_vector])
        
        # Predict
        prediction = model.predict(X)[0]  # 1 for normal, -1 for anomaly
        anomaly_score = model.score_samples(X)[0]  # Lower score = more anomalous
        
        return {
            'is_anomaly': prediction == -1,
            'anomaly_score': float(anomaly_score),
            'confidence': abs(anomaly_score)
        }
    
    except Exception as e:
        return {
            'is_anomaly': False,
            'anomaly_score': 0,
            'error': str(e)
        }

def analyze_with_ml(pcap_data):
    """
    Run a simple ML anomaly detection on packet features using IsolationForest.
    Expects parsed pcap_data containing packets or stats.
    """

    try:
        packets = pcap_data.get("packets", [])
        stats = pcap_data.get("stats", {})

        # 🟢 Feature extraction (very basic example)
        features = []
        for pkt in packets:
            size = pkt.get("size", 0)
            proto = 0 if pkt.get("protocol") == "TCP" else 1
            features.append([size, proto])

        # If no per‑packet features, fall back to stats
        if not features:
            features = [[
                stats.get("packet_count", 0),
                stats.get("total_bytes", 0),
                stats.get("duration_seconds", 0)
            ]]

        X = np.array(features)

        # 💡 Use IsolationForest for anomaly detection
        clf = IsolationForest(random_state=42)
        preds = clf.fit_predict(X)
        scores = clf.decision_function(X)

        anomaly_score = float(np.mean(scores))
        is_anomaly = int((preds == -1).sum()) > 0

        return {
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": anomaly_score,
            "total_packets": len(packets),
            "ml_comment": "Anomaly detected" if is_anomaly else "No anomaly detected"
        }

    except Exception as e:
        return {"error": f"ML analysis failed: {str(e)}"}




# ============================================================================
# ROUTELLM INTEGRATION
# ============================================================================

def query_routellm(question, context):
    """
    Query RouteLLM with PCAP context
    """
    import requests
    
    prompt = f"""You are a network analysis expert. Answer the following question about this PCAP capture.

PCAP Statistics:
{json.dumps(context.get('stats', {}), indent=2)}

Sample Packets (first 50):
{json.dumps(context.get('packets', [])[:50], indent=2)}

Question: {question}

Provide a detailed, technical answer based on the PCAP data above."""

    try:
        response = requests.post(
            ROUTELLM_ENDPOINT,
            headers={
                'Authorization': f'Bearer {ROUTELLM_API_KEY}',
                'Content-Type': 'application/json'
            },
            json={
                'model': ROUTELLM_MODEL,
                'messages': [
                    {'role': 'system', 'content': 'You are a network analysis expert specializing in VoIP and packet analysis.'},
                    {'role': 'user', 'content': prompt}
                ],
                'temperature': 0.7,
                'max_tokens': 1000
            },
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data['choices'][0]['message']['content']
        else:
            return f"Error from RouteLLM: {response.status_code} - {response.text}"
    
    except Exception as e:
        return f"Error querying RouteLLM: {str(e)}"


# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/pcap')
def pcap_page():
    return render_template('pcap.html')


@app.route('/api/pcap/upload', methods=['POST'])
def upload_pcap():
    """
    Upload a PCAP file, parse it, and create ML training sample
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Empty filename'}), 400
    
    # Save file
    filename = secure_filename(file.filename)
    pcap_id = str(uuid.uuid4())
    filepath = os.path.join(UPLOAD_DIR, f'{pcap_id}_{filename}')
    file.save(filepath)
    
    # Parse PCAP
    parsed_data = parse_pcap_file(filepath)
    
    # Save metadata
    metadata_file = os.path.join(METADATA_DIR, f'{pcap_id}.json')
    save_data(metadata_file, parsed_data)
    
    # Automatically create ML training sample from uploaded PCAP
    try:
        create_training_sample_from_pcap(pcap_id, parsed_data)
    except Exception as e:
        print(f"Warning: Could not create training sample: {e}")
    
    return jsonify({
        'pcap_id': pcap_id,
        'filename': filename,
        'stats': parsed_data.get('stats', {}),
        'message': 'PCAP uploaded and training sample created'
    }), 200

        
def ask_routellm(query, context=None, model="route-llm", temperature=0.3, stream=False):
    """
    Send a chat request to Abacus RouteLLM API.
    Supports both streaming and non-streaming.

    Args:
        query (str): The user question
        context (str, optional): System / context info
        model (str): Model name
        temperature (float): Response randomness
        stream (bool): Whether to request streaming mode

    Returns:
        - If stream=False: dict (JSON response)
        - If stream=True : generator (for Flask Response)
    """
    endpoint = os.getenv("ROUTELLM_ENDPOINT")
    api_key = os.getenv("ROUTELLM_API_KEY")

    if not endpoint or not api_key:
        return {"error": "RouteLLM not configured"}

    # Build messages
    messages = []
    if context:
        messages.append({"role": "system", "content": f"You are a helpful assistant. Context: {context}"})
    messages.append({"role": "user", "content": query})

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "stream": stream
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    if stream:
        # Return a generator for Flask streaming Response
        def generate():
            with requests.post(endpoint, headers=headers, json=payload, stream=True) as r:
                r.raise_for_status()
                for raw_line in r.iter_lines():
                    if not raw_line:
                        continue  # skip empty heartbeat lines
                    try:
                        decoded = raw_line.decode("utf-8").strip()
                        logging.debug("RAW STREAM: %s", decoded)

                        # Handle SSE-style format: "data: { ... }"
                        if decoded.startswith("data:"):
                            decoded = decoded[len("data:"):].strip()
                        if decoded == "" or decoded == "[DONE]":
                            break
                        # Try parse as JSON
                        data = json.loads(decoded)
                        if "answer" in data:
                            yield data["answer"]
                    except json.JSONDecodeError:
                        # Not JSON – just stream as raw text
                        continue
                    except Exception as e:
                        logging.error("Stream parse error: %s", e)
                        yield f"[Stream error: {str(e)}]\n"

        return generate()

    else:
        # Non-streaming request
        try:
            r = requests.post(endpoint, headers=headers, json=payload)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logging.error("Non-streaming request failed: %s", e)
            return {"error": str(e)}

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.json
    pcap_metadata = data.get("pcap_metadata", {})

    result = ask_routellm(
        query="Explain the results of this call",
        context={"pcap_metadata": pcap_metadata},
        model="gpt-4o-mini",
        temperature=0.3
    )

    if "error" in result:
        return jsonify(result), 500

    return jsonify({"answer": result["answer"]})

@app.route('/api/pcap/<pcap_id>/route-llm', methods=['POST'])
def route_llm_handler(pcap_id):
    """Stream responses from RouteLLM"""
    try:
        body = request.get_json() or {}
        question = (body.get("question") or "").strip()
        if not question:
            return jsonify({"error": "❌ Missing 'question'"}), 400

        # Load PCAP metadata
        metadata_path = os.path.join(METADATA_DIR, f"{pcap_id}.json")
        if not os.path.exists(metadata_path):
            return jsonify({"error": "❌ PCAP not found"}), 404

        parsed_data = load_data(metadata_path, default={})
        ml_analysis = analyze_with_ml(parsed_data)

        # Build context
        context = {
            "pcap_metadata": parsed_data,
            "ml_analysis": ml_analysis
        }

        # Stream the response
        def generate():
            messages = [
                {"role": "system", "content": f"You are a network analysis expert. Context: {json.dumps(context)}"},
                {"role": "user", "content": question}
            ]

            response = requests.post(
                ROUTELLM_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {ROUTELLM_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": ROUTELLM_MODEL,
                    "messages": messages,
                    "stream": True  # ✅ Enable streaming
                },
                stream=True
            )

            for line in response.iter_lines():
                if line:
                    line = line.decode("utf-8")
                    if line.startswith("data: "):
                        line = line[6:]
                        if line == "[DONE]":
                            break
                        try:
                            chunk = json.loads(line)
                            if chunk["choices"][0].get("delta", {}).get("content"):
                                yield f"data: {json.dumps({'content': chunk['choices'][0]['delta']['content']})}\n\n"
                        except:
                            continue

        return Response(stream_with_context(generate()), mimetype='text/event-stream')

    except Exception as e:
        app.logger.exception("Error in route-llm")
        return jsonify({"error": str(e)}), 500

@app.route('/api/pcap/<pcap_id>/label', methods=['POST'])
def label_pcap_for_ml(pcap_id):
    """
    Label a PCAP's training sample as normal or anomaly
    This is a convenience endpoint that finds the sample by pcap_id
    """
    data = request.get_json()
    label = data.get('label', 'normal')
    
    if label not in ['normal', 'anomaly']:
        return jsonify({'error': 'Label must be "normal" or "anomaly"'}), 400
    
    # Find sample file by pcap_id
    sample_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if pcap_id in f]
    
    if not sample_files:
        return jsonify({'error': 'No training sample found for this PCAP'}), 404
    
    # Update all matching samples (there should typically be only one)
    updated_count = 0
    for filename in sample_files:
        sample_file = os.path.join(ML_TRAINING_DATA_DIR, filename)
        sample = load_data(sample_file, default={})
        sample['label'] = label
        sample['label_updated_at'] = datetime.utcnow().isoformat()
        save_data(sample_file, sample)
        updated_count += 1
    
    return jsonify({
        'success': True,
        'pcap_id': pcap_id,
        'label': label,
        'updated_samples': updated_count,
        'message': f'PCAP labeled as {label}'
    })


# ============================================================================
# ML API ROUTES
# ============================================================================

@app.route('/api/ml/status', methods=['GET'])
def ml_status():
    """
    Get ML system status
    """
    model_path = os.path.join(ML_MODELS_DIR, 'anomaly_detector.pkl')
    model_exists = os.path.exists(model_path)
    
    training_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if f.endswith('.json')]
    
    model_info = {
        'trained': False,
        'path': model_path,
        'size_bytes': 0,
        'last_modified': None
    }
    
    if model_exists:
        model_info['trained'] = True
        model_info['size_bytes'] = os.path.getsize(model_path)
        model_info['last_modified'] = datetime.fromtimestamp(os.path.getmtime(model_path)).isoformat()
    
    return jsonify({
        'model': model_info,
        'training_samples': len(training_files),
        'min_samples_required': 10,
        'ready_to_train': len(training_files) >= 10
    })


@app.route('/api/ml/train', methods=['POST'])
def train_ml_model():
    """
    Train the anomaly detection model
    """
    result = train_anomaly_model()
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


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
    # Find the sample file (it may have timestamp suffix)
    sample_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if f.startswith(sample_id)]
    
    if not sample_files:
        return jsonify({'error': 'Sample not found'}), 404
    
    sample_file = os.path.join(ML_TRAINING_DATA_DIR, sample_files[0])
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
    # Find the sample file
    sample_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if sample_id in f]
    
    if not sample_files:
        return jsonify({'error': 'Sample not found'}), 404
    
    try:
        for filename in sample_files:
            sample_file = os.path.join(ML_TRAINING_DATA_DIR, filename)
            os.remove(sample_file)
        
        return jsonify({
            'success': True,
            'message': f'Sample {sample_id} deleted'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/samples/<sample_id>/label', methods=['PUT'])
def update_sample_label(sample_id):
    """
    Update the label of a training sample
    Allows users to mark samples as 'normal' or 'anomaly'
    """
    data = request.get_json()
    new_label = data.get('label', 'normal')
    
    if new_label not in ['normal', 'anomaly']:
        return jsonify({'error': 'Label must be "normal" or "anomaly"'}), 400
    
    # Find the sample file
    sample_files = [f for f in os.listdir(ML_TRAINING_DATA_DIR) if sample_id in f]
    
    if not sample_files:
        return jsonify({'error': 'Sample not found'}), 404
    
    sample_file = os.path.join(ML_TRAINING_DATA_DIR, sample_files[0])
    
    # Load, update, and save
    sample = load_data(sample_file, default={})
    sample['label'] = new_label
    sample['label_updated_at'] = datetime.utcnow().isoformat()
    save_data(sample_file, sample)
    
    return jsonify({
        'success': True,
        'sample_id': sample_id,
        'new_label': new_label,
        'message': f'Sample labeled as {new_label}'
    })


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
            model_data = pickle.load(f)
        
        model = model_data['model']
        
        model_info = {
            'trained': True,
            'model_type': type(model).__name__,
            'n_estimators': model.n_estimators if hasattr(model, 'n_estimators') else None,
            'contamination': model.contamination if hasattr(model, 'contamination') else None,
            'max_samples': model.max_samples if hasattr(model, 'max_samples') else None,
            'file_path': model_path,
            'size_bytes': os.path.getsize(model_path),
            'last_modified': datetime.fromtimestamp(os.path.getmtime(model_path)).isoformat(),
            'trained_at': model_data.get('trained_at'),
            'training_samples': model_data.get('training_samples'),
            'features_used': model_data.get('feature_keys', [])
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

@app.route('/api/debug/routellm-endpoint', methods=['GET'])
def debug_routellm_endpoint():
    """
    Debug endpoint: shows which RouteLLM endpoint Flask is using,
    whether the API key is injected, and if the endpoint looks valid.
    """
    looks_valid = "routellm/v1" not in ROUTELLM_ENDPOINT.lower() \
                  and "routeLLM/query" in ROUTELLM_ENDPOINT

    return jsonify({
        "configured_endpoint": ROUTELLM_ENDPOINT,
        "api_key_loaded": bool(ROUTELLM_API_KEY and ROUTELLM_API_KEY != "your-api-key-here"),
        "model": ROUTELLM_MODEL,
        "endpoint_looks_valid": looks_valid
    })

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8080)
