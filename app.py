from flask import Flask, request, Response, jsonify, render_template, stream_with_context, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import logging
import requests
import os
import json
import uuid
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from scapy.layers.inet import ICMP

app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_DIR = 'data/uploads'
METADATA_DIR = 'data/metadata'
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(METADATA_DIR, exist_ok=True)

# RouteLLM Configuration (update with your actual keys)
ROUTELLM_API_KEY = os.getenv('ROUTELLM_API_KEY')
ROUTELLM_MODEL = os.getenv('ROUTELLM_MODEL')
ROUTELLM_ENDPOINT = os.getenv('ROUTELLM_ENDPOINT')

# OpenAI configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4o')

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
# ROUTELLM INTEGRATION
# ============================================================================

def query_routellm(question, context):
    """
    Query RouteLLM with PCAP context
    """
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
                'temperature': 0.1,
                'max_tokens': 2000
            },
            timeout=300
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

@app.route('/research')
def research_page():
    return render_template('research.html')

@app.route('/multisearch')
def multi_search_query():
    return render_template('multisearch.html')

@app.route('/test')
def test_page():
    return render_template('test.html')

@app.route('/dual-research')
def dual_research_page():
    return render_template('dual_research.html')

# Add this new endpoint for dual LLM streaming
@app.route('/api/dual-research', methods=['POST'])
def dual_research_api():
    """Handle dual LLM requests with streaming from both OpenAI and RouteLLM"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        history = data.get('history', [])
        enable_web_search = data.get('enable_web_search', False)

        if not message:
            return jsonify({'error': 'No message provided'}), 400

        def generate_dual_responses():
            import threading
            from queue import Queue
            
            openai_queue = Queue()
            routellm_queue = Queue()
            
            def openai_stream():
                try:
                    # Build messages for OpenAI
                    messages = []
                    
                    # Add system message
                    if enable_web_search:
                        messages.append({
                            'role': 'system', 
                            'content': 'You are a helpful AI assistant. Provide accurate, detailed answers.'
                        })
                    else:
                        messages.append({
                            'role': 'system',
                            'content': 'You are a helpful AI assistant.'
                        })

                    # Add conversation history
                    for msg in history[-6:]:  # Use slightly less history for dual
                        if isinstance(msg, dict) and 'role' in msg and 'content' in msg:
                            messages.append(msg)

                    # Add current message
                    messages.append({'role': 'user', 'content': message})

                    # Call OpenAI API with streaming
                    response = requests.post(
                        'https://api.openai.com/v1/chat/completions',
                        headers={
                            'Authorization': f'Bearer {OPENAI_API_KEY}',
                            'Content-Type': 'application/json'
                        },
                        json={
                            'model': OPENAI_MODEL,
                            'messages': messages,
                            'temperature': 0.1,
                            'max_tokens': 1500,
                            'stream': True
                        },
                        stream=True,
                        timeout=300
                    )
                    
                    response.raise_for_status()
                    
                    full_content = ""
                    for line in response.iter_lines():
                        if line:
                            line = line.decode('utf-8')
                            if line.startswith('data: '):
                                data_str = line[6:]
                                if data_str == '[DONE]':
                                    openai_queue.put({'type': 'done'})
                                    break
                                try:
                                    data = json.loads(data_str)
                                    if data.get('choices') and len(data['choices']) > 0:
                                        delta = data['choices'][0].get('delta', {})
                                        content = delta.get('content', '')
                                        if content:
                                            full_content += content
                                            openai_queue.put({
                                                'type': 'content',
                                                'content': content,
                                                'provider': 'openai'
                                            })
                                except json.JSONDecodeError:
                                    continue
                    
                except Exception as e:
                    openai_queue.put({
                        'type': 'error',
                        'error': f'OpenAI Error: {str(e)}',
                        'provider': 'openai'
                    })
            
            def routellm_stream():
                try:
                    # Build messages for RouteLLM
                    messages = []
                    
                    if enable_web_search:
                        messages.append({
                            'role': 'system',
                            'content': 'You are a helpful AI assistant with access to current web information.'
                        })
                    else:
                        messages.append({
                            'role': 'system', 
                            'content': 'You are a helpful AI assistant.'
                        })

                    for msg in history[-6:]:
                        if isinstance(msg, dict) and 'role' in msg and 'content' in msg:
                            messages.append(msg)

                    messages.append({'role': 'user', 'content': message})

                    # Call RouteLLM API
                    response = requests.post(
                        ROUTELLM_ENDPOINT,
                        headers={
                            'Authorization': f'Bearer {ROUTELLM_API_KEY}',
                            'Content-Type': 'application/json'
                        },
                        json={
                            'model': ROUTELLM_MODEL,
                            'messages': messages,
                            'temperature': 0.1,
                            'max_tokens': 1500,
                            'stream': True
                        },
                        stream=True,
                        timeout=300
                    )
                    
                    response.raise_for_status()
                    
                    buffer = ""
                    for chunk in response.iter_content(chunk_size=None, decode_unicode=True):
                        if chunk:
                            buffer += chunk
                            while "\n" in buffer:
                                line, buffer = buffer.split("\n", 1)
                                line = line.strip()
                                if line.startswith("data: "):
                                    data_str = line[6:]
                                    if data_str == "[DONE]":
                                        routellm_queue.put({'type': 'done'})
                                        return
                                    try:
                                        data = json.loads(data_str)
                                        if data.get("choices") and len(data["choices"]) > 0:
                                            delta = data["choices"][0].get("delta", {})
                                            content = delta.get("content", "")
                                            if content:
                                                routellm_queue.put({
                                                    'type': 'content', 
                                                    'content': content,
                                                    'provider': 'routellm'
                                                })
                                    except json.JSONDecodeError:
                                        continue
                
                except Exception as e:
                    routellm_queue.put({
                        'type': 'error',
                        'error': f'RouteLLM Error: {str(e)}',
                        'provider': 'routellm'
                    })
            
            # Start both threads
            openai_thread = threading.Thread(target=openai_stream)
            routellm_thread = threading.Thread(target=routellm_stream)
            
            openai_thread.daemon = True
            routellm_thread.daemon = True
            
            openai_thread.start()
            routellm_thread.start()
            
            # Track completion
            openai_done = False
            routellm_done = False
            
            while not (openai_done and routellm_done):
                # Check OpenAI queue
                try:
                    openai_data = openai_queue.get(timeout=0.1)
                    if openai_data['type'] == 'done':
                        openai_done = True
                        yield f"data: {json.dumps({'provider': 'openai', 'done': True})}\n\n"
                    elif openai_data['type'] == 'content':
                        yield f"data: {json.dumps({'provider': 'openai', 'content': openai_data['content']})}\n\n"
                    elif openai_data['type'] == 'error':
                        yield f"data: {json.dumps({'provider': 'openai', 'error': openai_data['error']})}\n\n"
                        openai_done = True
                except:
                    pass
                
                # Check RouteLLM queue  
                try:
                    routellm_data = routellm_queue.get(timeout=0.1)
                    if routellm_data['type'] == 'done':
                        routellm_done = True
                        yield f"data: {json.dumps({'provider': 'routellm', 'done': True})}\n\n"
                    elif routellm_data['type'] == 'content':
                        yield f"data: {json.dumps({'provider': 'routellm', 'content': routellm_data['content']})}\n\n"
                    elif routellm_data['type'] == 'error':
                        yield f"data: {json.dumps({'provider': 'routellm', 'error': routellm_data['error']})}\n\n"
                        routellm_done = True
                except:
                    pass

        return Response(
            stream_with_context(generate_dual_responses()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )

    except Exception as e:
        app.logger.exception("Error in dual research API")
        return jsonify({'error': str(e)}), 500

@app.route('/api/test', methods=['POST', 'GET'])
def chat():
    if request.method == 'GET':
        user_message = request.args.get('message', '')
    else:
        data = request.get_json()
        user_message = data.get('message', '')

    if not user_message:
        return Response("No message provided", status=400)

    def generate_response():
        url = ROUTELLM_ENDPOINT
        headers = {
            "Authorization": f"Bearer {ROUTELLM_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": ROUTELLM_MODEL,
            "messages": [{"role": "user", "content": user_message}],
            "stream": True
        }

        try:
            response = requests.post(url, headers=headers, json=payload, stream=True)
            response.raise_for_status()
            
            # Use iter_content instead of iter_lines for true streaming
            buffer = ""
            for chunk in response.iter_content(chunk_size=1, decode_unicode=True):
                if chunk:
                    buffer += chunk
                    
                    # Process complete lines
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        
                        if line.startswith("data: "):
                            data_str = line[6:]  # Remove "data: " prefix
                            
                            if data_str == "[DONE]":
                                return
                            
                            try:
                                data = json.loads(data_str)
                                if data.get("choices") and len(data["choices"]) > 0:
                                    delta = data["choices"][0].get("delta", {})
                                    content = delta.get("content", "")
                                    
                                    if content:
                                        yield f"data: {json.dumps({'content': content})}\n\n"
                            except json.JSONDecodeError:
                                continue
                                
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(
        stream_with_context(generate_response()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/api/pcap/upload', methods=['POST'])
def upload_pcap():
    """
    Upload a PCAP file and parse it
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
    
    return jsonify({
        'pcap_id': pcap_id,
        'filename': filename,
        'stats': parsed_data.get('stats', {}),
        'message': 'PCAP uploaded successfully'
    }), 200

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.json
    pcap_metadata = data.get("pcap_metadata", {})

    result = query_routellm(
        "Explain the results of this call",
        {"pcap_metadata": pcap_metadata}
    )

    return jsonify({"answer": result})

@app.route('/api/research', methods=['POST'])
def chat_api():
    """Handle chat requests with streaming and optional web browsing"""
    try:
        data = request.get_json()
        message = data.get('message', '')
        history = data.get('history', [])
        enable_web_search = data.get('enable_web_search', False)

        if not message:
            return jsonify({'error': 'No message provided'}), 400

        def generate_response():
            try:
                # Build messages for RouteLLM
                messages = []

                # Add system message with web search capability
                if enable_web_search:
                    messages.append({
                        'role': 'system',
                        'content': 'You are a helpful AI assistant with access to current web information. Provide accurate, up-to-date answers.'
                    })
                else:
                    messages.append({
                        'role': 'system',
                        'content': 'You are a helpful AI assistant.'
                    })

                # Add conversation history (last 10 messages)
                for msg in history[-10:]:
                    if isinstance(msg, dict) and 'role' in msg and 'content' in msg:
                        messages.append(msg)

                # Add current message
                messages.append({
                    'role': 'user',
                    'content': message
                })

                # Call RouteLLM API with streaming
                response = requests.post(
                    ROUTELLM_ENDPOINT,
                    headers={
                        'Authorization': f'Bearer {ROUTELLM_API_KEY}',
                        'Content-Type': 'application/json'
                    },
                    json={
                        'model': ROUTELLM_MODEL,
                        'messages': messages,
                        'temperature': 0.5,
                        'max_tokens': 2000,
                        'stream': True
                    },
                    stream=True,
                    timeout=400
                )

                response.raise_for_status()

                # Stream the response using iter_content for true streaming
                buffer = ""
                for chunk in response.iter_content(chunk_size=None, decode_unicode=True):
                    if chunk:
                        buffer += chunk
                        
                        # Process complete lines
                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            line = line.strip()
                            
                            if line.startswith("data: "):
                                data_str = line[6:]  # Remove "data: " prefix
                                
                                if data_str == "[DONE]":
                                    return
                                
                                try:
                                    data = json.loads(data_str)
                                    if data.get("choices") and len(data["choices"]) > 0:
                                        delta = data["choices"][0].get("delta", {})
                                        content = delta.get("content", "")
                                        
                                        if content:
                                            yield f"data: {json.dumps({'content': content})}\n\n"
                                except json.JSONDecodeError:
                                    continue

            except requests.Timeout:
                yield f"data: {json.dumps({'error': 'Request timed out. Please try a simpler question.'})}\n\n"
            except Exception as e:
                app.logger.exception("Error in streaming response")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return Response(
            stream_with_context(generate_response()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no'
            }
        )

    except Exception as e:
        app.logger.exception("Error in chat_api")
        return jsonify({'error': str(e)}), 500

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

        # Build context
        context = {
            "pcap_metadata": parsed_data
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
                    "stream": True
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

@app.route('/api/debug/routellm-endpoint', methods=['GET'])
def debug_routellm_endpoint():
    """
    Debug endpoint: shows which RouteLLM endpoint Flask is using,
    whether the API key is injected, and if the endpoint looks valid.
    """
    looks_valid = "routellm/v1" not in ROUTELLM_ENDPOINT.lower() and "routeLLM/query" in ROUTELLM_ENDPOINT

    return jsonify({
        "configured_endpoint": ROUTELLM_ENDPOINT,
        "api_key_loaded": bool(ROUTELLM_API_KEY and ROUTELLM_API_KEY != "your-api-key-here"),
        "model": ROUTELLM_MODEL,
        "endpoint_looks_valid": looks_valid
    })

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8080)
