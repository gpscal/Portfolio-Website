from flask import Flask, render_template, request, jsonify, redirect, url_for
import json
import os
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Demo users (in production, use a proper database)
USERS = {
    'admin': 'password123',
    'user': 'demo123',
    'caleb': 'portfolio2024'
}

# File paths for data storage
DATA_DIR = 'data'
CATEGORIES_FILE = os.path.join(DATA_DIR, 'categories.json')
COMMANDS_FILE = os.path.join(DATA_DIR, 'commands.json')

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

def load_data(filename, default=None):
    """Load data from JSON file"""
    if default is None:
        default = []
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return default

def save_data(filename, data):
    """Save data to JSON file"""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def verify_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/')
def index():
    """Main portfolio page"""
    return render_template('index.html')

@app.route('/login')
def login_page():
    """Login page"""
    return render_template('login.html')

@app.route('/notes')
def notes_page():
    """Notes page (requires authentication)"""
    return render_template('notes.html')

@app.route('/api/login', methods=['POST'])
def api_login():
    """Handle login API request"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in USERS and USERS[username] == password:
        # Generate JWT token
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

@app.route('/api/categories', methods=['GET'])
def get_categories():
    """Get all categories"""
    categories = load_data(CATEGORIES_FILE)
    return jsonify(categories)

@app.route('/api/categories', methods=['POST'])
def create_category():
    """Create a new category"""
    # Verify authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not verify_token(auth_header.replace('Bearer ', '')):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    categories = load_data(CATEGORIES_FILE)

    new_category = {
        'id': str(len(categories) + 1),
        'name': data['name'],
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
    # Verify authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not verify_token(auth_header.replace('Bearer ', '')):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    categories = load_data(CATEGORIES_FILE)

    for category in categories:
        if category['id'] == category_id:
            category.update({
                'name': data['name'],
                'description': data.get('description', ''),
                'parentId': data.get('parentId'),
                'updated_at': datetime.utcnow().isoformat()
            })
            break

    save_data(CATEGORIES_FILE, categories)
    return jsonify({'success': True})

@app.route('/api/categories/<category_id>', methods=['DELETE'])
def delete_category(category_id):
    """Delete a category"""
    # Verify authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not verify_token(auth_header.replace('Bearer ', '')):
        return jsonify({'error': 'Unauthorized'}), 401

    categories = load_data(CATEGORIES_FILE)
    commands = load_data(COMMANDS_FILE)

    # Remove category and subcategories
    categories = [cat for cat in categories if cat['id'] != category_id and cat.get('parentId') != category_id]

    # Remove associated commands
    commands = [cmd for cmd in commands if cmd.get('categoryId') != category_id]

    save_data(CATEGORIES_FILE, categories)
    save_data(COMMANDS_FILE, commands)

    return jsonify({'success': True})

@app.route('/api/commands', methods=['GET'])
def get_commands():
    """Get all commands"""
    commands = load_data(COMMANDS_FILE)
    return jsonify(commands)

@app.route('/api/commands', methods=['POST'])
def create_command():
    """Create a new command"""
    # Verify authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not verify_token(auth_header.replace('Bearer ', '')):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    commands = load_data(COMMANDS_FILE)

    new_command = {
        'id': str(len(commands) + 1),
        'categoryId': data['categoryId'],
        'name': data['name'],
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
    # Verify authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not verify_token(auth_header.replace('Bearer ', '')):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    commands = load_data(COMMANDS_FILE)

    for command in commands:
        if command['id'] == command_id:
            command.update({
                'categoryId': data['categoryId'],
                'name': data['name'],
                'syntax': data.get('syntax', ''),
                'description': data.get('description', ''),
                'examples': data.get('examples', ''),
                'tags': data.get('tags', ''),
                'updated_at': datetime.utcnow().isoformat()
            })
            break

    save_data(COMMANDS_FILE, commands)
    return jsonify({'success': True})

@app.route('/api/commands/<command_id>', methods=['DELETE'])
def delete_command(command_id):
    """Delete a command"""
    # Verify authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or not verify_token(auth_header.replace('Bearer ', '')):
        return jsonify({'error': 'Unauthorized'}), 401

    commands = load_data(COMMANDS_FILE)
    commands = [cmd for cmd in commands if cmd['id'] != command_id]

    save_data(COMMANDS_FILE, commands)
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
