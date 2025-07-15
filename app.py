#!/usr/bin/env python3

from flask import Flask, render_template, send_from_directory
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

# Directory structure needed:
# project/
# ├── app.py (this file)
# ├── templates/
# │   └── index.html
# ├── static/
# │   ├── css/
# │   │   └── style.css
# │   ├── js/
# │   │   └── network.js
# │   └── images/
# │       └── profile.jpg
# └── requirements.txt
