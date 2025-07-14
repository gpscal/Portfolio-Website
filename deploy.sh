#!/bin/bash

# RedHat Linux deployment script for Flask Portfolio Website
# Run this script as root or with sudo privileges

set -e

PROJECT_NAME="portfolio"
PROJECT_DIR="/opt/$PROJECT_NAME"
PYTHON_VERSION="3.9"
USER="portfolio"
SERVICE_NAME="portfolio"

echo "🚀 Starting deployment of Flask Portfolio Website on RedHat Linux..."

# Update system packages
echo "📦 Updating system packages..."
dnf update -y

# Install Python and required packages
echo "🐍 Installing Python and dependencies..."
dnf install -y python${PYTHON_VERSION} python${PYTHON_VERSION}-pip python${PYTHON_VERSION}-devel
dnf install -y nginx git supervisor

# Create project user
echo "👤 Creating project user..."
if ! id "$USER" &>/dev/null; then
    useradd -r -s /bin/false $USER
fi

# Create project directory
echo "📁 Creating project directory..."
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# Create virtual environment
echo "🔧 Setting up virtual environment..."
python${PYTHON_VERSION} -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "📋 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Set up directory structure
echo "🏗️  Setting up directory structure..."
mkdir -p templates static/css static/js static/images logs

# Copy application files (you need to upload these files to the server)
echo "📄 Make sure to copy your application files to:"
echo "  - $PROJECT_DIR/app.py"
echo "  - $PROJECT_DIR/templates/index.html"
echo "  - $PROJECT_DIR/static/css/style.css"
echo "  - $PROJECT_DIR/static/js/network.js"
echo "  - $PROJECT_DIR/requirements.txt"
echo "  - Add profile image to $PROJECT_DIR/static/images/profile.jpg"

# Set permissions
echo "🔒 Setting permissions..."
chown -R $USER:$USER $PROJECT_DIR
chmod -R 755 $PROJECT_DIR

# Create systemd service file
echo "⚙️  Creating systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Flask Portfolio Website
After=network.target

[Service]
User=$USER
Group=$USER
WorkingDirectory=$PROJECT_DIR
Environment=PATH=$PROJECT_DIR/venv/bin
ExecStart=$PROJECT_DIR/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Create Nginx configuration
echo "🌐 Setting up Nginx..."
cat > /etc/nginx/conf.d/$PROJECT_NAME.conf << EOF
server {
    listen 80;
    server_name ryanmontgomery.me www.ryanmontgomery.me;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /static/ {
        alias $PROJECT_DIR/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
EOF

# Enable and start services
echo "🔄 Starting services..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl enable nginx

# Configure firewall
echo "🔥 Configuring firewall..."
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload

# SSL Setup (optional - requires domain)
echo "🔐 SSL Setup Instructions:"
echo "1. Install certbot: dnf install -y certbot python3-certbot-nginx"
echo "2. Get SSL certificate: certbot --nginx -d ryanmontgomery.me -d www.ryanmontgomery.me"
echo "3. Set up auto-renewal: echo '0 12 * * * /usr/bin/certbot renew --quiet' | crontab -"

# Start services
systemctl start nginx
systemctl start $SERVICE_NAME

echo "✅ Deployment complete!"
echo "📍 Your website should be accessible at: http://your-server-ip"
echo "🔍 Check service status: systemctl status $SERVICE_NAME"
echo "📋 View logs: journalctl -u $SERVICE_NAME -f"
echo "🌐 Nginx status: systemctl status nginx"

# Show service status
echo "📊 Service Status:"
systemctl is-active $SERVICE_NAME
systemctl is-active nginx
