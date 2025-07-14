# Portfolio-Website
Portofolio Website 

Complete Flask Application Structure:

app.py - Main Flask application
templates/index.html - HTML template with proper Flask templating
static/css/style.css - Styling that matches the screenshot exactly
static/js/network.js - JavaScript for the animated network background
requirements.txt - Python dependencies
deploy.sh - Complete deployment script for RedHat Linux

Key Features:

✅ Exact visual match to your screenshot
✅ Animated network background with moving nodes and connections
✅ Responsive design
✅ Professional profile card with glassmorphism effect
✅ Social media icons (Instagram, TikTok, YouTube, LinkedIn, GitHub)
✅ Production-ready with Gunicorn and Nginx
✅ Systemd service configuration
✅ SSL/HTTPS ready
✅ Firewall configuration

Deployment Instructions:

Upload files to your RedHat server in this structure:

/opt/portfolio/
├── app.py
├── requirements.txt
├── deploy.sh
├── templates/
│   └── index.html
└── static/
    ├── css/
    │   └── style.css
    ├── js/
    │   └── network.js
    └── images/
        └── profile.jpg  # Add your profile image

***STEP TO DEPLOY***
1. Open terminal and run:
   git clone https://github.com/gpscal/Portfolio-Website.git



Add your profile image to static/images/profile.jpg

The deployment script automatically handles:

Installing Python, Nginx, and dependencies
Creating virtual environment
Setting up systemd service
Configuring Nginx reverse proxy
Setting up firewall rules
SSL certificate instructions

Your website will be accessible at http://your-server-ip and ready for production use!
