#!/bin/bash
# start.sh - wrapper to set environment variables & launch Gunicorn

# === Set required environment variables ===
export ROUTELLM_API_KEY="s2_740eb068e89f4eec9d7c8762e09db7a0"
export ROUTELLM_ENDPOINT="https://api.abacus.ai/routellm"

# Optional: other settings
export WORKERS=2
export HOST=0.0.0.0
export PORT=8080

# === Launch Gunicorn ===
echo "Starting Gunicorn with ROUTELLM_API_KEY and ROUTELLM_ENDPOINT..."
exec /home/ubuntu/Portfolio-Website/venv/bin/gunicorn app:app -w $WORKERS -b $HOST:$PORT
