#!/usr/bin/env bash
# run.sh - sets up a venv (if not present) and starts the dashboard.
set -e
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt

echo
echo "Starting Tendaji PKI Registry on http://127.0.0.1:5000"
echo "Press CTRL+C to stop."
echo
python3 app.py
