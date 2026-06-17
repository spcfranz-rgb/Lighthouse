#!/bin/bash

echo "Initializing database migrations..."
python -c "from app import init_db; init_db()"

echo "Starting background monitor loop..."
# The '&' runs this infinitely in the background
python -c "from app import monitor_loop; monitor_loop()" &

echo "Starting Gunicorn web server..."
# 'exec' replaces the bash shell with Gunicorn as the primary container process
exec gunicorn -w 4 --threads 2 -b 0.0.0.0:5000 app:app
