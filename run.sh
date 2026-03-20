#!/bin/bash

# 1. Start C++ Data Plane
echo "[1/3] Launching C++ Core (Port 1300)..."
./server &
CPP_PID=$!

# 2. Start Python Control Plane
echo "[2/3] Launching Python Bridge (Port 8000)..."
# Using --host 127.0.0.1 ensures it matches the proxy target
fastapi dev src/App.py --host 127.0.0.1 &
PY_PID=$!

sleep 2

# 3. Start the Websockify Proxy
echo "[3/3] Launching Websockify Proxy (8080 -> 1300)..."
echo "-----------------------------------------------"
echo "CONCLAVE SYSTEM ACTIVE"
echo "ACCESS TERMINAL: http://127.0.0.1:8000"
echo "-----------------------------------------------"

# This remains in the foreground to show you real-time traffic
websockify 8080 127.0.0.1:1300

# 4. Cleanup on Exit (Ctrl+C)
echo "[SYSTEM] Shutting down all segments..."
kill $CPP_PID $PY_PID