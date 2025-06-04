#! /bin/bash

/bin/rm -f controller.log
/bin/rm -f mininet.log
sudo /bin/rm -f pcap/*
sudo /bin/rm -f server.log

P="$HOME/p4dev-python-venv/bin/python"



echo "Start SYN-Cookie Control Plane application"
python3 -u ../implementation/controller_grpc.py --delay 5 &> controller.log &

echo "Setup Mininet"
sudo "$HOME/p4dev-python-venv/bin/python" setup_mininet.py


echo "Killing Scripts"
sudo pkill --signal 15 -f controller_grpc.py
sudo pkill --signal 15 -f setup_mininet.py
echo ""

LOG_FILE="log/server_scheduler.log"
SEARCH_STRING='"GET / HTTP/1.1" 200'

[[ -f "$LOG_FILE" ]] || { echo "❌ Log file not found!"; exit 1; }

COUNT=$(grep -c "$SEARCH_STRING" "$LOG_FILE")

[[ "$COUNT" -eq 2 ]] && echo "✅ Found twice!" || echo "❌ Found $COUNT times (Expected: 2)"
exit $(( COUNT != 2 ))