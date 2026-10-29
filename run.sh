#!/bin/bash
# EventSphere: build, start, and open a public HTTPS link for phones
cd "$(dirname "$0")"
if ! command -v cmake >/dev/null || ! command -v g++ >/dev/null || [ ! -f /usr/include/sqlite3.h ] || [ ! -d /usr/include/openssl ] || [ ! -d /usr/include/x86_64-linux-gnu/curl ]; then
  echo "Installing required tools (asks for your Ubuntu password once)..."
  sudo apt update && sudo apt install -y g++ cmake libsqlite3-dev libssl-dev libcurl4-openssl-dev || exit 1
fi
cmake -S backend -B build >/dev/null && cmake --build build || { echo "Build failed"; exit 1; }
export ADMIN_EMAIL="${ADMIN_EMAIL:-admin@college.edu}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-ChangeMe123}"
# Optional certificate email (Gmail App Password): export SMTP_URL=smtps://smtp.gmail.com:465 SMTP_USER=you@gmail.com SMTP_PASS=apppassword
export COLLEGE_NAME="${COLLEGE_NAME:-Your College Name}"
pkill eventsphere 2>/dev/null; pkill cloudflared 2>/dev/null
trap 'kill $(jobs -p) 2>/dev/null' EXIT
./build/eventsphere &
sleep 1
u=""
if [ ! -x cloudflared ]; then curl -fsSL -o cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 && chmod +x cloudflared; fi
if [ -x cloudflared ]; then
  for try in 1 2 3; do
    : > tunnel.log; pkill cloudflared 2>/dev/null
    # http2 + IPv4 avoid the blocked-UDP / IPv6 problems that cause "Error 1033"
    ./cloudflared tunnel --no-autoupdate --protocol http2 --edge-ip-version 4 --url http://localhost:8080 >tunnel.log 2>&1 &
    for i in $(seq 1 40); do grep -q "Registered tunnel connection" tunnel.log && break; sleep 1; done
    if grep -q "Registered tunnel connection" tunnel.log; then u=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' tunnel.log | head -1); break; fi
    echo "Tunnel attempt $try failed, retrying..."
  done
fi
echo "=================================================="
if [ -n "$u" ]; then echo " PHONE LINK (any network, HTTPS): $u"; else echo " Phone link NOT available. Last tunnel log:"; tail -5 tunnel.log 2>/dev/null; fi
echo " This PC:  http://localhost:8080"
echo " Admin:    $ADMIN_EMAIL / $ADMIN_PASSWORD"
echo " Keep this window open. The link only works while it is open."
echo "=================================================="
wait
