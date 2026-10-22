#!/bin/bash
set -e
echo "[webserver] serving on 0.0.0.0:80"
exec python3 -m http.server 80
