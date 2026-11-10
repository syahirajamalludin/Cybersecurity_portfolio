#!/usr/bin/env bash
# Creates the proxy login file. Lab-only passwords.
# Needs: apache2-utils (Linux) or httpd (Mac: brew install httpd)
set -e
cd "$(dirname "$0")"
htpasswd -cb passwords student Lab-Proxy-2026
for u in farah hafiz dzul aina; do htpasswd -b passwords "$u" Lab-Proxy-2026; done
echo "Created ./passwords"
