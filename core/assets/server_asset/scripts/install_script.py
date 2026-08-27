#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Aug 12 07:33:06 2026

@author: hounsousamuel
"""

INSTALL_SCRIPT_TEMPLATE = """#!/bin/bash
set -euo pipefail

export LANG=C.UTF-8
export LC_ALL=C.UTF-8

TOKEN="{token}"
ASSET_ID="{asset_id}"
CENTRAL_HTTP_URL="{central_http_url}"
CENTRAL_WS_URL="{central_ws_url}"
INSTALL_DIR="/opt/obsidian-agent"
BIN_PATH="$INSTALL_DIR/bin/obsidian-agent"
CONFIG_PATH="$INSTALL_DIR/config.toml"
SERVICE_NAME="obsidian-agent"
SERVICE_USER="obsidian-agent"

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être exécuté en root (sudo)." >&2
    exit 1
fi

echo "==> Création de l'utilisateur dédié..."
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" "$SERVICE_USER"
fi

echo "==> Création des répertoires..."
mkdir -p "$INSTALL_DIR/bin"

echo "==> Téléchargement du binaire de l'agent..."
curl -sSL -H "Authorization: Bearer $TOKEN" -o "$BIN_PATH" "$CENTRAL_HTTP_URL/api/download/agent/agent_core"
chmod 700 "$BIN_PATH"

echo "==> Écriture de la configuration..."
cat > "$CONFIG_PATH" << CONF_EOF
asset_id = "$ASSET_ID"
central_http_url = "$CENTRAL_HTTP_URL"
central_ws_url = "$CENTRAL_WS_URL"
register_path = "/api/core/assets/server_asset/register"
download_tool_engine_path = "/api/download/agent/tool_engine"
pending_token = "$TOKEN"
CONF_EOF
chmod 600 "$CONFIG_PATH"

echo "==> Écriture du script de désinstallation..."
cat > "$INSTALL_DIR/uninstall.sh" << 'UNINSTALL_EOF'
#!/bin/bash
set -e
SERVICE_NAME="obsidian-agent"
INSTALL_DIR="/opt/obsidian-agent"
SERVICE_USER="obsidian-agent"

sleep 1

systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
rm -f "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload

rm -rf "$INSTALL_DIR"
userdel "$SERVICE_USER" 2>/dev/null || true
rm -f "/etc/sudoers.d/obsidian-agent"

echo "Agent désinstallé."
UNINSTALL_EOF
chmod 700 "$INSTALL_DIR/uninstall.sh"

echo "==> Règle sudoers restreinte pour l'auto-désinstallation..."
echo "$SERVICE_USER ALL=(root) NOPASSWD: $INSTALL_DIR/uninstall.sh" > /etc/sudoers.d/obsidian-agent
chmod 440 /etc/sudoers.d/obsidian-agent

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

echo "==> Écriture du service systemd..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << SERVICE_EOF
[Unit]
Description=Obsidian Hive Server Agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
ExecStart=$BIN_PATH
WorkingDirectory=$INSTALL_DIR
User=$SERVICE_USER
Group=$SERVICE_USER
Environment=OBSIDIAN_AGENT_CONFIG_PATH=$CONFIG_PATH
Environment=LANG=C.UTF-8
Environment=LC_ALL=C.UTF-8
KillMode=process # ne tue QUE le PID principal (ExecStart), pas le cgroup entier
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

echo "==> Activation et démarrage du service..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

echo "==> Agent installé et démarré. Vérifie avec: systemctl status $SERVICE_NAME"
"""