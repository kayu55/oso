#!/bin/bash

apt update
apt install python3 -y
apt install python3-pip -y
apt install python3-requests -y

wspro="/etc/aryapro"

mkdir -p $wspro1

repo="https://raw.githubusercontent.com/kayu55/oso/main/"

wget -q -O $wspro/ws.py "${repo}ws1.py"
chmod +x $wspro/ws1.py


# Installing Service
cat > /etc/systemd/system/ws.service << END
[Unit]
Description=Websocket
Documentation=https://google.com
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python3 -O $wspro/ws1.py 10015
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable ws.service
systemctl start ws.service
systemctl restart ws.service

rm -f $0
