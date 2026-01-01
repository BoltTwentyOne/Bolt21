# Bolt21 Community Node Proxy

Run this on your Lightning node to let Bolt21 users route payments through your node.

## Quick Start (MyNode)

```bash
# SSH into your node
ssh admin@192.168.1.128

# Clone or copy the proxy
cd ~
git clone https://github.com/BoltTwentyOne/Bolt21.git
cd Bolt21/community-node-proxy

# Run it
node server.js
```

## Configuration

Edit `server.js` CONFIG section, or use environment variables:

```bash
export LND_REST_URL="https://127.0.0.1:8080"
export MACAROON_PATH="/mnt/hdd/mynode/lnd/data/chain/bitcoin/mainnet/admin.macaroon"
export PROXY_PORT=8081
export FEE_RATE_PPM=0  # 0 = free, 1000 = 0.1%
```

## Run as Service (systemd)

```bash
sudo nano /etc/systemd/system/bolt21-proxy.service
```

```ini
[Unit]
Description=Bolt21 Community Node Proxy
After=lnd.service

[Service]
Type=simple
User=admin
WorkingDirectory=/home/admin/Bolt21/community-node-proxy
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10
Environment=LND_REST_URL=https://127.0.0.1:8080
Environment=MACAROON_PATH=/mnt/hdd/mynode/lnd/data/chain/bitcoin/mainnet/admin.macaroon

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable bolt21-proxy
sudo systemctl start bolt21-proxy
sudo systemctl status bolt21-proxy
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/status` | GET | Node status, capacity |
| `/pay` | POST | Pay an invoice |
| `/invoice` | POST | Generate invoice |

### Pay Invoice

```bash
curl -X POST http://your-node:8081/pay \
  -H "Content-Type: application/json" \
  -d '{"invoice": "lnbc..."}'
```

### Create Invoice

```bash
curl -X POST http://your-node:8081/invoice \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000, "memo": "Test"}'
```

## Security Notes

- Proxy never exposes your macaroon
- Rate limited (10/min, 100/hour per IP)
- Optional API key for restricted access
- Runs on separate port from LND REST

## Expose via Tailscale (Recommended)

If you have Tailscale on your node, the proxy is automatically available at:
```
http://100.x.x.x:8081
```

No port forwarding or Tor needed.
