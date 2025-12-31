---
title: 'Connect Your Own Node'
description: 'Advanced guide to connecting Bolt21 to your own LND Lightning node for full control over routing and channels.'
layout: 'docs'
weight: 8
css: ['docs.css']
---

# Connect Your Own Node

Advanced users can connect Bolt21 to their own LND (Lightning Network Daemon) node for full control over channels, routing, and fees.

## Requirements

- An LND node (v0.15+) running and synced
- REST API enabled on your node
- Admin macaroon for full access (or invoice+readonly for limited access)
- Network access from your phone to the node

## Why Connect Your Own Node?

| Feature | Breez SDK (Default) | Your Own Node |
|---------|---------------------|---------------|
| Setup | Instant | Requires running node |
| Channels | Managed for you | Full control |
| Routing fees | Shared | You keep them |
| Privacy | Good | Maximum |
| Maintenance | None | You manage |

## Setup Guide

### 1. Enable REST API on Your Node

Add to your `lnd.conf`:

```ini
[Application Options]
restlisten=0.0.0.0:8080

[Tor]
# If using Tor
tor.active=true
tor.v3=true
```

Restart LND after changes.

### 2. Get Your Macaroon

```bash
# Full access (admin)
base64 ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon

# Limited access (recommended for mobile)
lncli bakemacaroon invoices:read invoices:write offchain:read offchain:write onchain:read
```

### 3. Configure Bolt21

1. Open **Settings** → **Advanced** → **Connect Node**
2. Enter your node's REST URL:
   - Local: `https://192.168.1.x:8080`
   - Tor: `https://xxxxx.onion:8080`
   - Public: `https://your-node.com:8080`
3. Paste your macaroon (base64 encoded)
4. Tap **Test Connection**
5. If successful, tap **Save**

### 4. Verify Connection

After connecting, you should see:
- Your node's alias
- Channel count and capacity
- On-chain and Lightning balances

## Connection Options

### Local Network
Best for home use. Your phone must be on the same network as your node.

```
https://192.168.1.100:8080
```

### Tor Hidden Service
Works from anywhere. Requires Orbot or similar on Android.

```
https://abc123...xyz.onion:8080
```

### Reverse Proxy (Nginx/Caddy)
Expose your node securely over the internet.

```
https://node.yourdomain.com
```

## Channel Management

When connected to your own node, you have full control:

### View Channels
**Settings** → **Channels** shows:
- Active channels
- Pending channels
- Channel capacity and balance
- Remote node info

### Open Channels
Currently done via your node's interface (RTL, ThunderHub, or lncli). Mobile channel opening coming soon.

### Close Channels
Same as above - use your node's management interface.

## Switching Between Modes

You can switch between Breez SDK and your own node:

1. **Settings** → **Advanced** → **Node Connection**
2. Choose **Breez SDK** or **Custom Node**
3. Confirm the switch

When switching:
- Wallets are separate (different recovery phrases may apply)
- Balances don't transfer automatically
- Each mode has its own BOLT12 offer

## Troubleshooting

### "Connection Failed"
- Check your node is running: `lncli getinfo`
- Verify REST is enabled and port is correct
- Check firewall allows the connection
- Try accessing the REST URL in a browser

### "Invalid Macaroon"
- Re-export the macaroon in base64
- Ensure no extra whitespace
- Check you're using the correct network (mainnet/testnet)

### "Certificate Error"
- LND uses self-signed certificates by default
- Accept the certificate warning, or
- Set up a proper TLS certificate with Let's Encrypt

### "Channel Not Found"
- Wait for the channel to fully open (6 confirmations)
- Check channel status on your node directly

## Security Best Practices

1. **Use Tor or VPN** when connecting over the internet
2. **Limit macaroon permissions** to only what's needed
3. **Don't share your macaroon** - it grants access to your funds
4. **Keep your node updated** with security patches
5. **Enable watchtowers** for channel security

---

**Need help running an LND node?** Check out:
- [RaspiBolt](https://raspibolt.org/) - DIY Bitcoin/Lightning node
- [Umbrel](https://umbrel.com/) - Node-in-a-box solution
- [Start9](https://start9.com/) - Embassy personal server
