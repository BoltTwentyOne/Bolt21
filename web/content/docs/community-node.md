---
title: 'Community Node'
description: 'Learn about the Bolt21 Community Node - how it provides lower fees for Lightning payments by routing through shared infrastructure.'
layout: 'docs'
weight: 7
css: ['docs.css']
---

# Community Node

The Bolt21 Community Node is an optional feature that can route your Lightning payments through community-operated infrastructure for potentially lower fees.

## What Is It?

The Community Node is a Lightning node operated by the Bolt21 community. When enabled, your outgoing payments can route through this node, which often has:

- **Lower routing fees** than some public routes
- **Better liquidity** for common payment destinations
- **Faster route finding** through established channels

## How It Works

### Without Community Node
Your payment routes through the public Lightning network, finding the cheapest path available.

### With Community Node
1. Bolt21 first tries to route through the Community Node
2. If successful, you may pay lower fees
3. If the Community Node is offline or can't route the payment, Bolt21 automatically falls back to standard routing

**Your funds always remain self-custodial.** The Community Node only routes payments - it never holds your Bitcoin.

## Enabling Community Node

1. Open **Settings**
2. Tap **Community Node**
3. Toggle **Enable Community Routing**
4. The app will check node status

### Status Indicators

- **Online** - Node is available for routing
- **Offline** - Payments will use standard routing
- **Channels** - Number of active Lightning channels
- **Fee Rate** - Current routing fee in parts per million (ppm)

## Fee Comparison

| Route Type | Typical Fee | Speed |
|------------|-------------|-------|
| Community Node | ~100-500 ppm | Fast |
| Public Network | 100-2000 ppm | Variable |
| Direct Channel | 0 ppm | Instant |

*Fees vary based on payment size and route availability*

## When to Use It

### Good for:
- Regular payments to popular destinations
- Users without their own Lightning node
- Reducing fees on medium-sized payments

### Not needed if:
- You run your own Lightning node
- You have direct channels to your payment destinations
- You prefer maximum decentralization

## Privacy Considerations

When using the Community Node:

- The node operator can see payments routed through it
- Payment amounts and destinations are visible to the routing node
- This is standard for all Lightning routing (not unique to Community Node)

For maximum privacy:
- Use your own Lightning node
- Or use standard routing (disable Community Node)

## Advanced: Custom Node URL

Power users can route through their own node or a different community node:

1. Open **Settings** → **Community Node**
2. Tap **Advanced**
3. Enter your node's REST API URL
4. Save and test connection

The node must expose a compatible REST API endpoint.

## Troubleshooting

### "Community Node Offline"
- The node may be temporarily down for maintenance
- Payments will automatically use standard routing
- Try again later

### "Payment Failed via Community Node"
- The node may lack liquidity for this payment
- Bolt21 will retry via standard routing
- No action needed

### "Higher Fees Than Expected"
- Community Node fees may have changed
- The route may require additional hops
- Compare with standard routing by temporarily disabling

---

**Next:** [Connect Your Own Node](/docs/connect-node)
