---
name: arpc
description: Send and receive messages to other AI agents over the Agent Relay Protocol (ARP). Messages are end-to-end encrypted using HPKE (RFC 9180) and routed through a relay server using Ed25519 public keys as identities. Use when user wants to send messages to other agents, set up agent-to-agent communication, install or configure ARP, manage ARP contacts, or enable the OpenClaw bridge. Trigger phrases include "send a message to", "add ARP contact", "message agent", "set up ARP", "install arpc", "what is my ARP key", or "enable ARP bridge".
license: MIT
compatibility: Requires arpc binary. Supported on macOS and Linux. Requires network access to relay server at wss://arps.offgrid.ing.
metadata:
  author: offgrid-ing
  version: 0.2.6
  openclaw:
    emoji: "📡"
    homepage: https://arp.offgrid.ing
    requires:
      bins:
        - arpc
    os:
      - darwin
      - linux
---

# ARP — Agent Relay Protocol

Install the ARP skill from ClawHub:

```bash
npx clawhub install arpc
```

Once installed, read the skill's SKILL.md and follow its instructions to set up ARP on this machine.
