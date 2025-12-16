# vnet-driver Architecture

This document explains how the `vnet0` virtual Ethernet driver is structured, how packets move through the TX/RX paths, and how concurrency and ownership are handled.

> Goal: keep the design close to how real Linux NIC drivers work, while staying readable and learning-friendly.

---

## 1) High-level Design

`vnet-driver` is a Linux kernel module that registers a virtual Ethernet interface (default name: `vnet0`).

Core building blocks:

- **net_device**: the kernel's representation of a NIC
- **net_device_ops**: callback table that plugs the driver into the networking stack
- **TX ring**: stores outgoing `sk_buff`s until completion
- **RX ring**: stores incoming `sk_buff`s until NAPI drains them
- **Timer**: simulates RX interrupts by periodically generating a synthetic packet
- **NAPI**: polls RX ring in batches (interrupt mitigation)
- **Stats + ethtool**: exposes counters and driver info

---

## 2) Main Data Structures

### 2.1 `struct vnet_priv`

Allocated alongside `net_device` via `alloc_etherdev(sizeof(struct vnet_priv))`.

Contains:

- `spinlock_t lock`  
  Protects rings + counters (any shared state touched by multiple contexts)

- TX ring state:
  - `tx_ring[VNET_TX_RING_SIZE]`
  - `tx_head`, `tx_tail`

- RX ring state:
  - `rx_ring[VNET_RX_RING_SIZE]`
  - `rx_head`, `rx_tail`

- NAPI + RX timer:
  - `struct napi_struct napi`
  - `struct timer_list rx_timer`

- Statistics counters (aggregate + per-protocol)

---

## 3) Driver Lifecycle

### 3.1 Module init (`vnet_init`)
1. Allocate `net_device`:
   - `alloc_etherdev(sizeof(*priv))`
2. Initialize private state:
   - `spin_lock_init(&priv->lock)`
3. Set device identity:
   - `dev->name = "vnet%d"` (ensures `vnet0`, not `eth0`)
   - `eth_hw_addr_set(dev, mac)`
4. Register NAPI:
   - `netif_napi_add(dev, &priv->napi, vnet_napi_poll)`
5. Register device:
   - `register_netdev(dev)`

Result: `ip link show` displays `vnet0`.

### 3.2 Interface up (`ndo_open`)
1. Initialize TX/RX rings
2. Reset counters (explicit resets; avoids `memset` on sub-objects)
3. Enable NAPI:
   - `napi_enable(&priv->napi)`
4. Start RX timer:
   - `timer_setup(&priv->rx_timer, vnet_rx_timer_fn, 0)`
   - `mod_timer(...)`
5. Start TX queue:
   - `netif_start_queue(dev)`

### 3.3 Interface down (`ndo_stop`)
1. Stop TX queue: `netif_stop_queue(dev)`
2. Stop timer: `del_timer_sync(&priv->rx_timer)`
3. Disable NAPI: `napi_disable(&priv->napi)`

### 3.4 Module exit (`vnet_exit`)
1. `unregister_netdev(dev)`
2. `netif_napi_del(&priv->napi)`
3. `free_netdev(dev)`

---

## 4) TX Path (Outgoing Packets)

### 4.1 Entry point
Linux networking stack calls:
- `ndo_start_xmit(struct sk_buff *skb, struct net_device *dev)`

### 4.2 Steps
1. Acquire lock (protect ring + counters)
2. Classify protocol (EtherType) for stats:
   - ARP / IPv4 / IPv6 / other
3. Enqueue skb into TX ring:
   - `vnet_tx_enqueue(priv, skb)`
4. Update counters:
   - `tx_packets`, `tx_bytes`
5. Immediate completion (educational model):
   - dequeue one skb and `dev_kfree_skb_any()`
6. Release lock
7. Return `NETDEV_TX_OK`

### 4.3 Ownership rules (TX)
- On entry to `ndo_start_xmit`, skb is owned by the stack.
- After successful enqueue, skb is owned by the driver.
- On completion, the driver frees skb (or hands it off in a real NIC).

### 4.4 Backpressure
If TX ring is full:
- increment `tx_dropped`
- return `NETDEV_TX_BUSY` so the stack can retry later

---

## 5) RX Path (Incoming Packets)

RX is synthesized so you can observe behavior without external hardware.

### 5.1 RX timer callback (`vnet_rx_timer_fn`)
Runs in softirq/timer context.

Steps:
1. If interface is down (`!netif_running(dev)`), re-arm and return
2. Build a synthetic packet (currently: Ethernet + ARP request)
3. Enqueue skb into RX ring
   - if full: increment `rx_dropped`, free skb
4. Schedule NAPI:
   - `if (napi_schedule_prep(&priv->napi)) __napi_schedule(&priv->napi);`
5. Re-arm timer for the next tick

### 5.2 NAPI poll (`vnet_napi_poll`)
Runs in softirq context.

Steps:
1. While `work < budget`:
   - dequeue skb from RX ring
   - set skb metadata:
     - `skb->dev = dev`
     - `skb->protocol = eth_type_trans(skb, dev)`
   - update RX counters
   - deliver skb to stack:
     - `netif_rx(skb)`
2. If ring is empty before budget:
   - `napi_complete_done(napi, work)`

### 5.3 Ownership rules (RX)
- skb is owned by the driver while in the RX ring
- once passed to `netif_rx()`, the network stack owns and frees it

---

## 6) Packet Format: Synthetic ARP Request

The synthetic packet is a valid Ethernet frame with ARP payload:

- Ethernet:
  - dst MAC: `ff:ff:ff:ff:ff:ff` (broadcast)
  - src MAC: `dev->dev_addr`
  - EtherType: `0x0806` (ARP)

- ARP:
  - op: REQUEST
  - sender MAC/IP: device MAC + `10.0.0.1`
  - target MAC/IP: `00:00:00:00:00:00` + `10.0.0.2`

You can observe it with:
```bash
sudo tcpdump -i vnet0 -e -n arp
```

---

## 7) Concurrency Model

The driver operates in multiple contexts:

- Process context:
  - `ndo_open`, `ndo_stop`, `ndo_start_xmit`
- Softirq / timer context:
  - `vnet_rx_timer_fn`
- Softirq / NAPI context:
  - `vnet_napi_poll`

Shared state (rings + counters) is protected with:
- `spinlock_t lock`

Guideline used:
- **Allocate memory outside the lock** when possible.
- **Hold lock only for critical sections**: enqueue/dequeue + counter updates.

---

## 8) Statistics and Observability

### 8.1 Standard stats (`ip -s link`)
Implemented via:
- `ndo_get_stats64`

### 8.2 Extended stats (`ethtool -S`)
Exposes:
- tx/rx packets/bytes/drops
- per-protocol tx/rx counters

Commands:
```bash
ip -s link show vnet0
ethtool -S vnet0
```

### 8.3 Debug logs (dynamic debug)
If `pr_debug()` is used, enable at runtime:
```bash
echo 'module vnet_main +p' | sudo tee /sys/kernel/debug/dynamic_debug/control
sudo dmesg -w | grep vnet
```

---

## 9) Current Limitations (Intentional)

- TX completes immediately (no real DMA, IRQ completion, or qdisc interaction)
- RX is synthetic (timer-driven), not backed by userspace or real hardware
- No multi-queue, XDP, GRO, or advanced ethtool features (yet)

These are perfect candidates for future phases.

---

## 10) Suggested Next Step

**Userspace backend** (netlink or character device) to inject real frames into RX and read TX frames from userspace.

That upgrade will teach:
- netlink/char-dev plumbing
- copy_to_user/copy_from_user safety
- async wakeups and blocking reads
- realistic packet flows and testing with tools like `ping`, `arping`, `scapy`
