# 📦 vnet-driver — Virtual Linux Network Driver (Educational Project)

### **Author:** Karan Gandhi  
### **Status:** Phase 7 Complete (NAPI, ARP RX, Stats, ethtool, Docs)  
### **License:** GPL-2.0  

---

# 📘 Overview

This repository contains a **fully documented, educational Linux kernel virtual Ethernet driver** (`vnet0`).

The project is intentionally built **step-by-step**, mirroring how real Linux NIC drivers evolve over time.  
Each phase introduces a concept that exists in production drivers (e.g., `e1000`, `r8169`, `mlx5`), while keeping the code readable and learning-focused.

Unlike a tutorial dump, the final code is **clean, stable, and production‑style**, with the phases preserved here for learning context.

---

# 🚗 Project Roadmap (Phases)

| Phase | Description | Status |
|------:|------------|--------|
| **1** | Basic kernel module | ✅ Done |
| **2** | Minimal `net_device` skeleton | ✅ Done |
| **3** | TX ring buffer | ✅ Done |
| **4** | RX ring + timer-based packet generator | ✅ Done |
| **5** | NAPI-based RX polling | ✅ Done |
| **6** | Statistics + ethtool support | ✅ Done |
| **7** | ARP frame generation + documentation | ✅ Done |
| **8** | Userspace backend (netlink / char dev) | ⏳ Future |

---

# ✨ Features by Phase

## 🟦 Phase 1 — Basic Module
- Clean module load/unload
- Kernel log instrumentation

---

## 🟩 Phase 2 — Virtual Ethernet Device
- `alloc_etherdev()` allocation
- Implemented `net_device_ops`:
  - `ndo_open`
  - `ndo_stop`
  - `ndo_start_xmit`
- Deterministic MAC assignment via `eth_hw_addr_set()`
- Interface appears as:
  ```bash
  ip link show vnet0
  ```

---

## 🟨 Phase 3 — TX Ring Buffer
- Circular TX ring (`VNET_TX_RING_SIZE`)
- Enqueue/dequeue helpers
- Spinlock-protected access
- Immediate TX completion model (learning-friendly)
- Proper `NETDEV_TX_BUSY` handling

---

## 🟧 Phase 4 — RX Ring + Timer
- RX ring buffer (`VNET_RX_RING_SIZE`)
- Kernel timer simulates RX interrupts
- RX path separated from TX
- Foundation for NAPI polling

---

## 🟥 Phase 5 — NAPI-Based RX Polling
- Integrated NAPI via `netif_napi_add()`
- RX processed inside `vnet_napi_poll()`
- Timer acts as interrupt source:
  - Generates RX skb
  - Enqueues to RX ring
  - Schedules NAPI
- RX delivered using `netif_rx()`
- Demonstrates interrupt mitigation and batching

---

## 🟪 Phase 6 — Statistics & ethtool

### ✔ 64‑bit Statistics
Counters:
- `tx_packets`, `tx_bytes`, `tx_dropped`
- `rx_packets`, `rx_bytes`, `rx_dropped`

Visible via:
```bash
ip -s link show vnet0
```

### ✔ ethtool Support
```bash
ethtool -i vnet0
ethtool -S vnet0
```

Reports:
- Driver name and version
- Virtual bus info
- Per‑protocol TX/RX counters

---

## 🟫 Phase 7 — ARP RX + Documentation
- Builds valid **Ethernet + ARP request frames**
- Broadcast destination MAC
- Correct ARP header and payload layout
- Frames observable via:
  ```bash
  tcpdump -i vnet0 -e -n arp
  ```
- Extensive **Doxygen-style documentation**
- Clear ownership and concurrency rules explained inline

---

# 📂 Repository Structure

```
vnet-driver/
├── src/
│   ├── vnet_main.c      # Complete virtual NIC driver
│   └── Makefile
├── docs/
│   └── architecture.md # Driver architecture (Phase 7)
├── README.md
└── LICENSE
```

---

# 🛠️ Building the Module

Install prerequisites:
```bash
sudo apt install build-essential linux-headers-$(uname -r)
```

Build:
```bash
make clean
make
```

Output:
```
src/vnet_main.ko
```

---

# ▶️ Loading & Testing

Load:
```bash
sudo insmod src/vnet_main.ko
sudo ip link set vnet0 up
sudo ip addr add 10.0.0.1/24 dev vnet0
```

Observe traffic:
```bash
tcpdump -i vnet0 -e -n
```

Unload:
```bash
sudo rmmod vnet_main
```

---

# 🔧 Debugging (Dynamic Debug)

Enable:
```bash
echo 'module vnet_main +p' | sudo tee /sys/kernel/debug/dynamic_debug/control
```

Disable:
```bash
echo 'module vnet_main -p' | sudo tee /sys/kernel/debug/dynamic_debug/control
```

---

# 🎯 Learning Objectives

This project teaches:
- Linux kernel module fundamentals
- `net_device` internals
- TX/RX ring buffer design
- NAPI and softirq RX handling
- Kernel timers as interrupt analogs
- Ethernet + ARP frame construction
- Driver statistics and ethtool
- Concurrency with spinlocks
- Real-world GitHub workflows (branches, PRs, releases)

---

# 🚀 Future Work (Phase 8+)

- Userspace backend (netlink or char device)
- More realistic RX/TX traffic
- Advanced ethtool operations
- Network namespace integration

---

⭐ If this project helped you learn Linux driver development, consider starring the repo!
