# 📦 vnet-driver — Virtual Linux Network Driver (Educational Project)

### **Author:** Karan Gandhi  
### **Status:** Phase 6 Complete (TX/RX Rings, NAPI, Stats, ethtool)  
### **License:** GPL-2.0  

---

# 📘 Overview

This repository contains a fully documented, educational Linux kernel  
**virtual Ethernet driver** (`vnet0`).  
You build the driver step-by-step—exactly like real NIC driver development.

The project evolves through milestones (“phases”), each adding a real capability found in production drivers such as Intel e1000, Realtek r8169, mlx5, etc.

---

# 🚗 Project Roadmap (Phases)

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | Basic kernel module | ✅ Done |
| **2** | Minimal net_device skeleton | ✅ Done |
| **3** | TX ring buffer | ✅ Done |
| **4** | RX ring + timer-based packet generator | ✅ Done |
| **5** | NAPI-based RX polling | ✔️ Done |
| **6** | Driver statistics + basic ethtool support | ✔️ Done |
| **7** | Documentation & Architecture diagrams | ⏳ Upcoming |
| **8** | Userspace backend (netlink/ioctl) | ⏳ Future |

---

# ✨ Features Completed

## 🟦 Phase 1 — Basic Module
- Loads/unloads cleanly  
- Prints initialization message  

---

## 🟩 Phase 2 — Register a Virtual Ethernet Device
- `alloc_etherdev()` to create `struct net_device`  
- Implemented `net_device_ops`:  
  - `ndo_open`  
  - `ndo_stop`  
  - `ndo_start_xmit`  
- Custom MAC address using `eth_hw_addr_set()`  
- Interface appears as:  
  ```bash
  ip link show vnet0
  ```

---

## 🟨 Phase 3 — TX Ring Buffer
- Added circular TX queue (`VNET_TX_RING_SIZE`)  
- Helpers for enqueue/dequeue  
- Spinlock-based protection  
- Proper queue-stop + busy handling  
- Simulated TX completion  

---

## 🟧 Phase 4 — RX Ring + Timer-Based Packet Generator
- Added RX ring (`VNET_RX_RING_SIZE`)  
- Kernel timer generates packets every 1s  
- Dummy payload: `"Hello from vnet RX"`  
- Prepares for NAPI polling in next phase  

---

## 🟥 Phase 5 — NAPI-Based RX Polling
- Added NAPI support via `vnet_napi_poll()`  
- Timer mimics hardware interrupt:
  - Allocates fake SKB  
  - Enqueues it  
  - Schedules NAPI  
- RX processed inside poll loop  
- Packets delivered to kernel via `netif_rx()`  
- Prevents interrupt storms and increases throughput  

---

## 🟪 Phase 6 — Driver Statistics & ethtool Support

### ✔ Added 64-bit statistics
Counters added:
- `tx_packets`, `tx_bytes`, `tx_dropped`  
- `rx_packets`, `rx_bytes`, `rx_dropped`  

Exposed through:
```bash
ip -s link show vnet0
```

### ✔ Implemented `ndo_get_stats64`
Linux reads counters via kernel networking stack.

### ✔ Basic ethtool support
```bash
ethtool -i vnet0
ethtool vnet0
```

Reports:
- driver: vnet  
- version: 0.6  
- bus-info: virtual  
- link detected: yes  

---

# 📂 Repository Structure

```
vnet-driver/
├── src/
│   ├── vnet_main.c
│   └── Makefile
├── docs/
│   └── architecture.md   # Coming in Phase 7
├── README.md
└── LICENSE
```

---

# 🛠️ Building the Module

Install kernel headers:
```bash
sudo apt install build-essential linux-headers-$(uname -r)
```

Build:
```bash
make
```

Output:
```
src/vnet_main.ko
```

---

# ▶️ Loading the Driver

```bash
sudo insmod src/vnet_main.ko
sudo ip link set vnet0 up
sudo ip addr add 10.0.0.1/24 dev vnet0
```

Unload:
```bash
sudo rmmod vnet_main
```

---

# 🔧 Debugging with Dynamic Debug

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
- Linux kernel modules  
- net_device architecture  
- TX/RX ring buffers  
- Kernel timers  
- NAPI  
- Packet scheduling  
- ethtool driver introspection  
- Concurrency (spinlocks)  
- Clean GitHub CI & PR workflows  

---

# 🚀 Upcoming Work

- Architecture diagrams (Phase 7)  
- Userspace backend (Phase 8)  
- More advanced ethtool ops  
- More realistic Ethernet frame building  

---

⭐ If this helped you learn Linux driver development, consider starring the repo!
