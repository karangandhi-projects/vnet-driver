# 📦 vnet – Virtual Network Driver for Linux  
*A fully handcrafted Linux kernel network driver built from scratch.*

This project implements a **virtual Ethernet NIC** as a loadable Linux kernel module.  
It is intentionally designed like a **real-world production driver**, with:

- TX ring buffer  
- RX ring buffer  
- Timer-based packet generation  
- **NAPI-based RX polling** (Phase 5)  
- Clean modular architecture  
- Proper net_device operations  
- Doxygen-ready documentation  
- CI + PR pipeline  
- Feature-branch workflow  

The goal is to demonstrate **real Linux networking driver engineering**, matching the architecture of drivers like Intel e1000e, ixgbe, Mellanox mlx5, or Qualcomm WiFi.

---

# 🚗 Project Roadmap (Phases)

| Phase | Feature | Status |
|-------|---------|--------|
| **1** | Basic module + net_device registration | ✅ Done |
| **2** | Minimal NIC (`vnet0`) appearing in `ip link` | ✅ Done |
| **3** | TX ring buffer + real `ndo_start_xmit` path | ✅ Done |
| **4** | RX ring + timer-based packet generator | ✅ Done |
| **5** | **NAPI-based RX polling (real NIC behavior)** | ✅ Done |
| 6 | ethtool ops (driver info, stats) | ⏳ Next |
| 7 | More realistic Ethernet frames | ⏳ Planned |
| 8 | Userspace backend (ioctl / netlink) | ⏳ Future |

---

# ✨ Features Completed

## 🟦 Phase 1 — Basic Module + net_device Skeleton
- Minimal kernel module.
- Allocates Ethernet device using `alloc_etherdev()`.
- Registers/unregisters net_device.
- Hard-coded MAC address.

---

## 🟩 Phase 2 — Minimal Virtual NIC
- Device appears as `vnet0`.
- Supports:
  - `ip link set vnet0 up`
  - `ip link set vnet0 down`
- Packets dropped but interface is operational.

---

## 🟨 Phase 3 — TX Ring Buffer

### Implemented:
- Fixed-size TX ring (`VNET_TX_RING_SIZE`)
- Circular queue with:
  - `tx_head`
  - `tx_tail`
- Safe locking using `spin_lock_bh()`
- `ndo_start_xmit()` now:
  - Enqueues SKBs into TX ring  
  - Simulates asynchronous TX completion

---

## 🟧 Phase 4 — RX Ring + Timer-Based Packet Generator

### Implemented:
- RX ring (`VNET_RX_RING_SIZE`)
- RX enqueue/dequeue helpers
- Kernel timer to simulate RX interrupts
- Timer generates a dummy SKB every second and enqueues it into RX ring

---

# 🟥 Phase 5 — **NAPI-Based RX Polling** (Real NIC behavior)

### Implemented:
- Added `struct napi_struct napi` to `vnet_priv`
- Created `vnet_napi_poll()` to drain RX ring in poll context
- Registered NAPI with:
  ```c
  netif_napi_add(dev, &priv->napi, vnet_napi_poll);
  ```
- Enabled NAPI on device open, disabled on close
- Updated RX timer to:
  - Allocate packet
  - Enqueue into RX ring
  - Schedule NAPI
- Removed old direct RX processing helper

### Why NAPI?
NAPI improves performance by preventing interrupt storms.  
It switches from interrupt-driven RX to **polling** when traffic increases.

### NAPI Flow:
```
Timer → enqueue RX packet → schedule NAPI
NAPI → drain RX ring → netif_rx() → kernel stack
```

---

# 🔧 Build & Test

### Build:
```bash
make
```

### Load:
```bash
cd src
sudo insmod vnet_main.ko
sudo ip link set vnet0 up
sudo ip addr add 10.0.0.1/24 dev vnet0
```

### Logs:
```bash
sudo dmesg -w | grep vnet
```

### Disable:
```bash
sudo ip link set vnet0 down
```

---

# 🧪 Debugging

Enable debug:
```bash
echo 'module vnet_main +p' | sudo tee /sys/kernel/debug/dynamic_debug/control
```

Disable:
```bash
echo 'module vnet_main -p' | sudo tee /sys/kernel/debug/dynamic_debug/control
```

---

# 📁 Directory Structure

```
vnet-driver/
 ├── src/
 │    ├── vnet_main.c
 │    ├── Makefile
 ├── docs/
 ├── README.md
 └── LICENSE
```

---

# 📘 Version History

- **v0.2** — Basic NIC  
- **v0.3** — TX ring  
- **v0.4** — RX ring + timer  
- **v0.5** — NAPI-based RX polling
