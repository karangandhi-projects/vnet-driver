# 📦 **vnet-driver --- Virtual Linux Network Driver (Educational Project)**

### **Author:** Karan Gandhi

### **Status:** Phase 2 (Minimal net_device Skeleton)

### **License:** GPL-2.0

------------------------------------------------------------------------

## 📘 Overview

This repository contains a fully documented, educational Linux kernel
**virtual Ethernet driver** (`vnet0`).

The project is structured in multiple phases, each adding realistic
components found in professional NIC drivers:

  Phase         Description
  ------------- ----------------------------------------------
  **Phase 1**   Basic kernel module (`hello_vnet.ko`)
  **Phase 2**   Register a virtual Ethernet device (`vnet0`)
  **Phase 3**   TX/RX ring buffer implementation
  **Phase 4**   NAPI polling
  **Phase 5**   ethtool support
  **Phase 6**   User-space backend
  **Phase 7**   Architecture docs + Doxygen

This project is designed to teach modern Linux kernel driver development
step-by-step.

------------------------------------------------------------------------
## ✨ Features Completed (Phase 3)

- Everything from Phase 2, plus:
  - Fixed-size TX ring buffer (`VNET_TX_RING_SIZE`)
  - Ring management helpers (enqueue/dequeue/init)
  - `ndo_start_xmit` now uses the TX ring instead of dropping directly
  - Proper handling of `NETDEV_TX_BUSY` and `netif_stop_queue()/netif_wake_queue()`

## ✨ Features Completed (Phase 2)

-   `struct net_device` allocation via `alloc_etherdev()`
-   Basic `net_device_ops` callbacks
    -   `ndo_open`
    -   `ndo_stop`
    -   `ndo_start_xmit` (currently drops packets)
-   Custom MAC address assignment via `eth_hw_addr_set()`
-   Private driver state using `netdev_priv()`
-   Fully Doxygen-documented codebase
-   Interface visible via `ip link show` (e.g., **vnet0**)\
-   Compatible with modern Ubuntu kernels (6.x)

------------------------------------------------------------------------

## 📂 Repository Structure

    vnet-driver/
    ├── src/
    │   ├── vnet_main.c      # Main network driver (Phase 2)
    │   └── Makefile         # Kbuild-compatible
    ├── docs/
    │   └── architecture.md  # (Coming in Phase 7)
    ├── Makefile             # Top-level build file
    ├── .gitignore
    ├── README.md
    └── LICENSE

------------------------------------------------------------------------

## 🛠️ Building the Module

### Install kernel headers:

``` bash
sudo apt install build-essential linux-headers-$(uname -r)
```

### Build:

From project root:

``` bash
make
```

Resulting module:

    src/vnet_main.ko

------------------------------------------------------------------------

## ▶️ Loading the Driver

``` bash
sudo insmod src/vnet_main.ko
dmesg | tail
```

Expected output:

    vnet: virtual net device registered as vnet0

List interfaces:

``` bash
ip link show
```

Bring interface up:

``` bash
sudo ip link set vnet0 up
sudo ip addr add 10.0.0.1/24 dev vnet0
```

Unload:

``` bash
sudo rmmod vnet_main
```

------------------------------------------------------------------------

## 📚 Documentation (Doxygen)

To generate Doxygen docs (coming in Phase 7):

``` bash
sudo apt install doxygen graphviz
doxygen Doxyfile
```

------------------------------------------------------------------------

## 🎯 Learning Objectives

This project teaches:

-   Kernel modules\
-   net_device internals\
-   RX/TX ring design\
-   NAPI\
-   Packet scheduling\
-   ethtool integration\
-   Synchronization (spinlocks, atomic operations)\
-   Kernel ↔ userspace IPC (ioctl/netlink)

------------------------------------------------------------------------

## 🚀 Upcoming Work

-   TX/RX rings with descriptors\
-   NAPI poll loop\
-   Simulated packet generation\
-   Userspace backend for testing\
-   Performance counters\
-   Architecture diagrams

------------------------------------------------------------------------

**Star the repo ⭐ if you find it useful!**
