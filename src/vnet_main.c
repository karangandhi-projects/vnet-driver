/**
 * @file vnet_main.c
 * @brief Virtual Ethernet network driver (Phases 2–6: TX/RX rings, NAPI, stats).
 *
 * This module registers a simple virtual network interface (e.g. vnet0)
 * and wires up core net_device operations (open/stop/start_xmit), NAPI,
 * and basic ethtool support.
 *
 * At this stage, the driver:
 *   - Allocates a struct net_device with private data (vnet_priv).
 *   - Registers the device with the kernel networking stack.
 *   - Exposes a virtual interface visible via "ip link" (vnet0).
 *   - Implements TX and RX ring buffers protected by a spinlock.
 *   - Uses a kernel timer to simulate RX "interrupts" by generating packets.
 *   - Uses NAPI to poll the RX ring and deliver packets to the stack via netif_rx().
 *   - Tracks simple TX/RX statistics (packets/bytes/drops) and exposes them to userspace.
 *   - Provides basic ethtool hooks (driver info, link status).
 *
 * Future phases may add:
 *   - More realistic Ethernet frames and protocol handling.
 *   - Additional ethtool operations and extended statistics.
 *   - A user-space backend to exchange packets.
 */


#include <linux/module.h>      /**< Kernel module macros: module_init, module_exit, MODULE_* */
#include <linux/kernel.h>      /**< Kernel logging helpers like pr_info(), pr_err() */
#include <linux/init.h>        /**< __init, __exit macros */

#include <linux/netdevice.h>   /**< Core networking structures: struct net_device, net_device_ops */
#include <linux/etherdevice.h> /**< Helpers for Ethernet devices: alloc_etherdev(), ether_addr_copy() */
#include <linux/spinlock.h>    /**< spinlock_t and related APIs */
#include <linux/timer.h>       /**< Kernel timers: struct timer_list, mod_timer(), etc. */
#include <linux/string.h>      /**< String helpers like strlen(), memcpy() */
#include <linux/skbuff.h>      /**< SKB helpers (skb_reset_*, etc.) */
#include <linux/if_ether.h>    /**< Ethernet protocol types like ETH_P_IP */
#include <linux/ethtool.h>     /**< ethtool_ops, ethtool driver hooks */
#include <linux/rtnetlink.h>   /**< rtnl_link_stats64 for ndo_get_stats64 */

/**
 * @brief Size of the transmit ring.
 *
 * This is the number of packets that can be queued for transmission
 * at any given time. In a real NIC driver this is usually negotiated
 * with the hardware (e.g. 256, 512, etc.).
 */
#define VNET_TX_RING_SIZE 64

/**
 * @brief Single transmit ring slot.
 *
 * Each slot in the TX ring holds one sk_buff pointer and a flag
 * indicating whether the slot is currently in use.
 */
struct vnet_tx_slot {
    struct sk_buff *skb;  /**< Packet buffer queued for transmission */
    bool used;            /**< True if this slot is occupied */
};

/**
 * @brief Size of the receive ring.
 *
 * This defines how many packets can be buffered by the driver on the
 * receive side before they are processed. In a real NIC, this is often
 * negotiated with the hardware.
 */
#define VNET_RX_RING_SIZE 64

/**
 * @brief Single receive ring slot.
 *
 * Each slot in the RX ring holds one sk_buff pointer and a flag
 * indicating whether the slot is currently in use.
 */
struct vnet_rx_slot {
    struct sk_buff *skb;  /**< Packet buffer received from "hardware" */
    bool used;            /**< True if this slot is occupied */
};


/**
 * @brief Per-device private data for the vnet driver.
 *
 * One instance of this structure is allocated for each network interface
 * created by this driver. The memory is reserved by alloc_etherdev()
 * and accessed with netdev_priv().
 */
struct vnet_priv {
    struct net_device *dev;                        /**< Back-pointer to the associated net_device */
    spinlock_t lock;                               /**< Spinlock to protect shared state in the driver */

    /* ------------------ TX ring state ------------------ */

    struct vnet_tx_slot tx_ring[VNET_TX_RING_SIZE]; /**< Fixed-size circular buffer for TX packets */
    u16 tx_head;                                    /**< Index where the next packet will be enqueued */
    u16 tx_tail;                                    /**< Index where the next packet will be dequeued */

    /* ------------------ RX ring state ------------------ */

    struct vnet_rx_slot rx_ring[VNET_RX_RING_SIZE]; /**< Fixed-size circular buffer for RX packets */
    u16 rx_head;                                    /**< Index where the next packet will be written */
    u16 rx_tail;                                    /**< Index where the next packet will be read */

    /* ------------------ NAPI / RX scheduling ----------- */

    struct napi_struct napi;                        /**< NAPI context used for RX polling */


    /* ------------------ RX packet generator ------------ */

    struct timer_list rx_timer;                     /**< Timer that simulates incoming packets */

    /* ------------------ Statistics --------------------- */

    u64 tx_packets;                                 /**< Number of successfully transmitted packets */
    u64 tx_bytes;                                   /**< Number of bytes successfully transmitted */
    u64 tx_dropped;                                 /**< Number of TX packets dropped by the driver */

    u64 rx_packets;                                 /**< Number of successfully received packets */
    u64 rx_bytes;                                   /**< Number of bytes successfully received */
    u64 rx_dropped;                                 /**< Number of RX packets dropped by the driver */
};


/* ====================================================================== */
/*                          TX ring helpers                               */
/* ====================================================================== */

/**
 * @brief Check if the TX ring is full.
 *
 * The ring is considered full if the slot at tx_head is already in use.
 *
 * @param priv Pointer to the driver's private data.
 * @return true if the ring is full, false otherwise.
 */
static bool vnet_tx_ring_full(struct vnet_priv *priv)
{
    return priv->tx_ring[priv->tx_head].used;
}

/**
 * @brief Check if the TX ring is empty.
 *
 * The ring is considered empty if the slot at tx_tail is not in use.
 *
 * @param priv Pointer to the driver's private data.
 * @return true if the ring is empty, false otherwise.
 */
static bool vnet_tx_ring_empty(struct vnet_priv *priv)
{
    return !priv->tx_ring[priv->tx_tail].used;
}

/**
 * @brief Initialize the TX ring.
 *
 * This function resets the ring indices and marks all slots as unused.
 *
 * @param priv Pointer to the driver's private data.
 */
static void vnet_tx_ring_init(struct vnet_priv *priv)
{
    int i;

    priv->tx_head = 0;
    priv->tx_tail = 0;

    for (i = 0; i < VNET_TX_RING_SIZE; ++i) {
        priv->tx_ring[i].skb = NULL;
        priv->tx_ring[i].used = false;
    }
}

/**
 * @brief Enqueue a packet into the TX ring.
 *
 * If the ring is full, the packet is not enqueued and -ENOSPC is
 * returned to the caller.
 *
 * @param priv Pointer to the driver's private data.
 * @param skb  Packet to enqueue.
 * @return 0 on success, -ENOSPC if the ring is full.
 */
static int vnet_tx_enqueue(struct vnet_priv *priv, struct sk_buff *skb)
{
    struct vnet_tx_slot *slot;

    if (vnet_tx_ring_full(priv))
        return -ENOSPC;

    slot = &priv->tx_ring[priv->tx_head];
    slot->skb = skb;
    slot->used = true;

    priv->tx_head = (priv->tx_head + 1U) % VNET_TX_RING_SIZE;

    return 0;
}

/**
 * @brief Dequeue a packet from the TX ring.
 *
 * If the ring is empty, NULL is returned.
 *
 * @param priv Pointer to the driver's private data.
 * @return Pointer to the dequeued sk_buff, or NULL if the ring is empty.
 */
static struct sk_buff *vnet_tx_dequeue(struct vnet_priv *priv)
{
    struct vnet_tx_slot *slot;
    struct sk_buff *skb;

    if (vnet_tx_ring_empty(priv))
        return NULL;

    slot = &priv->tx_ring[priv->tx_tail];
    skb = slot->skb;

    slot->skb = NULL;
    slot->used = false;

    priv->tx_tail = (priv->tx_tail + 1U) % VNET_TX_RING_SIZE;

    return skb;
}

/**
 * @brief Complete all pending TX packets.
 *
 * In a real driver, completion is usually triggered by hardware
 * interrupts. For this learning driver we simulate completion by
 * draining the ring whenever we transmit.
 *
 * @param dev Pointer to the network device.
 */
static void vnet_tx_complete_all(struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);
    struct sk_buff *skb;
    unsigned int count = 0;

    while ((skb = vnet_tx_dequeue(priv)) != NULL) {
        dev_kfree_skb(skb);
        count++;
    }

    if (count > 0)
        pr_debug("vnet: completed %u TX packets\n", count);
}


/* ====================================================================== */
/*                          RX ring helpers                               */
/* ====================================================================== */

/**
 * @brief Check if the RX ring is full.
 *
 * The ring is considered full if the slot at rx_head is already
 * in use. In that case, new packets must be dropped or back-pressured.
 *
 * @param priv Pointer to the driver's private data.
 * @return true if the ring is full, false otherwise.
 */
static bool vnet_rx_ring_full(struct vnet_priv *priv)
{
    return priv->rx_ring[priv->rx_head].used;
}

/**
 * @brief Check if the RX ring is empty.
 *
 * The ring is empty if the slot at rx_tail is not in use.
 *
 * @param priv Pointer to the driver's private data.
 * @return true if the ring is empty, false otherwise.
 */
static bool vnet_rx_ring_empty(struct vnet_priv *priv)
{
    return !priv->rx_ring[priv->rx_tail].used;
}

/**
 * @brief Initialize the RX ring.
 *
 * Resets head/tail indices and marks all slots as unused.
 *
 * @param priv Pointer to the driver's private data.
 */
static void vnet_rx_ring_init(struct vnet_priv *priv)
{
    int i;

    priv->rx_head = 0;
    priv->rx_tail = 0;

    for (i = 0; i < VNET_RX_RING_SIZE; ++i) {
        priv->rx_ring[i].skb = NULL;
        priv->rx_ring[i].used = false;
    }
}

/**
 * @brief Enqueue a received packet into the RX ring.
 *
 * @param priv Pointer to the driver's private data.
 * @param skb  Packet to enqueue.
 * @return 0 on success, -ENOSPC if the ring is full.
 */
static int vnet_rx_enqueue(struct vnet_priv *priv, struct sk_buff *skb)
{
    struct vnet_rx_slot *slot;

    if (vnet_rx_ring_full(priv))
        return -ENOSPC;

    slot = &priv->rx_ring[priv->rx_head];
    slot->skb = skb;
    slot->used = true;

    priv->rx_head = (priv->rx_head + 1U) % VNET_RX_RING_SIZE;

    return 0;
}

/**
 * @brief Dequeue a packet from the RX ring.
 *
 * @param priv Pointer to the driver's private data.
 * @return Pointer to the dequeued sk_buff, or NULL if the ring is empty.
 */
static struct sk_buff *vnet_rx_dequeue(struct vnet_priv *priv)
{
    struct vnet_rx_slot *slot;
    struct sk_buff *skb;

    if (vnet_rx_ring_empty(priv))
        return NULL;

    slot = &priv->rx_ring[priv->rx_tail];
    skb = slot->skb;

    slot->skb = NULL;
    slot->used = false;

    priv->rx_tail = (priv->rx_tail + 1U) % VNET_RX_RING_SIZE;

    return skb;
}

/**
 * @brief NAPI poll function for the vnet driver.
 *
 * This function is invoked by the networking core when NAPI is scheduled.
 * It drains packets from the RX ring (up to @p budget packets) and, for
 * each packet, hands it to the networking stack.
 *
 * In a production driver, this would be invoked after an RX interrupt
 * disables further interrupts and schedules NAPI. Once the ring is empty,
 * napi_complete_done() is called so interrupts can be re-enabled.
 *
 * @param napi   Pointer to the NAPI context.
 * @param budget Maximum number of packets to process in this poll cycle.
 *
 * @return Number of packets actually processed.
 */
static int vnet_napi_poll(struct napi_struct *napi, int budget)
{
    struct vnet_priv *priv = container_of(napi, struct vnet_priv, napi);
    struct net_device *dev = priv->dev;
    struct sk_buff *skb;
    int work_done = 0;

    while (work_done < budget) {
        /* Dequeue one packet from the RX ring under the lock. */
        spin_lock(&priv->lock);
        skb = vnet_rx_dequeue(priv);
        spin_unlock(&priv->lock);

        if (!skb)
            break; /* No more packets available. */

        /* Update RX statistics before handing the packet to the stack. */
        spin_lock(&priv->lock);
        priv->rx_packets++;
        priv->rx_bytes += skb->len;
        spin_unlock(&priv->lock);

        /* Attach metadata so the stack knows how to handle the packet. */
        skb->dev = dev;
        skb_reset_mac_header(skb);
        skb_reset_network_header(skb);
        skb->protocol = htons(ETH_P_IP);  /* Dummy protocol tag. */
        skb->ip_summed = CHECKSUM_NONE;

        /* Hand the packet to the networking stack. The stack will
         * free the skb once it is done.
         */
        netif_rx(skb);

        work_done++;
    }

    if (work_done < budget) {
        napi_complete_done(napi, work_done);
        /* In a real driver, RX interrupts would be re-enabled here. */
    }

    return work_done;
}


/**
 * @brief RX timer callback: simulate incoming packets.
 *
 * This function is called periodically by the kernel timer. It simulates
 * incoming packets by allocating an sk_buff with a small text payload,
 * enqueuing it into the RX ring, and then scheduling NAPI to process
 * the ring.
 *
 * @param t Pointer to the timer_list embedded in vnet_priv.
 */
static void vnet_rx_timer_fn(struct timer_list *t)
{
    struct vnet_priv *priv = from_timer(priv, t, rx_timer);
    struct net_device *dev = priv->dev;
    struct sk_buff *skb;
    const char *msg = "Hello from vnet RX";
    size_t msg_len = strlen(msg);
    int ret;

    /* Allocate an sk_buff with room for our dummy payload. */
    skb = netdev_alloc_skb_ip_align(dev, msg_len);
    if (!skb) {
        spin_lock(&priv->lock);
        priv->rx_dropped++;
        spin_unlock(&priv->lock);

        pr_warn("vnet: RX timer failed to allocate skb\n");
        goto out_rearm;
    }

    /* Copy the dummy payload into the skb's data area. */
    memcpy(skb_put(skb, msg_len), msg, msg_len);

    /* Enqueue into the RX ring under lock. */
    spin_lock(&priv->lock);
    ret = vnet_rx_enqueue(priv, skb);
    if (ret) {
        spin_unlock(&priv->lock);
        spin_lock(&priv->lock);
        priv->rx_dropped++;
        spin_unlock(&priv->lock);

        pr_warn("vnet: RX ring full, dropping simulated packet\n");
        dev_kfree_skb_any(skb);
        goto out_rearm;
    }


    /* Schedule NAPI to process the RX ring. In a real driver this
     * would usually be done from an RX interrupt handler.
     */
    if (napi_schedule_prep(&priv->napi))
        __napi_schedule(&priv->napi);

    spin_unlock(&priv->lock);

out_rearm:
    /* Rearm the timer to fire again in 1 second. */
    mod_timer(&priv->rx_timer, jiffies + msecs_to_jiffies(1000));
}



/**
 * @brief Pointer to the single vnet device instance.
 *
 * For now, this driver only creates one device. Later it could be
 * extended to support multiple devices if needed.
 */
static struct net_device *vnet_dev;

/* ====================================================================== */
/*                    net_device_ops callback implementations             */
/* ====================================================================== */

/**
 * @brief Open callback for the network device.
 *
 * Initializes TX/RX rings, enables NAPI, and starts the RX timer used
 * to simulate incoming packets.
 *
 * @param dev Pointer to the network device being opened.
 * @return 0 on success, negative error code on failure.
 */
static int vnet_open(struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);

    /* Initialize the TX and RX rings each time the device is opened. */
    spin_lock_bh(&priv->lock);
    vnet_tx_ring_init(priv);
    vnet_rx_ring_init(priv);
    /* Reset statistics on open to start a fresh session. */
    priv->tx_packets = 0;
    priv->tx_bytes   = 0;
    priv->tx_dropped = 0;
    priv->rx_packets = 0;
    priv->rx_bytes   = 0;
    priv->rx_dropped = 0;
    spin_unlock_bh(&priv->lock);

    /* Enable NAPI so RX processing can run in poll context. */
    napi_enable(&priv->napi);

    /* Set up and start the RX timer to simulate incoming packets. */
    timer_setup(&priv->rx_timer, vnet_rx_timer_fn, 0);
    mod_timer(&priv->rx_timer, jiffies + msecs_to_jiffies(1000));

    netif_start_queue(dev);
    pr_info("vnet: device %s opened\n", dev->name);
    return 0;
}

/**
 * @brief Stop callback for the network device.
 *
 * Stops the TX queue, disables NAPI, cancels the RX timer, and drains
 * any remaining packets from both TX and RX rings.
 *
 * @param dev Pointer to the network device being stopped.
 * @return 0 on success, negative error code on failure.
 */
static int vnet_stop(struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);
    struct sk_buff *skb;

    netif_stop_queue(dev);     /* Disable the transmit queue to stop new packets */

    /* Disable NAPI before tearing down RX state. */
    napi_disable(&priv->napi);

    /* Stop the RX timer and wait for any running callback. */
    del_timer_sync(&priv->rx_timer);

    /* Drain any remaining packets in the TX and RX rings. */
    spin_lock_bh(&priv->lock);

    while ((skb = vnet_tx_dequeue(priv)) != NULL)
        dev_kfree_skb_any(skb);

    while ((skb = vnet_rx_dequeue(priv)) != NULL)
        dev_kfree_skb_any(skb);

    spin_unlock_bh(&priv->lock);

    pr_info("vnet: device %s stopped\n", dev->name);
    return 0;
}


/**
 * @brief Transmit callback for the network device.
 *
 * This function is called whenever the kernel has an outgoing packet
 * to send through this interface. The packet is provided as an sk_buff.
 *
 * For now, this implementation enqueues the packet into a TX ring and
 * immediately simulates completion. Later phases may move completion
 * to a separate context (e.g. timer, NAPI).
 *
 * @param skb Pointer to the socket buffer (packet) to transmit.
 * @param dev Pointer to the network device through which the packet is sent.
 * @return NETDEV_TX_OK on success, or other netdev_tx_t codes on error.
 */
static netdev_tx_t vnet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);
    int ret;

    /* Acquire lock to protect the TX ring and statistics. */
    spin_lock(&priv->lock);

    if (vnet_tx_ring_full(priv)) {
        /* Ring is full: stop the queue and tell the stack to retry later. */
        netif_stop_queue(dev);

        /* Count this as a dropped TX packet. */
        priv->tx_dropped++;

        spin_unlock(&priv->lock);

        pr_warn("vnet: TX ring full on %s, returning NETDEV_TX_BUSY\n", dev->name);
        return NETDEV_TX_BUSY;
    }

    ret = vnet_tx_enqueue(priv, skb);
    if (ret) {
        /* Should not happen if vnet_tx_ring_full() was checked, but
         * handle gracefully anyway.
         */
        priv->tx_dropped++;
        spin_unlock(&priv->lock);
        pr_err("vnet: failed to enqueue TX packet (err=%d)\n", ret);
        dev_kfree_skb(skb);
        return NETDEV_TX_OK;
    }

    /* Update TX statistics on successful enqueue. */
    priv->tx_packets++;
    priv->tx_bytes += skb->len;

    /* For this learning phase, we simulate immediate TX completion by
     * draining the ring synchronously. Later phases can move this to
     * a workqueue, timer, or NAPI poll loop.
     */
    vnet_tx_complete_all(dev);

    /* If there is space again in the ring, wake up the queue. */
    if (!vnet_tx_ring_full(priv))
        netif_wake_queue(dev);

    spin_unlock(&priv->lock);

    return NETDEV_TX_OK;
}

/**
 * @brief Retrieve device statistics (64-bit).
 *
 * This callback populates @p stats with the driver's internal counters so
 * that tools like "ip -s link" can display TX/RX packet and byte counts.
 *
 * @param dev   Pointer to the network device.
 * @param stats Pointer to the rtnl_link_stats64 structure to fill in.
 */
static void vnet_get_stats64(struct net_device *dev,
                             struct rtnl_link_stats64 *stats)
{
    struct vnet_priv *priv = netdev_priv(dev);

    /* Protect statistics with the same lock used for updates. */
    spin_lock_bh(&priv->lock);

    stats->rx_packets = priv->rx_packets;
    stats->rx_bytes   = priv->rx_bytes;
    stats->rx_dropped = priv->rx_dropped;

    stats->tx_packets = priv->tx_packets;
    stats->tx_bytes   = priv->tx_bytes;
    stats->tx_dropped = priv->tx_dropped;

    spin_unlock_bh(&priv->lock);
}

/**
 * @brief net_device_ops structure for the vnet driver.
 *
 * This table connects the generic networking stack to our driver-specific
 * implementations. The kernel calls these functions when operations are
 * performed on the interface (open, stop, transmit, etc.).
 */
static const struct net_device_ops vnet_netdev_ops = {
    .ndo_open       = vnet_open,       /**< Called when the interface is brought up */
    .ndo_stop       = vnet_stop,       /**< Called when the interface is brought down */
    .ndo_start_xmit = vnet_start_xmit, /**< Called to transmit a packet */
    .ndo_get_stats64 = vnet_get_stats64, /**< Provide 64-bit TX/RX statistics */
    /* Additional operations (set_mac_address, change_mtu, etc.) can be
     * added here in later phases if needed.
     */
};

/**
 * @brief Fill basic driver information for ethtool.
 *
 * This callback is used by "ethtool -i vnet0" to display the driver name,
 * version, and bus information.
 *
 * @param dev  Pointer to the network device.
 * @param info Pointer to the structure to fill in.
 */
static void vnet_get_drvinfo(struct net_device *dev,
                             struct ethtool_drvinfo *info)
{
    strscpy(info->driver,  "vnet", sizeof(info->driver));
    strscpy(info->version, "0.6", sizeof(info->version));
    strscpy(info->bus_info, "virtual", sizeof(info->bus_info));
}

/**
 * @brief Report link status for ethtool.
 *
 * This virtual device always reports the link as up.
 *
 * @param dev Pointer to the network device.
 * @return 1 if link is up, 0 otherwise.
 */
static u32 vnet_get_link(struct net_device *dev)
{
    return 1;
}

/**
 * @brief ethtool operations for the vnet driver.
 *
 * This table is used by ethtool to query basic driver information.
 */
static const struct ethtool_ops vnet_ethtool_ops = {
    .get_drvinfo = vnet_get_drvinfo,
    .get_link    = vnet_get_link,
};

/* ====================================================================== */
/*                        Module init / exit                              */
/* ====================================================================== */

/**
 * @brief Module initialization function.
 *
 * This function is called when the module is loaded into the kernel.
 * It performs the following steps:
 *
 *   1. Allocate an Ethernet net_device with space for vnet_priv.
 *   2. Initialize the device name pattern (vnet%d).
 *   3. Assign our net_device_ops.
 *   4. Initialize the private data (spinlock, back-pointer).
 *   5. Set a fixed, locally administered MAC address.
 *   6. Register the device with the kernel networking stack.
 *
 * On success, the new interface will appear in "ip link" output as
 * something like "vnet0".
 *
 * @return 0 on success, negative error code on failure.
 */
static int __init vnet_init(void)
{
    int ret;
    struct vnet_priv *priv;
    static const unsigned char mac_addr[ETH_ALEN] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01
    }; /**< Locally administered unicast MAC address */

    /* Allocate an Ethernet device with private data. The sizeof(struct vnet_priv)
     * is passed implicitly via alloc_etherdev().
     */
    vnet_dev = alloc_etherdev(sizeof(*priv));
    if (!vnet_dev) {
        pr_err("vnet: failed to allocate net_device\n");
        return -ENOMEM;
    }

    /* Set the name pattern (vnet0, vnet1, ...). */
    strscpy(vnet_dev->name, "vnet%d", IFNAMSIZ);

    /* Hook up our net_device_ops. */
    vnet_dev->netdev_ops = &vnet_netdev_ops;

    /* Connect ethtool operations so that "ethtool" can query this driver. */
    vnet_dev->ethtool_ops = &vnet_ethtool_ops;

    /* Initialize the private data area. */
    priv = netdev_priv(vnet_dev);
    priv->dev = vnet_dev;
    spin_lock_init(&priv->lock);
   
    /* Register NAPI context for RX polling.
     * On this kernel, netif_napi_add() takes only three arguments:
     *   - device
     *   - napi struct
     *   - poll function
     * The weight defaults to NAPI_POLL_WEIGHT.
     */
    netif_napi_add(vnet_dev, &priv->napi, vnet_napi_poll);

    /**
     * Set the hardware (MAC) address for this net_device.
     *
     * eth_hw_addr_set() is the preferred helper in modern kernels since
     * it updates both dev->dev_addr and the internal bookkeeping the
     * networking stack maintains.
     */
    eth_hw_addr_set(vnet_dev, mac_addr);

    /* Register the device with the networking core. */
    ret = register_netdev(vnet_dev);
    if (ret) {
        pr_err("vnet: failed to register net_device (ret=%d)\n", ret);
        free_netdev(vnet_dev);
        vnet_dev = NULL;
        return ret;
    }

    pr_info("vnet: registered device %s with MAC %pM\n", vnet_dev->name, vnet_dev->dev_addr);
    return 0;
}

/**
 * @brief Module cleanup function.
 *
 * This function is called when the module is unloaded from the kernel.
 * It unregisters the network device and frees the associated memory.
 */
static void __exit vnet_exit(void)
{
    if (vnet_dev) {
	 struct vnet_priv *priv = netdev_priv(vnet_dev);

	 pr_info("vnet: unregistering device %s\n", vnet_dev->name);

    	/* Remove NAPI context before freeing the device. */
    	netif_napi_del(&priv->napi);

    	unregister_netdev(vnet_dev);
    	free_netdev(vnet_dev);
    	vnet_dev = NULL;
    }
}

module_init(vnet_init);  /**< Register vnet_init() as the module's entry point */
module_exit(vnet_exit);  /**< Register vnet_exit() as the module's exit point */

MODULE_LICENSE("GPL");           /**< License: required to avoid "tainting" the kernel */
MODULE_AUTHOR("Karan Gandhi");   /**< Author name for documentation and diagnostics */
MODULE_DESCRIPTION("Virtual network device (vnet0) - Phases 2-6: TX/RX rings, NAPI, stats, ethtool");
MODULE_VERSION("0.6");           /**< Driver version string */

