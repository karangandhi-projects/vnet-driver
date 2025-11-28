/**
 * @file vnet_main.c
 * @brief Minimal virtual Ethernet network driver (Phase 4: TX/RX rings and timer-based RX).
 *
 * This module registers a simple virtual network interface (e.g. vnet0)
 * and wires up basic net_device operations (open/stop/start_xmit).
 *
 * At this stage, the driver:
 *   - Allocates a struct net_device with private data.
 *   - Registers the device with the kernel networking stack.
 *   - Exposes a virtual interface visible via "ip link".
 *   - Implements a TX ring to queue outgoing packets.
 *   - Implements an RX ring fed by a timer that simulates incoming packets.
 *   - Still drops all packets instead of handing them to the networking stack (learning phase).
 *
 * Later phases will add:
 *   - NAPI integration and real packet delivery to the networking stack.
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
    struct net_device *dev;                     /**< Back-pointer to the associated net_device */
    spinlock_t lock;                            /**< Spinlock to protect shared state in the driver */

    /* ------------------ TX ring state ------------------ */

    struct vnet_tx_slot tx_ring[VNET_TX_RING_SIZE]; /**< Fixed-size circular buffer for TX packets */
    u16 tx_head;                                    /**< Index where the next packet will be enqueued */
    u16 tx_tail;                                    /**< Index where the next packet will be dequeued */

    /* ------------------ RX ring state ------------------ */

    struct vnet_rx_slot rx_ring[VNET_RX_RING_SIZE]; /**< Fixed-size circular buffer for RX packets */
    u16 rx_head;                                    /**< Index where the next packet will be written */
    u16 rx_tail;                                    /**< Index where the next packet will be read */

    /* ------------------ RX packet generator ------------ */

    struct timer_list rx_timer;                     /**< Timer that simulates incoming packets */
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
 * @brief Process all packets currently queued in the RX ring.
 *
 * In a production driver this function (or NAPI poll) would deliver
 * packets to the networking stack via netif_receive_skb() or variants.
 * For learning purposes, we simply log and free each packet.
 *
 * @param dev Pointer to the network device.
 */
static void vnet_rx_process_all(struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);
    struct sk_buff *skb;
    unsigned int count = 0;

    while ((skb = vnet_rx_dequeue(priv)) != NULL) {
        pr_debug("vnet: RX packet of length %u bytes on %s\n",
                 skb->len, dev->name);

        dev_kfree_skb_any(skb);
        count++;
    }

    if (count > 0)
        pr_info("vnet: processed %u RX packets on %s\n", count, dev->name);
}

/**
 * @brief RX timer callback: simulate incoming packets.
 *
 * This function is called periodically by the kernel timer. It simulates
 * incoming packets by allocating an sk_buff with a small text payload,
 * enqueuing it into the RX ring, and then processing the ring.
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
        pr_warn("vnet: RX ring full, dropping simulated packet\n");
        dev_kfree_skb_any(skb);
        goto out_rearm;
    }

    /* Process everything currently in the RX ring.
     * In a later phase this will be replaced with NAPI scheduling.
     */
    vnet_rx_process_all(dev);
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
 * This function is called by the kernel when the interface is brought up,
 * for example via:
 *
 *   ip link set vnet0 up
 *
 * Typical responsibilities here include starting the TX queue and
 * initializing hardware. Since this is a virtual device, we only start
 * the queue, initialize our rings, and start the RX timer.
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
    spin_unlock_bh(&priv->lock);

    /* Set up and start the RX timer to simulate incoming packets. */
    timer_setup(&priv->rx_timer, vnet_rx_timer_fn, 0);
    mod_timer(&priv->rx_timer, jiffies + msecs_to_jiffies(1000));

    netif_start_queue(dev);    /**< Enable the transmit queue so the stack can send packets */
    pr_info("vnet: device %s opened\n", dev->name);
    return 0;
}

/**
 * @brief Stop callback for the network device.
 *
 * This function is called by the kernel when the interface is brought
 * down, for example via:
 *
 *   ip link set vnet0 down
 *
 * Typical responsibilities include stopping the TX queue and shutting
 * down hardware. Here we stop the queue, cancel the RX timer, and
 * drain all pending packets from TX and RX rings.
 *
 * @param dev Pointer to the network device being stopped.
 * @return 0 on success, negative error code on failure.
 */
static int vnet_stop(struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);
    struct sk_buff *skb;

    netif_stop_queue(dev);     /**< Disable the transmit queue to stop new packets */

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

    spin_lock(&priv->lock);

    if (vnet_tx_ring_full(priv)) {
        /* Ring is full: stop the queue and tell the stack to retry later. */
        netif_stop_queue(dev);
        spin_unlock(&priv->lock);

        pr_warn("vnet: TX ring full on %s, returning NETDEV_TX_BUSY\n", dev->name);
        return NETDEV_TX_BUSY;
    }

    ret = vnet_tx_enqueue(priv, skb);
    if (ret) {
        /* Should not happen if vnet_tx_ring_full() was checked, but
         * handle gracefully anyway.
         */
        spin_unlock(&priv->lock);
        pr_err("vnet: failed to enqueue TX packet on %s (ret=%d)\n", dev->name, ret);
        dev_kfree_skb_any(skb);
        return NETDEV_TX_OK;
    }

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
    /* Additional operations (set_mac_address, change_mtu, etc.) can be
     * added here in later phases if needed.
     */
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

    /* Initialize the private data area. */
    priv = netdev_priv(vnet_dev);
    priv->dev = vnet_dev;
    spin_lock_init(&priv->lock);

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
        pr_info("vnet: unregistering device %s\n", vnet_dev->name);
        unregister_netdev(vnet_dev);
        free_netdev(vnet_dev);
        vnet_dev = NULL;
    }
}

module_init(vnet_init);  /**< Register vnet_init() as the module's entry point */
module_exit(vnet_exit);  /**< Register vnet_exit() as the module's exit point */

MODULE_LICENSE("GPL");           /**< License: required to avoid "tainting" the kernel */
MODULE_AUTHOR("Karan Gandhi");   /**< Author name for documentation and diagnostics */
MODULE_DESCRIPTION("Minimal virtual network device (vnet0) - Phase 4 (TX/RX rings, timer-based RX)");
MODULE_VERSION("0.4");           /**< Driver version string */

