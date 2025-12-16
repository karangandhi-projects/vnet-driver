/**
 * @file vnet_main.c
 * @brief Virtual Ethernet network driver (vnet0).
 *
 * This module registers a software-only Ethernet interface and implements
 * the core mechanics you see in real Linux NIC drivers:
 *  - net_device lifecycle management (register/unregister, open/stop)
 *  - TX/RX ring buffers with explicit skb ownership
 *  - NAPI-based RX processing (polling with budget)
 *  - A timer used to simulate RX interrupts by generating synthetic frames
 *  - Valid Ethernet framing for synthetic RX (ARP request)
 *  - Per-protocol statistics and `ethtool -S` reporting
 *
 * The driver is intentionally simple: TX is completed immediately after
 * enqueueing (learning-friendly), while RX follows a realistic ring + NAPI model.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#define VNET_TX_RING_SIZE 64
#define VNET_RX_RING_SIZE 64

/**
 * Global device pointer.
 *
 * Keeping a stable pointer makes module teardown deterministic and mirrors
 * how real drivers manage registered devices.
 */
static struct net_device *g_vnet_dev;

/**
 * @brief TX ring slot
 *
 * A slot owns an skb while `used==true`. Ownership transfers:
 *  - from stack -> driver in ndo_start_xmit
 *  - from driver -> freed at completion time
 */
struct vnet_tx_slot {
    struct sk_buff *skb; /**< skb currently owned by this slot */
    bool used;           /**< occupancy flag */
};

/**
 * @brief RX ring slot
 *
 * RX skb objects are owned by the driver until NAPI dequeues them and hands
 * them to the network stack via netif_rx().
 */
struct vnet_rx_slot {
    struct sk_buff *skb; /**< skb currently owned by this slot */
    bool used;           /**< occupancy flag */
};

/**
 * @brief Per-device private state
 *
 * Stored in netdev_priv(dev). Protect shared state with `lock`.
 */
struct vnet_priv {
    struct net_device *dev; /**< back-pointer */

    spinlock_t lock;        /**< protects rings and stats */

    /* TX ring */
    struct vnet_tx_slot tx_ring[VNET_TX_RING_SIZE];
    u16 tx_head; /**< enqueue index */
    u16 tx_tail; /**< dequeue index */

    /* RX ring */
    struct vnet_rx_slot rx_ring[VNET_RX_RING_SIZE];
    u16 rx_head; /**< enqueue index */
    u16 rx_tail; /**< dequeue index */

    /* RX scheduling */
    struct napi_struct napi;    /**< NAPI context for RX */
    struct timer_list rx_timer; /**< simulates RX interrupts */

    /* Aggregate statistics */
    u64 tx_packets;
    u64 tx_bytes;
    u64 tx_dropped;

    u64 rx_packets;
    u64 rx_bytes;
    u64 rx_dropped;

    /* Per-protocol statistics (EtherType based) */
    u64 tx_arp;
    u64 tx_ipv4;
    u64 tx_ipv6;
    u64 tx_other;

    u64 rx_arp;
    u64 rx_ipv4;
    u64 rx_ipv6;
    u64 rx_other;
};

/* -------------------------------------------------------------------------- */
/*                               TX ring helpers                              */
/* -------------------------------------------------------------------------- */

/**
 * @brief Initialize TX ring to empty state.
 */
static void vnet_tx_ring_init(struct vnet_priv *priv)
{
    int i;

    priv->tx_head = 0;
    priv->tx_tail = 0;

    for (i = 0; i < VNET_TX_RING_SIZE; i++) {
        priv->tx_ring[i].skb = NULL;
        priv->tx_ring[i].used = false;
    }
}

/**
 * @brief Check if TX ring is full.
 *
 * We treat the ring as full when the slot at tx_head is still occupied.
 */
static bool vnet_tx_ring_full(struct vnet_priv *priv)
{
    return priv->tx_ring[priv->tx_head].used;
}

/**
 * @brief Enqueue skb into TX ring.
 *
 * @param priv Driver private data
 * @param skb  Packet owned by the stack (ownership transfers to driver)
 *
 * @return 0 on success, -ENOSPC if ring is full
 */
static int vnet_tx_enqueue(struct vnet_priv *priv, struct sk_buff *skb)
{
    if (vnet_tx_ring_full(priv))
        return -ENOSPC;

    priv->tx_ring[priv->tx_head].skb = skb;
    priv->tx_ring[priv->tx_head].used = true;
    priv->tx_head = (priv->tx_head + 1) % VNET_TX_RING_SIZE;

    return 0;
}

/**
 * @brief Dequeue skb from TX ring.
 *
 * Returns NULL if the ring is empty.
 */
static struct sk_buff *vnet_tx_dequeue(struct vnet_priv *priv)
{
    struct sk_buff *skb;

    if (!priv->tx_ring[priv->tx_tail].used)
        return NULL;

    skb = priv->tx_ring[priv->tx_tail].skb;
    priv->tx_ring[priv->tx_tail].skb = NULL;
    priv->tx_ring[priv->tx_tail].used = false;
    priv->tx_tail = (priv->tx_tail + 1) % VNET_TX_RING_SIZE;

    return skb;
}

/* -------------------------------------------------------------------------- */
/*                               RX ring helpers                              */
/* -------------------------------------------------------------------------- */

/**
 * @brief Initialize RX ring to empty state.
 */
static void vnet_rx_ring_init(struct vnet_priv *priv)
{
    int i;

    priv->rx_head = 0;
    priv->rx_tail = 0;

    for (i = 0; i < VNET_RX_RING_SIZE; i++) {
        priv->rx_ring[i].skb = NULL;
        priv->rx_ring[i].used = false;
    }
}

/**
 * @brief Enqueue skb into RX ring.
 *
 * @return 0 on success, -ENOSPC if ring is full.
 */
static int vnet_rx_enqueue(struct vnet_priv *priv, struct sk_buff *skb)
{
    if (priv->rx_ring[priv->rx_head].used)
        return -ENOSPC;

    priv->rx_ring[priv->rx_head].skb = skb;
    priv->rx_ring[priv->rx_head].used = true;
    priv->rx_head = (priv->rx_head + 1) % VNET_RX_RING_SIZE;

    return 0;
}

/**
 * @brief Check if RX ring is empty.
 */
static bool vnet_rx_ring_empty(struct vnet_priv *priv)
{
    return !priv->rx_ring[priv->rx_tail].used;
}

/**
 * @brief Dequeue skb from RX ring.
 *
 * Returns NULL if empty.
 */
static struct sk_buff *vnet_rx_dequeue(struct vnet_priv *priv)
{
    struct sk_buff *skb;

    if (vnet_rx_ring_empty(priv))
        return NULL;

    skb = priv->rx_ring[priv->rx_tail].skb;
    priv->rx_ring[priv->rx_tail].skb = NULL;
    priv->rx_ring[priv->rx_tail].used = false;
    priv->rx_tail = (priv->rx_tail + 1) % VNET_RX_RING_SIZE;

    return skb;
}

/* -------------------------------------------------------------------------- */
/*                        Synthetic RX frame generation                        */
/* -------------------------------------------------------------------------- */

/**
 * @brief Build a synthetic ARP request Ethernet frame.
 *
 * This constructs a valid Ethernet + ARP request:
 *  - Ethernet destination: broadcast (ff:ff:ff:ff:ff:ff)
 *  - Ethernet source: device MAC
 *  - ARP: "Who has 10.0.0.2? Tell 10.0.0.1"
 *
 * The returned skb is owned by the caller.
 */
static struct sk_buff *vnet_build_rx_arp(struct net_device *dev)
{
    struct sk_buff *skb;
    struct ethhdr *eth;
    struct arphdr *arp;
    unsigned char *ptr;

    const size_t arp_payload_len =
        sizeof(struct arphdr) + (2 * ETH_ALEN) + (2 * sizeof(__be32));

    skb = netdev_alloc_skb_ip_align(dev, ETH_HLEN + arp_payload_len);
    if (!skb)
        return NULL;

    /* Ethernet header */
    eth = (struct ethhdr *)skb_put(skb, ETH_HLEN);
    eth_broadcast_addr(eth->h_dest);
    ether_addr_copy(eth->h_source, dev->dev_addr);
    eth->h_proto = htons(ETH_P_ARP);

    /* ARP header */
    arp = (struct arphdr *)skb_put(skb, sizeof(*arp));
    arp->ar_hrd = htons(ARPHRD_ETHER);
    arp->ar_pro = htons(ETH_P_IP);
    arp->ar_hln = ETH_ALEN;
    arp->ar_pln = sizeof(__be32);
    arp->ar_op  = htons(ARPOP_REQUEST);

    /* ARP payload layout:
     *   sender_hw (6) | sender_ip (4) | target_hw (6) | target_ip (4)
     */
    ptr = skb_put(skb, (2 * ETH_ALEN) + (2 * sizeof(__be32)));

    memcpy(ptr, dev->dev_addr, ETH_ALEN);
    ptr += ETH_ALEN;

    *(__be32 *)ptr = htonl(0x0A000001); /* 10.0.0.1 */
    ptr += sizeof(__be32);

    memset(ptr, 0, ETH_ALEN);
    ptr += ETH_ALEN;

    *(__be32 *)ptr = htonl(0x0A000002); /* 10.0.0.2 */

    return skb;
}

/* -------------------------------------------------------------------------- */
/*                                    NAPI                                    */
/* -------------------------------------------------------------------------- */

/**
 * @brief NAPI poll handler for RX processing.
 *
 * NAPI runs in softirq context. We dequeue up to @p budget packets from the RX
 * ring and pass them to the networking stack via netif_rx().
 *
 * @return Number of packets processed.
 */
static int vnet_napi_poll(struct napi_struct *napi, int budget)
{
    struct vnet_priv *priv = container_of(napi, struct vnet_priv, napi);
    struct sk_buff *skb;
    int work = 0;

    while (work < budget) {
        /* Dequeue one skb from RX ring under lock */
        spin_lock(&priv->lock);
        skb = vnet_rx_dequeue(priv);
        spin_unlock(&priv->lock);

        if (!skb)
            break;

        /* Populate skb metadata for the stack */
        skb->dev = priv->dev;
        skb->protocol = eth_type_trans(skb, priv->dev);

        /* Update RX counters */
        spin_lock(&priv->lock);

        priv->rx_packets++;
        priv->rx_bytes += skb->len;

        switch (ntohs(skb->protocol)) {
        case ETH_P_ARP:  priv->rx_arp++;  break;
        case ETH_P_IP:   priv->rx_ipv4++; break;
        case ETH_P_IPV6: priv->rx_ipv6++; break;
        default:         priv->rx_other++; break;
        }

        spin_unlock(&priv->lock);

        /* Hand skb to stack (stack will free it) */
        netif_rx(skb);
        work++;
    }

    /* If we drained the ring before budget, complete NAPI */
    if (work < budget)
        napi_complete_done(napi, work);

    return work;
}

/* -------------------------------------------------------------------------- */
/*                               RX timer callback                            */
/* -------------------------------------------------------------------------- */

/**
 * @brief Timer callback to simulate RX interrupt arrival.
 *
 * Real NIC drivers receive interrupts; for this virtual driver we periodically
 * generate a synthetic frame and schedule NAPI to process it.
 *
 * Important invariants:
 *  - If RX ring is full, we increment rx_dropped and free the skb.
 *  - We do not hold spinlocks while calling memory allocation helpers.
 */
static void vnet_rx_timer_fn(struct timer_list *t)
{
    struct vnet_priv *priv = from_timer(priv, t, rx_timer);
    struct sk_buff *skb;
    int ret;

    if (!netif_running(priv->dev))
        goto rearm;

    skb = vnet_build_rx_arp(priv->dev);
    if (!skb) {
        spin_lock(&priv->lock);
        priv->rx_dropped++;
        spin_unlock(&priv->lock);
        goto rearm;
    }

    spin_lock(&priv->lock);
    ret = vnet_rx_enqueue(priv, skb);
    if (ret) {
        priv->rx_dropped++;
        spin_unlock(&priv->lock);
        dev_kfree_skb_any(skb);
        goto rearm;
    }

    /* Schedule NAPI (acts like "interrupt -> poll") */
    if (napi_schedule_prep(&priv->napi))
        __napi_schedule(&priv->napi);

    spin_unlock(&priv->lock);

rearm:
    mod_timer(&priv->rx_timer, jiffies + msecs_to_jiffies(1000));
}

/* -------------------------------------------------------------------------- */
/*                              net_device ops                                */
/* -------------------------------------------------------------------------- */

/**
 * @brief ndo_open: bring interface up.
 *
 * Initializes rings, resets stats, enables NAPI, and starts RX timer.
 */
static int vnet_open(struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);

    spin_lock_bh(&priv->lock);

    vnet_tx_ring_init(priv);
    vnet_rx_ring_init(priv);

    /* Explicit resets are FORTIFY-safe and robust against struct reordering. */
    priv->tx_packets = 0;
    priv->tx_bytes   = 0;
    priv->tx_dropped = 0;

    priv->rx_packets = 0;
    priv->rx_bytes   = 0;
    priv->rx_dropped = 0;

    priv->tx_arp   = 0;
    priv->tx_ipv4  = 0;
    priv->tx_ipv6  = 0;
    priv->tx_other = 0;

    priv->rx_arp   = 0;
    priv->rx_ipv4  = 0;
    priv->rx_ipv6  = 0;
    priv->rx_other = 0;

    spin_unlock_bh(&priv->lock);

    napi_enable(&priv->napi);

    timer_setup(&priv->rx_timer, vnet_rx_timer_fn, 0);
    mod_timer(&priv->rx_timer, jiffies + msecs_to_jiffies(1000));

    netif_start_queue(dev);
    pr_info("vnet: device %s opened\n", dev->name);
    return 0;
}

/**
 * @brief ndo_stop: bring interface down.
 *
 * Stops queue, stops timer, disables NAPI.
 */
static int vnet_stop(struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);

    netif_stop_queue(dev);
    del_timer_sync(&priv->rx_timer);
    napi_disable(&priv->napi);

    pr_info("vnet: device %s stopped\n", dev->name);
    return 0;
}

/**
 * @brief ndo_set_mac_address: update device MAC.
 *
 * Uses eth_hw_addr_set() to avoid const-related warnings and keep
 * the update consistent with kernel expectations.
 */
static int vnet_set_mac_address(struct net_device *dev, void *p)
{
    struct sockaddr *addr = (struct sockaddr *)p;
    struct vnet_priv *priv = netdev_priv(dev);

    if (addr->sa_family != ARPHRD_ETHER)
        return -EINVAL;

    if (!is_valid_ether_addr((const u8 *)addr->sa_data))
        return -EADDRNOTAVAIL;

    /* Keep this strict (bring interface down before changing MAC). */
    if (netif_running(dev) && !(dev->flags & IFF_LIVE_ADDR_CHANGE))
        return -EBUSY;

    spin_lock_bh(&priv->lock);
    eth_hw_addr_set(dev, (const u8 *)addr->sa_data);
    spin_unlock_bh(&priv->lock);

    pr_info("vnet: %s MAC updated to %pM\n", dev->name, dev->dev_addr);
    return 0;
}

/**
 * @brief ndo_start_xmit: transmit a packet.
 *
 * Ownership rules:
 *  - On entry, skb is owned by the stack.
 *  - If we enqueue successfully, skb is owned by the driver.
 *  - In this driver we complete immediately by freeing one dequeued skb.
 *
 * Note: returning NETDEV_TX_BUSY tells the stack to retry later.
 */
static netdev_tx_t vnet_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct vnet_priv *priv = netdev_priv(dev);

    spin_lock(&priv->lock);

    /* Classify EtherType for per-protocol stats + debugging visibility */
    if (likely(skb->len >= ETH_HLEN)) {
        const struct ethhdr *eth = eth_hdr(skb);
        const u16 proto = ntohs(eth->h_proto);

        switch (proto) {
        case ETH_P_ARP:  priv->tx_arp++;  break;
        case ETH_P_IP:   priv->tx_ipv4++; break;
        case ETH_P_IPV6: priv->tx_ipv6++; break;
        default:         priv->tx_other++; break;
        }

        pr_debug("vnet: TX %s proto=0x%04x src=%pM dst=%pM len=%u\n",
                 dev->name, proto, eth->h_source, eth->h_dest, skb->len);
    } else {
        priv->tx_other++;
        pr_debug("vnet: TX %s short frame len=%u\n", dev->name, skb->len);
    }

    if (vnet_tx_enqueue(priv, skb)) {
        priv->tx_dropped++;
        spin_unlock(&priv->lock);
        return NETDEV_TX_BUSY;
    }

    priv->tx_packets++;
    priv->tx_bytes += skb->len;

    /* Immediate completion model: free one queued skb. */
    dev_kfree_skb_any(vnet_tx_dequeue(priv));

    spin_unlock(&priv->lock);
    return NETDEV_TX_OK;
}

/**
 * @brief ndo_get_stats64: expose aggregate stats via ip -s link.
 */
static void vnet_get_stats64(struct net_device *dev,
                             struct rtnl_link_stats64 *stats)
{
    struct vnet_priv *priv = netdev_priv(dev);

    spin_lock_bh(&priv->lock);

    stats->tx_packets = priv->tx_packets;
    stats->tx_bytes   = priv->tx_bytes;
    stats->tx_dropped = priv->tx_dropped;

    stats->rx_packets = priv->rx_packets;
    stats->rx_bytes   = priv->rx_bytes;
    stats->rx_dropped = priv->rx_dropped;

    spin_unlock_bh(&priv->lock);
}

static const struct net_device_ops vnet_netdev_ops = {
    .ndo_open            = vnet_open,
    .ndo_stop            = vnet_stop,
    .ndo_start_xmit      = vnet_start_xmit,
    .ndo_get_stats64     = vnet_get_stats64,
    .ndo_set_mac_address = vnet_set_mac_address,
};

/* -------------------------------------------------------------------------- */
/*                                   ethtool                                  */
/* -------------------------------------------------------------------------- */

/**
 * @brief Provide driver information to ethtool.
 */
static void vnet_get_drvinfo(struct net_device *dev,
                             struct ethtool_drvinfo *info)
{
    strscpy(info->driver, "vnet", sizeof(info->driver));
    strscpy(info->version, "0.7", sizeof(info->version));
    strscpy(info->bus_info, "virtual", sizeof(info->bus_info));
}

/**
 * @brief Link is always "up" for this virtual device.
 */
static u32 vnet_get_link(struct net_device *dev)
{
    return 1;
}

/**
 * @brief Statistic names exposed via `ethtool -S vnet0`.
 *
 * `ethtool` expects fixed-size strings (ETH_GSTRING_LEN).
 */
static const char vnet_stat_names[][ETH_GSTRING_LEN] = {
    "tx_packets",
    "tx_bytes",
    "tx_dropped",
    "rx_packets",
    "rx_bytes",
    "rx_dropped",
    "tx_arp",
    "tx_ipv4",
    "tx_ipv6",
    "tx_other",
    "rx_arp",
    "rx_ipv4",
    "rx_ipv6",
    "rx_other",
};

static int vnet_get_sset_count(struct net_device *dev, int sset)
{
    if (sset != ETH_SS_STATS)
        return -EOPNOTSUPP;

    return ARRAY_SIZE(vnet_stat_names);
}

static void vnet_get_strings(struct net_device *dev, u32 sset, u8 *data)
{
    if (sset != ETH_SS_STATS)
        return;

    memcpy(data, vnet_stat_names, sizeof(vnet_stat_names));
}

static void vnet_get_ethtool_stats(struct net_device *dev,
                                   struct ethtool_stats *stats,
                                   u64 *data)
{
    struct vnet_priv *priv = netdev_priv(dev);
    int i = 0;

    spin_lock_bh(&priv->lock);

    data[i++] = priv->tx_packets;
    data[i++] = priv->tx_bytes;
    data[i++] = priv->tx_dropped;

    data[i++] = priv->rx_packets;
    data[i++] = priv->rx_bytes;
    data[i++] = priv->rx_dropped;

    data[i++] = priv->tx_arp;
    data[i++] = priv->tx_ipv4;
    data[i++] = priv->tx_ipv6;
    data[i++] = priv->tx_other;

    data[i++] = priv->rx_arp;
    data[i++] = priv->rx_ipv4;
    data[i++] = priv->rx_ipv6;
    data[i++] = priv->rx_other;

    spin_unlock_bh(&priv->lock);
}

static const struct ethtool_ops vnet_ethtool_ops = {
    .get_drvinfo       = vnet_get_drvinfo,
    .get_link          = vnet_get_link,
    .get_sset_count    = vnet_get_sset_count,
    .get_strings       = vnet_get_strings,
    .get_ethtool_stats = vnet_get_ethtool_stats,
};

/* -------------------------------------------------------------------------- */
/*                              module init/exit                              */
/* -------------------------------------------------------------------------- */

/**
 * @brief Module init: allocate and register net_device.
 */
static int __init vnet_init(void)
{
    struct vnet_priv *priv;
    const u8 mac[ETH_ALEN] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

    g_vnet_dev = alloc_etherdev(sizeof(*priv));
    if (!g_vnet_dev)
        return -ENOMEM;

    priv = netdev_priv(g_vnet_dev);
    priv->dev = g_vnet_dev;
    spin_lock_init(&priv->lock);

    g_vnet_dev->netdev_ops  = &vnet_netdev_ops;
    g_vnet_dev->ethtool_ops = &vnet_ethtool_ops;

    /* Ensure the interface shows up as vnet0/vnet1/... instead of ethX */
    strscpy(g_vnet_dev->name, "vnet%d", IFNAMSIZ);

    eth_hw_addr_set(g_vnet_dev, mac);

    /* Attach NAPI context; enabled during ndo_open() */
    netif_napi_add(g_vnet_dev, &priv->napi, vnet_napi_poll);

    if (register_netdev(g_vnet_dev)) {
        netif_napi_del(&priv->napi);
        free_netdev(g_vnet_dev);
        g_vnet_dev = NULL;
        return -ENODEV;
    }

    pr_info("vnet: registered device %s\n", g_vnet_dev->name);
    return 0;
}

/**
 * @brief Module exit: unregister and free net_device.
 */
static void __exit vnet_exit(void)
{
    struct vnet_priv *priv;

    if (!g_vnet_dev)
        return;

    priv = netdev_priv(g_vnet_dev);

    pr_info("vnet: unregistering device %s\n", g_vnet_dev->name);

    unregister_netdev(g_vnet_dev);
    netif_napi_del(&priv->napi);
    free_netdev(g_vnet_dev);

    g_vnet_dev = NULL;
}

module_init(vnet_init);
module_exit(vnet_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Karan Gandhi");
MODULE_DESCRIPTION("Virtual Ethernet network driver (vnet0)");
MODULE_VERSION("0.7");
