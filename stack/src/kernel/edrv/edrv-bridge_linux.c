/**
********************************************************************************
\file   edrv-bridge_linux.c

\brief  Implementation of Linux OPLK-conformant 'bridge' driver

Uses the same API used by the bridge, bonding et al. drivers to claim a single
interface, which is then used exclusively for openPOWERLINK communication.

\bug FIXME currently needs network namespace configuration, so user processes
           don't access the slave interface. Can exclusion be realized here?
           e.g. with dev_change_net_namespace

\ingroup module_edrv
*******************************************************************************/

/*
 * Copyright (c) 2017, Ahmad Fatoum <ahmad[AT]a3f.at>
 * SPDX-License-Identifier: GPL-2.0
 */

//------------------------------------------------------------------------------
// includes
//------------------------------------------------------------------------------
#include <common/oplkinc.h>
#include <common/ftracedebug.h>
#include <kernel/edrv.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/rtnetlink.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/netpoll.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/sch_generic.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>


//============================================================================//
//            G L O B A L   D E F I N I T I O N S                             //
//============================================================================//

#define EDRV_TAILROOM        SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
#define EDRV_MAX_FRAME_SIZE  0x0600

#define SEC_TO_NSEC              1000000000

//------------------------------------------------------------------------------
// const defines
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// module global vars
//------------------------------------------------------------------------------

static char *slave_interface;
module_param(slave_interface, charp, 0);
MODULE_PARM_DESC(slave_interface, "Slave interface to claim");

static bool use_qdisc = false;
module_param(use_qdisc, bool, 0);
MODULE_PARM_DESC(use_qdisc, "Use Qdisc? 0 = no (default), 1 = yes");

#ifdef CONFIG_NETPOLL
static bool use_netpoll = true;
MODULE_PARM_DESC(use_netpoll, "Use netpoll if possible? 0 = no, 1 = yes (default)");
module_param(use_netpoll, bool, 0);
#else
static int use_netpoll = false;
#endif

static bool use_build_skb = false; /* FIXME Seems to suffer from use-after-free */
module_param(use_build_skb, bool, 0);
MODULE_PARM_DESC(use_build_skb, "Use build_skb? 0 = no (default), 1 = yes");


//------------------------------------------------------------------------------
// global function prototypes
//------------------------------------------------------------------------------

//============================================================================//
//            P R I V A T E   D E F I N I T I O N S                           //
//============================================================================//

//------------------------------------------------------------------------------
// const defines
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// local types
//------------------------------------------------------------------------------
/**
\brief Structure describing an instance of the Edrv

This structure describes an instance of the Ethernet driver.
*/
typedef struct
{
    tEdrvInitParam      initParam;                          ///< Init parameters
    struct net_device  *pSlave;
    tOplkError        (*pfnXmit)(struct sk_buff *pSkb_p);
#ifdef CONFIG_NETPOLL
    struct netpoll      np;
#endif
} tEdrvInstance;

//------------------------------------------------------------------------------
// local vars
//------------------------------------------------------------------------------
static tEdrvInstance edrvInstance_l;

//------------------------------------------------------------------------------
// local function prototypes
//------------------------------------------------------------------------------
static rx_handler_result_t rxPacketHandler(struct sk_buff **pSkb_p);
static void                txPacketHandler(struct sk_buff *pSkb_p);
static int enslave(struct net_device *pSlaveDevice_p);
static int emancipate(struct net_device *pSlaveDevice_p);
static UINT8 getMacAdrs(UINT8* pMacAddr_p, struct net_device *pSlaveDevice_p, UINT8 size_p);
static tOplkError packet_direct_xmit(struct sk_buff *skb);
static tOplkError packet_queue_xmit(struct sk_buff *skb);
static tOplkError packet_netpoll_xmit(struct sk_buff *skb);


//============================================================================//
//            P U B L I C   F U N C T I O N S                                 //
//============================================================================//

//------------------------------------------------------------------------------
/**
\brief  Ethernet driver initialization

This function initializes the Ethernet driver.

\param[in]      pEdrvInitParam_p    Edrv initialization parameters

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_init(const tEdrvInitParam* pEdrvInitParam_p)
{
    tOplkError ret = kErrorEdrvInit;
    int err;
    struct net_device *pSlaveDevice;

    // Check parameter validity
    ASSERT(pEdrvInitParam_p != NULL);

    // clear instance structure
    OPLK_MEMSET(&edrvInstance_l, 0, sizeof(edrvInstance_l));

    // save the init data
    edrvInstance_l.initParam = *pEdrvInitParam_p;

    DEBUG_LVL_EDRV_TRACE("%s() starting up...\n", __func__);

    edrvInstance_l.initParam.hwParam.pDevName = slave_interface;
    if (!slave_interface || !*slave_interface)
    {
        DEBUG_LVL_ERROR_TRACE("%s() wasn't supplied a slave interface as kernel module parameter\n", __func__);
        return kErrorEdrvInit;
    }

    // init and fill buffer allocation instance
    rtnl_lock();

    pSlaveDevice = __dev_get_by_name(current->nsproxy->net_ns, slave_interface);

    if (!pSlaveDevice)
    {
        DEBUG_LVL_ERROR_TRACE("%s() was supplied an invalid slave interface name: %s\n", __func__, pSlaveDevice->name);
        goto unlock;
    }

    if (enslave(pSlaveDevice) != 0)
        goto unlock;

    /* if no MAC address was specified read MAC address of used
     * Ethernet interface
     */
    if (!is_zero_ether_addr(edrvInstance_l.initParam.aMacAddr))
    {   // write MAC address to controller
        struct sockaddr addr;
        memcpy(addr.sa_data, edrvInstance_l.initParam.aMacAddr, ETH_ALEN);
        addr.sa_family = pSlaveDevice->type;
        err = dev_set_mac_address(pSlaveDevice, &addr);
        if (err)
        {
            DEBUG_LVL_ERROR_TRACE("%s() Error %d setting mac address to %pM\n",
                    __func__, err, edrvInstance_l.initParam.aMacAddr);
            goto unlock;
        }
        DEBUG_LVL_EDRV_TRACE("%s() %s's MAC address was set to %pM\n", __func__, pSlaveDevice->name, edrvInstance_l.initParam.aMacAddr);
    }
    else
    {   // read MAC address from controller
        UINT8 bytes = getMacAdrs(edrvInstance_l.initParam.aMacAddr, pSlaveDevice, ETH_ALEN);
        if (bytes == 0)
        { /* generate a new mac address */
            eth_hw_addr_random(pSlaveDevice);
            DEBUG_LVL_EDRV_TRACE("%s() Generating random hardware address for %s\n", __func__, pSlaveDevice->name);
        }
        else if (bytes != ETH_ALEN)
        {
            DEBUG_LVL_ERROR_TRACE("%s() %s doesn't have a 6 byte hardware address\n", __func__, pSlaveDevice->name);
            goto unlock;
        }
    }

#ifdef CONFIG_NETPOLL
    if (use_netpoll)
    {
        edrvInstance_l.np.name = "oplk-edrv-bridge";
        strlcpy(edrvInstance_l.np.dev_name, slave_interface, IFNAMSIZ);
        err = __netpoll_setup(&edrvInstance_l.np, pSlaveDevice);
        if (err < 0)
        {
            DEBUG_LVL_ERROR_TRACE("%s() Failed to setup netpoll for %s: error %d\n", __func__, pSlaveDevice, err);
            edrvInstance_l.np.dev = NULL;
            goto unlock;
        }
    }
#endif

    edrvInstance_l.pfnXmit = use_qdisc   ? packet_queue_xmit
                           : use_netpoll ? packet_netpoll_xmit
                           :               packet_direct_xmit;

    DEBUG_LVL_ALWAYS_TRACE("edrv-bridge: %s mode will be used on %s\n",
            use_qdisc   ? "Qdisc" :
            use_netpoll ? "Netpoll" :
                          "Direct-xmit",
            slave_interface);

    ret = kErrorOk;

unlock:
    rtnl_unlock();
    return ret;
}

//------------------------------------------------------------------------------
/**
\brief  Shut down Ethernet driver

This function shuts down the Ethernet driver.

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_exit(void)
{
#ifdef CONFIG_NETPOLL
    if (edrvInstance_l.np.dev)
        netpoll_cleanup(&edrvInstance_l.np);
#endif

    rtnl_lock();
    emancipate(edrvInstance_l.pSlave);
    rtnl_unlock();

    // Clear instance structure
    OPLK_MEMSET(&edrvInstance_l, 0, sizeof(edrvInstance_l));

    return kErrorOk;
}

//------------------------------------------------------------------------------
/**
\brief  Get MAC address

This function returns the MAC address of the Ethernet controller

\return The function returns a pointer to the MAC address.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
const UINT8* edrv_getMacAddr(void)
{
    return edrvInstance_l.initParam.aMacAddr;
}

//------------------------------------------------------------------------------
/**
\brief  Send Tx buffer

This function sends the Tx buffer.

\param[in,out]  pBuffer_p           Tx buffer descriptor

\return The function returns a tOplkError error code.

\NOTE    This is called in hardirq context

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_sendTxBuffer(tEdrvTxBuffer* pBuffer_p)
{
    struct sk_buff *skb;

    if (!netif_carrier_ok(edrvInstance_l.pSlave))
    {
        if (pBuffer_p->pfnTxHandler != NULL) {
            pBuffer_p->is_lock_protected = TRUE;
            pBuffer_p->pfnTxHandler(pBuffer_p);
            pBuffer_p->is_lock_protected = FALSE;
        }
        return kErrorOk;
    }

    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    /* build a socket buffer */
    if (use_build_skb)
    {
        skb = build_skb(pBuffer_p->pBuffer, 0);
        if (!skb)
        {
            DEBUG_LVL_ERROR_TRACE("%s() build_skb failed\n", __func__);
            return kErrorEdrvNoFreeTxDesc;
        }
    }
    else
    {
        skb = skb_clone(pBuffer_p->txBufferNumber.pArg, GFP_ATOMIC);
    }

    skb_put(skb, pBuffer_p->txFrameSize);

    skb->dev = edrvInstance_l.pSlave;
    skb_reset_network_header(skb); /* silences protocol 0000 is buggy WARNs */

    skb_shinfo(skb)->destructor_arg = pBuffer_p;
    skb->destructor = txPacketHandler;

    return edrvInstance_l.pfnXmit(skb);
}

/* Taken out of net/packet/af_packet.c */
static u16 __packet_pick_tx_queue(struct net_device *dev, struct sk_buff *skb)
{
	return (u16) raw_smp_processor_id() % dev->real_num_tx_queues;
}


static void packet_pick_tx_queue(struct net_device *dev, struct sk_buff *skb)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	u16 queue_index;

	if (ops->ndo_select_queue)
        {
		queue_index = ops->ndo_select_queue(dev, skb, NULL,
						    __packet_pick_tx_queue);
		queue_index = netdev_cap_txqueue(dev, queue_index);
	} else {
		queue_index = __packet_pick_tx_queue(dev, skb);
	}

	skb_set_queue_mapping(skb, queue_index);
}
static int __packet_direct_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct sk_buff *orig_skb = skb;
	struct netdev_queue *txq;
	int ret = NETDEV_TX_BUSY;

	if (unlikely(!netif_running(dev) ||
		     !netif_carrier_ok(dev)))
		goto drop;

	skb = validate_xmit_skb_list(skb, dev);
	if (skb != orig_skb)
		goto drop;

	packet_pick_tx_queue(dev, skb);
	txq = skb_get_tx_queue(dev, skb);

	local_bh_disable();

	HARD_TX_LOCK(dev, txq, smp_processor_id());
	if (!netif_xmit_frozen_or_drv_stopped(txq))
		ret = netdev_start_xmit(skb, dev, txq, false);
	HARD_TX_UNLOCK(dev, txq);

	local_bh_enable();

	if (!dev_xmit_complete(ret))
		kfree_skb(skb);

	return ret;
drop:
	atomic_long_inc(&dev->tx_dropped);
	kfree_skb_list(skb);
	return NET_XMIT_DROP;
}

//------------------------------------------------------------------------------
/**
\brief  TODO Would using a softirq be better in any way?
        TODO this assumes that the function don't sleep!

dev_queue_xmit can't be used with interrupts disabled, so we first reenable
irqs.

\NOTE runs in hardirq context

\param[in,out]  pSkb_p            Socket Buffer with reclaimable transmistted packet
*/
//------------------------------------------------------------------------------
static inline tOplkError __packet_xmit_irq_enabled(int pfnXmit_p(struct sk_buff *),
                                                  struct sk_buff *pSkb_p)
{
    netdev_tx_t ret;
    bool enable_irq = irqs_disabled();

    if (enable_irq) local_irq_enable();
    ret = pfnXmit_p(pSkb_p);
    if (enable_irq) local_irq_disable();

    if (ret !=  NETDEV_TX_OK)
    {
        DEBUG_LVL_ERROR_TRACE("%s() xmit returned %d\n", __func__, ret);
        return kErrorInvalidOperation;
    }

    return kErrorOk;
}
static tOplkError packet_queue_xmit(struct sk_buff *skb)
{
    BUILD_BUG_ON(sizeof(skb->queue_mapping) !=
            sizeof(qdisc_skb_cb(skb)->slave_dev_queue_mapping));
    skb_set_queue_mapping(skb, qdisc_skb_cb(skb)->slave_dev_queue_mapping);

    return __packet_xmit_irq_enabled(dev_queue_xmit, skb);
}
static tOplkError packet_direct_xmit(struct sk_buff *skb)
{
    return __packet_xmit_irq_enabled(__packet_direct_xmit, skb);
}
static tOplkError packet_netpoll_xmit(struct sk_buff *skb)
{
#ifdef CONFIG_NETPOLL
    netpoll_send_skb(&edrvInstance_l.np, skb);
#endif
    return kErrorOk;
}



//------------------------------------------------------------------------------
/**
\brief  Allocate Tx buffer

This function allocates a Tx buffer.

\param[in,out]  pBuffer_p           Tx buffer descriptor

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_allocTxBuffer(tEdrvTxBuffer* pBuffer_p)
{
    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    BUG_ON(in_interrupt());
    if (pBuffer_p->maxBufferSize > EDRV_MAX_FRAME_SIZE)
        return kErrorEdrvNoFreeBufEntry;

    /* TODO Maybe we should check that we don't have an ISA device or something
     * else with quirky DMA range limitations?
     * We could use edrvInstance_l.pSlave->dev for that...
     */

    if (use_build_skb)
    {
        pBuffer_p->pBuffer = kzalloc(EDRV_MAX_FRAME_SIZE + EDRV_TAILROOM, GFP_KERNEL);
    }
    else
    {
        struct sk_buff *skb;
        pBuffer_p->pBuffer = NULL;
        skb = alloc_skb(EDRV_MAX_FRAME_SIZE, GFP_KERNEL);
        if (skb)
        {
            pBuffer_p->txBufferNumber.pArg = skb;
            pBuffer_p->pBuffer = skb->data;
        }
    }

    if (!pBuffer_p->pBuffer)
        return kErrorEdrvNoFreeTxDesc;

    pBuffer_p->maxBufferSize = EDRV_MAX_FRAME_SIZE;
    pBuffer_p->is_lock_protected = FALSE;

    return kErrorOk;
}

//------------------------------------------------------------------------------
/**
\brief  Free Tx buffer

This function releases the Tx buffer.

\param[in,out]  pBuffer_p           Tx buffer descriptor

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_freeTxBuffer(tEdrvTxBuffer* pBuffer_p)
{
    ASSERT(pBuffer_p != NULL);
    BUG_ON(in_interrupt());

    if (use_build_skb)
    {
        kfree(pBuffer_p->pBuffer);
    }
    else
    {
        struct sk_buff *skb = pBuffer_p->txBufferNumber.pArg;
        skb->destructor = NULL;
        dev_kfree_skb(skb);
    }
    return kErrorOk;
}

//------------------------------------------------------------------------------
/**
\brief  Change Rx filter setup

This function changes the Rx filter setup. The parameter entryChanged_p
selects the Rx filter entry that shall be changed and \p changeFlags_p determines
the property.
If \p entryChanged_p is equal or larger count_p all Rx filters shall be changed.

\note Rx filters are not supported by this driver!

\param[in,out]  pFilter_p           Base pointer of Rx filter array
\param[in]      count_p             Number of Rx filter array entries
\param[in]      entryChanged_p      Index of Rx filter entry that shall be changed
\param[in]      changeFlags_p       Bit mask that selects the changing Rx filter property

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_changeRxFilter(tEdrvFilter* pFilter_p,
                               UINT count_p,
                               UINT entryChanged_p,
                               UINT changeFlags_p)
{
    UNUSED_PARAMETER(pFilter_p);
    UNUSED_PARAMETER(count_p);
    UNUSED_PARAMETER(entryChanged_p);
    UNUSED_PARAMETER(changeFlags_p);

    return kErrorOk;
}

//------------------------------------------------------------------------------
/**
\brief  Set multicast address entry

This function sets a multicast entry into the Ethernet controller.

\note The multicast filters are not supported by this driver.

\param[in]      pMacAddr_p          Multicast address.

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_setRxMulticastMacAddr(const UINT8* pMacAddr_p)
{
    tOplkError ret;
    rtnl_lock();
    ret = dev_mc_add(edrvInstance_l.pSlave, pMacAddr_p) ? kErrorEdrvInit : kErrorOk;
    rtnl_unlock();
    return ret;
}

//------------------------------------------------------------------------------
/**
\brief  Clear multicast address entry

This function removes the multicast entry from the Ethernet controller.

\note The multicast filters are not supported by this driver.

\param[in]      pMacAddr_p          Multicast address

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_clearRxMulticastMacAddr(const UINT8* pMacAddr_p)
{
    tOplkError ret;
    rtnl_lock();
    ret = dev_mc_del(edrvInstance_l.pSlave, pMacAddr_p) ? kErrorEdrvInit : kErrorOk;
    rtnl_unlock();
    return ret;
}


//============================================================================//
//            P R I V A T E   F U N C T I O N S                               //
//============================================================================//
/// \name Private Functions
/// \{

//------------------------------------------------------------------------------
/**
\brief  Edrv packet handler

This function is the packet handler forwarding the frames to the dllk.

\NOTE function is called in softirq context

\param[in,out]  pSkb_p            Socket Buffer with received packet
*/
//------------------------------------------------------------------------------
static rx_handler_result_t rxPacketHandler(struct sk_buff **pSkb_p)
{
    tEdrvRxBuffer   rxBuffer;
    tEdrvInstance*  pInstance;
    struct sk_buff *skb = *pSkb_p;

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (unlikely(!skb)) {
        DEBUG_LVL_ERROR_TRACE("%s() Allocation failure in skb_share_check\n", __func__);
        return RX_HANDLER_CONSUMED;
    }

    if (skb_linearize(skb)) {
        DEBUG_LVL_ERROR_TRACE("%s() No memory to skb_linearize\n", __func__);
        goto out; /* drop packet */
    }

    *pSkb_p = skb;
    pInstance = rcu_dereference(skb->dev->rx_handler_data);

    // skb->data points is at the network header
    rxBuffer.pBuffer = __skb_push(skb, skb->data - skb_mac_header(skb));
    rxBuffer.rxFrameSize = skb->len;
    rxBuffer.bufferInFrame = kEdrvBufferLastInFrame;

    // Rx handler disables hardirqs, so this is safe to call from softirq context
    if (pInstance->initParam.pfnRxHandler != NULL)
        pInstance->initParam.pfnRxHandler(&rxBuffer);

out:
    consume_skb(skb);
    return RX_HANDLER_CONSUMED;
}

//------------------------------------------------------------------------------
/**
\brief  Edrv transmission completion handler

This function is called as destructor of the socket buffer passed to the driver.
This signals that the packet has been sent out and space can be reclaimed by DLL

\NOTE runs in NET_RX_SOFTIRQ softirq context
      FIXME This will deadlock if the destructor is called further down the call stack,
            from edrv_sendTxBuffer. We need to detect this somewhow and schedule a
            tasklet... Till then use this ugly .is_lock_protected workaround

\param[in,out]  pSkb_p            Socket Buffer with reclaimable transmistted packet
*/
//------------------------------------------------------------------------------
static void txPacketHandler(struct sk_buff *skb)
{
    tEdrvTxBuffer *pTxBuffer = skb_shinfo(skb)->destructor_arg;

    // Tx handler disables hardirqs, so this is safe to call from softirq context
    if (pTxBuffer->pfnTxHandler != NULL) {
        if (!use_netpoll) pTxBuffer->is_lock_protected = TRUE;
        pTxBuffer->pfnTxHandler(pTxBuffer);
        if (!use_netpoll) pTxBuffer->is_lock_protected = FALSE;
    }

    /* Don't reclaim our buffer, we could also bump reference counter... */
    if (use_build_skb)
        skb->head = NULL;
}

//------------------------------------------------------------------------------
/**
\brief  Get Edrv MAC address

This function gets the interface's MAC address. Call with rtnl_lock held

\param[in]      pSlaveDevice_p        Slave net_device
\param[out]     pMacAddr_p          Pointer to store MAC address
*/
//------------------------------------------------------------------------------
static UINT8 getMacAdrs(UINT8* pMacAddr_p, struct net_device *pSlaveDevice_p, UINT8 size_p)
{
    UINT size = min(size_p, pSlaveDevice_p->addr_len);

    OPLK_MEMCPY(pMacAddr_p, pSlaveDevice_p->dev_addr, size);
    return size;
}

static int enslave(struct net_device *pSlaveDevice_p)
{
    int res = 0;

    /* already in-use? */
    if (netdev_is_rx_handler_busy(pSlaveDevice_p)) {
        DEBUG_LVL_ERROR_TRACE("%s() Error: Device %s is in use and cannot be enslaved\n", __func__, pSlaveDevice_p->name);
        return -EBUSY;
    }

    if (pSlaveDevice_p->type != ARPHRD_ETHER) {
        DEBUG_LVL_ERROR_TRACE("%s() Error: uman can only enslave ethernet devices.\n", __func__);
        return -EPERM;
    }


    /* Old ifenslave binaries are no longer supported.  These can
     * be identified with moderate accuracy by the state of the slave:
     * the current ifenslave will set the interface down prior to
     * enslaving it; the old ifenslave will not.
     */
    if (pSlaveDevice_p->flags & IFF_UP) {
        DEBUG_LVL_ERROR_TRACE("%s() Error: %s is up - this may be due to an out of date ifenslave\n", __func__, pSlaveDevice_p->name);
        return -EPERM;
    }

    call_netdevice_notifiers(NETDEV_JOIN, pSlaveDevice_p);


    edrvInstance_l.pSlave = pSlaveDevice_p;

    /* set slave flag before open to prevent IPv6 addrconf */
    pSlaveDevice_p->flags |= IFF_SLAVE;

    /* open the slave since the application closed it */
    res = dev_open(pSlaveDevice_p);
    if (res) {
        DEBUG_LVL_ERROR_TRACE("%s() Error: Opening slave %s failed\n", __func__, pSlaveDevice_p->name);
        goto err_unslave;
    }

    res = netdev_rx_handler_register(pSlaveDevice_p, rxPacketHandler, &edrvInstance_l);
    if (res) {
        DEBUG_LVL_ERROR_TRACE("%s() Error: Error %d calling netdev_rx_handler_register\n", __func__, res);
        goto err_detach;
    }

#if 0
    res = uman_master_upper_dev_link(uman, new_slave);
    if (res) {
        DEBUG_LVL_ERROR_TRACE("%s() Error: Error %d calling bond_master_upper_dev_link\n", __func__, res);
        goto err_unregister;
    }

    uman_set_carrier(uman);
#endif

    DEBUG_LVL_EDRV_TRACE("%s() Enslaving %s interface\n", __func__, pSlaveDevice_p->name);

    return 0;

/* Undo stages on error */
#if 0
err_unregister:
    uman_upper_dev_unlink(uman, new_slave);
#endif
    netdev_rx_handler_unregister(pSlaveDevice_p);

err_detach:
    dev_close(pSlaveDevice_p);

err_unslave:
    pSlaveDevice_p->flags &= ~IFF_SLAVE;
    edrvInstance_l.pSlave = NULL;

    return res;
}

/* Try to release the slave device <slave> from the bond device <master>
 * It is legal to access curr_active_slave without a lock because all the function
 * is RTNL-locked. If "all" is true it means that the function is being called
 * while destroying a bond interface and all slaves are being released.
 *
 * The rules for slave state should be:
 *   for Active/Backup:
 *     Active stays on all backups go down
 *   for Bonded connections:
 *     The first up interface should be left on and all others downed.
 */
static int emancipate(struct net_device *pSlaveDevice_p)
{
    if (!pSlaveDevice_p)
        return 0; /* nothing to do */

    /* slave is not a slave or master is not master of this slave */
    if (!(pSlaveDevice_p->flags & IFF_SLAVE)) {
        DEBUG_LVL_ERROR_TRACE("%s() Error: cannot release %s\n", __func__, pSlaveDevice_p->name);
        return -EINVAL;
    }

#if 0
    slave = uman_slave(uman);
    if (!slave) {
        /* not a slave of this uman */
        DEBUG_LVL_ERROR_TRACE("%s() %s not enslaved\n", __func__, pSlaveDevice_p->name);
        return -EINVAL;
    }

    uman_upper_dev_unlink(uman, slave);
#endif
    /* unregister rx_handler early so uman_handle_frame wouldn't be called
     * for this slave anymore.
     */
    netdev_rx_handler_unregister(pSlaveDevice_p);

    DEBUG_LVL_EDRV_TRACE("%s() Releasing interface %s\n", __func__, pSlaveDevice_p->name);


#if 0
    call_netdevice_notifiers(NETDEV_CHANGEADDR, uman->dev);
    call_netdevice_notifiers(NETDEV_RELEASE, uman->dev);
#endif


    /* Flush bond's hardware addresses from slave */
    dev_uc_flush(pSlaveDevice_p);
    dev_mc_flush(pSlaveDevice_p);

    dev_close(pSlaveDevice_p);

    return 0;
}

//------------------------------------------------------------------------------
// Timer helper functions
//------------------------------------------------------------------------------
#if (EDRV_USE_TTTX != FALSE)
#include <linux/ptp_clock_kernel.h>
//------------------------------------------------------------------------------
/**
\brief  Retrieve current MAC time

The function retrieves the current MAC time.

\param[out]     pCurtime_p          Pointer to store the current MAC time.

\return The function returns a tOplkError error code.
*/
//------------------------------------------------------------------------------
tOplkError edrv_getMacTime(UINT64* pCurtime_p)
{
    struct ptp_clock_info *ptp /* get this somehow */;
    struct timespec64 ts;

    if (pCurtime_p == NULL)
        return kErrorNoResource;

    if (ptp->gettime64(ptp, &ts))
        return kErrorNoResource;

    *pCurtime_p = ts.tv_sec * SEC_TO_NSEC + ts.tv_nsec;
    return kErrorOk;
}
#endif



/// \}
