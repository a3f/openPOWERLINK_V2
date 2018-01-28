/**
********************************************************************************
\file   edrv-bond_linux.c

\brief  Implementation of Linux OPLK-conformant 'bridge' driver

Uses the same API used by the bridge, bonding et al. drivers to claim a single
interface, which is then used exclusively for openPOWERLINK communication.

\bug FIXME currently needs network namespace configuration, so user processes
           don't access the slave interface. Can exclusion be realized here?
           e.g. with dev_change_net_namespace

\ingroup module_edrv
*******************************************************************************/

/*------------------------------------------------------------------------------
Copyright (c) 2017, Ahmad Fatoum <ahmad[AT]a3f.at>
Copyright (c) 2016, Bernecker+Rainer Industrie-Elektronik Ges.m.b.H. (B&R)
Copyright (c) 2013, Kalycito Infotech Private Limited
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holders nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDERS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
------------------------------------------------------------------------------*/

//------------------------------------------------------------------------------
// includes
//------------------------------------------------------------------------------
#include <common/oplkinc.h>
#include <common/ftracedebug.h>
#include <common/bufalloc.h>
#include <kernel/edrv.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/rtnetlink.h>

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <asm/system.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <net/sch_generic.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>


//============================================================================//
//            G L O B A L   D E F I N I T I O N S                             //
//============================================================================//

#ifndef TRACE
#define TRACE printk
#endif

#ifndef EDRV_MAX_TX_BUFFERS
#define EDRV_MAX_TX_BUFFERS      256             // Max no of Buffers
#endif
#define EDRV_MAX_FRAME_SIZE     0x0600
#define TXBUF_HEADROOM (NET_SKB_PAD + NET_IP_ALIGN)
#define EDRV_MAX_SKB_DATA_SIZE (SKB_DATA_ALIGN(TXBUF_HEADROOM + EDRV_MAX_FRAME_SIZE) + \
                                SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#define EDRV_TX_BUFFER_SIZE (EDRV_MAX_SKB_DATA_SIZE * EDRV_MAX_TX_BUFFERS)

//------------------------------------------------------------------------------
// const defines
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// module global vars
//------------------------------------------------------------------------------

static char *slave_interface; /* TODO */
module_param(slave_interface, charp, 0);
MODULE_PARM_DESC(slave_interface, "Slave interface to claim");

/*  __dev_queue_xmit says When calling this method, interrupts MUST be enabled.
 *  So we don't really have any choice... FIXME
 *  Replace with a use_netpoll option?
 */
int qdisc_enabled = 0;
module_param(qdisc_enabled, int, 0);
MODULE_PARM_DESC(qdisc_enabled, "Qdisc, 0 = disabled (default), 1 = enabled");

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
    BOOL                afTxBufUsed[EDRV_MAX_TX_BUFFERS];   ///< Array indicating the use of a specific TX buffer
    UINT8*              pTxBuf;                             ///< Pointer to the TX buffer	
    struct net_device  *pSlave;
} tEdrvInstance;

//------------------------------------------------------------------------------
// local vars
//------------------------------------------------------------------------------
static tEdrvInstance edrvInstance_l;
static tBufAlloc* pBufAlloc_l = NULL;
static int (*packet_xmit)(struct sk_buff *skb) = dev_queue_xmit;

//------------------------------------------------------------------------------
// local function prototypes
//------------------------------------------------------------------------------
static rx_handler_result_t rxPacketHandler(struct sk_buff **pSkb_p);
static int enslave(struct net_device *pSlaveDevice_p);
static int emancipate(struct net_device *pSlaveDevice_p);
static UINT8 getMacAdrs(UINT8* pMacAddr_p, struct net_device *pSlaveDevice_p, UINT8 size_p);
static BOOL     getLinkStatus(struct net_device *pSlaveDevice_p);
static int packet_direct_xmit(struct sk_buff *skb);


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
    int i;
    tOplkError ret = kErrorEdrvInit;
    struct net_device *pSlaveDevice;
    tBufData        bufData;

    // Check parameter validity
    ASSERT(pEdrvInitParam_p != NULL);

    // clear instance structure
    OPLK_MEMSET(&edrvInstance_l, 0, sizeof(edrvInstance_l));

    // save the init data
    edrvInstance_l.initParam = *pEdrvInitParam_p;

    DEBUG_LVL_EDRV_TRACE("%s() starting up...\n", __func__);

    edrvInstance_l.initParam.hwParam.pDevName = slave_interface;
    if (!slave_interface || !*slave_interface) {
        DEBUG_LVL_ERROR_TRACE("%s() wasn't supplied a slave interface as kernel module parameter\n", __func__);
        return kErrorEdrvInit;
    }

    if (qdisc_enabled)
        packet_xmit = packet_direct_xmit;

    // init and fill buffer allocation instance
    if ((pBufAlloc_l = bufalloc_init(EDRV_MAX_TX_BUFFERS)) == NULL)
    {
        DEBUG_LVL_ERROR_TRACE("%s() bufalloc_init failed\n", __func__);
        return kErrorNoResource;
    }

    // allocate tx-buffers (TODO we could use dma_alloc_coherent too...)	
    edrvInstance_l.pTxBuf = kmalloc(EDRV_TX_BUFFER_SIZE, GFP_KERNEL); // FIXME use GFP_USER?	
    if (edrvInstance_l.pTxBuf == NULL)	
    {	
        DEBUG_LVL_ERROR_TRACE("%s() kmalloc for %u bytes failed\n", __func__, EDRV_TX_BUFFER_SIZE);	
        return kErrorNoResource;	
    }	
	
    for (i = 0; i < EDRV_MAX_TX_BUFFERS; i++)
    {
        bufData.bufferNumber = i;
        bufData.pBuffer = edrvInstance_l.pTxBuf + (i * EDRV_MAX_SKB_DATA_SIZE);	

        bufalloc_addBuffer(pBufAlloc_l, &bufData);
    }

    rtnl_lock();

    pSlaveDevice = __dev_get_by_name(current->nsproxy->net_ns, slave_interface);

    if (!pSlaveDevice) {
        DEBUG_LVL_ERROR_TRACE("%s() was supplied an invalid slave interface name: %s\n", __func__, pSlaveDevice->name);
        goto unlock;
    }

    if (enslave(pSlaveDevice) != 0) {
        goto unlock;
    }

    /* if no MAC address was specified read MAC address of used
     * Ethernet interface
     */
    if (!is_zero_ether_addr(edrvInstance_l.initParam.aMacAddr))
    {   // write MAC address to controller
        int res;
        struct sockaddr addr;
        memcpy(addr.sa_data, edrvInstance_l.initParam.aMacAddr, ETH_ALEN);
        addr.sa_family = pSlaveDevice->type;
        res = dev_set_mac_address(pSlaveDevice, &addr);
        if (res) {
            DEBUG_LVL_ERROR_TRACE("%s() Error %d setting mac address to %pM\n",
                    __func__, res, edrvInstance_l.initParam.aMacAddr);
            goto unlock;
        }
        DEBUG_LVL_EDRV_TRACE("%s() %s's MAC address was set to %pM\n", __func__, pSlaveDevice->name, edrvInstance_l.initParam.aMacAddr);
    }
    else
    {   // read MAC address from controller
        UINT8 bytes = getMacAdrs(edrvInstance_l.initParam.aMacAddr, pSlaveDevice, ETH_ALEN);
        if (bytes == 0) { /* generate a new mac address */
            eth_hw_addr_random(pSlaveDevice);
            DEBUG_LVL_EDRV_TRACE("%s() Generating random hardware address for %s\n", __func__, pSlaveDevice->name);
        } else if (bytes != ETH_ALEN) {
            DEBUG_LVL_ERROR_TRACE("%s() %s doesn't have a 6 byte hardware address\n", __func__, pSlaveDevice->name);
            goto unlock;
        }
    }

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
    // End the pcap loop and wait for the worker thread to terminate
    rtnl_lock();
    emancipate(edrvInstance_l.pSlave);
    rtnl_unlock();

    // Clear instance structure
    bufalloc_exit(pBufAlloc_l);
    pBufAlloc_l = NULL;
    kfree(edrvInstance_l.pTxBuf);
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

\bug XXX Now that I am calling the Tx handler in here, is this function supposed
         to be reentrant?
\note    This is called in interrupt context

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_sendTxBuffer(tEdrvTxBuffer* pBuffer_p)
{
    netdev_tx_t     ret;
    UINT            bufferNumber;

    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    bufferNumber = pBuffer_p->txBufferNumber.value;

    BUG_ON(pBuffer_p->is_lock_protected); /* XXX we aren't reentrant */

    if (pBuffer_p->txBufferNumber.value >= EDRV_MAX_TX_BUFFERS ||
        edrvInstance_l.afTxBufUsed[bufferNumber] == FALSE)
    {
        return kErrorInvalidOperation;
    }

    /* FIXME this could be optimized by using netdev notification listener. Is that worth it? */
    if (getLinkStatus(edrvInstance_l.pSlave))
    {
        /* build a socket buffer */
        struct sk_buff *skb;
        skb = build_skb(pBuffer_p->pBuffer - TXBUF_HEADROOM, 0);
        if (!skb) {
            DEBUG_LVL_ERROR_TRACE("%s() build_skb returned %d\n",
                                __func__, PTR_ERR(skb));
            return kErrorEdrvNoFreeTxDesc;
        }



        // build a socket buffer
        skb_reserve(skb, TXBUF_HEADROOM);
        skb_put(skb, pBuffer_p->txFrameSize);
        skb->dev = edrvInstance_l.pSlave;
        skb_reset_network_header(skb); /* silences protocol 0000 is buggy WARNs */

        BUILD_BUG_ON(sizeof(skb->queue_mapping) !=
                 sizeof(qdisc_skb_cb(skb)->slave_dev_queue_mapping));
        skb_set_queue_mapping(skb, qdisc_skb_cb(skb)->slave_dev_queue_mapping);

        skb->cloned = 1; /* Inform the network driver not to free the skb->data */
      	atomic_inc(&(skb_shinfo(skb)->dataref));

        ret = packet_xmit(skb);

        if (ret != NETDEV_TX_OK)
        {
            DEBUG_LVL_ERROR_TRACE("%s() dev_queue_xmit returned %d\n",
                                 __func__, ret);
            return kErrorInvalidOperation;
        }
    } else {
        /* there's no link! We pretend that packet is sent and immediately call
         * tx handler! Otherwise the stack would hang! */
        DEBUG_LVL_EDRV_TRACE("%s() slave link is down!\n", __func__);
    }

    /* FIXME: _actual_ transmission confirmation? e.g. via timestaping */
    if (pBuffer_p->pfnTxHandler != NULL)
    {
        pBuffer_p->is_lock_protected = TRUE;
        pBuffer_p->pfnTxHandler(pBuffer_p);
        pBuffer_p->is_lock_protected = FALSE;
    }

    return kErrorOk;
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

	if (ops->ndo_select_queue) {
		queue_index = ops->ndo_select_queue(dev, skb, NULL,
						    __packet_pick_tx_queue);
		queue_index = netdev_cap_txqueue(dev, queue_index);
	} else {
		queue_index = __packet_pick_tx_queue(dev, skb);
	}

	skb_set_queue_mapping(skb, queue_index);
}
static int packet_direct_xmit(struct sk_buff *skb)
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
\brief  Allocate Tx buffer

This function allocates a Tx buffer.

\param[in,out]  pBuffer_p           Tx buffer descriptor

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_allocTxBuffer(tEdrvTxBuffer* pBuffer_p)
{
    tOplkError          ret = kErrorOk;
    tBufData            bufData;

    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    if (pBuffer_p->maxBufferSize > EDRV_MAX_FRAME_SIZE)
    {
        ret = kErrorEdrvNoFreeBufEntry;
        goto Exit;
    }

    // get a free Tx buffer from the allocation instance
    ret = bufalloc_getBuffer(pBufAlloc_l, &bufData);
    if (ret != kErrorOk)
    {
        ret = kErrorEdrvNoFreeBufEntry;
        goto Exit;
    }

    pBuffer_p->pBuffer = bufData.pBuffer + TXBUF_HEADROOM;
    pBuffer_p->txBufferNumber.value = bufData.bufferNumber;
    pBuffer_p->maxBufferSize = EDRV_MAX_FRAME_SIZE;
    pBuffer_p->is_lock_protected = FALSE;
    edrvInstance_l.afTxBufUsed[bufData.bufferNumber] = TRUE;

Exit:
    return ret;
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
    tOplkError  ret;
    tBufData    bufData;

    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    bufData.pBuffer = pBuffer_p->pBuffer - TXBUF_HEADROOM;
    bufData.bufferNumber = pBuffer_p->txBufferNumber.value;

    edrvInstance_l.afTxBufUsed[pBuffer_p->txBufferNumber.value] = FALSE;
    ret = bufalloc_releaseBuffer(pBufAlloc_l, &bufData);

    return ret;
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
    UNUSED_PARAMETER(pMacAddr_p);

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
    UNUSED_PARAMETER(pMacAddr_p);

    return kErrorOk;
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

\param[in,out]  pParam_p            User specific pointer pointing to the instance structure
\param[in]      pHeader_p           Packet header information (e.g. size)
\param[in]      pPktData_p          Packet buffer
*/
//------------------------------------------------------------------------------
static rx_handler_result_t rxPacketHandler(struct sk_buff **pSkb_p)
{
    tEdrvRxBuffer   rxBuffer;
    tEdrvInstance*  pInstance;
    struct sk_buff *skb = *pSkb_p;

    skb = skb_share_check(skb, GFP_ATOMIC);
    if (unlikely(!skb))
        return RX_HANDLER_CONSUMED;

    if (skb_linearize(skb))
        goto out; /* drop packet */

    *pSkb_p = skb;
    pInstance = rcu_dereference(skb->dev->rx_handler_data);

    rxBuffer.bufferInFrame = kEdrvBufferLastInFrame;
    rxBuffer.rxFrameSize = skb->len;
    rxBuffer.pBuffer = skb->data;

    if (edrvInstance_l.initParam.pfnRxHandler != NULL)
    {
        unsigned long flags;
        /* We're running in softirq context. If we enter the stack through the Rx handler,
         * claim the lock and get preempted by the timer ISR, which also tries to enter
         * the stack for cyclic Tx, we will deadlock. Therefore disable IRQs.
         * TODO can't we just do disable/enable?
         * TODO couldn't we just mask the timer IRQ?
         * TODO couldn't we just replace the locking with one that disables interrupts?
         *      pros/cons? Look where locking happens and decide
         */
        local_irq_save(flags);
        pInstance->initParam.pfnRxHandler(&rxBuffer);
        local_irq_restore(flags);
    }

out:
    consume_skb(skb);
    return RX_HANDLER_CONSUMED;
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

//------------------------------------------------------------------------------
/**
\brief  Get link status

This function returns the interface link status.

\param[in]      pSlaveDevice_p        Slave net_device

\return The function returns the link status.
\retval TRUE    The link is up.
\retval FALSE   The link is down.
*/
//------------------------------------------------------------------------------
static BOOL getLinkStatus(struct net_device * pSlaveDevice_p)
{
    return netif_carrier_ok(pSlaveDevice_p);
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

    pSlaveDevice_p->priv_flags |= IFF_BONDING;

    /* set promiscuity level to new slave */

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
    pSlaveDevice_p->priv_flags &= ~IFF_BONDING;
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

    dev_close(pSlaveDevice_p);

    pSlaveDevice_p->priv_flags &= ~IFF_BONDING;

    return 0;
}


/// \}
