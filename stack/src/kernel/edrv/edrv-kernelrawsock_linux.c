/**
********************************************************************************
\file   edrv-kernelrawsock_linux.c

\brief  Implementation of Linux kernel-side raw socket Ethernet driver

This file is based on the Linux pcap Ethernet driver, with the difference that
instead of leveraging pcap in userspace, the raw socket is used in kernelspace.
(Just out of curiousity about how it affects jitter, if at all).

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
#include <kernel/edrv.h>

#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/nsproxy.h>
#include <linux/if_ether.h>
#include <uapi/linux/if.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/uio.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h>
#endif

//============================================================================//
//            G L O B A L   D E F I N I T I O N S                             //
//============================================================================//

//------------------------------------------------------------------------------
// const defines
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// module global vars
//------------------------------------------------------------------------------

static char *slave_interface; /* TODO */
module_param(slave_interface, charp, 0);
MODULE_PARM_DESC(slave_interface, "Slave interface to claim");

int qdisc_enabled = 1;
module_param(qdisc_enabled, int, 0);
MODULE_PARM_DESC(qdisc_enabled, "Qdisc, 0 = disabled, 1 = enabled (default)");

//------------------------------------------------------------------------------
// global function prototypes
//------------------------------------------------------------------------------

//============================================================================//
//            P R I V A T E   D E F I N I T I O N S                           //
//============================================================================//

//------------------------------------------------------------------------------
// const defines
//------------------------------------------------------------------------------
#define EDRV_MAX_FRAME_SIZE     0x0600
#ifndef TRACE
#define TRACE printk
#endif

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
    int                 ifIndex;                            ///< Interface index
    tEdrvTxBuffer*      pTransmittedTxBufferLastEntry;      ///< Pointer to the last entry of the transmitted TX buffer
    tEdrvTxBuffer*      pTransmittedTxBufferFirstEntry;     ///< Pointer to the first entry of the transmitted Tx buffer
    struct mutex        mutex;                              ///< Mutex for locking of critical sections
    struct completion   syncStart;                          ///< Completion for signaling the start of the worker thread
    struct socket*      pTxSocket;                          ///< Tx socket
    struct task_struct *pThread;                            ///< Handle of the worker thread
    struct net_device  *pDev;                            ///< Handle of the worker thread
} tEdrvInstance;

//------------------------------------------------------------------------------
// local vars
//------------------------------------------------------------------------------
static tEdrvInstance edrvInstance_l;

//------------------------------------------------------------------------------
// local function prototypes
//------------------------------------------------------------------------------
static void           packetHandler(tEdrvInstance *pInstance, u8* pPktData_p, size_t dataLen_p);
static int            workerThread(void* pArgument_p);
static int            getMacAdrs(struct net_device *pDev_p, UINT8* pMacAddr_p, int *pIfIndex_p);
static struct socket *startSocket(int ifIndex_p);
static BOOL           getLinkStatus(struct net_device *pDev_p);

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
    int err;
    // Check parameter validity
    ASSERT(pEdrvInitParam_p != NULL);

    // clear instance structure
    OPLK_MEMSET(&edrvInstance_l, 0, sizeof(edrvInstance_l));

    // save the init data
    edrvInstance_l.initParam = *pEdrvInitParam_p;

    edrvInstance_l.initParam.hwParam.pDevName = slave_interface;
    if (!slave_interface || !*slave_interface) {
        DEBUG_LVL_ERROR_TRACE("%s() wasn't supplied a slave interface as kernel module parameter\n", __func__);
        return kErrorEdrvInit;
    }

    dev_load(current->nsproxy->net_ns, slave_interface);
    edrvInstance_l.pDev = dev_get_by_name(current->nsproxy->net_ns, slave_interface);
    if (!edrvInstance_l.pDev)
    {
        DEBUG_LVL_ERROR_TRACE("%s() Error!! Can't find driver for interface %s\n", __func__, slave_interface);
        return kErrorEdrvInit;
    }

    /* if no MAC address was specified read MAC address of used
     * Ethernet interface
     */
    if ((edrvInstance_l.initParam.aMacAddr[0] == 0) &&
        (edrvInstance_l.initParam.aMacAddr[1] == 0) &&
        (edrvInstance_l.initParam.aMacAddr[2] == 0) &&
        (edrvInstance_l.initParam.aMacAddr[3] == 0) &&
        (edrvInstance_l.initParam.aMacAddr[4] == 0) &&
        (edrvInstance_l.initParam.aMacAddr[5] == 0))
    {   // read MAC address from controller
        err = getMacAdrs(edrvInstance_l.pDev,
                   edrvInstance_l.initParam.aMacAddr, &edrvInstance_l.ifIndex);
        if (err)
        {
            return kErrorEdrvInit;
        }
    }

    edrvInstance_l.pTxSocket = startSocket(edrvInstance_l.ifIndex);
    if (edrvInstance_l.pTxSocket == NULL)
    {
        return kErrorEdrvInit;
    }

    if (qdisc_enabled == 1) {
        err = kernel_setsockopt(edrvInstance_l.pTxSocket, SOL_PACKET, PACKET_QDISC_BYPASS, (char*)&qdisc_enabled, sizeof qdisc_enabled);
        if (err < 0)
            DEBUG_LVL_EDRV_TRACE("%s() Couldn't configure PACKET_QDISC_BYPASS on Tx: reason %d\n", __func__, err);
    }


    mutex_init(&edrvInstance_l.mutex);

    init_completion(&edrvInstance_l.syncStart);

    if (IS_ERR(edrvInstance_l.pThread = kthread_run(workerThread, &edrvInstance_l, "oplk-edrvrawsock")))
    {
        DEBUG_LVL_ERROR_TRACE("%s() Couldn't create worker thread!\n", __func__);
        return kErrorEdrvInit;
    }

#if 0 /* TODO necessary ? */
    schedParam.sched_priority = CONFIG_THREAD_PRIORITY_MEDIUM;
    if (pthread_setschedparam(edrvInstance_l.hThread, SCHED_FIFO, &schedParam) != 0)
    {
        DEBUG_LVL_ERROR_TRACE("%s() couldn't set thread scheduling parameters!\n", __func__);
    }
#endif

    /* wait until thread is started */
    wait_for_completion(&edrvInstance_l.syncStart);

    return kErrorOk;
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
    // End the packet capture loop and wait for the worker thread to terminate
    kthread_stop(edrvInstance_l.pThread);

    kernel_sock_shutdown(edrvInstance_l.pTxSocket, SHUT_RDWR);
    sock_release(edrvInstance_l.pTxSocket);

    // Destroy the mutex
    mutex_destroy(&edrvInstance_l.mutex);

    dev_put(edrvInstance_l.pDev);

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

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_sendTxBuffer(tEdrvTxBuffer* pBuffer_p)
{
    int         bytesSent;

    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    if (pBuffer_p->txBufferNumber.pArg != NULL)
        return kErrorInvalidOperation;

    if (getLinkStatus(edrvInstance_l.pDev) == FALSE)
    {
        /* there's no link! We pretend that packet is sent and immediately call
         * tx handler! Otherwise the stack would hang! */
        if (pBuffer_p->pfnTxHandler != NULL)
        {
            pBuffer_p->is_lock_protected = TRUE;
            pBuffer_p->pfnTxHandler(pBuffer_p);
            pBuffer_p->is_lock_protected = FALSE;
        }
    }
    else
    {
        struct kvec iov;
        struct msghdr msg = {};

        iov.iov_base = pBuffer_p->pBuffer;
        iov.iov_len = pBuffer_p->txFrameSize;

        mutex_lock(&edrvInstance_l.mutex);
        if (edrvInstance_l.pTransmittedTxBufferLastEntry == NULL)
        {
            edrvInstance_l.pTransmittedTxBufferLastEntry =
                edrvInstance_l.pTransmittedTxBufferFirstEntry = pBuffer_p;
        }
        else
        {
            edrvInstance_l.pTransmittedTxBufferLastEntry->txBufferNumber.pArg = pBuffer_p;
            edrvInstance_l.pTransmittedTxBufferLastEntry = pBuffer_p;
        }
        mutex_unlock(&edrvInstance_l.mutex);

        bytesSent = kernel_sendmsg(edrvInstance_l.pTxSocket, &msg, &iov, 1, pBuffer_p->txFrameSize);

        if (unlikely(bytesSent != pBuffer_p->txFrameSize))
        {
            DEBUG_LVL_EDRV_TRACE("%s() kernel_sendmsg returned %d instead of %zu\n",
                                 __func__, bytesSent, pBuffer_p->txFrameSize);
            return kErrorInvalidOperation;
        }
    }

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

    if (pBuffer_p->maxBufferSize > EDRV_MAX_FRAME_SIZE)
        return kErrorEdrvNoFreeBufEntry;

    // allocate buffer with malloc
    pBuffer_p->pBuffer = (UINT8*)OPLK_MALLOC(pBuffer_p->maxBufferSize);
    if (pBuffer_p->pBuffer == NULL)
        return kErrorEdrvNoFreeBufEntry;

    pBuffer_p->txBufferNumber.pArg = NULL;

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
    UINT8* pBuffer;

    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    pBuffer = pBuffer_p->pBuffer;

    // mark buffer as free, before actually freeing it
    pBuffer_p->pBuffer = NULL;

    OPLK_FREE(pBuffer);

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

\param[in,out]  pInstance           User specific pointer pointing to the instance structure
\param[in]      pPktData_p          Packet buffer
*/
//------------------------------------------------------------------------------
static void packetHandler(tEdrvInstance *pInstance, u8* pPktData_p, size_t dataLen_p)
{
    tEdrvRxBuffer   rxBuffer;

    if (OPLK_MEMCMP(pPktData_p + 6, pInstance->initParam.aMacAddr, 6) != 0)
    {   // filter out self generated traffic
        rxBuffer.bufferInFrame = kEdrvBufferLastInFrame;
        rxBuffer.rxFrameSize = dataLen_p;
        rxBuffer.pBuffer = pPktData_p;

        if (edrvInstance_l.initParam.pfnRxHandler != NULL)
        {
            pInstance->initParam.pfnRxHandler(&rxBuffer);
        }
    }
    else
    {   // self generated traffic

        if (pInstance->pTransmittedTxBufferFirstEntry != NULL)
        {
            tEdrvTxBuffer* pTxBuffer = pInstance->pTransmittedTxBufferFirstEntry;

            if (pTxBuffer->pBuffer != NULL)
            {
                if (OPLK_MEMCMP(pPktData_p, pTxBuffer->pBuffer, 6) == 0)
                {
                    mutex_lock(&pInstance->mutex);
                    pInstance->pTransmittedTxBufferFirstEntry = (tEdrvTxBuffer*)pInstance->pTransmittedTxBufferFirstEntry->txBufferNumber.pArg;
                    if (pInstance->pTransmittedTxBufferFirstEntry == NULL)
                    {
                        pInstance->pTransmittedTxBufferLastEntry = NULL;
                    }
                    mutex_unlock(&pInstance->mutex);

                    pTxBuffer->txBufferNumber.pArg = NULL;

                    if (pTxBuffer->pfnTxHandler != NULL)
                    {
                        pTxBuffer->pfnTxHandler(pTxBuffer);
                    }
                }
                else
                {
                    TRACE("%s: no matching TxB: DstMAC=%02X%02X%02X%02X%02X%02X\n",
                          __func__,
                          (UINT)pPktData_p[0],
                          (UINT)pPktData_p[1],
                          (UINT)pPktData_p[2],
                          (UINT)pPktData_p[3],
                          (UINT)pPktData_p[4],
                          (UINT)pPktData_p[5]);
                    TRACE("   current TxB %p: DstMAC=%02X%02X%02X%02X%02X%02X\n",
                          (void*)pTxBuffer,
                          (UINT)pTxBuffer->pBuffer[0],
                          (UINT)pTxBuffer->pBuffer[1],
                          (UINT)pTxBuffer->pBuffer[2],
                          (UINT)pTxBuffer->pBuffer[3],
                          (UINT)pTxBuffer->pBuffer[4],
                          (UINT)pTxBuffer->pBuffer[5]);
                }
            }
        }
        else
        {
            TRACE("%s: no TxB: DstMAC=%02X%02X%02X%02X%02X%02X\n", __func__,
                  pPktData_p[0],
                  pPktData_p[1],
                  pPktData_p[2],
                  pPktData_p[3],
                  pPktData_p[4],
                  pPktData_p[5]);
        }
    }
}

//------------------------------------------------------------------------------
/**
\brief  Edrv worker thread

This function implements the edrv worker thread. It is responsible to handle
socket events.

\param[in,out]  pArgument_p         User specific pointer pointing to the instance structure

\return The function returns a thread error code.
*/
//------------------------------------------------------------------------------
static int workerThread(void* pArgument_p)
{
    tEdrvInstance*  pInstance = (tEdrvInstance*)pArgument_p;
    struct socket  *pRxSocket;
    int             numBytes = 1;
    struct kvec     iov;

    DEBUG_LVL_EDRV_TRACE("%s(): ThreadId:%ld\n", __func__, syscall(SYS_gettid));

    allow_signal(SIGTERM);

    // Set up and activate the socket for live capture
    pRxSocket = startSocket(pInstance->ifIndex);
    if (pRxSocket == NULL)
    {
        return -1;
    }

    iov.iov_len = EDRV_MAX_FRAME_SIZE;
    iov.iov_base = kmalloc(iov.iov_len, GFP_KERNEL);

   // signal that thread is successfully started
   complete(&pInstance->syncStart);

    while (!kthread_should_stop()) {
        struct msghdr msg = {};
        numBytes = kernel_recvmsg(pRxSocket, &msg, &iov, 1, iov.iov_len, msg.msg_flags);
        if (numBytes <= 0) {
           break;
        }

        packetHandler(pInstance, iov.iov_base, iov.iov_len);
   }

   kfree(iov.iov_base);

   if (signal_pending(current) == SIGTERM)
       DEBUG_LVL_ERROR_TRACE("%s(): was cancelled normally.\n", __func__);
   else if (numBytes == 0)
       DEBUG_LVL_ERROR_TRACE("%s(): ended because peer shutdown socket.\n", __func__);
   else if (numBytes > 0)
       DEBUG_LVL_ERROR_TRACE("%s(): experienced an incomplete read: %d\n", __func__, numBytes);
   else
       DEBUG_LVL_ERROR_TRACE("%s(): ended because of an error: %d\n", __func__, numBytes);

   sock_release(pRxSocket);

   return 0;
}

//------------------------------------------------------------------------------
/**
\brief  Start socket

This function configures the parameter for a socket and activates it.

\return The function returns a pointer to a struct socket.
*/
//------------------------------------------------------------------------------
static struct socket *startSocket(int ifIndex_p)
{
    int                 err;
    struct sockaddr_ll  sll;
    struct socket      *sock;
    struct packet_mreq  mr  = {};


    err = sock_create_kern(current->nsproxy->net_ns, PF_PACKET, SOCK_RAW, htons(ETH_P_ALL), &sock);
    if (err)
    {
        DEBUG_LVL_ERROR_TRACE("%s() Error!! Can't open raw socket: %d\n", __func__, err);
        return NULL;
    }

    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifIndex_p;
    sll.sll_protocol = htons(ETH_P_ALL);

    err = kernel_bind(sock, (struct sockaddr *)&sll, sizeof(sll));
    if(err < 0)
    {
        sock_release(sock);
        DEBUG_LVL_ERROR_TRACE("%s() Error!! Can't bind raw sock to interface: %d\n", __func__, err);
        return NULL;
    }

    // Set promiscuous mode
    mr.mr_ifindex = ifIndex_p;
    mr.mr_type    = PACKET_MR_PROMISC;
    err = kernel_setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void*)&mr, sizeof mr);
    if (err < 0)
    {
        sock_release(sock);
        DEBUG_LVL_ERROR_TRACE("%s() couldn't set promiscious mode\n", __func__);
        return NULL;
    }

    return sock;
}

//------------------------------------------------------------------------------
/**
\brief  Get Edrv MAC address

This function gets the interface's MAC address.

\param[in]      pDev_p              Pointer to net_device
\param[out]     pMacAddr_p          Pointer to store MAC address
\param[out]     pIfIndex_p          Pointer to store interface index
*/
//------------------------------------------------------------------------------
static int getMacAdrs(struct net_device *pDev_p, UINT8* pMacAddr_p, int *pIfIndex_p)
{
    int                err = 0;

    rcu_read_lock();

    if (pDev_p->addr_len == ETH_ALEN)
    {
        /* we can't use kernel_sock_ioctl,
         * because SIOCGIFHWADDR isn't handled by sock->ops->ioctl */
        OPLK_MEMCPY(pMacAddr_p, pDev_p->dev_addr, ETH_ALEN);
        *pIfIndex_p = pDev_p->ifindex;
    }
    else
    {
        DEBUG_LVL_ERROR_TRACE("%s() Error!! Interface %s hardware address has %u bytes but 6 expected\n", __func__, pDev_p->name, pDev_p->addr_len);
        err = -EIO;
    }

    rcu_read_unlock();
    return err;
}

//------------------------------------------------------------------------------
/**
\brief  Get link status

This function returns the interface link status.

\param[in]      pIfName_p           Ethernet interface device name

\return The function returns the link status.
\retval TRUE    The link is up.
\retval FALSE   The link is down.
*/
//------------------------------------------------------------------------------
static BOOL getLinkStatus(struct net_device* pDev_p)
{
    BOOL fRunning;
    rcu_read_lock();

    if (dev_get_flags(pDev_p) & IFF_RUNNING)
    {
        fRunning = TRUE;
    }
    else
    {
        fRunning = FALSE;
    }

    rcu_read_unlock();
    return fRunning;
}

/// \}
