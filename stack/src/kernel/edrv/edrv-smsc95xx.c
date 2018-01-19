/**
********************************************************************************
\file   edrv-smsc95xx.c

\brief  Implementation of Ethernet driver for smsc95xx

This file contains an implementation of the Ethernet driver for
smsc95xx available on the Raspberry Pi B.

It's based on following drivers:
* U-Boot smsc95xx driver
* XinuOS SMSC9512 annotated register definitions, itself based on the
* Linux SMSC95xx driver


\ingroup module_edrv
*******************************************************************************/

/*------------------------------------------------------------------------------
Copyright (c) 2017, Ahmad Fatoum <ahmad[AT]a3f.at>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as included in
the Linux' kernel's top level COPYING file, available at
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/COPYING

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
------------------------------------------------------------------------------*/

/*
 * Copyright (c) 2008, Douglas Comer and Dennis Brylow
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted for use in any lawful way, provided that
 * the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the names of the authors nor their contributors may be
 *       used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHORS AND CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2011 The Chromium OS Authors.
 * Copyright (C) 2009 NVIDIA, Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

 /***************************************************************************
 *
 * Copyright (C) 2007-2008 SMSC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *****************************************************************************/


//------------------------------------------------------------------------------
// includes
//------------------------------------------------------------------------------
#include <common/oplkinc.h>
#include <common/bufalloc.h>
#include <kernel/edrv.h>
#include <linux/usb.h>
#include <linux/of_net.h>
#include <linux/etherdevice.h>
#include <linux/hrtimer.h>

//============================================================================//
//            G L O B A L   D E F I N I T I O N S                             //
//============================================================================//

//------------------------------------------------------------------------------
// const defines
//------------------------------------------------------------------------------
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 47))
/* TODO loosen this if tested working with older versions */
#error "Linux Kernel versions older than 4.9.47 are not supported by this driver!"
#endif

#ifndef TRACE
#define TRACE printk
#endif
#undef DEBUG_LVL_EDRV_TRACE
#define DEBUG_LVL_EDRV_TRACE printk

//------------------------------------------------------------------------------
// module global vars
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// global function prototypes
//------------------------------------------------------------------------------

//============================================================================//
//            P R I V A T E   D E F I N I T I O N S                           //
//============================================================================//

//------------------------------------------------------------------------------
// const defines {
//------------------------------------------------------------------------------
#define DRV_NAME                    "plk"

#ifndef EDRV_MAX_TX_BUFFERS
#define EDRV_MAX_TX_BUFFERS         256
#endif

#ifndef EDRV_MAX_TX_DESCS
#define EDRV_MAX_TX_DESCS           16
#define EDRV_TX_DESC_MASK           (EDRV_MAX_TX_DESCS - 1)
#endif

#ifndef EDRV_MAX_RX_BUFFERS
#define EDRV_MAX_RX_BUFFERS         256
#endif

#ifndef EDRV_MAX_RX_DESCS
#define EDRV_MAX_RX_DESCS           16
#define EDRV_RX_DESC_MASK           (EDRV_MAX_RX_DESCS - 1)
#endif

#define EDRV_MAX_FRAME_SIZE         2048

#define USB_CTRL_SET_TIMEOUT 5000
#define USB_CTRL_GET_TIMEOUT 5000
#define USB_BULK_SEND_TIMEOUT 5000
#define USB_BULK_RECV_TIMEOUT 5000
#define PHY_CONNECT_TIMEOUT 5000


#define HS_USB_PKT_SIZE            512
#define FS_USB_PKT_SIZE            64
#define DEFAULT_HS_BURST_CAP_SIZE    (16 * 1024 + 5 * HS_USB_PKT_SIZE)
#define DEFAULT_FS_BURST_CAP_SIZE    (6 * 1024 + 33 * FS_USB_PKT_SIZE)
#define DEFAULT_BULK_IN_DELAY        0x00002000
#define AX_RX_URB_SIZE 2048



/** idVendor in the USB device descriptor for this device */
#define SMSC9512_VENDOR_ID  0x0424

/** idProduct in the USB device descriptor for this device */
#define SMSC9512_PRODUCT_ID 0xEC00

#define SMSC95XX_INTERNAL_PHY_ID 1

/** TODO */
#define SMSC9512_TX_OVERHEAD 8

/** TODO */
#define SMSC9512_RX_OVERHEAD 4

/** TODO */
#define SMSC9512_HS_USB_PKT_SIZE 512

/** TODO */
#define SMSC9512_DEFAULT_HS_BURST_CAP_SIZE (16 * 1024 + 5 * SMSC9512_HS_USB_PKT_SIZE)

/** TODO */
#define SMSC9512_DEFAULT_BULK_IN_DELAY 0x2000

#define SMSC9512_MAX_TX_REQUESTS 1
/* TODO */
//#define SMSC9512_MAX_RX_REQUESTS (DIV_ROUND_UP(60 * 1518, SMSC9512_DEFAULT_HS_BURST_CAP_SIZE))
#define SMSC9512_MAX_RX_REQUESTS 1

/****************************************************************************/


/*
 * Transmitted Ethernet frames (as written to the SMSC LAN9512's Bulk OUT
 * endpoint) must be prefixed with an 8-byte header containing the "Tx command
 * word A" followed by the "Tx command word B".  It apparently is possible to
 * use these command words to set up the transmission of multiple Ethernet
 * frames in a single USB Bulk transfer, although we do not use this
 * functionality in this driver.
 */

/* Tx command word A */
#define TX_CMD_A_DATA_OFFSET           0x001F0000
#define TX_CMD_A_FIRST_SEG             0x00002000
#define TX_CMD_A_LAST_SEG              0x00001000
#define TX_CMD_A_BUF_SIZE              0x000007FF

/* Tx command word B */
#define TX_CMD_B_CSUM_ENABLE           0x00004000
#define TX_CMD_B_ADD_CRC_DISABLE       0x00002000
#define TX_CMD_B_DISABLE_PADDING       0x00001000
#define TX_CMD_B_PKT_BYTE_LENGTH       0x000007FF

/****************************************************************************/

/*
 * Received Ethernet frames (as read from the SMSC LAN9512's Bulk IN endpoint)
 * are prefixed with a 4-byte Rx Status word containing the flags below.  A
 * single USB Bulk IN transfer may contain multiple Ethernet frames (provided
 * that HW_CFG_MEF is set in HW_CFG), each of which is prepended by a Rx Status
 * word and padded to a 4-byte boundary.
 */

#define RX_STS_FF                      0x40000000    /* Filter Fail */
#define RX_STS_FL                      0x3FFF0000    /* Frame Length */
#define RX_STS_ES                      0x00008000    /* Error Summary */
#define RX_STS_BF                      0x00002000    /* Broadcast Frame */
#define RX_STS_LE                      0x00001000    /* Length Error */
#define RX_STS_RF                      0x00000800    /* Runt Frame */
#define RX_STS_MF                      0x00000400    /* Multicast Frame */
#define RX_STS_TL                      0x00000080    /* Frame too long */
#define RX_STS_CS                      0x00000040    /* Collision Seen */
#define RX_STS_FT                      0x00000020    /* Frame Type */
#define RX_STS_RW                      0x00000010    /* Receive Watchdog */
#define RX_STS_ME                      0x00000008    /* Mii Error */
#define RX_STS_DB                      0x00000004    /* Dribbling */
#define RX_STS_CRC                     0x00000002    /* CRC Error */

/****************************************************************************/

/**
 * Offset of Device ID / Revision Register.  TODO
 */
#define ID_REV                         0x00
#define ID_REV_CHIP_ID_MASK            0xFFFF0000
#define ID_REV_CHIP_REV_MASK           0x0000FFFF
#define ID_REV_CHIP_ID_9500            0x9500
#define ID_REV_CHIP_ID_9500A           0x9E00
#define ID_REV_CHIP_ID_9512            0xEC00
#define ID_REV_CHIP_ID_9530            0x9530
#define ID_REV_CHIP_ID_89530           0x9E08
#define ID_REV_CHIP_ID_9730            0x9730

/****************************************************************************/

/**
 * Offset of Interrupt Status Register.  TODO
 */
#define INT_STS                        0x08
#define INT_STS_TX_STOP                0x00020000
#define INT_STS_RX_STOP                0x00010000
#define INT_STS_PHY_INT                0x00008000
#define INT_STS_TXE                    0x00004000
#define INT_STS_TDFU                   0x00002000
#define INT_STS_TDFO                   0x00001000
#define INT_STS_RXDF                   0x00000800
#define INT_STS_GPIOS                  0x000007FF
#define INT_STS_CLEAR_ALL              0xFFFFFFFF

/****************************************************************************/

/** Offset of Receive Configuration Register.  */
#define RX_CFG                         0x0C

/** Most likely, software can write 1 to this flag discard all the Rx packets
 * currently buffered by the device.  */
#define RX_FIFO_FLUSH                  0x00000001

/****************************************************************************/

/** Offset of Transmit Configuration Register.  */
#define TX_CFG                         0x10

/** Transmit On flag.  Software can write 1 here to enable transmit
 * functionality (at the PHY layer?).  Writing 0 is ignored.  Reads as current
 * on (1) / off (0) state.  However, to actually allow packets to be
 * transmitted, software also must set the ::MAC_CR_TXEN flag in the ::MAC_CR
 * register.  */
#define TX_CFG_ON                      0x00000004

/** Transmit Stop flag.  Software can write 1 here to turn transmit
 * functionality off.  Writing 0 is ignored.  Always reads as 0.  */
#define TX_CFG_STOP                    0x00000002

/** Most likely, software can write 1 to this flag to discard all the Tx packets
 * currently buffered by the device.  */
#define TX_CFG_FIFO_FLUSH              0x00000001

/****************************************************************************/

/** Offset of Hardware Configuration Register.  As implied by the name, this
 * contains a number of flags that software can modify to configure the Ethernet
 * Adapter.   After reset, this register contains all 0's.  */
#define HW_CFG                         0x14

/** TODO: this is set by SMSC's Linux driver.  I don't know what BIR stands for,
 * but the BI might stand for Bulk In.  The observed behavior is that if you
 * don't set this flag, latency for Rx, Tx, or both appears to increase, and
 * Bulk IN transfers can complete immediately with 0 length even when no data
 * has been received.  */
#define HW_CFG_BIR                     0x00001000

/** TODO */
#define HW_CFG_LEDB                    0x00000800

/** Rx packet offset:  Software can modify this 2-bit field to cause Rx packets
 * to be offset by the specified number of bytes.  This is apparently intended
 * to allow software to align the IP header on a 4 byte boundary.  */
#define HW_CFG_RXDOFF                  0x00000600

/** TODO */
#define HW_CFG_DRP                     0x00000040

/** Multiple Ethernet Frames:  Software can set this flag in HW_CFG to allow
 * multiple Ethernet frames to be received in a single USB Bulk In transfer.
 * The default value after reset is 0, meaning that the hardware will by default
 * provide each received Ethernet frame in a separate USB Bulk In transfer.  */
#define HW_CFG_MEF                     0x00000020

/** "Lite" Reset flag.  Software can write 1 to this flag in HW_CFG to start a
 * "lite" reset on the device, whatever that means.  The hardware will
 * automatically clear this flag when the device has finished resetting, which
 * should take no longer than 1 second.  */
#define HW_CFG_LRST                    0x00000008

/** TODO */
#define HW_CFG_PSEL                    0x00000004

/** TODO: this is set by SMSC's Linux driver at the same time as HW_CFG_MEF.  I
 * have no idea what it stands for or what it does.  */
#define HW_CFG_BCE                     0x00000002

/** TODO */
#define HW_CFG_SRST                    0x00000001

/****************************************************************************/

/** TODO */
#define RX_FIFO_INF                    0x18

/****************************************************************************/

/** Offset of Power Management Control Register.  TODO */
#define PM_CTRL                        0x20
#define PM_CTL_RES_CLR_WKP_STS         0x00000200
#define PM_CTL_DEV_RDY                 0x00000080
#define PM_CTL_SUS_MODE                0x00000060
#define PM_CTL_SUS_MODE_0              0x00000000
#define PM_CTL_SUS_MODE_1              0x00000020
#define PM_CTL_SUS_MODE_2              0x00000040
#define PM_CTL_SUS_MODE_3              0x00000060

/** PHY Reset flag:  Software can write 1 here to start a PHY reset on the
 * device.  The hardware will automatically clear this flag when the PHY has
 * finished resetting, which should take no longer than 1 second.  */
#define PM_CTL_PHY_RST                 0x00000010
#define PM_CTL_WOL_EN                  0x00000008
#define PM_CTL_ED_EN                   0x00000004
#define PM_CTL_WUPS                    0x00000003
#define PM_CTL_WUPS_NO                 0x00000000
#define PM_CTL_WUPS_ED                 0x00000001
#define PM_CTL_WUPS_WOL                0x00000002
#define PM_CTL_WUPS_MULTI              0x00000003

/****************************************************************************/

/** Offset of LED General Purpose I/O Configuration Register.  */
#define LED_GPIO_CFG                   0x24
#define LED_GPIO_CFG_SPD_LED           0x01000000
#define LED_GPIO_CFG_LNK_LED           0x00100000
#define LED_GPIO_CFG_FDX_LED           0x00010000

/* USB Vendor Requests */
#define USB_VENDOR_REQUEST_WRITE_REGISTER    0xA0
#define USB_VENDOR_REQUEST_READ_REGISTER    0xA1
#define USB_VENDOR_REQUEST_GET_STATS        0xA2

/****************************************************************************/

/** Offset of General Purpose I/O Configuration Register.  */
#define GPIO_CFG                       0x28

/****************************************************************************/

/** Offset of (Advanced?) Flow Control Configuration Register.
 * After reset, this register is 0.  */
#define AFC_CFG                        0x2C

/**
 * Value written to AFC_CFG by the Linux driver, with the following explanation:
 *
 *     Hi watermark = 15.5Kb (~10 mtu pkts)
 *     low watermark = 3k (~2 mtu pkts)
 *     backpressure duration = ~ 350us
 *     Apply FC on any frame.
 */
#define AFC_CFG_DEFAULT                0x00F830A1

/****************************************************************************/

/** TODO */
#define E2P_CMD                        0x30
#define E2P_CMD_BUSY                   0x80000000
#define E2P_CMD_MASK                   0x70000000
#define E2P_CMD_READ                   0x00000000
#define E2P_CMD_EWDS                   0x10000000
#define E2P_CMD_EWEN                   0x20000000
#define E2P_CMD_WRITE                  0x30000000
#define E2P_CMD_WRAL                   0x40000000
#define E2P_CMD_ERASE                  0x50000000
#define E2P_CMD_ERAL                   0x60000000
#define E2P_CMD_RELOAD                 0x70000000
#define E2P_CMD_TIMEOUT                0x00000400
#define E2P_CMD_LOADED                 0x00000200
#define E2P_CMD_ADDR                   0x000001FF

#define MAX_EEPROM_SIZE                512
#define EEPROM_MAC_OFFSET               (0x01)

/****************************************************************************/

/** TODO */
#define E2P_DATA                       0x34
#define E2P_DATA_MASK                  0x000000FF

/****************************************************************************/

/** Offset of Burst Cap Register.
 *
 * When multiple Ethernet frames per USB bulk transfer are enabled, this
 * register must be set by software to specify the maximum number of USB (not
 * networking!) packets the hardware will provide in a single Bulk In transfer.
 *
 * This register is ignored if HW_CFG_MEF is not set.  Otherwise, this must be
 * set to at least 5, which represents a maximum of 5 * 512 = 2560 bytes of data
 * per transfer from the high speed Bulk In endpoint.  */
#define BURST_CAP                      0x38

/****************************************************************************/

/** TODO */
#define GPIO_WAKE                      0x64

/****************************************************************************/

/** TODO */
#define INT_EP_CTL                     0x68
#define INT_EP_CTL_INTEP               0x80000000
#define INT_EP_CTL_MACRTO              0x00080000
#define INT_EP_CTL_TX_STOP             0x00020000
#define INT_EP_CTL_RX_STOP             0x00010000
#define INT_EP_CTL_PHY_INT             0x00008000
#define INT_EP_CTL_TXE                 0x00004000
#define INT_EP_CTL_TDFU                0x00002000
#define INT_EP_CTL_TDFO                0x00001000
#define INT_EP_CTL_RXDF                0x00000800
#define INT_EP_CTL_GPIOS               0x000007FF

/****************************************************************************/

/**
 * Offset of Bulk In Delay Register.
 *
 * The low 16 bits of this register contain a value that indicates the maximum
 * amount of time the hardware waits for additional packets before responding to
 * a Bulk In request once a packet has been received.  From experiment, the time
 * is specified on a linear scale where each unit is approximately 17
 * nanoseconds.  The default value in this register after reset is 0x800 which
 * indicates a delay of about 34.8 microseconds, assuming that the scale is
 * 0-based.  SMSC's Linux driver changes this to 0x2000, or a delay of about 139
 * microseconds.
 *
 * The high 16 bits of this register are ignored, as far as I can tell.
 *
 * The value in this register no effect if HW_CFG_MEF is not set in the
 * HW_CFG register.
 */
#define BULK_IN_DLY                    0x6C

/****************************************************************************/

/** Offset of Media Access Control Control Register  */
#define MAC_CR                         0x100

/** ??? */
#define MAC_CR_RXALL                   0x80000000

/** Half duplex mode. */
#define MAC_CR_RCVOWN                  0x00800000

/** Loopback mode. */
#define MAC_CR_LOOPBK                  0x00200000

/** Full duplex mode. */
#define MAC_CR_FDPX                    0x00100000

/** Multicast pass: receive all multicast packets.  */
#define MAC_CR_MCPAS                   0x00080000

/** Promiscuous mode. */
#define MAC_CR_PRMS                    0x00040000

/** Inverse filtering. */
#define MAC_CR_INVFILT                 0x00020000

/** Pass on bad frames. */
#define MAC_CR_PASSBAD                 0x00010000

/** ??? */
#define MAC_CR_HFILT                   0x00008000

/** Filter received multicast packets by the set of addresses specified by HASHH
 * and HASHL.  */
#define MAC_CR_HPFILT                  0x00002000

/** ??? */
#define MAC_CR_LCOLL                   0x00001000

/** Receive broadcast packets?  */
#define MAC_CR_BCAST                   0x00000800

/** ??? */
#define MAC_CR_DISRTY                  0x00000400

/** ??? */
#define MAC_CR_PADSTR                  0x00000100

/** ??? */
#define MAC_CR_BOLMT_MASK              0x000000C0

/** ??? */
#define MAC_CR_DFCHK                   0x00000020

/** Transmit enabled at the MAC layer.  Software can write 1 to enable or write
 * 0 to disable.  However, to actually allow packets to be transmitted, software
 * also must set the ::TX_CFG_ON flag in the ::TX_CFG register.  */
#define MAC_CR_TXEN                    0x00000008

/** Receive enabled.  Software can write 1 to enable or write 0 to disable.  */
#define MAC_CR_RXEN                    0x00000004

/****************************************************************************/

/** Offset of Address High Register.  This contains the high 2 bytes of the MAC
 * address used by the device, stored in little endian order.
 *
 * As they are not part of the MAC address, the hardware ignores the values
 * written to the upper 2 bytes of this register and always reads them as 0.
 *
 * Software can change the MAC address used by the device by writing to the
 * ::ADDRH and ::ADDRL registers, and it can retrieve the current MAC address by
 * reading them.  On reset, the device will read its MAC address from the EEPROM
 * if one is attached; otherwise it will set its MAC address to 0xFFFFFFFFFFFF.
 * */
#define ADDRH                          0x104

/** Offset of Address Low Register.  This contains the low 4 bytes of the MAC
 * address used by the device, stored in little endian order.  See ::ADDRH.  */
#define ADDRL                          0x108

/****************************************************************************/

/** Offset of Hash High register, used together with HASHL to filter specific
 * multicast packets.  TODO */
#define HASHH                          0x10C

/** Offset of Hash Low register, used together with HASHH to filter specific
 * multicast packets.  TODO */
#define HASHL                          0x110

/****************************************************************************/

/** TODO */
#define MII_ADDR                       0x114
#define MII_WRITE                      0x02
#define MII_BUSY                       0x01
#define MII_READ                       0x00 /* ~of MII Write bit */

/** TODO */
#define MII_DATA                       0x118

/****************************************************************************/

/** TODO.  After reset, this is 0.  */
#define FLOW                           0x11C
#define FLOW_FCPT                      0xFFFF0000
#define FLOW_FCPASS                    0x00000004
#define FLOW_FCEN                      0x00000002
#define FLOW_FCBSY                     0x00000001

/****************************************************************************/

/** TODO */
#define VLAN1                           0x120

/** TODO */
#define VLAN2                           0x124

/****************************************************************************/

/** TODO */
#define WUFF                            0x128
#define LAN9500_WUFF_NUM                4
#define LAN9500A_WUFF_NUM               8

/****************************************************************************/

/** TODO */
#define WUCSR                          0x12C
#define WUCSR_WFF_PTR_RST              0x80000000
#define WUCSR_GUE                      0x00000200
#define WUCSR_WUFR                     0x00000040
#define WUCSR_MPR                      0x00000020
#define WUCSR_WAKE_EN                  0x00000004
#define WUCSR_MPEN                     0x00000002

/****************************************************************************/

/** Offset of Checksum Offload Engine/Enable Control Register.  This register
 * can be used to enable or disable Tx and Rx checksum offload.  These refer
 * specifically to the TCP/UDP checksums and not to the CRC32 calculated for
 * an Ethernet frame itself, which is controlled separately and is done by
 * default, unlike this which must be explicitly enabled.  */
#define COE_CR                         0x130

/** Transmit checksum offload enabled.  Software can write 1 here to enable or
 * write 0 here to disable.  After reset, this is disabled (0).  */
#define Tx_COE_EN                      0x00010000

/** TODO.  After reset, this is 0.  */
#define Rx_COE_MODE                    0x00000002

/** Receive checksum offload enabled.  Software can write 1 here to enable or
 * write 0 here to disable.  After reset, this is disabled (0).  */
#define Rx_COE_EN                      0x00000001

/****************************************************************************/

/* Vendor-specific PHY Definitions */

/* EDPD NLP / crossover time configuration (LAN9500A only) */
#define PHY_EDPD_CONFIG                 16
#define PHY_EDPD_CONFIG_TX_NLP_EN      ((u16)0x8000)
#define PHY_EDPD_CONFIG_TX_NLP_1000    ((u16)0x0000)
#define PHY_EDPD_CONFIG_TX_NLP_768     ((u16)0x2000)
#define PHY_EDPD_CONFIG_TX_NLP_512     ((u16)0x4000)
#define PHY_EDPD_CONFIG_TX_NLP_256     ((u16)0x6000)
#define PHY_EDPD_CONFIG_RX_1_NLP       ((u16)0x1000)
#define PHY_EDPD_CONFIG_RX_NLP_64      ((u16)0x0000)
#define PHY_EDPD_CONFIG_RX_NLP_256     ((u16)0x0400)
#define PHY_EDPD_CONFIG_RX_NLP_512     ((u16)0x0800)
#define PHY_EDPD_CONFIG_RX_NLP_1000    ((u16)0x0C00)
#define PHY_EDPD_CONFIG_EXT_CROSSOVER  ((u16)0x0001)
#define PHY_EDPD_CONFIG_DEFAULT         (PHY_EDPD_CONFIG_TX_NLP_EN | \
                                         PHY_EDPD_CONFIG_TX_NLP_768 | \
                                         PHY_EDPD_CONFIG_RX_1_NLP)

/* Mode Control/Status Register */
#define PHY_MODE_CTRL_STS               17
#define MODE_CTRL_STS_EDPWRDOWN        ((u16)0x2000)
#define MODE_CTRL_STS_ENERGYON         ((u16)0x0002)

#define SPECIAL_CTRL_STS                27
#define SPECIAL_CTRL_STS_OVRRD_AMDIX   ((u16)0x8000)
#define SPECIAL_CTRL_STS_AMDIX_ENABLE  ((u16)0x4000)
#define SPECIAL_CTRL_STS_AMDIX_STATE   ((u16)0x2000)

#define PHY_INT_SRC                     29
#define PHY_INT_SRC_ENERGY_ON          ((u16)0x0080)
#define PHY_INT_SRC_ANEG_COMP          ((u16)0x0040)
#define PHY_INT_SRC_REMOTE_FAULT       ((u16)0x0020)
#define PHY_INT_SRC_LINK_DOWN          ((u16)0x0010)

#define PHY_INT_MASK                    30
#define PHY_INT_MASK_ENERGY_ON         ((u16)0x0080)
#define PHY_INT_MASK_ANEG_COMP         ((u16)0x0040)
#define PHY_INT_MASK_REMOTE_FAULT      ((u16)0x0020)
#define PHY_INT_MASK_LINK_DOWN         ((u16)0x0010)
#define PHY_INT_MASK_DEFAULT           (PHY_INT_MASK_ANEG_COMP | \
                                         PHY_INT_MASK_LINK_DOWN)

#define PHY_SPECIAL                     31
#define PHY_SPECIAL_SPD                ((u16)0x001C)
#define PHY_SPECIAL_SPD_10HALF         ((u16)0x0004)
#define PHY_SPECIAL_SPD_10FULL         ((u16)0x0014)
#define PHY_SPECIAL_SPD_100HALF        ((u16)0x0008)
#define PHY_SPECIAL_SPD_100FULL        ((u16)0x0018)

/****************************************************************************/

/* SMSC LAN9512 USB Vendor Requests */

/** Write Register:  Specify as bRequest of a USB control message to write a
 * register on the SMSC LAN9512.  bmRequestType must specify a vendor-specific
 * request in the host-to-device direction, wIndex must specify the offset of
 * the register, and the transfer data must be 4 bytes containing the value to
 * write.  */
#define SMSC9512_VENDOR_REQUEST_WRITE_REGISTER       0xA0

/** Read Register:  Specify as bRequest of a USB control message to read a
 * register from the SMSC LAN9512.  bmRequestType must specify a vendor-specific
 * request in the device-to-host direction, wIndex must specify the offset of
 * the register, and the transfer data must be a 4-byte location in which to
 * store the register's contents.  */
#define SMSC9512_VENDOR_REQUEST_READ_REGISTER        0xA1

/** TODO */
#define SMSC9512_VENDOR_REQUEST_GET_STATS            0xA2

/****************************************************************************/

/* Interrupt Endpoint status word bitfields */
#define INT_ENP_TX_STOP                (1 << 17)
#define INT_ENP_RX_STOP                (1 << 16)
#define INT_ENP_PHY_INT                (1 << 15)
#define INT_ENP_TXE                    (1 << 14)
#define INT_ENP_TDFU                   (1 << 13)
#define INT_ENP_TDFO                   (1 << 12)
#define INT_ENP_RXDF                   (1 << 11)

/***************** } ******************/

#define USE_TX_CSUM 1
#define USE_RX_CSUM 2

//------------------------------------------------------------------------------
// local types
//------------------------------------------------------------------------------
typedef struct
{
    tEdrvInitParam      initParam;                       ///< Init parameters
    struct usb_device*  pUsbDev;                         ///< Pointer to the USB device structure
    int                 ep_in, ep_out, ep_int;           ///< USB endpoints
       size_t              rx_urb_size;                     ///< Maximum USB URB size
    UINT32              mac_cr;
    struct tasklet_hrtimer poll_timer;
    UINT8                irqinterval;                     ///< IRQ Pipe Intervall
    int                 phyId;                           ///< PHY ID
    UINT8*              pRxBuf;                          ///< Pointer to the RX buffer
    UINT8*              pTxBuf;                          ///< Pointer to the TX buffer
    BOOL                afTxBufUsed[EDRV_MAX_TX_BUFFERS];///< Array describing whether a TX buffer is used
    tEdrvTxBuffer*      apTxBuffer[EDRV_MAX_TX_DESCS];   ///< Array of TX buffers
    spinlock_t          txSpinlock;                      ///< Spinlock to protect critical sections
} tEdrvInstance;

//------------------------------------------------------------------------------
// local function prototypes
//------------------------------------------------------------------------------
static int initOneUsbDev(struct usb_interface *pUsbInterface_p, const struct usb_device_id *pUsbDeviceId_p);
static void removeOneUsbDev(struct usb_interface *);
static int smsc95xx_write_reg(tEdrvInstance *dev, u32 index, u32 data);
static int smsc95xx_read_reg(tEdrvInstance *dev, u32 index, u32 *data);
static int smsc95xx_phy_wait_not_busy(tEdrvInstance *dev);
static int smsc95xx_mdio_read(tEdrvInstance *dev, int phy_id, int idx);
static void smsc95xx_mdio_write(tEdrvInstance *dev, int phy_id, int idx, int regval);
static int smsc95xx_eeprom_confirm_not_busy(tEdrvInstance *dev);
static int smsc95xx_wait_eeprom(tEdrvInstance *dev);
static int smsc95xx_read_eeprom(tEdrvInstance *dev, u32 offset, u32 length, u8 *data);
static int smsc95xx_mii_nway_restart(tEdrvInstance *dev);
static int smsc95xx_phy_initialize(tEdrvInstance *dev);
static void smsc95xx_init_mac_address(tEdrvInstance *inst);
static int smsc95xx_write_hwaddr(tEdrvInstance *inst);
static int smsc95xx_set_csums(tEdrvInstance *dev, int csums);
static void smsc95xx_set_multicast(tEdrvInstance *dev);
static void smsc95xx_start_tx_path(tEdrvInstance *dev);
static void smsc95xx_start_rx_path(tEdrvInstance *dev);
static enum hrtimer_restart smsc95xx_recv(struct hrtimer *timer);

//------------------------------------------------------------------------------
// local vars
//------------------------------------------------------------------------------
static bool turbo_mode = true;
module_param(turbo_mode, bool, 0644);
MODULE_PARM_DESC(turbo_mode, "Enable multiple frames per Rx transaction");

static tEdrvInstance edrvInstance_l;
static tBufAlloc *pBufAlloc_l;

static const struct usb_device_id aEdrvUsbTbl_l[] = {
    {
        /* SMSC9500 USB Ethernet Device */
        USB_DEVICE(0x0424, 0x9500),
    },
    {
        /* SMSC9505 USB Ethernet Device */
        USB_DEVICE(0x0424, 0x9505),
    },
    {
        /* SMSC9500A USB Ethernet Device */
        USB_DEVICE(0x0424, 0x9E00),
    },
    {
        /* SMSC9505A USB Ethernet Device */
        USB_DEVICE(0x0424, 0x9E01),
    },
    {
        /* SMSC9512/9514 USB Hub & Ethernet Device */
        USB_DEVICE(0x0424, 0xec00),
    },
    {
        /* SMSC9500 USB Ethernet Device (SAL10) */
        USB_DEVICE(0x0424, 0x9900),
    },
    {
        /* SMSC9505 USB Ethernet Device (SAL10) */
        USB_DEVICE(0x0424, 0x9901),
    },
    {
        /* SMSC9500A USB Ethernet Device (SAL10) */
        USB_DEVICE(0x0424, 0x9902),
    },
    {
        /* SMSC9505A USB Ethernet Device (SAL10) */
        USB_DEVICE(0x0424, 0x9903),
    },
    {
        /* SMSC9512/9514 USB Hub & Ethernet Device (SAL10) */
        USB_DEVICE(0x0424, 0x9904),
    },
    {
        /* SMSC9500A USB Ethernet Device (HAL) */
        USB_DEVICE(0x0424, 0x9905),
    },
    {
        /* SMSC9505A USB Ethernet Device (HAL) */
        USB_DEVICE(0x0424, 0x9906),
    },
    {
        /* SMSC9500 USB Ethernet Device (Alternate ID) */
        USB_DEVICE(0x0424, 0x9907),
    },
    {
        /* SMSC9500A USB Ethernet Device (Alternate ID) */
        USB_DEVICE(0x0424, 0x9908),
    },
    {
        /* SMSC9512/9514 USB Hub & Ethernet Device (Alternate ID) */
        USB_DEVICE(0x0424, 0x9909),
    },
    {
        /* SMSC LAN9530 USB Ethernet Device */
        USB_DEVICE(0x0424, 0x9530),
    },
    {
        /* SMSC LAN9730 USB Ethernet Device */
        USB_DEVICE(0x0424, 0x9730),
    },
    {
        /* SMSC LAN89530 USB Ethernet Device */
        USB_DEVICE(0x0424, 0x9E08),
    },
    { },        /* END */
};
MODULE_DEVICE_TABLE(usb, aEdrvUsbTbl_l);

/* XXX can I use usbnet functions here? (usbnet_probe, usbnet_disconnect) */
static struct usb_driver edrvDriver_l = {
    .name                      = DRV_NAME,
    .id_table                  = aEdrvUsbTbl_l,
    .probe                     = initOneUsbDev,
    .disconnect                = removeOneUsbDev,
    .disable_hub_initiated_lpm = 1,
};

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
    tBufData    bufData;
    ASSERT(pEdrvInitParam_p != NULL);

    OPLK_MEMSET(&edrvInstance_l, 0, sizeof edrvInstance_l);

    edrvInstance_l.initParam = *pEdrvInitParam_p;

    OPLK_MEMSET(&edrvDriver_l, 0, sizeof(edrvDriver_l));
    edrvDriver_l.name         = DRV_NAME;
    edrvDriver_l.id_table     = aEdrvUsbTbl_l;
    edrvDriver_l.probe        = initOneUsbDev;
    edrvDriver_l.disconnect   = removeOneUsbDev;

    if (usb_register(&edrvDriver_l)) {
        DEBUG_LVL_ERROR_TRACE("smsc95xx: unable to register usb driver\n");
        return kErrorNoResource;
    }

    // init and fill buffer allocation instance
    if ((pBufAlloc_l = bufalloc_init(EDRV_MAX_TX_BUFFERS)) == NULL)
        return kErrorNoResource;

    for (i = 0; i < EDRV_MAX_TX_BUFFERS; i++)
    {
        bufData.bufferNumber = i;
        bufData.pBuffer = edrvInstance_l.pTxBuf + (i * EDRV_MAX_FRAME_SIZE);

        bufalloc_addBuffer(pBufAlloc_l, &bufData);
    }

    // local MAC address might have been changed in initOneUsbDev
    DEBUG_LVL_EDRV_TRACE("%s local MAC = %pM\n", __func__, edrvInstance_l.initParam.aMacAddr);

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
    if (edrvDriver_l.name != NULL)
    {
        DEBUG_LVL_EDRV_TRACE("%s calling usb_unregister_driver()\n", __func__);
        usb_deregister(&edrvDriver_l);
        // clear buffer allocation
        bufalloc_exit(pBufAlloc_l);
        pBufAlloc_l = NULL;
        // clear driver structure
        OPLK_MEMSET(&edrvDriver_l, 0, sizeof(edrvDriver_l));
    }
    else
    {
        DEBUG_LVL_EDRV_TRACE("%s USB driver for openPOWERLINK already unregistered\n", __func__);
    }
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
    u8 *packet = pBuffer_p->pBuffer;
    u32 length = pBuffer_p->txFrameSize;
    int err = -E2BIG;
    int actual_len;
    u32 tx_cmd[2]; /* A & B */

    DEBUG_LVL_EDRV_TRACE("** %s(), len %d", __func__, length);
    if (length > 1536)
        goto Exit;

    tx_cmd[0] = length | TX_CMD_A_FIRST_SEG | TX_CMD_A_LAST_SEG;
    tx_cmd[1] = length;
    cpu_to_le32s(&tx_cmd[0]);
    cpu_to_le32s(&tx_cmd[1]);

    /* prepend cmd_a and cmd_b */
    packet -= sizeof tx_cmd;
    memcpy(packet, tx_cmd, sizeof tx_cmd);
    length += sizeof tx_cmd;

    err = usb_bulk_msg(edrvInstance_l.pUsbDev, edrvInstance_l.ep_out, packet,
                length, &actual_len,
                USB_BULK_SEND_TIMEOUT);
    DEBUG_LVL_EDRV_TRACE("Tx: len = %u, actual = %u, err = %d\n", length, actual_len, err);

Exit:
    if (pBuffer_p->pfnTxHandler != NULL)
    {
        pBuffer_p->pfnTxHandler(pBuffer_p);
    }
    return err ? kErrorGeneralError : kErrorOk;
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
    tBufData    bufData;

    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    if (pBuffer_p->maxBufferSize > EDRV_MAX_FRAME_SIZE)
        return kErrorEdrvNoFreeBufEntry;

    if (edrvInstance_l.pTxBuf == NULL)
    {
        DEBUG_LVL_ERROR_TRACE("%s Tx buffers currently not allocated\n", __func__);
        return kErrorEdrvNoFreeBufEntry;
    }

    // get a free Tx buffer from the allocation instance
    if (bufalloc_getBuffer(pBufAlloc_l, &bufData) != kErrorOk)
        return kErrorEdrvNoFreeBufEntry;

    pBuffer_p->pBuffer = bufData.pBuffer + 16;
    pBuffer_p->txBufferNumber.value = bufData.bufferNumber;
    pBuffer_p->maxBufferSize = EDRV_MAX_FRAME_SIZE - 16;
    edrvInstance_l.afTxBufUsed[bufData.bufferNumber] = TRUE;

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
    tBufData    bufData;

    // Check parameter validity
    ASSERT(pBuffer_p != NULL);

    bufData.pBuffer = pBuffer_p->pBuffer - 16;
    bufData.bufferNumber = pBuffer_p->txBufferNumber.value;

    edrvInstance_l.afTxBufUsed[pBuffer_p->txBufferNumber.value] = FALSE;
    return bufalloc_releaseBuffer(pBufAlloc_l, &bufData);
}

//------------------------------------------------------------------------------
/**
\brief  Change Rx filter setup

This function changes the Rx filter setup. The parameter entryChanged_p
selects the Rx filter entry that shall be changed and \p changeFlags_p determines
the property.
If \p entryChanged_p is equal or larger count_p all Rx filters shall be changed.

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
    return kErrorOk; /* FIXME how to configure Rx Filters? */
}

//------------------------------------------------------------------------------
/**
\brief  Clear multicast address entry

This function removes the multicast entry from the Ethernet controller.

\param[in]      pMacAddr_p          Multicast address

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_clearRxMulticastMacAddr(const UINT8* pMacAddr_p)
{
    return kErrorOk;
}

//------------------------------------------------------------------------------
/**
\brief  Set multicast address entry

This function sets a multicast entry into the Ethernet controller.

\param[in]      pMacAddr_p          Multicast address

\return The function returns a tOplkError error code.

\ingroup module_edrv
*/
//------------------------------------------------------------------------------
tOplkError edrv_setRxMulticastMacAddr(const UINT8* pMacAddr_p)
{
    return kErrorOk;
}

//============================================================================//
//            P R I V A T E   F U N C T I O N S                               //
//============================================================================//
/// \name Private Functions
/// \{

static int initOneUsbDev(struct usb_interface* pUsbInterface_p, const struct usb_device_id *pUsbDeviceId_p)
{
    unsigned  tmp;
    int ret;
    u32 write_buf;
    u32 read_buf;
    u32 burst_cap;
    int timeout;
    tEdrvInstance *dev = &edrvInstance_l;
#define TIMEOUT_RESOLUTION 50    /* ms */
    int link_detected;
    struct usb_host_endpoint *in = NULL, *out = NULL, *intr = NULL;

    dev->pUsbDev = interface_to_usbdev(pUsbInterface_p);
    DEBUG_LVL_EDRV_TRACE("** %s()\n", __func__);

    for (tmp = 0; tmp < pUsbInterface_p->num_altsetting; tmp++) {
        struct usb_host_interface *alt = &pUsbInterface_p->altsetting[tmp];
        /*
         * We are expecting a minimum of 3 endpoints - in, out (bulk), and int.
         * We will ignore any others.
         */
        unsigned i;
        for (i = 0; i < alt->desc.bNumEndpoints; i++) {
            struct usb_host_endpoint *ep = &alt->endpoint[i];
            /* is it an BULK endpoint? */
            if ((ep->desc.bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK) {
                if (ep->desc.bEndpointAddress & USB_DIR_IN)
                    in = ep;
                else
                    out = ep;
            }

            /* is it an interrupt endpoint? */
            if ((ep->desc.bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_INT) {
                intr = ep;
            }
        }
        DEBUG_LVL_EDRV_TRACE("Endpoints In %d Out %d Int %d\n", dev->ep_in, dev->ep_out, dev->ep_int);
    }

    /* Do some basic sanity checks, and bail if we find a problem */
    if (!in || !out || !intr) {
        DEBUG_LVL_ERROR_TRACE("Problems with device: Endpoint is 0\n");
        return -EIO;
    }

    dev->ep_in  = usb_rcvbulkpipe(dev->pUsbDev, in->desc.bEndpointAddress  & USB_ENDPOINT_NUMBER_MASK);
    dev->ep_out = usb_sndbulkpipe(dev->pUsbDev, out->desc.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK);
    dev->ep_int = usb_rcvintpipe(dev->pUsbDev, intr->desc.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK); // FIXME unused and untested
    dev->irqinterval = intr->desc.bInterval;

    dev->phyId = SMSC95XX_INTERNAL_PHY_ID; /* fixed phy id */

    write_buf = HW_CFG_LRST;
    ret = smsc95xx_write_reg(dev, HW_CFG, write_buf);
    if (ret < 0)
        return ret;

    timeout = 0;
    do {
        ret = smsc95xx_read_reg(dev, HW_CFG, &read_buf);
        if (ret < 0)
            return ret;
        mdelay(10);
        timeout++;
    } while ((read_buf & HW_CFG_LRST) && (timeout < 100));

    if (timeout >= 100) {
        DEBUG_LVL_ERROR_TRACE("timeout waiting for completion of Lite Reset\n");
        return -EBUSY;
    }

    write_buf = PM_CTL_PHY_RST;
    ret = smsc95xx_write_reg(dev, PM_CTRL, write_buf);
    if (ret < 0)
        return ret;

    timeout = 0;
    do {
        ret = smsc95xx_read_reg(dev, PM_CTRL, &read_buf);
        if (ret < 0)
            return ret;
        mdelay(10);
        timeout++;
    } while ((read_buf & PM_CTL_PHY_RST) && (timeout < 100));
    if (timeout >= 100) {
        DEBUG_LVL_ERROR_TRACE("timeout waiting for PHY Reset\n");
        return -EBUSY;
    }
    if (!is_zero_ether_addr(dev->initParam.aMacAddr)) {
        if ((ret = smsc95xx_write_hwaddr(dev)))
            return ret;
    } else {
        smsc95xx_init_mac_address(dev);
    }

    ret = smsc95xx_read_reg(dev, HW_CFG, &read_buf);
    if (ret < 0)
        return ret;
    DEBUG_LVL_EDRV_TRACE("Read Value from HW_CFG : 0x%08x\n", read_buf);

    read_buf |= HW_CFG_BIR;
    ret = smsc95xx_write_reg(dev, HW_CFG, read_buf);
    if (ret < 0)
        return ret;

    ret = smsc95xx_read_reg(dev, HW_CFG, &read_buf);
    if (ret < 0)
        return ret;
    DEBUG_LVL_EDRV_TRACE("Read Value from HW_CFG after writing "
            "HW_CFG_BIR: 0x%08x\n", read_buf);

    if (turbo_mode) {
        if (dev->pUsbDev->speed == USB_SPEED_HIGH) {
            burst_cap = DEFAULT_HS_BURST_CAP_SIZE / HS_USB_PKT_SIZE;
            dev->rx_urb_size = DEFAULT_HS_BURST_CAP_SIZE;
        } else {
            burst_cap = DEFAULT_FS_BURST_CAP_SIZE / FS_USB_PKT_SIZE;
            dev->rx_urb_size = DEFAULT_FS_BURST_CAP_SIZE;
        }
    } else {
        burst_cap = 0;
        dev->rx_urb_size = EDRV_MAX_FRAME_SIZE;
    }
    DEBUG_LVL_EDRV_TRACE("rx_urb_size=%ld\n", (ulong)dev->rx_urb_size);

    ret = smsc95xx_write_reg(dev, BURST_CAP, burst_cap);
    if (ret < 0)
        return ret;

    ret = smsc95xx_read_reg(dev, BURST_CAP, &read_buf);
    if (ret < 0)
        return ret;
    DEBUG_LVL_EDRV_TRACE("Read Value from BURST_CAP after writing: 0x%08x\n", read_buf);

    read_buf = DEFAULT_BULK_IN_DELAY;
    ret = smsc95xx_write_reg(dev, BULK_IN_DLY, read_buf);
    if (ret < 0)
        return ret;

    ret = smsc95xx_read_reg(dev, BULK_IN_DLY, &read_buf);
    if (ret < 0)
        return ret;
    DEBUG_LVL_EDRV_TRACE("Read Value from BULK_IN_DLY after writing: "
            "0x%08x\n", read_buf);

    ret = smsc95xx_read_reg(dev, HW_CFG, &read_buf);
    if (ret < 0)
        return ret;
    DEBUG_LVL_EDRV_TRACE("Read Value from HW_CFG: 0x%08x\n", read_buf);

    if (turbo_mode)
        read_buf |= (HW_CFG_MEF | HW_CFG_BCE);

    read_buf &= ~HW_CFG_RXDOFF;

#undef NET_IP_ALIGN // TODO hmm?
#define NET_IP_ALIGN 0
    read_buf |= NET_IP_ALIGN << 9;

    ret = smsc95xx_write_reg(dev, HW_CFG, read_buf);
    if (ret < 0)
        return ret;

    ret = smsc95xx_read_reg(dev, HW_CFG, &read_buf);
    if (ret < 0)
        return ret;
    DEBUG_LVL_EDRV_TRACE("Read Value from HW_CFG after writing: 0x%08x\n", read_buf);

    write_buf = 0xFFFFFFFF;
    ret = smsc95xx_write_reg(dev, INT_STS, write_buf);
    if (ret < 0)
        return ret;

    ret = smsc95xx_read_reg(dev, ID_REV, &read_buf);
    if (ret < 0)
        return ret;
    DEBUG_LVL_EDRV_TRACE("ID_REV = 0x%08x\n", read_buf);

    /* Init Tx */
    write_buf = 0;
    ret = smsc95xx_write_reg(dev, FLOW, write_buf);
    if (ret < 0)
        return ret;

    read_buf = AFC_CFG_DEFAULT;
    ret = smsc95xx_write_reg(dev, AFC_CFG, read_buf);
    if (ret < 0)
        return ret;

    ret = smsc95xx_read_reg(dev, MAC_CR, &dev->mac_cr);
    if (ret < 0)
        return ret;

    /* Init Rx. Set Vlan */
    write_buf = (u32)ETH_P_8021Q;
    ret = smsc95xx_write_reg(dev, VLAN1, write_buf);
    if (ret < 0)
        return ret;

    /* Disable checksum offload engines */
    ret = smsc95xx_set_csums(dev, USE_TX_CSUM | USE_RX_CSUM);
    if (ret < 0) {
        DEBUG_LVL_ERROR_TRACE("Failed to set csum offload: %d\n", ret);
        return ret;
    }
    smsc95xx_set_multicast(dev);

    if (smsc95xx_phy_initialize(dev) < 0)
        return -EIO;
    ret = smsc95xx_read_reg(dev, INT_EP_CTL, &read_buf);
    if (ret < 0)
        return ret;

    /* enable PHY interrupts */
    read_buf |= INT_EP_CTL_PHY_INT;

    ret = smsc95xx_write_reg(dev, INT_EP_CTL, read_buf);
    if (ret < 0)
        return ret;

    smsc95xx_start_tx_path(dev);
    smsc95xx_start_rx_path(dev);

    timeout = 0;
    do {
        link_detected = smsc95xx_mdio_read(dev, dev->phyId, MII_BMSR)
            & BMSR_LSTATUS;
        if (!link_detected) {
            if (timeout == 0)
                DEBUG_LVL_ERROR_TRACE("Waiting for Ethernet connection... ");
            mdelay(TIMEOUT_RESOLUTION);
            timeout += TIMEOUT_RESOLUTION;
        }
    } while (!link_detected && timeout < PHY_CONNECT_TIMEOUT);
    if (link_detected) {
        if (timeout != 0)
            DEBUG_LVL_EDRV_TRACE("done.\n");
    } else {
        DEBUG_LVL_ERROR_TRACE("unable to connect.\n");
        return -EBUSY;
    }

    // FIXME figure out how to use USB interrupts
    tasklet_hrtimer_init(&dev->poll_timer, smsc95xx_recv, CLOCK_MONOTONIC, HRTIMER_MODE_REL);

    tasklet_hrtimer_start(&dev->poll_timer, ktime_set(0, 1000*1000), HRTIMER_MODE_REL);
    return 0;
}

static void removeOneUsbDev(struct usb_interface *pUsbInterface_p)
{
    if (edrvInstance_l.pUsbDev != interface_to_usbdev(pUsbInterface_p))
        return;

    /* That's it? */
    tasklet_hrtimer_cancel(&edrvInstance_l.poll_timer);
    edrvInstance_l.pUsbDev = NULL;
}
/*
 * Smsc95xx infrastructure commands
 */
static int smsc95xx_write_reg(tEdrvInstance *dev, u32 index, u32 data)
{
    int len;

    cpu_to_le32s(&data);

    len = usb_control_msg(dev->pUsbDev, usb_sndctrlpipe(dev->pUsbDev, 0),
        USB_VENDOR_REQUEST_WRITE_REGISTER,
        USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
        00, index, &data, sizeof(data), USB_CTRL_SET_TIMEOUT
    );
    if (len != sizeof(data)) {
        DEBUG_LVL_ERROR_TRACE("smsc95xx_write_reg failed: index=%d, data=%d, len=%d", index, data, len);
        return -EIO;
    }
    return 0;
}

static int smsc95xx_read_reg(tEdrvInstance *dev, u32 index, u32 *data)
{
    int len;

    len = usb_control_msg(dev->pUsbDev, usb_rcvctrlpipe(dev->pUsbDev, 0),
        USB_VENDOR_REQUEST_READ_REGISTER,
        USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
        00, index, data, sizeof(data), USB_CTRL_GET_TIMEOUT);
    if (len != sizeof(data)) {
        DEBUG_LVL_ERROR_TRACE("smsc95xx_read_reg failed: index=%d, len=%d", index, len);
        return -EIO;
    }

    le32_to_cpus(data);
    return 0;
}

/* Loop until the read is completed with timeout */
static int smsc95xx_phy_wait_not_busy(tEdrvInstance *dev)
{
    unsigned long start_time = jiffies;
    u32 val;
    int ret;

    do {
        ret = smsc95xx_read_reg(dev, MII_ADDR, &val);
        if (ret < 0) {
            DEBUG_LVL_ERROR_TRACE("Error reading MII_ACCESS\n");
            return ret;
        }

        if (!(val & MII_BUSY))
            return 0;
    } while (!time_after(jiffies, start_time + HZ));

    return -EIO;
}

static int smsc95xx_mdio_read(tEdrvInstance *dev, int phy_id, int idx)
{
    u32 val, addr;

    /* confirm MII not busy */
    if (smsc95xx_phy_wait_not_busy(dev)) {
        DEBUG_LVL_ERROR_TRACE("MII is busy in smsc95xx_mdio_read\n");
        return -EBUSY;
    }

    /* set the address, index & direction (read from PHY) */
    addr = (phy_id << 11) | (idx << 6) | MII_READ;
    smsc95xx_write_reg(dev, MII_ADDR, addr);

    if (smsc95xx_phy_wait_not_busy(dev)) {
        DEBUG_LVL_ERROR_TRACE("Timed out reading MII reg %02X\n", idx);
        return -EBUSY;
    }

    smsc95xx_read_reg(dev, MII_DATA, &val);

    return (u16)(val & 0xFFFF);
}

static void smsc95xx_mdio_write(tEdrvInstance *dev, int phy_id, int idx,
                int regval)
{
    u32 val, addr;

    /* confirm MII not busy */
    if (smsc95xx_phy_wait_not_busy(dev)) {
        DEBUG_LVL_ERROR_TRACE("MII is busy in smsc95xx_mdio_write\n");
        return;
    }

    val = regval;
    smsc95xx_write_reg(dev, MII_DATA, val);

    /* set the address, index & direction (write to PHY) */
    addr = (phy_id << 11) | (idx << 6) | MII_WRITE;
    smsc95xx_write_reg(dev, MII_ADDR, addr);

    if (smsc95xx_phy_wait_not_busy(dev))
        DEBUG_LVL_ERROR_TRACE("Timed out writing MII reg %02X\n", idx);
    // TODO error code?
}

static int smsc95xx_eeprom_confirm_not_busy(tEdrvInstance *dev)
{
    unsigned long start_time = jiffies;
    u32 val;
    int ret;

    do {
        ret = smsc95xx_read_reg(dev, E2P_CMD, &val);
        if (ret < 0) {
            DEBUG_LVL_ERROR_TRACE("Error reading E2P_CMD\n");
            return ret;
        }

        if (!(val & E2P_CMD_BUSY))
            return 0;

        udelay(40);
    } while (!time_after(jiffies, start_time + HZ));

    DEBUG_LVL_ERROR_TRACE("EEPROM is busy\n");
    return -EBUSY;
}

static int smsc95xx_wait_eeprom(tEdrvInstance *dev)
{
    unsigned long start_time = jiffies;
    u32 val;
    int ret;

    do {
        ret = smsc95xx_read_reg(dev, E2P_CMD, &val);
        if (ret < 0) {
            DEBUG_LVL_ERROR_TRACE("Error reading E2P_CMD\n");
            return ret;
        }

        if (!(val & E2P_CMD_BUSY) || (val & E2P_CMD_TIMEOUT))
            break;
        udelay(40);
    } while (!time_after(jiffies, start_time + HZ));

    if (val & (E2P_CMD_TIMEOUT | E2P_CMD_BUSY)) {
        DEBUG_LVL_ERROR_TRACE("EEPROM read operation timeout\n");
        return -EIO;
    }

    return 0;
}

static int smsc95xx_read_eeprom(tEdrvInstance *dev, u32 offset, u32 length,
                u8 *data)
{
    u32 val;
    int i, ret;

    ret = smsc95xx_eeprom_confirm_not_busy(dev);
    if (ret)
        return ret;

    for (i = 0; i < length; i++) {
        val = E2P_CMD_BUSY | E2P_CMD_READ | (offset & E2P_CMD_ADDR);
        smsc95xx_write_reg(dev, E2P_CMD, val);

        ret = smsc95xx_wait_eeprom(dev);
        if (ret < 0)
            return ret;

        smsc95xx_read_reg(dev, E2P_DATA, &val);
        data[i] = val & 0xFF;
        offset++;
    }
    return 0;
}

/*
 * smsc95xx_mii_nway_restart - restart NWay (autonegotiation) for this interface
 *
 * Returns 0 on success, negative on error.
 * TODO maybe use mii_if_info and associated functions instead
 */
static int smsc95xx_mii_nway_restart(tEdrvInstance *dev)
{
    int bmcr;
    int r = -EIO;

    /* if autoneg is off, it's an error */
    bmcr = smsc95xx_mdio_read(dev, dev->phyId, MII_BMCR);

    if (bmcr & BMCR_ANENABLE) {
        bmcr |= BMCR_ANRESTART;
        smsc95xx_mdio_write(dev, dev->phyId, MII_BMCR, bmcr);
        r = 0;
    }
    return r;
}

static int smsc95xx_phy_initialize(tEdrvInstance *dev)
{
    smsc95xx_mdio_write(dev, dev->phyId, MII_BMCR, BMCR_RESET);
    smsc95xx_mdio_write(dev, dev->phyId, MII_ADVERTISE,
        ADVERTISE_ALL | ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP |
        ADVERTISE_PAUSE_ASYM);

    /* read to clear */
    smsc95xx_mdio_read(dev, dev->phyId, PHY_INT_SRC);

    smsc95xx_mdio_write(dev, dev->phyId, PHY_INT_MASK,
        PHY_INT_MASK_DEFAULT);
    smsc95xx_mii_nway_restart(dev);

    DEBUG_LVL_EDRV_TRACE("phy initialised succesfully\n");
    return 0;
}

static void smsc95xx_init_mac_address(tEdrvInstance *inst)
{
    const char *from;
    const u8 *mac_of;
    u8 *mac = inst->initParam.aMacAddr;

    /* maybe the boot loader passed the MAC address in devicetree */
    if ((mac_of = of_get_mac_address(inst->pUsbDev->dev.of_node))) {
        from = "read from device tree";
        memcpy(mac, mac_of, ETH_ALEN);
    } else if (smsc95xx_read_eeprom(inst, EEPROM_MAC_OFFSET, ETH_ALEN, mac) == 0
        && is_valid_ether_addr(mac)) {
            /* eeprom values are valid so use them */
            from = "read from EEPROM";
    } else { /* No eeprom, or eeprom values are invalid. Generating a random MAC address */
        eth_random_addr(mac);
        from = "randomly generated";
    }

    DEBUG_LVL_EDRV_TRACE("MAC address was %s: %pM\n", from, mac);
}

static int smsc95xx_write_hwaddr(tEdrvInstance *inst)
{
    u32 temp = 0;
    int ret;

    /* set hardware address */
    DEBUG_LVL_EDRV_TRACE("** %s()\n", __func__);
    temp |= inst->initParam.aMacAddr[0] <<  0;
    temp |= inst->initParam.aMacAddr[1] <<  8;
    temp |= inst->initParam.aMacAddr[2] << 16;
    temp |= inst->initParam.aMacAddr[3] << 24;
    ret = smsc95xx_write_reg(inst, ADDRL, temp);
    if (ret < 0)
        return ret;

    temp = 0;
    temp |= inst->initParam.aMacAddr[4] <<  0;
    temp |= inst->initParam.aMacAddr[5] <<  8;
    ret = smsc95xx_write_reg(inst, ADDRH, temp);
    if (ret < 0)
        return ret;

    DEBUG_LVL_EDRV_TRACE("MAC %pM\n", inst->initParam.aMacAddr);
    return 0;
}

/* Enable or disable Tx & Rx checksum offload engines */
static int smsc95xx_set_csums(tEdrvInstance *dev, int csums)
{
    u32 read_buf;
    int ret = smsc95xx_read_reg(dev, COE_CR, &read_buf);
    if (ret < 0)
        return ret;

    if (csums & USE_TX_CSUM)
        read_buf |= Tx_COE_EN;
    else
        read_buf &= ~Tx_COE_EN;

    if (csums & USE_RX_CSUM)
        read_buf |= Rx_COE_EN;
    else
        read_buf &= ~Rx_COE_EN;

    ret = smsc95xx_write_reg(dev, COE_CR, read_buf);
    if (ret < 0)
        return ret;

    DEBUG_LVL_EDRV_TRACE("COE_CR = 0x%08x\n", read_buf);
    return 0;
}

static void smsc95xx_set_multicast(tEdrvInstance *dev)
{
    /* No multicast in u-boot */
    dev->mac_cr &= ~(MAC_CR_PRMS | MAC_CR_MCPAS | MAC_CR_HPFILT);
}

/* starts the TX path */
static void smsc95xx_start_tx_path(tEdrvInstance *dev)
{
    u32 reg_val;

    /* Enable Tx at MAC */
    dev->mac_cr |= MAC_CR_TXEN;

    smsc95xx_write_reg(dev, MAC_CR, dev->mac_cr);

    /* Enable Tx at SCSRs */
    reg_val = TX_CFG_ON;
    smsc95xx_write_reg(dev, TX_CFG, reg_val);
}

/* Starts the Receive path */
static void smsc95xx_start_rx_path(tEdrvInstance *dev)
{
    dev->mac_cr |= MAC_CR_RXEN;
    smsc95xx_write_reg(dev, MAC_CR, dev->mac_cr);
}

static enum hrtimer_restart smsc95xx_recv(struct hrtimer *timer)
{
    static unsigned char  recv_buf[AX_RX_URB_SIZE]; /* kzalloc instead? */
    unsigned char *buf_ptr;
    int err;
    int actual_len;
    u32 packet_len;
    int cur_buf_align;
    struct tasklet_hrtimer *thr = container_of(timer, struct tasklet_hrtimer, timer);
    tEdrvInstance *dev = container_of(thr, tEdrvInstance, poll_timer);

    DEBUG_LVL_EDRV_TRACE("** %s()\n", __func__);
    err = usb_bulk_msg(dev->pUsbDev,
                dev->ep_in,
                (void *)recv_buf,
                AX_RX_URB_SIZE,
                &actual_len,
                500);
    if (err == -ETIMEDOUT)
        goto Exit;
    DEBUG_LVL_EDRV_TRACE("Rx: len = %u, actual = %u, err = %d\n", AX_RX_URB_SIZE,
          actual_len, err);
    if (err != 0) {
        DEBUG_LVL_ERROR_TRACE("Rx: failed to receive\n");
        goto Exit;
    }
    if (actual_len > AX_RX_URB_SIZE) {
        DEBUG_LVL_ERROR_TRACE("Rx: received too many bytes %d\n", actual_len);
        err = -EIO;
        goto Exit;
    }

    buf_ptr = recv_buf;
    while (actual_len > 0) {
        /*
         * 1st 4 bytes contain the length of the actual data plus error
         * info. Extract data length.
         */
        if (actual_len < sizeof(packet_len)) {
            DEBUG_LVL_ERROR_TRACE("Rx: incomplete packet length\n");
            err = -EIO;
            goto Exit;
        }
        memcpy(&packet_len, buf_ptr, sizeof(packet_len));
        le32_to_cpus(&packet_len);
        if (packet_len & RX_STS_ES) {
            DEBUG_LVL_ERROR_TRACE("Rx: Error header=%#x", packet_len);
            err = -EIO;
            goto Exit;
        }
        packet_len = ((packet_len & RX_STS_FL) >> 16);

        if (packet_len > actual_len - sizeof(packet_len)) {
            DEBUG_LVL_ERROR_TRACE("Rx: too large packet: %d\n", packet_len);
            err = -EIO;
            goto Exit;
        }

        /* Notify state machine */
        if (edrvInstance_l.initParam.pfnRxHandler != NULL)
        {
            tEdrvRxBuffer rxBuffer;
            rxBuffer.bufferInFrame = kEdrvBufferLastInFrame;
            rxBuffer.rxFrameSize = packet_len - 4;
            rxBuffer.pBuffer = buf_ptr + sizeof packet_len;

            edrvInstance_l.initParam.pfnRxHandler(&rxBuffer);
        }

        /* Adjust for next iteration */
        actual_len -= sizeof(packet_len) + packet_len;
        buf_ptr += sizeof(packet_len) + packet_len;
        cur_buf_align = (int)buf_ptr - (int)recv_buf;

        if (cur_buf_align & 0x03) {
            int align = 4 - (cur_buf_align & 0x03);

            actual_len -= align;
            buf_ptr += align;
        }
    }
Exit:
    return HRTIMER_RESTART;
    //return err;
}

/// \}
