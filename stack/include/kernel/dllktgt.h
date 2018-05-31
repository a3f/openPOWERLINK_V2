/**
********************************************************************************
\file   kernel/dllktgt.h

\brief  Target specific definitions for DLL kernel module files

This file contains target specific definitions used by the DLL kernel
implementation files.
*******************************************************************************/

/*------------------------------------------------------------------------------
Copyright (c) 2013, SYSTEC electronic GmbH
Copyright (c) 2016, B&R Industrial Automation GmbH
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
#ifndef _INC_kernel_dllktgt_H_
#define _INC_kernel_dllktgt_H_

//------------------------------------------------------------------------------
// includes
//------------------------------------------------------------------------------
#include <common/oplkinc.h>

//------------------------------------------------------------------------------
// const defines
//------------------------------------------------------------------------------
#if ((TARGET_SYSTEM == _LINUX_) && defined(__KERNEL__))
// Linux kernel requires the critical section within DLL
#include <linux/spinlock.h>

typedef struct {
    spinlock_t lock;
    int pid;
    atomic_t count;
} tRecursiveLock;

static inline void dll_recursiveSpinLock_irqsave(tRecursiveLock *lock, ULONG tgtDllkFlags)
{
    if (lock->pid == current->pid) {
        atomic_inc(&lock->count);
        tgtDllkFlags = 0;
    } else {
        spin_lock_irqsave(&lock->lock, tgtDllkFlags);
        atomic_inc(&lock->count);
        lock->pid = current->pid;
    }
}
static inline void dll_recursiveSpinUnlock_irqrestore(tRecursiveLock *lock, ULONG tgtDllkFlags)
{
    if (atomic_dec_and_test(&lock->count)) {
        lock->pid = NULL;
        spin_unlock_irqrestore(&lock->lock, tgtDllkFlags);
    }
}

// edrv-bridge_linux might call into DLL for Tx confirmation while holding the lock,
// so we use a recursive lock instead.
static inline void dll_recursiveSpinLockInit(tRecursiveLock *lock) {
        spin_lock_init(&lock->lock);
        lock->pid = -1;
        atomic_set(&lock->count, 0);
}

#ifdef DLL_USE_RECURSIVE_LOCK

#define TGT_DLLK_DEFINE_CRITICAL_SECTION    tRecursiveLock tgtDllkCriticalSection_l;
#define TGT_DLLK_DECLARE_CRITICAL_SECTION   extern tRecursiveLock tgtDllkCriticalSection_l;
#define TGT_DLLK_INITIALIZE_CRITICAL_SECTION()  dll_recursiveSpinLockInit(&tgtDllkCriticalSection_l);
#define TGT_DLLK_DECLARE_FLAGS              ULONG tgtDllkFlags;
#define TGT_DLLK_ENTER_CRITICAL_SECTION()   dll_recursiveSpinLock_irqsave(&tgtDllkCriticalSection_l, tgtDllkFlags);
#define TGT_DLLK_LEAVE_CRITICAL_SECTION()   dll_recursiveSpinUnlock_irqrestore(&tgtDllkCriticalSection_l, tgtDllkFlags);

#else /* DLL_USE_RECURSIVE_LOCK */

#define TGT_DLLK_DEFINE_CRITICAL_SECTION    DEFINE_SPINLOCK(tgtDllkCriticalSection_l);
#define TGT_DLLK_DECLARE_CRITICAL_SECTION   extern spinlock_t tgtDllkCriticalSection_l;
#define TGT_DLLK_INITIALIZE_CRITICAL_SECTION()
#define TGT_DLLK_DECLARE_FLAGS              ULONG tgtDllkFlags;
#define TGT_DLLK_ENTER_CRITICAL_SECTION()   spin_lock_irqsave(&tgtDllkCriticalSection_l, tgtDllkFlags);
#define TGT_DLLK_LEAVE_CRITICAL_SECTION()   spin_unlock_irqrestore(&tgtDllkCriticalSection_l, tgtDllkFlags);

#endif /* DLL_USE_RECURSIVE_LOCK */


#else   /* ((TARGET_SYSTEM == _LINUX_) && defined(__KERNEL__)) */

// all other targets do not need the critical section within DLL
#define TGT_DLLK_DEFINE_CRITICAL_SECTION
#define TGT_DLLK_DECLARE_CRITICAL_SECTION
#define TGT_DLLK_INITIALIZE_CRITICAL_SECTION()
#define TGT_DLLK_DECLARE_FLAGS
#define TGT_DLLK_ENTER_CRITICAL_SECTION()
#define TGT_DLLK_LEAVE_CRITICAL_SECTION()

#endif /* ((TARGET_SYSTEM == _LINUX_) && defined(__KERNEL__)) */

#endif  /* #ifndef _INC_kernel_dllktgt_H_ */
