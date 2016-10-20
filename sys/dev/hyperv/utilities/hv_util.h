/*-
 * Copyright (c) 2009-2012,2016 Microsoft Corp.
 * Copyright (c) 2012 NetApp Inc.
 * Copyright (c) 2012 Citrix Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _HVUTIL_H_
#define _HVUTIL_H_

#include <dev/hyperv/include/hyperv.h>
#include <dev/hyperv/include/vmbus.h>

/**
 * hv_util related structures
 *
 */
typedef struct hv_util_sc {
	device_t		ic_dev;
	uint8_t			*receive_buffer;
	int			ic_buflen;
} hv_util_sc;

struct vmbus_ic_desc {
	const struct hyperv_guid	ic_guid;
	const char			*ic_desc;
};

#define VMBUS_IC_DESC_END	{ .ic_desc = NULL }

int hv_util_attach(device_t dev, vmbus_chan_callback_t cb);
int hv_util_detach(device_t dev);
int vmbus_ic_probe(device_t dev, const struct vmbus_ic_desc descs[]);
int vmbus_ic_negomsg(device_t dev, void *data, int *dlen0,
    uint32_t fw_ver, uint32_t msg_ver);
/*
 * Framework version for util services.
 */
#define UTIL_FW_MINOR              0

#define UTIL_WS2008_FW_MAJOR       1
#define UTIL_WS2008_FW_VERSION     VMBUS_IC_VERSION(UTIL_WS2008_FW_MAJOR, UTIL_FW_MINOR)

#define UTIL_FW_MAJOR              3
#define UTIL_FW_VERSION            VMBUS_IC_VERSION(UTIL_FW_MAJOR, UTIL_FW_MINOR)

#endif
