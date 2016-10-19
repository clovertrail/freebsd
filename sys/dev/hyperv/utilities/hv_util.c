/*-
 * Copyright (c) 2014,2016 Microsoft Corp.
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

/*
 * A common driver for all hyper-V util services.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/reboot.h>
#include <sys/systm.h>
#include <sys/timetc.h>

#include <dev/hyperv/include/hyperv.h>
#include <dev/hyperv/include/vmbus.h>
#include <dev/hyperv/utilities/hv_util.h>
#include <dev/hyperv/utilities/vmbus_icreg.h>
#include <dev/hyperv/utilities/hv_utilreg.h>
#include <dev/hyperv/utilities/hv_common.h>

#include "vmbus_if.h"

#define VMBUS_IC_BRSIZE		(4 * PAGE_SIZE)

#define VMBUS_IC_VERCNT		2
#define VMBUS_IC_NEGOSZ		\
	__offsetof(struct vmbus_icmsg_negotiate, ic_ver[VMBUS_IC_VERCNT])
CTASSERT(VMBUS_IC_NEGOSZ < VMBUS_IC_BRSIZE);

int util_fw_ver = UTIL_FW_VERSION;
int sd_srv_ver  = SD_VERSION;
int ts_srv_ver  = TS_VERSION;
int hb_srv_ver  = HB_VERSION;
int kvp_srv_ver = KVP_WIN8_SRV_VERSION;

int
vmbus_ic_probe(device_t dev, const struct vmbus_ic_desc descs[])
{
	device_t bus = device_get_parent(dev);
	const struct vmbus_ic_desc *d;

	if (resource_disabled(device_get_name(dev), 0))
		return (ENXIO);

	for (d = descs; d->ic_desc != NULL; ++d) {
		if (VMBUS_PROBE_GUID(bus, dev, &d->ic_guid) == 0) {
			device_set_desc(dev, d->ic_desc);
			return (BUS_PROBE_DEFAULT);
		}
	}
	return (ENXIO);
}

int
hv_util_attach(device_t dev, vmbus_chan_callback_t cb)
{
	struct hv_util_sc *sc = device_get_softc(dev);
	struct vmbus_channel *chan = vmbus_get_channel(dev);
	uint32_t vmbus_version;
	int error;

	vmbus_version = VMBUS_GET_VERSION(device_get_parent(dev), dev);
	sc->ic_dev = dev;
	sc->ic_buflen = VMBUS_IC_BRSIZE;
	sc->receive_buffer = malloc(VMBUS_IC_BRSIZE, M_DEVBUF,
	    M_WAITOK | M_ZERO);

	switch(vmbus_version) {
	case VMBUS_VERSION_WS2008:
		util_fw_ver = UTIL_WS2K8_FW_VERSION;
		kvp_srv_ver = KVP_WS2008_SRV_VERSION;
		sd_srv_ver = SD_WS2008_VERSION;
		ts_srv_ver = TS_WS2008_VERSION;
		hb_srv_ver = HB_WS2008_VERSION;
		break;
	case VMBUS_VERSION_WIN7:
		util_fw_ver = UTIL_FW_VERSION;
		kvp_srv_ver = KVP_WIN7_SRV_VERSION;
		sd_srv_ver = SD_VERSION;
		ts_srv_ver = TS_VERSION;
		hb_srv_ver = HB_VERSION;
		break;
	default:
		util_fw_ver = UTIL_FW_VERSION;
		kvp_srv_ver = KVP_WIN8_SRV_VERSION;
		sd_srv_ver = SD_VERSION;
		ts_srv_ver = TS_VERSION;
		hb_srv_ver = HB_VERSION;
	}
	/*
	 * These services are not performance critical and do not need
	 * batched reading. Furthermore, some services such as KVP can
	 * only handle one message from the host at a time.
	 * Turn off batched reading for all util drivers before we open the
	 * channel.
	 */
	vmbus_chan_set_readbatch(chan, false);

	error = vmbus_chan_open(chan, VMBUS_IC_BRSIZE, VMBUS_IC_BRSIZE, NULL, 0,
	    cb, sc);
	if (error) {
		free(sc->receive_buffer, M_DEVBUF);
		return (error);
	}
	return (0);
}

int
hv_util_detach(device_t dev)
{
	struct hv_util_sc *sc = device_get_softc(dev);

	vmbus_chan_close(vmbus_get_channel(dev));
	free(sc->receive_buffer, M_DEVBUF);

	return (0);
}

/*
 * version neogtiation function
 * Create default response for Hyper-V Negotiate message
 * @buf: Raw buffer channel data
 * @framewrk_ver specifies the  framework version that we can support
 * @service_ver specifies the service version we can support.
 */

boolean_t
hv_util_negotiate_version(uint8_t *buf, int framewrk_ver, int service_ver)
{
	struct hv_vmbus_icmsg_negotiate *negop;
	int icmsg_major, icmsg_minor;
	int fw_major, fw_minor;
	int srv_major, srv_minor;
	int i;
	int icframe_major, icframe_minor;
	struct hv_vmbus_icmsg_hdr *icmsghdrp;
	boolean_t found = FALSE;

	icmsghdrp = (struct hv_vmbus_icmsg_hdr *)
	    &buf[sizeof(struct hv_vmbus_pipe_hdr)];
	icmsghdrp->icmsgsize = 0x10;

	fw_major = (framewrk_ver >> 16);
	fw_minor = (framewrk_ver & 0xFFFF);

	srv_major = (service_ver >> 16);
	srv_minor = (service_ver & 0xFFFF);

	negop = (struct hv_vmbus_icmsg_negotiate *)&buf[
		sizeof(struct hv_vmbus_pipe_hdr) +
		sizeof(struct hv_vmbus_icmsg_hdr)];

	icframe_major = negop->icframe_vercnt;
	icframe_minor = 0;
	icmsg_major = negop->icmsg_vercnt;
	icmsg_minor = 0;
	/*
	 * Select the framework version number we will support
	 */
	for (i = 0; i < negop->icframe_vercnt; i++) {
		if ((negop->icversion_data[i].major == fw_major) &&
		   (negop->icversion_data[i].minor == fw_minor)) {
			icframe_major = negop->icversion_data[i].major;
			icframe_minor = negop->icversion_data[i].minor;
			found = true;
		}
	}

	if (!found)
		goto handle_error;
	found = false;

	for (i = negop->icframe_vercnt;
	    i < negop->icframe_vercnt + negop->icmsg_vercnt; i++) {
		if ((negop->icversion_data[i].major == srv_major) &&
		   (negop->icversion_data[i].minor == srv_minor)) {
			icmsg_major = negop->icversion_data[i].major;
			icmsg_minor = negop->icversion_data[i].minor;
			found = true;
		}
	}

handle_error:
	if (!found) {
		negop->icframe_vercnt = 0;
		negop->icmsg_vercnt = 0;
	} else {
		negop->icframe_vercnt = 1;
		negop->icmsg_vercnt = 1;
	}

	negop->icversion_data[0].major = icframe_major;
	negop->icversion_data[0].minor = icframe_minor;
	negop->icversion_data[1].major = icmsg_major;
	negop->icversion_data[1].minor = icmsg_minor;
	return found;
}
