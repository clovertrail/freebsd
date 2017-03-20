/*-
 * Copyright (c) 2017 Microsoft Corp.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/bus.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/lock.h>
#include <sys/taskqueue.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/kthread.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/sema.h>
#include <sys/signal.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/callout.h>

#include <dev/hyperv/include/hyperv.h>
#include <dev/hyperv/utilities/hv_utilreg.h>
#include <dev/hyperv/utilities/vmbus_icreg.h>
#include <dev/hyperv/utilities/vmbus_icvar.h>
#include <dev/hyperv/include/vmbus_xact.h>

#define HV_KBD_VER_MAJOR	(1)
#define HV_KBD_VER_MINOR	(0)

#define HV_KBD_VER		(HV_KBD_VER_MINOR | (HV_KBD_VER_MAJOR) << 16)

#define IS_UNICODE		(1)
#define IS_BREAK		(2)
#define IS_E0			(4)
#define IS_E1			(8)
//#define IS_TERMSRV_SET_LED	(8)
//#define IS_TERMSRV_SHADOW	(0x10)
//#define IS_TERMSRV_VKPACKET	(0x20)

#define HV_KBD_PROTO_ACCEPTED	(1)

#define HV_BUFF_SIZE		(4*PAGE_SIZE)
#define HV_KBD_RINGBUFF_SEND_SZ	(10*PAGE_SIZE)
#define HV_KBD_RINGBUFF_RECV_SZ (10*PAGE_SIZE)

enum hv_kbd_msg_type_t {
	HV_KBD_PROTO_REQUEST        = 1,
	HV_KBD_PROTO_RESPONSE       = 2,
	HV_KBD_PROTO_EVENT          = 3,
	HV_KBD_PROTO_LED_INDICATORS = 4,
};

typedef struct hv_kbd_msg_hdr_t {
	enum hv_kbd_msg_type_t type;
} hv_kbd_msg_hdr;

typedef struct hv_kbd_msg_t {
	hv_kbd_msg_hdr hdr;
	char data[];
} hv_kbd_msg;

typedef struct hv_kbd_proto_req_t {
	hv_kbd_msg_hdr	hdr;
	uint32_t	ver;
} hv_kbd_proto_req;

typedef struct hv_kbd_proto_resp_t {
	hv_kbd_msg_hdr  hdr;
	uint32_t	status;
} hv_kbd_proto_resp;

#define HV_KBD_PROTO_REQ_SZ	(sizeof(hv_kbd_proto_req))
#define HV_KBD_PROTO_RESP_SZ	(sizeof(hv_kbd_proto_resp))

typedef struct hv_kbd_keystroke_t {
	hv_kbd_msg_hdr  hdr;
	uint16_t	makecode;
	/* the struct in win host:
	 * typedef struct _HK_MESSAGE_KEYSTROKE
	 * {
	 *     HK_MESSAGE_HEADER Header;
	 *     UINT16 MakeCode;
	 *     UINT32 IsUnicode:1;
	 *     UINT32 IsBreak:1;
	 *     UINT32 IsE0:1;
	 *     UINT32 IsE1:1;
	 *     UINT32 Reserved:28;
	 * } HK_MESSAGE_KEYSTROKE
	 **/
	uint32_t	info;
} hv_kbd_keystroke;

typedef struct hv_kbd_sc {
	struct vmbus_channel	*hs_chan;
	device_t		dev;
	struct vmbus_xact_ctx	*hs_xact;
	hv_kbd_proto_resp	resp;
	int32_t			buflen;
	uint8_t			*buf;
} hv_kbd_sc;

static const struct vmbus_ic_desc vmbus_kbd_descs[] = {
	{
		.ic_guid = { .hv_guid = {
		    0x6d, 0xad, 0x12, 0xf9, 0x17, 0x2b, 0xea, 0x48,
		    0xbd, 0x65, 0xf9, 0x27, 0xa6, 0x1c, 0x76,  0x84} },
		.ic_desc = "Hyper-V KBD"
	},
	VMBUS_IC_DESC_END
};

static int hv_kbd_attach(device_t dev);
static int hv_kbd_detach(device_t dev);

static int
hv_kbd_probe(device_t dev)
{
	return (vmbus_ic_probe(dev, vmbus_kbd_descs));
}

static void
hv_kbd_on_received(hv_kbd_sc *sc, struct vmbus_chanpkt_hdr *pkt)
{

	const hv_kbd_msg *msg = VMBUS_CHANPKT_CONST_DATA(pkt);
	const hv_kbd_proto_resp *resp =
	    VMBUS_CHANPKT_CONST_DATA(pkt);
	const hv_kbd_keystroke *keystroke =
	    VMBUS_CHANPKT_CONST_DATA(pkt);
	uint32_t msg_len = VMBUS_CHANPKT_DATALEN(pkt);
	enum hv_kbd_msg_type_t msg_type;
	uint32_t info;
	uint16_t scan_code;

	if (msg_len <= sizeof(hv_kbd_msg)) {
		device_printf(sc->dev, "Illegal packet\n");
		return;
	}
	msg_type = msg->hdr.type;
	switch (msg_type) {
		case HV_KBD_PROTO_RESPONSE:
			device_printf(sc->dev, "==resp: 0x%x\n",
			    resp->status);
			break;
		case HV_KBD_PROTO_EVENT:
			info = keystroke->info;
			scan_code = keystroke->makecode;
			device_printf(sc->dev, "--key info: 0x%x, scan: 0x%x\n",
			    info, scan_code);
		default:
			break;
	}
}
static void 
hv_kbd_on_channel_callback(struct vmbus_channel *channel, void *xsc)
{
	uint8_t *buf;
	uint32_t buflen = 0;
	int ret = 0;

	hv_kbd_sc *sc = (hv_kbd_sc*)xsc;
	buf = sc->buf;
	buflen = sc->buflen;
	while (1) {
		struct vmbus_chanpkt_hdr *pkt = (struct vmbus_chanpkt_hdr *)buf;
		uint32_t rxed = buflen;

		ret = vmbus_chan_recv_pkt(channel, pkt, &rxed);
		if (ret == ENOBUFS) {
			buflen = sc->buflen * 2;
			while (buflen < rxed)
				buflen *= 2;
			buf = malloc(buflen, M_DEVBUF, M_WAITOK | M_ZERO);
			device_printf(sc->dev, "expand recvbuf %d -> %d\n",
			    sc->buflen, buflen);
			free(sc->buf, M_DEVBUF);
			sc->buf = buf;
			sc->buflen = buflen;
			continue;
		}
		switch (pkt->cph_type) {
			case VMBUS_CHANPKT_TYPE_COMP:
			case VMBUS_CHANPKT_TYPE_RXBUF:
				break;
			case VMBUS_CHANPKT_TYPE_INBAND:
				hv_kbd_on_received(sc, pkt);
				break;
			default:
				break;
		}
		vmbus_xact_ctx_wakeup(sc->hs_xact, VMBUS_CHANPKT_CONST_DATA(pkt),
		    VMBUS_CHANPKT_DATALEN(pkt));
	}
}

static int
hv_kbd_connect_vsp(hv_kbd_sc *sc)
{
	int ret;
	size_t resplen;
	struct vmbus_xact *xact;
	hv_kbd_proto_req *req;
	const hv_kbd_proto_resp *resp;
	//bzero(req, sizeof(hv_kbd_proto_req));

	xact = vmbus_xact_get(sc->hs_xact, sizeof(*req));
	if (xact == NULL) {
		device_printf(sc->dev, "no xact for kbd init");
		return (ENODEV);
	}
	req = vmbus_xact_req_data(xact);
	req->hdr.type = HV_KBD_PROTO_REQUEST;
	req->ver = HV_KBD_VER;

	vmbus_xact_activate(xact);
	ret = vmbus_chan_send(sc->hs_chan,
		VMBUS_CHANPKT_TYPE_INBAND,
		VMBUS_CHANPKT_FLAG_RC,
		req, sizeof(hv_kbd_proto_req),
		(uint64_t)(uintptr_t)req);
	if (ret) {
		vmbus_xact_deactivate(xact);
		return (ret);
	}
	resp = vmbus_chan_xact_wait(sc->hs_chan, xact, &resplen, true);
	if (resplen < HV_KBD_PROTO_RESP_SZ) {
		device_printf(sc->dev, "hv_kbd init communicate failed\n");
		return (ENODEV);
	}

	if (!(resp->status & HV_KBD_PROTO_ACCEPTED)) {
		device_printf(sc->dev, "hv_kbd protocol request failed\n");
		return (ENODEV);
	}
	return (0);
}

static int
hv_kbd_attach1(device_t dev, vmbus_chan_callback_t cb)
{
	int ret;
	hv_kbd_sc *sc;

        sc = device_get_softc(dev);
	sc->buflen = HV_BUFF_SIZE;
	sc->buf = malloc(sc->buflen, M_DEVBUF, M_WAITOK | M_ZERO);
	vmbus_chan_set_readbatch(sc->hs_chan, false);
	ret = vmbus_chan_open(
		sc->hs_chan,
		HV_KBD_RINGBUFF_SEND_SZ,
		HV_KBD_RINGBUFF_RECV_SZ,
		NULL, 0,
		cb,
		sc);
	if (ret != 0) {
		free(sc->buf, M_DEVBUF);
	}
	return (ret);
}

static int
hv_kbd_detach1(device_t dev)
{
	hv_kbd_sc *sc = device_get_softc(dev);
	vmbus_chan_close(vmbus_get_channel(dev));
	free(sc->buf, M_DEVBUF);
	return (0);
}

static int
hv_kbd_attach(device_t dev)
{
	int error = 0;
	hv_kbd_sc *sc;

	sc = device_get_softc(dev);
	sc->hs_chan = vmbus_get_channel(dev);
	sc->dev = dev;
	sc->hs_xact = vmbus_xact_ctx_create(bus_get_dma_tag(dev),
	    HV_KBD_PROTO_REQ_SZ, HV_KBD_PROTO_RESP_SZ, 0);
	if (sc->hs_xact == NULL) {
		error = ENOMEM;
		goto failed;
	}

	hv_kbd_attach1(dev, hv_kbd_on_channel_callback);
	error = hv_kbd_connect_vsp(sc);
	if (error)
		goto failed;
failed:
	hv_kbd_detach(dev);
	return (error);
}

static int
hv_kbd_detach(device_t dev)
{
	hv_kbd_sc *sc = device_get_softc(dev);
	if (sc->hs_xact != NULL)
		vmbus_xact_ctx_destroy(sc->hs_xact);
	return (hv_kbd_detach1(dev));
}

static device_method_t kbd_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, hv_kbd_probe),
	DEVMETHOD(device_attach, hv_kbd_attach),
	DEVMETHOD(device_detach, hv_kbd_detach),
	{ 0, 0 }
};

static driver_t kbd_driver = { "hvkbd", kbd_methods, sizeof(hv_kbd_sc)};

static devclass_t kbd_devclass;

DRIVER_MODULE(hv_kbd, vmbus, kbd_driver, kbd_devclass, NULL, NULL);
MODULE_VERSION(hv_kbd, 1);
MODULE_DEPEND(hv_kbd, vmbus, 1, 1, 1);
