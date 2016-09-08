/*-
 * Copyright (c) 2016 Microsoft Corp.
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
#include <sys/un.h>
#include <sys/endian.h>
#include <sys/sema.h>
#include <sys/signal.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/callout.h>

#include <dev/hyperv/include/hyperv.h>
#include <dev/hyperv/utilities/hv_utilreg.h>
#include <dev/hyperv/utilities/vmbus_icreg.h>

#include "hv_util.h"
#include "hv_snapshot.h"
#include "vmbus_if.h"

#define VSS_MAJOR		5
#define VSS_MINOR		0
#define VSS_MSGVER		VMBUS_IC_VERSION(VSS_MAJOR, VSS_MINOR)

#define VSS_FWVER_MAJOR		3
#define VSS_FWVER		VMBUS_IC_VERSION(VSS_FWVER_MAJOR, 0)

enum hv_vss_op {
	VSS_OP_CREATE = 0,
	VSS_OP_DELETE,
	VSS_OP_HOT_BACKUP,
	VSS_OP_GET_DM_INFO,
	VSS_OP_BU_COMPLETE,
	/*
	 * Following operations are only supported with IC version >= 5.0
	 */
	VSS_OP_FREEZE, /* Freeze the file systems in the VM */
	VSS_OP_THAW, /* Unfreeze the file systems */
	VSS_OP_AUTO_RECOVER,
	VSS_OP_COUNT /* Number of operations, must be last */
};

/*
 * Header for all VSS messages.
 */
struct hv_vss_hdr {
	struct vmbus_icmsg_hdr	ic_hdr;
	uint8_t			operation;
	uint8_t			reserved[7];
} __attribute__((packed));


/*
 * Flag values for the hv_vss_check_feature. Here supports only
 * one value.
 */
#define VSS_HBU_HAS_NON_SNAPSHOTTABLE_VOLS	0x00000002
#define VSS_HBU_NO_AUTO_RECOVERY		0x00000005

struct hv_vss_check_feature {
	uint32_t flags;
} __attribute__((packed));

struct hv_vss_check_dm_info {
	uint32_t flags;
} __attribute__((packed));

struct hv_vss_msg {
	union {
		struct hv_vss_hdr vss_hdr;
	} hdr;
	union {
		struct hv_vss_check_feature vss_cf;
		struct hv_vss_check_dm_info dm_info;
	} body;
} __attribute__((packed));

struct hv_vss_req {
	struct hv_vss_opt_msg	opt_msg;	/* used to communicate with daemon */
	struct hv_vss_msg	msg;		/* used to communicate with host */
} __attribute__((packed));

#define BUFFERSIZE		sizeof(struct hv_vss_req)
#define OPENED_REF_LIMIT	2
/* hv_vss debug control */
static int hv_vss_log = 0;

#define	hv_vss_log_error(...)	do {				\
	if (hv_vss_log > 0)					\
		log(LOG_ERR, "hv_vss: " __VA_ARGS__);		\
} while (0)

#define	hv_vss_log_info(...) do {				\
	if (hv_vss_log > 1)					\
		log(LOG_INFO, "hv_vss: " __VA_ARGS__);		\
} while (0)

static const struct vmbus_ic_desc vmbus_vss_descs[] = {
	{
		.ic_guid = { .hv_guid = {
		    0x29, 0x2e, 0xfa, 0x35, 0x23, 0xea, 0x36, 0x42,
		    0x96, 0xae, 0x3a, 0x6e, 0xba, 0xcb, 0xa4,  0x40} },
		.ic_desc = "Hyper-V VSS"
	},
	VMBUS_IC_DESC_END
};

static const char * vss_opt_name[] = {"None", "VSSCheck", "Freeze", "Thaw"};

/* character device prototypes */
static d_open_t		hv_vss_dev_open;
static d_close_t	hv_vss_dev_close;
static d_poll_t		hv_vss_dev_daemon_poll;
static d_ioctl_t	hv_vss_dev_daemon_ioctl;

static d_open_t		hv_appvss_dev_open;
static d_close_t	hv_appvss_dev_close;
static d_poll_t		hv_appvss_dev_daemon_poll;
static d_ioctl_t	hv_appvss_dev_daemon_ioctl;

typedef void vss_timeout_t(void *arg);
static vss_timeout_t	hv_vss_freeze_timeout;
static vss_timeout_t	hv_vss_thaw_timeout;
static vss_timeout_t	hv_vss_check_timeout;
static vss_timeout_t	hv_appvss_freeze_timeout;
static vss_timeout_t	hv_appvss_thaw_timeout;
static vss_timeout_t	hv_appvss_check_timeout;
/* hv_vss character device structure */
static struct cdevsw hv_vss_cdevsw =
{
	.d_version	= D_VERSION,
	.d_open		= hv_vss_dev_open,
	.d_close	= hv_vss_dev_close,
	.d_poll		= hv_vss_dev_daemon_poll,
	.d_ioctl	= hv_vss_dev_daemon_ioctl,
	.d_name		= FS_VSS_DEV_NAME,
};

static struct cdevsw hv_appvss_cdevsw =
{
	.d_version	= D_VERSION,
	.d_open		= hv_appvss_dev_open,
	.d_close	= hv_appvss_dev_close,
	.d_poll		= hv_appvss_dev_daemon_poll,
	.d_ioctl	= hv_appvss_dev_daemon_ioctl,
	.d_name		= APP_VSS_DEV_NAME,
};

/*
 * Global state to track and synchronize multiple
 * KVP transaction requests from the host.
 */
typedef struct hv_vss_sc {
	struct hv_util_sc	util_sc;
	device_t		dev;

	struct task		task;

	/*
	 * mutex is used to protect access of list/queue,
	 * callout in request is also used this mutex.
	 */
	struct mtx		pending_mutex;
	/*
	 * req_free_list contains all free items
	 */
	LIST_HEAD(, hv_vss_req_internal)   req_free_list;
	/*
	 * msg was transferred from host to notify queue, and
	 * ack queue. Finally, it was recyled to free list.
	 */
	STAILQ_HEAD(, hv_vss_req_internal) to_daemon_notify_queue;
	STAILQ_HEAD(, hv_vss_req_internal) to_daemon_ack_queue;
	STAILQ_HEAD(, hv_vss_req_internal) to_app_notify_queue;
	STAILQ_HEAD(, hv_vss_req_internal) to_app_ack_queue;

	/* Indicates if daemon registered with driver */
	boolean_t		register_done;

	boolean_t		app_register_done;

	/* cdev for file system freeze/thaw */
	struct cdev		*hv_vss_dev;
	/* cdev for application freeze/thaw */
	struct cdev		*hv_appvss_dev;

	struct proc		*daemon_task;

	struct proc		*app_task;

	struct selinfo		hv_vss_selinfo;

	struct selinfo		hv_appvss_selinfo;

	/* count the registered vss service */
	uint32_t		vss_serv_count;

	uint32_t		hbu_status;
} hv_vss_sc;

typedef struct hv_vss_req_internal {
	LIST_ENTRY(hv_vss_req_internal)		link;
	STAILQ_ENTRY(hv_vss_req_internal)	slink;
	struct hv_vss_req			vss_req;

	/* Rcv buffer for communicating with the host*/
	uint8_t					*rcv_buf;
	/* Length of host message */
	uint32_t				host_msg_len;
	/* Host message id */
	uint64_t				host_msg_id;

	hv_vss_sc				*sc;

	struct callout				callout;
} hv_vss_req_internal;

#define SEARCH_REMOVE_REQ_LOCKED(reqp, queue, link, tmp, id)		\
	do {								\
		STAILQ_FOREACH_SAFE(reqp, queue, link, tmp) {		\
			if (reqp->vss_req.opt_msg.msgid == id) {	\
				STAILQ_REMOVE(queue,			\
				    reqp, hv_vss_req_internal, link);	\
				break;					\
			}						\
		}							\
	} while (0)
/*
 * Callback routine that gets called whenever there is a message from host
 */
static void
hv_vss_callback(struct vmbus_channel *chan __unused, void *context)
{
	hv_vss_sc *sc = (hv_vss_sc*)context;
	if (sc->register_done) {
		hv_vss_log_info("%s: Queuing work item\n", __func__);
		taskqueue_enqueue(taskqueue_thread, &sc->task);
	} else {
		if (sc->daemon_task)
			hv_vss_log_info("%s: daemon was killed!\n", __func__);
	}
	hv_vss_log_info("%s: received msg from host\n", __func__);
}
/*
 * Send the response back to the host.
 */
static void
hv_vss_respond_host(uint8_t *rcv_buf, struct vmbus_channel *ch,
    uint32_t recvlen, uint64_t requestid, uint32_t error)
{
	struct vmbus_icmsg_hdr *hv_icmsg_hdrp;

	hv_icmsg_hdrp = (struct vmbus_icmsg_hdr *)rcv_buf;

	hv_icmsg_hdrp->ic_status = error;
	hv_icmsg_hdrp->ic_flags = HV_ICMSGHDRFLAG_TRANSACTION | HV_ICMSGHDRFLAG_RESPONSE;

	error = vmbus_chan_send(ch, VMBUS_CHANPKT_TYPE_INBAND, 0,
	    rcv_buf, recvlen, requestid);
	if (error)
		hv_vss_log_info("%s: hv_vss_respond_host: sendpacket error:%d\n",
		    __func__, error);
}

static void
hv_vss_notify_host_result(struct hv_vss_req_internal *reqp, uint32_t status)
{
	hv_vss_sc *sc = reqp->sc;
	/* stop VSS since error was found */
	hv_vss_respond_host(reqp->rcv_buf, vmbus_get_channel(reqp->sc->dev),
	    reqp->host_msg_len, reqp->host_msg_id, status);
	/* recycle the request */
	mtx_lock(&sc->pending_mutex);
	LIST_INSERT_HEAD(&sc->req_free_list, reqp, link);
	mtx_unlock(&sc->pending_mutex);
}

static void
hv_vss_notify_host_hbu_status(void *arg, uint32_t status)
{
	hv_vss_req_internal *reqp 	= arg;
	hv_vss_sc* sc			= reqp->sc;
	uint32_t volatile ref;
	struct hv_vss_msg* msg = (struct hv_vss_msg *)reqp->rcv_buf;
	sc->hbu_status |= status;
	ref = atomic_fetchadd_int(&sc->vss_serv_count, 0);
	if (ref == 0 || sc->hbu_status == VSS_FAIL) {
		if (sc->hbu_status == VSS_FAIL)
			status = HV_E_FAIL;
		else
			status = HV_S_OK;
		msg->body.vss_cf.flags = VSS_HBU_NO_AUTO_RECOVERY;
		hv_vss_notify_host_result(reqp, status);
		hv_vss_log_info("%s, response %s to host\n",
		    __func__, status == HV_S_OK ? "HBU supp" : "HBU Not supp");
		atomic_set_int(&sc->vss_serv_count, 0);
		sc->hbu_status = 0;
	}
}

static void
hv_vss_cp_vssreq_to_user(struct hv_vss_req_internal *reqp, struct hv_vss_opt_msg *userdata)
{
	struct hv_vss_req *hv_vss_dev_buf;
	hv_vss_dev_buf = &reqp->vss_req;
	hv_vss_dev_buf->opt_msg.opt = HV_VSS_NONE;
	switch (reqp->vss_req.msg.hdr.vss_hdr.operation) {
	case VSS_OP_FREEZE:
		hv_vss_dev_buf->opt_msg.opt = HV_VSS_FREEZE;
		break;
	case VSS_OP_THAW:
		hv_vss_dev_buf->opt_msg.opt = HV_VSS_THAW;
		break;
	case VSS_OP_HOT_BACKUP:
		hv_vss_dev_buf->opt_msg.opt = HV_VSS_CHECK;
		break;
	}
	*userdata = hv_vss_dev_buf->opt_msg;
	hv_vss_log_info("%s, read data from user for "
	    "%s (%ld) \n",__func__, vss_opt_name[userdata->opt], userdata->msgid);
}

/**
 * Remove the request id from app notifiy or ack queue,
 * and recyle the request by inserting it to free list.
 *
 * When app was notified but not yet sending ack, the request
 * should locate in either notify queue or ack queue.
 */
static struct hv_vss_req_internal*
hv_vss_app_req_recyle(hv_vss_sc *sc, uint64_t req_id)
{
	struct hv_vss_req_internal *reqp, *tmp;
	mtx_lock(&sc->pending_mutex);
	SEARCH_REMOVE_REQ_LOCKED(reqp, &sc->to_app_notify_queue, slink, tmp, req_id);
	if (reqp == NULL)
		SEARCH_REMOVE_REQ_LOCKED(reqp, &sc->to_app_ack_queue, slink, tmp, req_id);
	if (reqp != NULL)
		LIST_INSERT_HEAD(&sc->req_free_list, reqp, link);
	mtx_unlock(&sc->pending_mutex);
	return (reqp);
}

/**
 * Remove the request id from app notifiy or ack queue,
 * and recyle the request by inserting it to free list.
 *
 * When app was notified but not yet sending ack, the request
 * should locate in either notify queue or ack queue.
 */
static struct hv_vss_req_internal*
hv_vss_daemon_req_recyle(hv_vss_sc *sc, uint64_t req_id)
{
	struct hv_vss_req_internal *reqp, *tmp;
	mtx_lock(&sc->pending_mutex);
	SEARCH_REMOVE_REQ_LOCKED(reqp, &sc->to_daemon_notify_queue, slink, tmp, req_id);
	if (reqp == NULL)
		SEARCH_REMOVE_REQ_LOCKED(reqp, &sc->to_daemon_ack_queue, slink, tmp, req_id);
	if (reqp != NULL)
		LIST_INSERT_HEAD(&sc->req_free_list, reqp, link);
	mtx_unlock(&sc->pending_mutex);
	return (reqp);
}
/**
 * Actions for daemon who has been notified.
 */
static void
hv_vss_daemon_notified(hv_vss_sc *sc, struct hv_vss_opt_msg *userdata)
{
	struct hv_vss_req_internal *reqp;
	mtx_lock(&sc->pending_mutex);
	if (!STAILQ_EMPTY(&sc->to_daemon_notify_queue)) {
		reqp = STAILQ_FIRST(&sc->to_daemon_notify_queue);
		hv_vss_cp_vssreq_to_user(reqp, userdata);
		STAILQ_REMOVE_HEAD(&sc->to_daemon_notify_queue, slink);
		/* insert the msg to queue for write */
		STAILQ_INSERT_TAIL(&sc->to_daemon_ack_queue, reqp, slink);
		userdata->status = VSS_SUCCESS;
	} else {
		/* Timeout occur, thus request was removed from queue. */
		hv_vss_log_info("%s: daemon notify queue is empty!\n", __func__);
		userdata->status = VSS_FAIL;
	}
	mtx_unlock(&sc->pending_mutex);
}

static void
hv_vss_notify_daemon(hv_vss_sc *sc, struct hv_vss_req_internal *reqp, vss_timeout_t t)
{
	uint32_t opt = reqp->vss_req.opt_msg.opt;
	mtx_lock(&sc->pending_mutex);
	STAILQ_INSERT_TAIL(&sc->to_daemon_notify_queue, reqp, slink);
	mtx_unlock(&sc->pending_mutex);
	selwakeup(&sc->hv_vss_selinfo);
	callout_reset_sbt(&reqp->callout, SBT_1S * 5, 0, t, reqp, 0);
	hv_vss_log_info("%s: issuing query %s (%ld) to daemon\n", __func__,
	    vss_opt_name[opt], reqp->vss_req.opt_msg.msgid);
}

static void
hv_vss_notify_app(hv_vss_sc *sc, struct hv_vss_req_internal *reqp, vss_timeout_t t)
{
	uint32_t opt = reqp->vss_req.opt_msg.opt;
	mtx_lock(&sc->pending_mutex);
	STAILQ_INSERT_TAIL(&sc->to_app_notify_queue, reqp, slink);
	mtx_unlock(&sc->pending_mutex);
	selwakeup(&sc->hv_appvss_selinfo);
	callout_reset_sbt(&reqp->callout, SBT_1S * 5, 0, t, reqp, 0);
	hv_vss_log_info("%s: issuing query %s (%ld) to app\n", __func__,
	    vss_opt_name[opt], reqp->vss_req.opt_msg.msgid);
}
/**
 * Actions for daemon who has acknowledged.
 */
static void
hv_vss_daemon_acked(hv_vss_sc *sc, struct hv_vss_opt_msg *userdata)
{
	struct hv_vss_req_internal	*reqp, *tmp;
	uint64_t			req_id;
	int				opt;
	uint32_t			status;

	opt = userdata->opt;
	req_id = userdata->msgid;
	status = userdata->status;
	mtx_lock(&sc->pending_mutex);
	SEARCH_REMOVE_REQ_LOCKED(reqp, &sc->to_daemon_ack_queue, slink, tmp, req_id);
	mtx_unlock(&sc->pending_mutex);
	if (reqp == NULL) {
		hv_vss_log_info("%s Timeout: fail to find daemon ack request\n",
		    __func__);
		userdata->status = VSS_FAIL;
		return;
	}
	callout_drain(&reqp->callout);
	KASSERT(opt == reqp->vss_req.opt_msg.opt, ("Mismatched VSS operation!"));
	hv_vss_log_info("%s, get response %d from daemon for %s (%ld) \n", __func__,
	    status, vss_opt_name[opt], req_id);
	if (sc->app_register_done &&
	    status == VSS_SUCCESS &&
	    opt == HV_VSS_THAW) {
		hv_vss_notify_app(sc, reqp, hv_appvss_thaw_timeout);
	} else if (opt != HV_VSS_CHECK) {
		hv_vss_notify_host_result(reqp,
		    status == VSS_SUCCESS ? HV_S_OK : HV_E_FAIL);
	} else {
		/* VSS check ack */
		atomic_subtract_int(&sc->vss_serv_count, 1);
		hv_vss_notify_host_hbu_status(reqp, status);
	}
}

/**
 * Actions for app who has acknowledged.
 */
static void
hv_vss_app_acked(hv_vss_sc *sc, struct hv_vss_opt_msg *userdata)
{
	struct hv_vss_req_internal	*reqp, *tmp;
	uint64_t			req_id;
	int				opt;
	uint8_t				status;

	opt = userdata->opt;
	req_id = userdata->msgid;
	status = userdata->status;
	mtx_lock(&sc->pending_mutex);
	SEARCH_REMOVE_REQ_LOCKED(reqp, &sc->to_app_ack_queue, slink, tmp, req_id);
	mtx_unlock(&sc->pending_mutex);
	if (reqp == NULL) {
		hv_vss_log_info("%s Timeout: fail to find app ack request\n",
		    __func__);
		userdata->status = VSS_FAIL;
		return;
	}
	callout_drain(&reqp->callout);
	KASSERT(opt == reqp->vss_req.opt_msg.opt, ("Mismatched VSS operation!"));
	hv_vss_log_info("%s, get response %d from app for %s (%ld) \n",
	    __func__, status, vss_opt_name[opt], req_id);
	if (sc->register_done &&
	    status == VSS_SUCCESS &&
	    opt == HV_VSS_FREEZE) {
		hv_vss_notify_daemon(sc, reqp, hv_vss_freeze_timeout);
	} else if (opt != HV_VSS_CHECK) {
		hv_vss_notify_host_result(reqp,
		    status == VSS_SUCCESS ? HV_S_OK : HV_E_FAIL);
	} else {
		/* VSS check ack */
		atomic_subtract_int(&sc->vss_serv_count, 1);
		hv_vss_notify_host_hbu_status(reqp, VSS_SUCCESS);
	}
}
/**
 * Actions for app who has been notified.
 */
static void
hv_vss_app_notified(hv_vss_sc *sc, struct hv_vss_opt_msg *userdata)
{
	struct hv_vss_req_internal *reqp;
	mtx_lock(&sc->pending_mutex);
	if (!STAILQ_EMPTY(&sc->to_app_notify_queue)) {
		reqp = STAILQ_FIRST(&sc->to_app_notify_queue);
		hv_vss_cp_vssreq_to_user(reqp, userdata);
		STAILQ_REMOVE_HEAD(&sc->to_app_notify_queue, slink);
		/* insert the msg to ack queue for write */
		STAILQ_INSERT_TAIL(&sc->to_app_ack_queue, reqp, slink);
		userdata->status = VSS_SUCCESS;
	} else {
		/* Timeout occur, thus request was removed from queue. */
		hv_vss_log_info("%s: app notify queue is empty!\n", __func__);
		userdata->status = VSS_FAIL;
	}
	mtx_unlock(&sc->pending_mutex);
}

static int
hv_vss_dev_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct proc     *td_proc;
	td_proc = td->td_proc;

	hv_vss_sc *sc = (hv_vss_sc*)dev->si_drv1;
	hv_vss_log_info("%s: %s opens device \"%s\" successfully.\n",
	    __func__, td_proc->p_comm, FS_VSS_DEV_NAME);

	if (sc->register_done)
		return (-EBUSY);

	sc->register_done = true;
	hv_vss_callback(vmbus_get_channel(sc->dev), dev->si_drv1);

	sc->daemon_task = curproc;
	return (0);
}

static int
hv_vss_dev_close(struct cdev *dev, int fflag __unused, int devtype __unused,
				 struct thread *td)
{
	struct proc     *td_proc;
	td_proc = td->td_proc;

	hv_vss_sc *sc = (hv_vss_sc*)dev->si_drv1;

	hv_vss_log_info("%s: %s closes device \"%s\"\n",
	    __func__, td_proc->p_comm, FS_VSS_DEV_NAME);
	sc->register_done = false;
	return (0);
}

static int
hv_vss_dev_daemon_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flag, struct thread *td)
{
	struct proc			*td_proc;
	hv_vss_sc			*sc;

	td_proc = td->td_proc;
	sc = (hv_vss_sc*)dev->si_drv1;

	hv_vss_log_info("%s: %s invoked vss ioctl\n", __func__, td_proc->p_comm);

	struct hv_vss_opt_msg* userdata = (struct hv_vss_opt_msg*)data;
	switch(cmd) {
	case IOCHVVSSREAD:
		hv_vss_daemon_notified(sc, userdata);
		break;
	case IOCHVVSSWRITE:
		hv_vss_daemon_acked(sc, userdata);
		break;
	}
	return (0);
}

/*
 * hv_vss_daemon poll invokes this function to check if data is available
 * for daemon to read.
 */
static int
hv_vss_dev_daemon_poll(struct cdev *dev, int events, struct thread *td)
{
	int revent = 0;
	hv_vss_sc *sc = (hv_vss_sc*)dev->si_drv1;

	mtx_lock(&sc->pending_mutex);
	/**
	 * if there is data ready, inform daemon's poll
	 */
	if (!STAILQ_EMPTY(&sc->to_daemon_notify_queue)) {
		revent = POLLIN;
	}
	mtx_unlock(&sc->pending_mutex);
	selrecord(td, &sc->hv_vss_selinfo);

	hv_vss_log_info("%s return 0x%x\n", __func__, revent);
	return (revent);
}

static int
hv_appvss_dev_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	struct proc     *td_proc;
	td_proc = td->td_proc;

	hv_vss_sc *sc = (hv_vss_sc*)dev->si_drv1;
	hv_vss_log_info("%s: %s opens device \"%s\" successfully.\n",
	    __func__, td_proc->p_comm, APP_VSS_DEV_NAME);

	if (sc->app_register_done)
		return (-EBUSY);

	sc->app_register_done = true;
	sc->app_task = curproc;
	return (0);
}

static int
hv_appvss_dev_close(struct cdev *dev, int fflag __unused, int devtype __unused,
				 struct thread *td)
{
	struct proc     *td_proc;
	td_proc = td->td_proc;

	hv_vss_sc *sc = (hv_vss_sc*)dev->si_drv1;

	hv_vss_log_info("%s: %s closes device \"%s\".\n",
	    __func__, td_proc->p_comm, APP_VSS_DEV_NAME);
	sc->app_register_done = false;
	return (0);
}

static int
hv_appvss_dev_daemon_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int flag, struct thread *td)
{
	struct proc			*td_proc;
	hv_vss_sc			*sc;

	td_proc = td->td_proc;
	sc = (hv_vss_sc*)dev->si_drv1;

	hv_vss_log_info("%s: %s invoked vss ioctl\n", __func__, td_proc->p_comm);

	struct hv_vss_opt_msg* userdata = (struct hv_vss_opt_msg*)data;
	switch(cmd) {
	case IOCHVVSSREAD:
		hv_vss_app_notified(sc, userdata);
		break;
	case IOCHVVSSWRITE:
		hv_vss_app_acked(sc, userdata);
		break;
	}
	return (0);
}

/*
 * hv_vss_daemon poll invokes this function to check if data is available
 * for daemon to read.
 */
static int
hv_appvss_dev_daemon_poll(struct cdev *dev, int events, struct thread *td)
{
	int revent = 0;
	hv_vss_sc *sc = (hv_vss_sc*)dev->si_drv1;

	mtx_lock(&sc->pending_mutex);
	/**
	 * if there is data ready, inform daemon's poll
	 */
	if (!STAILQ_EMPTY(&sc->to_app_notify_queue)) {
		revent = POLLIN;
	}
	mtx_unlock(&sc->pending_mutex);
	selrecord(td, &sc->hv_appvss_selinfo);

	hv_vss_log_info("%s return 0x%x\n", __func__, revent);
	return (revent);
}

static void
hv_vss_freeze_timeout(void *arg)
{
	hv_vss_req_internal *reqp = arg;
	hv_vss_req_internal *request;
	hv_vss_sc* sc = reqp->sc;
	uint64_t req_id = reqp->vss_req.opt_msg.msgid;

	hv_vss_log_info("request sent to daemon timeout\n");
	request = hv_vss_daemon_req_recyle(sc, req_id);
	KASSERT(request != NULL, ("daemon freeze timeout but fail to find request"));
	hv_vss_notify_host_result(reqp, HV_E_FAIL);
}

static void
hv_appvss_freeze_timeout(void *arg)
{
	hv_vss_req_internal *reqp = arg;
	hv_vss_req_internal *request;
	hv_vss_sc* sc = reqp->sc;
	uint64_t req_id = reqp->vss_req.opt_msg.msgid;

	hv_vss_log_info("application vss freeze timeout\n");
	request = hv_vss_app_req_recyle(sc, req_id);
	KASSERT(request != NULL, ("appvss freeze timeout but fail to find request"));
	hv_vss_notify_daemon(sc, reqp, hv_vss_freeze_timeout);
}

static void
hv_appvss_thaw_timeout(void *arg)
{
	hv_vss_req_internal *reqp = arg;
	hv_vss_req_internal *request;
	hv_vss_sc* sc = reqp->sc;
	uint64_t req_id = reqp->vss_req.opt_msg.msgid;

	hv_vss_log_info("request sent to daemon timeout\n");
	request = hv_vss_app_req_recyle(sc, req_id);
	KASSERT(request != NULL, ("appvss thaw timeout but fail to find request"));
	hv_vss_respond_host(reqp->rcv_buf,
	    vmbus_get_channel(reqp->sc->dev),
	    reqp->host_msg_len, reqp->host_msg_id, VSS_FAIL);
}

static void
hv_vss_thaw_timeout(void *arg)
{
	hv_vss_req_internal *reqp = arg;
	hv_vss_req_internal *request;
	hv_vss_sc* sc = reqp->sc;
	uint64_t req_id = reqp->vss_req.opt_msg.msgid;

	hv_vss_log_info("request sent to daemon timeout\n");
	request = hv_vss_daemon_req_recyle(sc, req_id);
	KASSERT(request != NULL, ("daemon thaw timeout but fail to find request"));
	if (sc->app_register_done) {
		hv_vss_notify_app(sc, reqp, hv_appvss_thaw_timeout);
	} else {
		hv_vss_notify_host_result(reqp, HV_E_FAIL);
	}
}

static void
hv_vss_check_timeout(void *arg)
{
	hv_vss_notify_host_hbu_status(arg, VSS_FAIL);
}

static void
hv_appvss_check_timeout(void *arg)
{
	hv_vss_notify_host_hbu_status(arg, VSS_FAIL);
}

/*
 * This routine is called whenever a message is received from the host
 */
static void
hv_vss_init_req(hv_vss_req_internal *reqp,
    uint32_t recvlen, uint64_t requestid, uint8_t *vss_buf, hv_vss_sc *sc)
{
	struct timespec vm_ts;
	struct hv_vss_msg* msg = (struct hv_vss_msg *)vss_buf;

	memset(reqp, 0, __offsetof(hv_vss_req_internal, callout));
	reqp->host_msg_len = recvlen;
	reqp->host_msg_id = requestid;
	reqp->rcv_buf = vss_buf;
	reqp->sc = sc;
	memcpy(&reqp->vss_req.msg,
	    (struct hv_vss_msg *)vss_buf, sizeof(struct hv_vss_msg));
	/* set the opt for users */
	switch (msg->hdr.vss_hdr.operation) {
	case VSS_OP_FREEZE:
		reqp->vss_req.opt_msg.opt = HV_VSS_FREEZE;
		break;
	case VSS_OP_THAW:
		reqp->vss_req.opt_msg.opt = HV_VSS_THAW;
		break;
	case VSS_OP_HOT_BACKUP:
		reqp->vss_req.opt_msg.opt = HV_VSS_CHECK;
		break;
	}
	/* Use a timestamp as msg request ID */
	nanotime(&vm_ts);
	reqp->vss_req.opt_msg.msgid = (vm_ts.tv_sec * NANOSEC) + vm_ts.tv_nsec;
}

static void
hv_vss_notify(hv_vss_req_internal *reqp, uint32_t opt)
{
	hv_vss_sc *sc = reqp->sc;
	/*
	 * Freeze notification sequence: kernel -> app -> daemon(fs)
	 * Thaw notification sequence:   kernel -> daemon(fs) -> app
	 *
	 * We should wake up the daemon, in case it's doing poll().
	 * The response should be received after 5s, otherwise, trigger timeout.
	 */
	switch (opt) {
	case VSS_OP_FREEZE:
		if (sc->app_register_done)
			hv_vss_notify_app(sc, reqp, hv_appvss_freeze_timeout);
		else
			hv_vss_notify_daemon(sc, reqp, hv_vss_freeze_timeout);
		break;
	case VSS_OP_THAW:
		hv_vss_notify_daemon(sc, reqp, hv_vss_thaw_timeout);
		break;
	case VSS_OP_HOT_BACKUP:
		hv_vss_notify_daemon(sc, reqp, hv_vss_check_timeout);
		atomic_fetchadd_int(&sc->vss_serv_count, 1);
		if (sc->app_register_done) {
			hv_vss_notify_app(sc, reqp, hv_appvss_check_timeout);
			atomic_fetchadd_int(&sc->vss_serv_count, 1);
		}
		break;
	}
}

static hv_vss_req_internal*
hv_vss_get_new_req_locked(hv_vss_sc *sc)
{
	hv_vss_req_internal *reqp;
	if (!STAILQ_EMPTY(&sc->to_daemon_notify_queue) ||
	    !STAILQ_EMPTY(&sc->to_daemon_ack_queue) ||
	    !STAILQ_EMPTY(&sc->to_app_notify_queue) ||
	    !STAILQ_EMPTY(&sc->to_app_ack_queue)) {
		/*
		 * There is request coming from host before
		 * finishing previous requests
		 */
		hv_vss_log_info("%s: Warning: there is new request "
		    "coming before finishing previous requests\n", __func__);
		return (NULL);
	}
	if (LIST_EMPTY(&sc->req_free_list)) {
		/* TODO Error: no buffer */
		hv_vss_log_info("Error: No buffer\n");
		return (NULL);
	}
	reqp = LIST_FIRST(&sc->req_free_list);
	LIST_REMOVE(reqp, link);
	return (reqp);
}
/*
 * Function to read the vss request buffer from host
 * and interact with daemon
 */
static void
hv_vss_process_request(void *context, int pending __unused)
{
	uint8_t *vss_buf;
	struct vmbus_channel *channel;
	uint32_t recvlen = 0;
	uint64_t requestid;
	struct vmbus_icmsg_hdr *icmsghdrp;
	int ret = 0;
	hv_vss_sc *sc;
	hv_vss_req_internal *reqp;

	hv_vss_log_info("%s: entering hv_vss_process_request\n", __func__);

	sc = (hv_vss_sc*)context;
	vss_buf = sc->util_sc.receive_buffer;
	channel = vmbus_get_channel(sc->dev);

	recvlen = sc->util_sc.ic_buflen;
	ret = vmbus_chan_recv(channel, vss_buf, &recvlen, &requestid);
	KASSERT(ret != ENOBUFS, ("hvvss recvbuf is not large enough"));
	/* XXX check recvlen to make sure that it contains enough data */

	while ((ret == 0) && (recvlen > 0)) {
		icmsghdrp = (struct vmbus_icmsg_hdr *)vss_buf;

		if (icmsghdrp->ic_type == HV_ICMSGTYPE_NEGOTIATE) {
			ret = vmbus_ic_negomsg(&sc->util_sc, vss_buf,
			    &recvlen, VSS_FWVER, VSS_MSGVER);
			hv_vss_respond_host(vss_buf, vmbus_get_channel(sc->dev),
			    recvlen, requestid, ret);
			hv_vss_log_info("%s: version negotiated\n", __func__);
		} else {
			struct hv_vss_msg* msg = (struct hv_vss_msg *)vss_buf;
			switch(msg->hdr.vss_hdr.operation) {
			case VSS_OP_FREEZE:
			case VSS_OP_THAW:
			case VSS_OP_HOT_BACKUP:
				mtx_lock(&sc->pending_mutex);
				reqp = hv_vss_get_new_req_locked(sc);
				mtx_unlock(&sc->pending_mutex);
				if (reqp == NULL) {
					/* ignore this request from host */
					break;
				}
				hv_vss_init_req(reqp, recvlen, requestid, vss_buf, sc);
				hv_vss_log_info("%s: receive %s (%ld) from host\n",
				    __func__,
				    vss_opt_name[reqp->vss_req.opt_msg.opt],
				    reqp->vss_req.opt_msg.msgid);
				hv_vss_notify(reqp, msg->hdr.vss_hdr.operation);
				break;
			case VSS_OP_GET_DM_INFO:
				hv_vss_log_info("%s: receive GET_DM_INFO from host\n",
				    __func__);
				msg->body.dm_info.flags = 0;
				hv_vss_respond_host(vss_buf, vmbus_get_channel(sc->dev),
				    recvlen, requestid, HV_S_OK);
				break;
			default:
				device_printf(sc->dev, "Unknown opt from host: %d\n",
				    msg->hdr.vss_hdr.operation);
				break;
			}
		}

		/*
		 * Try reading next buffer
		 */
		recvlen = sc->util_sc.ic_buflen;
		ret = vmbus_chan_recv(channel, vss_buf, &recvlen, &requestid);
		KASSERT(ret != ENOBUFS, ("hvvss recvbuf is not large enough"));
		/* XXX check recvlen to make sure that it contains enough data */

		hv_vss_log_info("%s: read: context %p, ret =%d, recvlen=%d\n",
		    __func__, context, ret, recvlen);
	}
}

static int
hv_vss_probe(device_t dev)
{
	return (vmbus_ic_probe(dev, vmbus_vss_descs));
}

static int
hv_vss_init_send_receive_queue(device_t dev)
{
	hv_vss_sc *sc = (hv_vss_sc*)device_get_softc(dev);
	int i;
	const int max_list = 64; /* It is big enough for the list */
	struct hv_vss_req_internal* reqp;

	LIST_INIT(&sc->req_free_list);
	STAILQ_INIT(&sc->to_app_notify_queue);
	STAILQ_INIT(&sc->to_app_ack_queue);
	STAILQ_INIT(&sc->to_daemon_notify_queue);
	STAILQ_INIT(&sc->to_daemon_ack_queue);

	for (i = 0; i < max_list; i++) {
		reqp = malloc(sizeof(struct hv_vss_req_internal),
		    M_DEVBUF, M_WAITOK|M_ZERO);
		LIST_INSERT_HEAD(&sc->req_free_list, reqp, link);
		callout_init_mtx(&reqp->callout, &sc->pending_mutex, 0);
	}
	return (0);
}

static int
hv_vss_destroy_send_receive_queue(device_t dev)
{
	hv_vss_sc *sc = (hv_vss_sc*)device_get_softc(dev);
	hv_vss_req_internal* reqp;

	while (!LIST_EMPTY(&sc->req_free_list)) {
		reqp = LIST_FIRST(&sc->req_free_list);
		LIST_REMOVE(reqp, link);
		free(reqp, M_DEVBUF);
	}

	while (!STAILQ_EMPTY(&sc->to_daemon_notify_queue)) {
		reqp = STAILQ_FIRST(&sc->to_daemon_notify_queue);
		STAILQ_REMOVE_HEAD(&sc->to_daemon_notify_queue, slink);
		free(reqp, M_DEVBUF);
	}

	while (!STAILQ_EMPTY(&sc->to_app_notify_queue)) {
		reqp = STAILQ_FIRST(&sc->to_app_notify_queue);
		STAILQ_REMOVE_HEAD(&sc->to_app_notify_queue, slink);
		free(reqp, M_DEVBUF);
	}

	while (!STAILQ_EMPTY(&sc->to_daemon_ack_queue)) {
		reqp = STAILQ_FIRST(&sc->to_daemon_ack_queue);
		STAILQ_REMOVE_HEAD(&sc->to_daemon_ack_queue, slink);
		free(reqp, M_DEVBUF);
	}

	while (!STAILQ_EMPTY(&sc->to_app_ack_queue)) {
		reqp = STAILQ_FIRST(&sc->to_app_ack_queue);
		STAILQ_REMOVE_HEAD(&sc->to_app_ack_queue, slink);
		free(reqp, M_DEVBUF);
	}
	return (0);
}

static int
hv_vss_attach(device_t dev)
{
	int error;
	struct sysctl_oid_list *child;
	struct sysctl_ctx_list *ctx;

	hv_vss_sc *sc = (hv_vss_sc*)device_get_softc(dev);

	sc->dev = dev;
	mtx_init(&sc->pending_mutex, "hv_vss pending mutex",
	    NULL, MTX_DEF);

	ctx = device_get_sysctl_ctx(dev);
	child = SYSCTL_CHILDREN(device_get_sysctl_tree(dev));

	SYSCTL_ADD_INT(ctx, child, OID_AUTO, "hv_vss_log",
	    CTLFLAG_RWTUN, &hv_vss_log, 0, "Hyperv VSS service log level");

	TASK_INIT(&sc->task, 0, hv_vss_process_request, sc);

	/* create character device for file system freeze/thaw */
	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
		    &sc->hv_vss_dev,
		    &hv_vss_cdevsw,
		    0,
		    UID_ROOT,
		    GID_WHEEL,
		    0640,
		    FS_VSS_DEV_NAME);

	if (error != 0) {
		hv_vss_log_info("Fail to create '%s': %d\n", FS_VSS_DEV_NAME, error);
		return (error);
	}
	sc->hv_vss_dev->si_drv1 = sc;

	/* create character device for application freeze/thaw */
	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
		    &sc->hv_appvss_dev,
		    &hv_appvss_cdevsw,
		    0,
		    UID_ROOT,
		    GID_WHEEL,
		    0640,
		    APP_VSS_DEV_NAME);

	if (error != 0) {
		hv_vss_log_info("Fail to create '%s': %d\n", APP_VSS_DEV_NAME, error);
		return (error);
	}
	sc->hv_appvss_dev->si_drv1 = sc;

	hv_vss_init_send_receive_queue(dev);

	return hv_util_attach(dev, hv_vss_callback);
}

static int
hv_vss_detach(device_t dev)
{
	hv_vss_sc *sc = (hv_vss_sc*)device_get_softc(dev);

	if (sc->daemon_task != NULL) {
		PROC_LOCK(sc->daemon_task);
		kern_psignal(sc->daemon_task, SIGKILL);
		PROC_UNLOCK(sc->daemon_task);
	}
	if (sc->app_task != NULL) {
		PROC_LOCK(sc->app_task);
		kern_psignal(sc->app_task, SIGKILL);
		PROC_UNLOCK(sc->app_task);
	}
	hv_vss_destroy_send_receive_queue(dev);
	destroy_dev(sc->hv_vss_dev);
	destroy_dev(sc->hv_appvss_dev);
	return hv_util_detach(dev);
}

static device_method_t vss_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe, hv_vss_probe),
	DEVMETHOD(device_attach, hv_vss_attach),
	DEVMETHOD(device_detach, hv_vss_detach),
	{ 0, 0 }
};

static driver_t vss_driver = { "hvvss", vss_methods, sizeof(hv_vss_sc)};

static devclass_t vss_devclass;

DRIVER_MODULE(hv_vss, vmbus, vss_driver, vss_devclass, NULL, NULL);
MODULE_VERSION(hv_vss, 1);
MODULE_DEPEND(hv_vss, vmbus, 1, 1, 1);
