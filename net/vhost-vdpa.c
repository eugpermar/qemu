/*
 * vhost-vdpa.c
 *
 * Copyright(c) 2017-2018 Intel Corporation.
 * Copyright(c) 2020 Red Hat, Inc.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "clients.h"
#include "hw/virtio/virtio-net.h"
#include "net/vhost_net.h"
#include "net/vhost-vdpa.h"
#include "hw/virtio/vhost-vdpa.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/option.h"
#include "qapi/error.h"
#include <linux/vhost.h>
#include <sys/ioctl.h>
#include <err.h>
#include "standard-headers/linux/virtio_net.h"
#include "monitor/monitor.h"
#include "hw/virtio/vhost.h"

/* Todo:need to add the multiqueue support here */
typedef struct VhostVDPAState {
    NetClientState nc;
    struct vhost_vdpa vhost_vdpa;
    VHostNetState *vhost_net;
    bool started;
} VhostVDPAState;

const int vdpa_feature_bits[] = {
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_F_ANY_LAYOUT,
    VIRTIO_F_VERSION_1,
    VIRTIO_NET_F_CSUM,
    VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GSO,
    VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_ECN,
    VIRTIO_NET_F_GUEST_UFO,
    VIRTIO_NET_F_HOST_TSO4,
    VIRTIO_NET_F_HOST_TSO6,
    VIRTIO_NET_F_HOST_ECN,
    VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MRG_RXBUF,
    VIRTIO_NET_F_MTU,
    VIRTIO_NET_F_CTRL_RX,
    VIRTIO_NET_F_CTRL_RX_EXTRA,
    VIRTIO_NET_F_CTRL_VLAN,
    VIRTIO_NET_F_GUEST_ANNOUNCE,
    VIRTIO_NET_F_CTRL_MAC_ADDR,
    VIRTIO_NET_F_RSS,
    VIRTIO_NET_F_MQ,
    VIRTIO_NET_F_CTRL_VQ,
    VIRTIO_F_IOMMU_PLATFORM,
    VIRTIO_F_RING_PACKED,
    VIRTIO_NET_F_RSS,
    VIRTIO_NET_F_HASH_REPORT,
    VIRTIO_NET_F_GUEST_ANNOUNCE,
    VIRTIO_NET_F_STATUS,
    VHOST_INVALID_FEATURE_BIT
};

/** Supported device specific feature bits with SVQ */
static const uint64_t vdpa_svq_device_features =
    BIT_ULL(VIRTIO_NET_F_CSUM) |
    BIT_ULL(VIRTIO_NET_F_GUEST_CSUM) |
    BIT_ULL(VIRTIO_NET_F_CTRL_GUEST_OFFLOADS) |
    BIT_ULL(VIRTIO_NET_F_MTU) |
    BIT_ULL(VIRTIO_NET_F_MAC) |
    BIT_ULL(VIRTIO_NET_F_GUEST_TSO4) |
    BIT_ULL(VIRTIO_NET_F_GUEST_TSO6) |
    BIT_ULL(VIRTIO_NET_F_GUEST_ECN) |
    BIT_ULL(VIRTIO_NET_F_GUEST_UFO) |
    BIT_ULL(VIRTIO_NET_F_HOST_TSO4) |
    BIT_ULL(VIRTIO_NET_F_HOST_TSO6) |
    BIT_ULL(VIRTIO_NET_F_HOST_ECN) |
    BIT_ULL(VIRTIO_NET_F_HOST_UFO) |
    BIT_ULL(VIRTIO_NET_F_MRG_RXBUF) |
    BIT_ULL(VIRTIO_NET_F_STATUS) |
    BIT_ULL(VIRTIO_NET_F_CTRL_VQ) |
    BIT_ULL(VIRTIO_NET_F_MQ) |
    BIT_ULL(VIRTIO_F_ANY_LAYOUT) |
    BIT_ULL(VIRTIO_NET_F_CTRL_MAC_ADDR) |
    BIT_ULL(VIRTIO_NET_F_RSC_EXT) |
    BIT_ULL(VIRTIO_NET_F_STANDBY);

VHostNetState *vhost_vdpa_get_vhost_net(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    return s->vhost_net;
}

static int vhost_vdpa_net_check_device_id(struct vhost_net *net)
{
    uint32_t device_id;
    int ret;
    struct vhost_dev *hdev;

    hdev = (struct vhost_dev *)&net->dev;
    ret = hdev->vhost_ops->vhost_get_device_id(hdev, &device_id);
    if (device_id != VIRTIO_ID_NET) {
        return -ENOTSUP;
    }
    return ret;
}

static int vhost_vdpa_add(NetClientState *ncs, void *be,
                          int queue_pair_index, int nvqs)
{
    VhostNetOptions options;
    struct vhost_net *net = NULL;
    VhostVDPAState *s;
    int ret;

    options.backend_type = VHOST_BACKEND_TYPE_VDPA;
    assert(ncs->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    s = DO_UPCAST(VhostVDPAState, nc, ncs);
    options.net_backend = ncs;
    options.opaque      = be;
    options.busyloop_timeout = 0;
    options.nvqs = nvqs;

    net = vhost_net_init(&options);
    if (!net) {
        error_report("failed to init vhost_net for queue");
        goto err_init;
    }
    s->vhost_net = net;
    ret = vhost_vdpa_net_check_device_id(net);
    if (ret) {
        goto err_check;
    }
    return 0;
err_check:
    vhost_net_cleanup(net);
    g_free(net);
err_init:
    return -1;
}

static void vhost_vdpa_cleanup(NetClientState *nc)
{
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    struct vhost_dev *dev = &s->vhost_net->dev;

    if (dev->vq_index + dev->nvqs == dev->vq_index_end) {
        vhost_iova_tree_delete(s->vhost_vdpa.iova_tree);
    }
    if (s->vhost_net) {
        vhost_net_cleanup(s->vhost_net);
        g_free(s->vhost_net);
        s->vhost_net = NULL;
    }
     if (s->vhost_vdpa.device_fd >= 0) {
        qemu_close(s->vhost_vdpa.device_fd);
        s->vhost_vdpa.device_fd = -1;
    }
}

static bool vhost_vdpa_has_vnet_hdr(NetClientState *nc)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);

    return true;
}

static bool vhost_vdpa_has_ufo(NetClientState *nc)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    VhostVDPAState *s = DO_UPCAST(VhostVDPAState, nc, nc);
    uint64_t features = 0;
    features |= (1ULL << VIRTIO_NET_F_HOST_UFO);
    features = vhost_net_get_features(s->vhost_net, features);
    return !!(features & (1ULL << VIRTIO_NET_F_HOST_UFO));

}

static bool vhost_vdpa_check_peer_type(NetClientState *nc, ObjectClass *oc,
                                       Error **errp)
{
    const char *driver = object_class_get_name(oc);

    if (!g_str_has_prefix(driver, "virtio-net-")) {
        error_setg(errp, "vhost-vdpa requires frontend driver virtio-net-*");
        return false;
    }

    return true;
}

/** Dummy receive in case qemu falls back to userland tap networking */
static ssize_t vhost_vdpa_receive(NetClientState *nc, const uint8_t *buf,
                                  size_t size)
{
    return 0;
}

static NetClientInfo net_vhost_vdpa_info = {
        .type = NET_CLIENT_DRIVER_VHOST_VDPA,
        .size = sizeof(VhostVDPAState),
        .receive = vhost_vdpa_receive,
        .cleanup = vhost_vdpa_cleanup,
        .has_vnet_hdr = vhost_vdpa_has_vnet_hdr,
        .has_ufo = vhost_vdpa_has_ufo,
        .check_peer_type = vhost_vdpa_check_peer_type,
};

static int vhost_vdpa_get_iova_range(int fd,
                                     struct vhost_vdpa_iova_range *iova_range)
{
    int ret = ioctl(fd, VHOST_VDPA_GET_IOVA_RANGE, iova_range);

    return ret < 0 ? -errno : 0;
}

static int vhost_vdpa_start_control_svq(VhostShadowVirtqueue *svq,
                                        struct vhost_dev *dev)
{
    struct vhost_vring_state state = {
        .index = virtio_get_queue_index(svq->vq),
        .num = 1,
    };
    struct vhost_vdpa *v = dev->opaque;
    VirtIONet *n = VIRTIO_NET(dev->vdev);
    uint64_t features = dev->vdev->host_features;
    int r;
    size_t num = 0;

    assert(dev->vhost_ops->backend_type == VHOST_BACKEND_TYPE_VDPA);

    r = ioctl(v->device_fd, VHOST_VDPA_SET_VRING_ENABLE, &state);
    if (r < 0) {
        return -errno;
    }

    if (features & BIT_ULL(VIRTIO_NET_F_CTRL_MAC_ADDR)) {
        const struct virtio_net_ctrl_hdr ctrl = {
            .class = VIRTIO_NET_CTRL_MAC,
            .cmd = VIRTIO_NET_CTRL_MAC_ADDR_SET,
        };
        uint8_t mac[6];
        virtio_net_ctrl_ack ack;
        const struct iovec data[] = {
            {
                .iov_base = (void *)&ctrl,
                .iov_len = sizeof(ctrl),
            },{
                .iov_base = mac,
                .iov_len = sizeof(mac),
            },{
                .iov_base = &ack,
                .iov_len = sizeof(ack),
            }
        };

        memcpy(mac, n->mac, sizeof(mac));
        r = vhost_svq_inject(svq, data, 2, 1);
        if (unlikely(r)) {
            return r;
        }
        num++;
    }

    while (num) {
        /*
         * We can call vhost_svq_poll here because BQL protects calls to run.
         */
        size_t used = vhost_svq_poll(svq);
        assert(used <= num);
        num -= used;
    }

    return 0;
}

static void vhost_vdpa_net_handle_ctrl(VirtIODevice *vdev,
                                       const VirtQueueElement *elem)
{
    struct virtio_net_ctrl_hdr ctrl;
    virtio_net_ctrl_ack status = VIRTIO_NET_ERR;
    size_t s;
    struct iovec in = {
        .iov_base = &status,
        .iov_len = sizeof(status),
    };

    s = iov_to_buf(elem->out_sg, elem->out_num, 0, &ctrl, sizeof(ctrl.class));
    if (s != sizeof(ctrl.class)) {
        return;
    }

    switch (ctrl.class) {
    case VIRTIO_NET_CTRL_MAC_ADDR_SET:
    case VIRTIO_NET_CTRL_MQ:
        break;
    default:
        return;
    };

    s = iov_to_buf(elem->in_sg, elem->in_num, 0, &status, sizeof(status));
    if (s != sizeof(status) || status != VIRTIO_NET_OK) {
        return;
    }

    status = VIRTIO_NET_ERR;
    virtio_net_handle_ctrl_iov(vdev, &in, 1, elem->out_sg, elem->out_num);
    if (status != VIRTIO_NET_OK) {
        error_report("Bad CVQ processing in model");
    }
}

static const VhostShadowVirtqueueOps vhost_vdpa_net_svq_ops = {
    .used_elem_handler = vhost_vdpa_net_handle_ctrl,
    .start = vhost_vdpa_start_control_svq,
};

static NetClientState *net_vhost_vdpa_init(NetClientState *peer,
                                           const char *device,
                                           const char *name,
                                           int vdpa_device_fd,
                                           int queue_pair_index,
                                           int nvqs,
                                           bool is_datapath,
                                           bool svq,
                                           VhostIOVATree *iova_tree)
{
    NetClientState *nc = NULL;
    VhostVDPAState *s;
    int ret = 0;
    assert(name);
    if (is_datapath) {
        nc = qemu_new_net_client(&net_vhost_vdpa_info, peer, device,
                                 name);
    } else {
        nc = qemu_new_net_control_client(&net_vhost_vdpa_info, peer,
                                         device, name);
    }
    snprintf(nc->info_str, sizeof(nc->info_str), TYPE_VHOST_VDPA);
    s = DO_UPCAST(VhostVDPAState, nc, nc);

    s->vhost_vdpa.device_fd = vdpa_device_fd;
    s->vhost_vdpa.index = queue_pair_index;
    s->vhost_vdpa.shadow_vqs_enabled = svq;
    s->vhost_vdpa.iova_tree = iova_tree;
    if (!is_datapath) {
        s->vhost_vdpa.shadow_vq_ops = &vhost_vdpa_net_svq_ops;
        s->vhost_vdpa.svq_copy_descs = true;
        s->vhost_vdpa.independent_vq_group = true;
        s->vhost_vdpa.address_space_id = 1;
        error_setg(&s->vhost_vdpa.migration_blocker, "Guest have CVQ");
    }
    ret = vhost_vdpa_add(nc, (void *)&s->vhost_vdpa, queue_pair_index, nvqs);
    if (ret) {
        qemu_del_net_client(nc);
        return NULL;
    }
    return nc;
}

static int vhost_vdpa_get_features(int fd, uint64_t *features, Error **errp)
{
    int ret = ioctl(fd, VHOST_GET_FEATURES, features);
    if (ret) {
        error_setg_errno(errp, errno,
                         "Fail to query features from vhost-vDPA device");
    }
    return ret;
}

static int vhost_vdpa_get_backend_features(int fd, uint64_t *features,
                                           Error **errp)
{
    int ret = ioctl(fd, VHOST_GET_BACKEND_FEATURES, features);
    if (ret) {
        error_setg_errno(errp, errno,
            "Fail to query backend features from vhost-vDPA device");
    }
    return ret;
}

static int vhost_vdpa_get_max_queue_pairs(int fd, uint64_t features,
                                          int *has_cvq, Error **errp)
{
    unsigned long config_size = offsetof(struct vhost_vdpa_config, buf);
    g_autofree struct vhost_vdpa_config *config = NULL;
    __virtio16 *max_queue_pairs;
    int ret;

    if (features & (1 << VIRTIO_NET_F_CTRL_VQ)) {
        *has_cvq = 1;
    } else {
        *has_cvq = 0;
    }

    if (features & (1 << VIRTIO_NET_F_MQ)) {
        config = g_malloc0(config_size + sizeof(*max_queue_pairs));
        config->off = offsetof(struct virtio_net_config, max_virtqueue_pairs);
        config->len = sizeof(*max_queue_pairs);

        ret = ioctl(fd, VHOST_VDPA_GET_CONFIG, config);
        if (ret) {
            error_setg(errp, "Fail to get config from vhost-vDPA device");
            return -ret;
        }

        max_queue_pairs = (__virtio16 *)&config->buf;

        return lduw_le_p(max_queue_pairs);
    }

    return 1;
}

/**
 * Check vdpa device to support CVQ group asid 1
 *
 * @vdpa_device_fd: Vdpa device fd
 * @dev_name: Name of the device (for error reporting)
 */
static bool vhost_vdpa_check_cvq_svq(int vdpa_device_fd, const char *dev_name)
{
    uint64_t backend_features;
    unsigned num_as;
    int r;
    Error *errp = NULL;

    r = vhost_vdpa_get_backend_features(vdpa_device_fd, &backend_features,
                                        &errp);
    if (unlikely(r)) {
        error_prepend(&errp, "Cannot get backend features: ");
        goto err;
    }

    if (unlikely(!(backend_features & VHOST_BACKEND_F_IOTLB_ASID))) {
        error_setg(&errp, "Device without IOTLB_ASID feature");
        goto err;
    }

    r = ioctl(vdpa_device_fd, VHOST_VDPA_GET_AS_NUM, &num_as);
    if (unlikely(r)) {
        error_setg_errno(&errp, errno,
                         "Cannot retrieve number of supported ASs");
        goto err;
    }
    if (unlikely(num_as < 2)) {
        error_setg(&errp, "Insufficient number of ASs (%u, min: 2)", num_as);
        goto err;
    }

    return true;

err:
    warn_reportf_err(errp,
        "Cannot configure SVQ on CVQ of dev %s, device not migratable: ",
        dev_name);
    return false;
}

int net_init_vhost_vdpa(const Netdev *netdev, const char *name,
                        NetClientState *peer, Error **errp)
{
    const NetdevVhostVDPAOptions *opts;
    struct vhost_vdpa_iova_range iova_range;
    uint64_t features;
    int vdpa_device_fd;
    g_autofree NetClientState **ncs = NULL;
    g_autoptr(VhostIOVATree) iova_tree = NULL;
    NetClientState *nc;
    int queue_pairs, r, i, has_cvq = 0;
    bool svq_cvq = false;

    assert(netdev->type == NET_CLIENT_DRIVER_VHOST_VDPA);
    opts = &netdev->u.vhost_vdpa;
    if (!opts->vhostdev) {
        error_setg(errp, "vdpa character device not specified with vhostdev");
        return -1;
    }

    vdpa_device_fd = qemu_open(opts->vhostdev, O_RDWR, errp);
    if (vdpa_device_fd == -1) {
        return -errno;
    }

    r = vhost_vdpa_get_features(vdpa_device_fd, &features, errp);
    if (r) {
        return r;
    }

    queue_pairs = vhost_vdpa_get_max_queue_pairs(vdpa_device_fd, features,
                                                 &has_cvq, errp);
    if (queue_pairs < 0) {
        qemu_close(vdpa_device_fd);
        return queue_pairs;
    }

    if (has_cvq) {
        /* TODO: Add migration blocker */
        svq_cvq = vhost_vdpa_check_cvq_svq(vdpa_device_fd, name);
    }

    if (svq_cvq) {
        vhost_vdpa_get_iova_range(vdpa_device_fd, &iova_range);

        uint64_t invalid_dev_features =
            features & ~vdpa_svq_device_features &
            /* Transport are all accepted at this point */
            ~MAKE_64BIT_MASK(VIRTIO_TRANSPORT_F_START,
                             VIRTIO_TRANSPORT_F_END - VIRTIO_TRANSPORT_F_START);

        if (invalid_dev_features) {
            error_setg(errp, "vdpa svq does not work with features 0x%" PRIx64,
                       invalid_dev_features);
            goto err_svq;
        }

        iova_tree = vhost_iova_tree_new(iova_range.first, iova_range.last);
    }

    ncs = g_malloc0(sizeof(*ncs) * queue_pairs);

    for (i = 0; i < queue_pairs; i++) {
        ncs[i] = net_vhost_vdpa_init(peer, TYPE_VHOST_VDPA, name,
                                     vdpa_device_fd, i, 2, true, false,
                                     iova_tree);
        if (!ncs[i])
            goto err;
    }

    if (has_cvq) {
        nc = net_vhost_vdpa_init(peer, TYPE_VHOST_VDPA, name,
                                 vdpa_device_fd, i, 1, false,
                                 svq_cvq, iova_tree);
        if (!nc)
            goto err;
    }

    /* iova_tree ownership belongs to last NetClientState */
    g_steal_pointer(&iova_tree);
    return 0;

err:
    if (i) {
        for (i--; i >= 0; i--) {
            qemu_del_net_client(ncs[i]);
        }
    }

err_svq:
    qemu_close(vdpa_device_fd);

    return -1;
}
