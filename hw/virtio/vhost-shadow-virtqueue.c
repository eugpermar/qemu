/*
 * vhost software live migration ring
 *
 * SPDX-FileCopyrightText: Red Hat, Inc. 2021
 * SPDX-FileContributor: Author: Eugenio Pérez <eperezma@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "hw/virtio/vhost-shadow-virtqueue.h"
#include "hw/virtio/vhost.h"
#include "hw/virtio/virtio-access.h"

#include "standard-headers/linux/vhost_types.h"
#include "standard-headers/linux/virtio_ring.h"

#include "qemu/error-report.h"
#include "qemu/main-loop.h"

typedef struct VhostShadowVirtqueue {
    EventNotifier kick_notifier;
    EventNotifier call_notifier;
    const struct vhost_virtqueue *hvq;
    VirtIODevice *vdev;
    VirtQueue *vq;
} VhostShadowVirtqueue;

static uint16_t vhost_shadow_vring_used_flags(VhostShadowVirtqueue *svq)
{
    const struct vring_used *used = svq->hvq->used;
    return virtio_tswap16(svq->vdev, used->flags);
}

static bool vhost_shadow_vring_should_kick(VhostShadowVirtqueue *vq)
{
    return !(vhost_shadow_vring_used_flags(vq) & VRING_USED_F_NO_NOTIFY);
}

static void vhost_shadow_vring_kick(VhostShadowVirtqueue *vq)
{
    if (vhost_shadow_vring_should_kick(vq)) {
        event_notifier_set(&vq->kick_notifier);
    }
}

static void handle_shadow_vq(VirtIODevice *vdev, VirtQueue *vq)
{
    struct vhost_dev *hdev = vhost_dev_from_virtio(vdev);
    uint16_t idx = virtio_get_queue_index(vq);

    VhostShadowVirtqueue *svq = hdev->shadow_vqs[idx];

    vhost_shadow_vring_kick(svq);
}

static void vhost_handle_call(EventNotifier *n)
{
    VhostShadowVirtqueue *svq = container_of(n, VhostShadowVirtqueue,
                                             call_notifier);

    if (event_notifier_test_and_clear(n)) {
        unsigned idx = virtio_queue_get_idx(svq->vdev, svq->vq);
        virtio_queue_invalidate_signalled_used(svq->vdev, idx);
        virtio_notify_irqfd(svq->vdev, svq->vq);
    }
}

/* Creates vhost shadow virtqueue, and instruct vhost device to use the shadow
 * methods and file descriptors.
 */
VhostShadowVirtqueue *vhost_shadow_vq_new(struct vhost_dev *dev, int idx)
{
    const VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(dev->vdev);
    VhostShadowVirtqueue *svq = g_new0(VhostShadowVirtqueue, 1);
    struct vhost_vring_file kick_file = {
        .index = idx,
    };
    struct vhost_vring_file call_file = {
        .index = idx,
    };
    int vq_idx = dev->vhost_ops->vhost_get_vq_index(dev, dev->vq_index + idx);
    int r;
    bool ok;

    svq->vq = virtio_get_queue(dev->vdev, vq_idx);
    svq->hvq = &dev->vqs[idx];
    svq->vdev = dev->vdev;

    r = event_notifier_init(&svq->kick_notifier, 0);
    if (r != 0) {
        error_report("Couldn't create kick event notifier: %s", strerror(errno));
        goto err_init_kick_notifier;
    }

    r = event_notifier_init(&svq->call_notifier, 0);
    if (r != 0) {
        error_report("Couldn't create call event notifier: %s",
                     strerror(errno));
        goto err_init_call_notifier;
    }

    kick_file.fd = event_notifier_get_fd(&svq->kick_notifier);
    call_file.fd = event_notifier_get_fd(&svq->call_notifier);
    event_notifier_set_handler(&svq->call_notifier, vhost_handle_call);

    RCU_READ_LOCK_GUARD();

    /* Check that notifications are still going directly to vhost dev */
    assert(virtio_queue_host_notifier_status(svq->vq));

    ok = k->set_vq_handler(dev->vdev, idx, handle_shadow_vq);
    if (!ok) {
        error_report("Couldn't set the vq handler");
        goto err_set_kick_handler;
    }

    r = dev->vhost_ops->vhost_set_vring_kick(dev, &kick_file);
    if (r != 0) {
        error_report("Couldn't set kick fd: %s", strerror(errno));
        goto err_set_vring_kick;
    }

    r = dev->vhost_ops->vhost_set_vring_call(dev, &call_file);
    if (r != 0) {
        error_report("Couldn't set call fd: %s", strerror(errno));
        goto err_set_vring_call;
    }

    return svq;

err_set_vring_call:
    kick_file.fd = event_notifier_get_fd(virtio_queue_get_host_notifier(svq->vq));
    r = dev->vhost_ops->vhost_set_vring_kick(dev, &kick_file);
    assert(r == 0);

err_set_vring_kick:
    k->set_vq_handler(dev->vdev, idx, NULL);

err_set_kick_handler:
    event_notifier_cleanup(&svq->call_notifier);

err_init_call_notifier:
    event_notifier_cleanup(&svq->kick_notifier);

err_init_kick_notifier:
    g_free(svq);
    return NULL;
}

/* Free the resources of the shadow virtqueue.
 *
 * Note that this function does not restore vhost file descriptors, only the
 * virtqueue handler.
 */
void vhost_shadow_vq_free(VhostShadowVirtqueue *vq)
{
    const VirtioDeviceClass *k = VIRTIO_DEVICE_GET_CLASS(vq->vdev);
    const unsigned vq_idx = virtio_queue_get_idx(vq->vdev, vq->vq);

    /* We are probably being called with RCU already, but acquire just in case
     */
    WITH_RCU_READ_LOCK_GUARD() {
        k->set_vq_handler(vq->vdev, vq_idx, NULL);
    }

    event_notifier_cleanup(&vq->kick_notifier);
    event_notifier_cleanup(&vq->call_notifier);
    g_free(vq);
}
