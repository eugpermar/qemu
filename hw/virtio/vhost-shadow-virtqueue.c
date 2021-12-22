/*
 * vhost shadow virtqueue
 *
 * SPDX-FileCopyrightText: Red Hat, Inc. 2021
 * SPDX-FileContributor: Author: Eugenio Pérez <eperezma@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/virtio/vhost-shadow-virtqueue.h"

#include "qemu/error-report.h"
#include "qemu/main-loop.h"

/* Shadow virtqueue to relay notifications */
typedef struct VhostShadowVirtqueue {
    /* Shadow kick notifier, sent to vhost */
    EventNotifier hdev_kick;
    /* Shadow call notifier, sent to vhost */
    EventNotifier hdev_call;

    /*
     * Borrowed virtqueue's guest to host notifier.
     * To borrow it in this event notifier allows to register on the event
     * loop and access the associated shadow virtqueue easily. If we use the
     * VirtQueue, we don't have an easy way to retrieve it.
     *
     * So shadow virtqueue must not clean it, or we would lose VirtQueue one.
     */
    EventNotifier svq_kick;
} VhostShadowVirtqueue;

/**
 * The notifier that SVQ will use to notify the device.
 */
const EventNotifier *vhost_svq_get_dev_kick_notifier(
                                               const VhostShadowVirtqueue *svq)
{
    return &svq->hdev_kick;
}

/* Forward guest notifications */
static void vhost_handle_guest_kick(EventNotifier *n)
{
    VhostShadowVirtqueue *svq = container_of(n, VhostShadowVirtqueue,
                                             svq_kick);

    if (unlikely(!event_notifier_test_and_clear(n))) {
        return;
    }

    event_notifier_set(&svq->hdev_kick);
}

/**
 * Convenience function to set guest to SVQ kick fd
 *
 * @svq         The shadow VirtQueue
 * @svq_kick_fd The guest to SVQ kick fd
 * @check_old   Check old file descriptor for pending notifications
 */
static void vhost_svq_set_svq_kick_fd_internal(VhostShadowVirtqueue *svq,
                                               int svq_kick_fd,
                                               bool check_old)
{
    EventNotifier tmp;

    if (check_old) {
        event_notifier_set_handler(&svq->svq_kick, NULL);
        event_notifier_init_fd(&tmp, event_notifier_get_fd(&svq->svq_kick));
    }

    /*
     * event_notifier_set_handler already checks for guest's notifications if
     * they arrive to the new file descriptor in the switch, so there is no
     * need to explicitely check for them.
     */
    event_notifier_init_fd(&svq->svq_kick, svq_kick_fd);
    event_notifier_set_handler(&svq->svq_kick, vhost_handle_guest_kick);

    /*
     * !check_old means that we are starting SVQ, taking the descriptor from
     * vhost-vdpa device. This means that we can't trust old file descriptor
     * pending notifications, since they could have been swallowed by kernel
     * vhost or paused device. So let it enabled, and qemu event loop will call
     * us to handle guest avail ring when SVQ is ready.
     */
    if (!check_old || event_notifier_test_and_clear(&tmp)) {
        event_notifier_set(&svq->hdev_kick);
    }
}

/**
 * Set a new file descriptor for the guest to kick SVQ and notify for avail
 *
 * @svq          The svq
 * @svq_kick_fd  The svq kick fd
 *
 * Note that SVQ will never close the old file descriptor.
 */
void vhost_svq_set_svq_kick_fd(VhostShadowVirtqueue *svq, int svq_kick_fd)
{
    vhost_svq_set_svq_kick_fd_internal(svq, svq_kick_fd, true);
}

/*
 * Start shadow virtqueue operation.
 * @svq Shadow Virtqueue
 * @svq_kick_fd Kick file descriptor
 */
void vhost_svq_start(VhostShadowVirtqueue *svq, int svq_kick_fd)
{
    vhost_svq_set_svq_kick_fd_internal(svq, svq_kick_fd, false);
}

/*
 * Stop shadow virtqueue operation.
 * @svq Shadow Virtqueue
 */
void vhost_svq_stop(VhostShadowVirtqueue *svq)
{
    event_notifier_set_handler(&svq->svq_kick, NULL);
}

/*
 * Creates vhost shadow virtqueue, and instruct vhost device to use the shadow
 * methods and file descriptors.
 */
VhostShadowVirtqueue *vhost_svq_new(struct vhost_dev *dev)
{
    g_autofree VhostShadowVirtqueue *svq = g_new0(VhostShadowVirtqueue, 1);
    int r;

    r = event_notifier_init(&svq->hdev_kick, 0);
    if (r != 0) {
        error_report("Couldn't create kick event notifier: %s",
                     strerror(errno));
        goto err_init_hdev_kick;
    }

    r = event_notifier_init(&svq->hdev_call, 0);
    if (r != 0) {
        error_report("Couldn't create call event notifier: %s",
                     strerror(errno));
        goto err_init_hdev_call;
    }

    return g_steal_pointer(&svq);

err_init_hdev_call:
    event_notifier_cleanup(&svq->hdev_kick);

err_init_hdev_kick:
    return NULL;
}

/*
 * Free the resources of the shadow virtqueue.
 */
void vhost_svq_free(VhostShadowVirtqueue *vq)
{
    event_notifier_cleanup(&vq->hdev_kick);
    event_notifier_cleanup(&vq->hdev_call);
    g_free(vq);
}
