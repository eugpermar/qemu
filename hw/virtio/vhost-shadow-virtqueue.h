/*
 * vhost shadow virtqueue
 *
 * SPDX-FileCopyrightText: Red Hat, Inc. 2021
 * SPDX-FileContributor: Author: Eugenio Pérez <eperezma@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VHOST_SHADOW_VIRTQUEUE_H
#define VHOST_SHADOW_VIRTQUEUE_H

#include "hw/virtio/vhost.h"
#include "qemu/event_notifier.h"

typedef struct VhostShadowVirtqueue VhostShadowVirtqueue;

void vhost_svq_set_svq_kick_fd(VhostShadowVirtqueue *svq, int svq_kick_fd);
const EventNotifier *vhost_svq_get_dev_kick_notifier(
                                              const VhostShadowVirtqueue *svq);

VhostShadowVirtqueue *vhost_svq_new(struct vhost_dev *dev);

void vhost_svq_free(VhostShadowVirtqueue *vq);

#endif
