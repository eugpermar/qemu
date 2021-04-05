/*
 * vhost software live migration ring
 *
 * SPDX-FileCopyrightText: Red Hat, Inc. 2021
 * SPDX-FileContributor: Author: Eugenio Pérez <eperezma@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HW_VIRTIO_VHOST_IOVA_TREE_H
#define HW_VIRTIO_VHOST_IOVA_TREE_H

#include <gmodule.h>

#include "exec/memory.h"

typedef struct VhostDMAMap {
    void *translated_addr;
    hwaddr iova;
    hwaddr size;                /* Inclusive */
    IOMMUAccessFlags perm;
} VhostDMAMap;

typedef enum VhostDMAMapNewRC {
    VHOST_DMA_MAP_OVERLAP = -2,
    VHOST_DMA_MAP_INVALID = -1,
    VHOST_DMA_MAP_OK = 0,
} VhostDMAMapNewRC;

/**
 * VhostIOVATree
 *
 * Store and search IOVA -> Translated mappings.
 *
 * Note that it cannot remove nodes.
 */
typedef struct VhostIOVATree {
    /* Ordered array of reverse translations, IOVA address to qemu memory. */
    GArray *iova_taddr_map;
} VhostIOVATree;

void vhost_iova_tree_new(VhostIOVATree *iova_rm);
void vhost_iova_tree_destroy(VhostIOVATree *iova_rm);

const VhostDMAMap *vhost_iova_tree_find_taddr(const VhostIOVATree *iova_rm,
                                              const VhostDMAMap *map);
VhostDMAMapNewRC vhost_iova_tree_insert(VhostIOVATree *iova_rm,
                                        VhostDMAMap *map);

#endif
