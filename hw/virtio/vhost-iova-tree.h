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
    VHOST_DMA_MAP_NO_SPACE = -3,
    VHOST_DMA_MAP_OVERLAP = -2,
    VHOST_DMA_MAP_INVALID = -1,
    VHOST_DMA_MAP_OK = 0,
} VhostDMAMapNewRC;

/**
 * VhostIOVATree, able to:
 * - Translate iova address
 * - Reverse translate iova address (from translated to iova)
 * - Allocate IOVA regions for translated range (potentially slow operation)
 *
 * Note that it cannot remove nodes.
 */
typedef struct VhostIOVATree {
    /* Ordered array of reverse translations, IOVA address to qemu memory. */
    GArray *iova_taddr_map;

    /*
     * Ordered array of translations from qemu virtual memory address to iova
     */
    GArray *taddr_iova_map;
} VhostIOVATree;

void vhost_iova_tree_new(VhostIOVATree *iova_rm);
void vhost_iova_tree_destroy(VhostIOVATree *iova_rm);

const VhostDMAMap *vhost_iova_tree_find_iova(const VhostIOVATree *iova_rm,
                                             const VhostDMAMap *map);
const VhostDMAMap *vhost_iova_tree_find_taddr(const VhostIOVATree *iova_rm,
                                              const VhostDMAMap *map);
VhostDMAMapNewRC vhost_iova_tree_insert(VhostIOVATree *iova_rm,
                                        VhostDMAMap *map);
VhostDMAMapNewRC vhost_iova_tree_alloc(VhostIOVATree *iova_rm,
                                       VhostDMAMap *map);

#endif
