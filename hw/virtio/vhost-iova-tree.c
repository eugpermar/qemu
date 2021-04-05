/*
 * vhost software live migration ring
 *
 * SPDX-FileCopyrightText: Red Hat, Inc. 2021
 * SPDX-FileContributor: Author: Eugenio Pérez <eperezma@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "vhost-iova-tree.h"

#define G_ARRAY_NOT_ZERO_TERMINATED false
#define G_ARRAY_NOT_CLEAR_ON_ALLOC false

/**
 * Inserts an element after an existing one in garray.
 *
 * @array      The array
 * @prev_elem  The previous element of array of NULL if prepending
 * @map        The DMA map
 *
 * It provides the aditional advantage of being type safe over
 * g_array_insert_val, which accepts a reference pointer instead of a value
 * with no complains.
 */
static void vhost_iova_tree_insert_after(GArray *array,
                                         const VhostDMAMap *prev_elem,
                                         const VhostDMAMap *map)
{
    size_t pos;

    if (!prev_elem) {
        pos = 0;
    } else {
        pos = prev_elem - &g_array_index(array, typeof(*prev_elem), 0) + 1;
    }

    g_array_insert_val(array, pos, *map);
}

static gint vhost_iova_tree_cmp_iova(gconstpointer a, gconstpointer b)
{
    const VhostDMAMap *m1 = a, *m2 = b;

    if (m1->iova > m2->iova + m2->size) {
        return 1;
    }

    if (m1->iova + m1->size < m2->iova) {
        return -1;
    }

    /* Overlapped */
    return 0;
}

/**
 * Find the previous node to a given iova
 *
 * @array  The ascending ordered-by-translated-addr array of VhostDMAMap
 * @map    The map to insert
 * @prev   Returned location of the previous map
 *
 * Return VHOST_DMA_MAP_OK if everything went well, or VHOST_DMA_MAP_OVERLAP if
 * it already exists. It is ok to use this function to check if a given range
 * exists, but it will use a linear search.
 *
 * TODO: We can use bsearch to locate the entry if we save the state in the
 * needle, knowing that the needle is always the first argument to
 * compare_func.
 */
static VhostDMAMapNewRC vhost_iova_tree_find_prev(const GArray *array,
                                                  GCompareFunc compare_func,
                                                  const VhostDMAMap *map,
                                                  const VhostDMAMap **prev)
{
    size_t i;
    int r;

    *prev = NULL;
    for (i = 0; i < array->len; ++i) {
        r = compare_func(map, &g_array_index(array, typeof(*map), i));
        if (r == 0) {
            return VHOST_DMA_MAP_OVERLAP;
        }
        if (r < 0) {
            return VHOST_DMA_MAP_OK;
        }

        *prev = &g_array_index(array, typeof(**prev), i);
    }

    return VHOST_DMA_MAP_OK;
}

/**
 * Create a new IOVA tree
 *
 * @tree  The IOVA tree
 */
void vhost_iova_tree_new(VhostIOVATree *tree)
{
    assert(tree);

    tree->iova_taddr_map = g_array_new(G_ARRAY_NOT_ZERO_TERMINATED,
                                       G_ARRAY_NOT_CLEAR_ON_ALLOC,
                                       sizeof(VhostDMAMap));
}

/**
 * Destroy an IOVA tree
 *
 * @tree  The iova tree
 */
void vhost_iova_tree_destroy(VhostIOVATree *tree)
{
    g_array_unref(g_steal_pointer(&tree->iova_taddr_map));
}

/**
 * Perform a search on a GArray.
 *
 * @array Glib array
 * @map Map to look up
 * @compare_func Compare function to use
 *
 * Return The found element or NULL if not found.
 *
 * This can be replaced with g_array_binary_search (Since glib 2.62) when that
 * is common enough.
 */
static const VhostDMAMap *vhost_iova_tree_bsearch(const GArray *array,
                                                  const VhostDMAMap *map,
                                                  GCompareFunc compare_func)
{
    return bsearch(map, array->data, array->len, sizeof(*map), compare_func);
}

/**
 * Find the translated address stored from a IOVA address
 *
 * @tree  The iova tree
 * @map   The map with the memory address
 *
 * Return the stored mapping, or NULL if not found.
 */
const VhostDMAMap *vhost_iova_tree_find_taddr(const VhostIOVATree *tree,
                                              const VhostDMAMap *map)
{
    return vhost_iova_tree_bsearch(tree->iova_taddr_map, map,
                                  vhost_iova_tree_cmp_iova);
}

/**
 * Insert a new map
 *
 * @tree  The iova tree
 * @map   The iova map
 *
 * Returns:
 * - VHOST_DMA_MAP_OK if the map fits in the container
 * - VHOST_DMA_MAP_INVALID if the map does not make sense (like size overflow)
 * - VHOST_DMA_MAP_OVERLAP if the tree already contains that map
 * Can query the assignated iova in map.
 */
VhostDMAMapNewRC vhost_iova_tree_insert(VhostIOVATree *tree,
                                        VhostDMAMap *map)
{
    const VhostDMAMap *prev;
    int find_prev_rc;

    if (map->translated_addr + map->size < map->translated_addr ||
        map->iova + map->size < map->iova || map->perm == IOMMU_NONE) {
        return VHOST_DMA_MAP_INVALID;
    }

    /* Check for duplicates, and save position for insertion */
    find_prev_rc = vhost_iova_tree_find_prev(tree->iova_taddr_map,
                                             vhost_iova_tree_cmp_iova, map,
                                             &prev);
    if (find_prev_rc == VHOST_DMA_MAP_OVERLAP) {
        return VHOST_DMA_MAP_OVERLAP;
    }

    vhost_iova_tree_insert_after(tree->iova_taddr_map, prev, map);
    return VHOST_DMA_MAP_OK;
}
