/** @file
 * Definitions for the Wireshark Memory Manager Hash Map
 * Copyright 2014, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_MAP_H__
#define __WMEM_MAP_H__

#include <glib.h>

#include "wmem_core.h"
#include "wmem_list.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup wmem
 *  @{
 *    @defgroup wmem-map Hash Map
 *
 *    A hash map implementation on top of wmem. Provides insertion, deletion and
 *    lookup in expected amortized constant time. Uses universal hashing to map
 *    keys into buckets, and provides a generic strong hash function that makes
 *    it secure against algorithmic complexity attacks, and suitable for use
 *    even with untrusted data.
 *
 *    @{
 */

struct _wmem_map_t;
typedef struct _wmem_map_t wmem_map_t;

/** Creates a map with the given allocator scope. When the scope is emptied,
 * the map is fully destroyed. Items stored in it will not be freed unless they
 * were allocated from the same scope. For details on the GHashFunc and
 * GEqualFunc parameters, see the glib documentation at:
 * https://docs.gtk.org/glib/struct.HashTable.html
 *
 * If the keys are coming from untrusted data, do *not* use glib's default hash
 * functions for strings, int64s or doubles. Wmem provides stronger equivalents
 * below. Feel free to use the g_direct_hash, g_int_hash, and any of the
 * g_*_equal functions though, as they should be safe.
 *
 * @param allocator The allocator scope with which to create the map.
 * @param hash_func The hash function used to place inserted keys.
 * @param eql_func  The equality function used to compare inserted keys.
 * @return The newly-allocated map.
 *
 * @note It is technically possible to use this with a NULL allocator scope,
 * but a GHashTable should probably be used instead, as it has more capabilities
 * to help manage memory that must be freed manually.
 */
WS_DLL_PUBLIC
wmem_map_t *
wmem_map_new(wmem_allocator_t *allocator,
        GHashFunc hash_func, GEqualFunc eql_func)
G_GNUC_MALLOC;

/** Creates a map with two allocator scopes. The base structure lives in the
 * metadata scope, and the map data lives in the data scope. Every time free_all
 * occurs in the data scope the map is transparently emptied without affecting
 * the location of the base / metadata structure.
 *
 * WARNING: None of the map (even the part in the metadata scope) can be used
 * after the data scope has been *destroyed*.
 *
 * The primary use for this function is to create maps that reset for each new
 * capture file that is loaded. This can be done by specifying wmem_epan_scope()
 * as the metadata scope and wmem_file_scope() as the data scope.
 *
 * @warning This cannot be used with either allocator scope being NULL.
 */
WS_DLL_PUBLIC
wmem_map_t *
wmem_map_new_autoreset(wmem_allocator_t *metadata_scope, wmem_allocator_t *data_scope,
        GHashFunc hash_func, GEqualFunc eql_func)
G_GNUC_MALLOC;

/** Inserts a value into the map.
 *
 * @param map The map to insert into. Must not be NULL.
 * @param key The key to insert by.
 * @param value The value to insert.
 * @return The previous value stored at this key if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_map_insert(wmem_map_t *map, const void *key, void *value);

/** Check if a value is in the map.
 *
 * @param map The map to search in. May be NULL.
 * @param key The key to lookup.
 * @return true if the key is in the map, otherwise false.
 */
WS_DLL_PUBLIC
bool
wmem_map_contains(wmem_map_t *map, const void *key);

/** Lookup a value in the map.
 *
 * @param map The map to search in. May be NULL.
 * @param key The key to lookup.
 * @return The value stored at the key if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_map_lookup(wmem_map_t *map, const void *key);

/** Lookup a value in the map, returning the key, value, and a boolean which
 * is true if the key is found.
 *
 * @param map The map to search in. May be NULL.
 * @param key The key to lookup.
 * @param orig_key (optional) The key that was determined to be a match, if any.
 * @param value (optional) The value stored at the key, if any.
 * @return true if the key is in the map, otherwise false.
 */
WS_DLL_PUBLIC
bool
wmem_map_lookup_extended(wmem_map_t *map, const void *key, const void **orig_key, void **value);

/** Remove a value from the map. If no value is stored at that key, nothing
 * happens.
 *
 * @param map The map to remove from. May be NULL.
 * @param key The key of the value to remove.
 * @return The (removed) value stored at the key if any, or NULL.
 */
WS_DLL_PUBLIC
void *
wmem_map_remove(wmem_map_t *map, const void *key);

/** Remove a key and value from the map but does not destroy (free) them. If no
 * value is stored at that key, nothing happens.
 *
 * @param map The map to remove from. May be NULL.
 * @param key The key of the value to remove.
 * @return true if key is found false if not.
 */
WS_DLL_PUBLIC
bool
wmem_map_steal(wmem_map_t *map, const void *key);

/** Retrieves a list of keys inside the map
 *
 * @param list_allocator The allocator scope for the returned list.
 * @param map The map to extract keys from
 * @return list of keys in the map
 */
WS_DLL_PUBLIC
wmem_list_t*
wmem_map_get_keys(wmem_allocator_t *list_allocator, wmem_map_t *map);

/** Run a function against all key/value pairs in the map. The order
 * of the calls is unpredictable, since it is based on the internal
 * storage of data.
 *
 * @param map The map to use. May be NULL.
 * @param foreach_func the function to call for each key/value pair
 * @param user_data user data to pass to the function
 */
WS_DLL_PUBLIC
void
wmem_map_foreach(wmem_map_t *map, GHFunc foreach_func, void * user_data);

/** Run a function against all key/value pairs in the map. If the
 * function returns true, then the key/value pair is removed from
 * the map. The order of the calls is unpredictable, since it is
 * based on the internal storage of data.
 *
 * @param map The map to use. May be NULL.
 * @param foreach_func the function to call for each key/value pair
 * @param user_data user data to pass to the function
 * @return The number of items removed
 */
WS_DLL_PUBLIC
unsigned
wmem_map_foreach_remove(wmem_map_t *map, GHRFunc foreach_func, void * user_data);

/** Run a function against all key/value pairs in the map until the
 * function returns true, at which point the value of matching pair
 * is returned. If no pair that matches the function is found, NULL
 * is returned. The order of the calls is unpredictable, since it is
 * based on the internal storage of data.
 *
 * @param map The map to use. May be NULL.
 * @param foreach_func the function to call for each key/value pair
 * @param user_data user data to pass to the function
 * @return The value of the first key/value pair found for which foreach_func
 * returns TRUE. NULL if no matching pair is found.
 */
WS_DLL_PUBLIC
void *
wmem_map_find(wmem_map_t *map, GHRFunc foreach_func, void * user_data);

/** Return the number of elements of the map.
 *
 * @param map The map to use
 * @return the number of elements
*/
WS_DLL_PUBLIC
unsigned
wmem_map_size(wmem_map_t *map);

/** Ensure that a certain number of elements can be stored in the wmem_map
 * without having to grow the internal table. This can be useful if a very
 * large number of elements need to be inserted. It preallocates a certain
 * number of buckets and avoids automatic reallocation and copies as the
 * map grows.
 *
 * @param map The map to use
 * @return the number of buckets actually reserved
 *
 * @note This value persists on reset for autoreset maps. Passing 0 for the
 * capacity results in undefined behavior. It is rare to need this function.
*/
WS_DLL_PUBLIC
size_t
wmem_map_reserve(wmem_map_t *map, uint64_t capacity);

/** Cleanup memory used by the map instead of waiting for the allocator pool
 * to be freed or destroyed. Do NOT simply call wmem_free on a wmem_map_t.
 *
 * @param map The map to use
 * @param free_keys Whether to free the keys as well
 * @param free_values Whether to free the keys as well
 *
 * @warning The implementation is still incomplete; free_keys and free_values
 * have no effect yet. wmem_map, like other wmem functions, is designed to be
 * automatically cleaned up when the allocator pool is reset. If you find
 * yourself calling this function, consider whether too many maps are being
 * created or the maps should have a custom allocator with its own lifetime.
 * NULL allocated maps should be a GHashTable instead.
 */
WS_DLL_PUBLIC
void
wmem_map_destroy(wmem_map_t *map, bool free_keys, bool free_values);

/** Compute a strong hash value for an arbitrary sequence of bytes. Use of this
 * hash value should be secure against algorithmic complexity attacks, even for
 * short keys. The computation uses a random seed which is generated on wmem
 * initialization, so the same key will hash to different values on different
 * runs of the application.
 *
 * @param buf The buffer of bytes (does not have to be aligned).
 * @param len The length of buf to use for the hash computation.
 * @return The hash value.
 */
WS_DLL_PUBLIC
uint32_t
wmem_strong_hash(const uint8_t *buf, const size_t len);

/** An implementation of GHashFunc using wmem_strong_hash. Prefer this over
 * g_str_hash when the data comes from an untrusted source.
 */
WS_DLL_PUBLIC
unsigned
wmem_str_hash(const void *key);

/** An implementation of GHashFunc using wmem_strong_hash. Prefer this over
 * g_int64_hash when the data comes from an untrusted source.
 */
WS_DLL_PUBLIC
unsigned
wmem_int64_hash(const void *key);

/** An implementation of GHashFunc using wmem_strong_hash. Prefer this over
 * g_double_hash when the data comes from an untrusted source.
 */
WS_DLL_PUBLIC
unsigned
wmem_double_hash(const void *key);

/**   @}
 *  @} */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_MAP_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
