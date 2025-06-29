/* wtap_opttypes.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include "wtap_opttypes.h"

#define WS_LOG_DOMAIN LOG_DOMAIN_WIRETAP

#include <glib.h>
#include <string.h>

#include "wtap.h"
#include "wtap-int.h"
#include "pcapng_module.h"
#include <wsutil/ws_assert.h>

#include <wsutil/glib-compat.h>
#include <wsutil/unicode-utils.h>

#if 0
#define wtap_debug(...) ws_warning(__VA_ARGS__)
#define DEBUG_COUNT_REFS
#else
#define wtap_debug(...)
#endif

#define ROUND_TO_4BYTE(len) (((len) + 3) & ~3)

/* Flags */
#define WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED 0x00000001 /* multiple instances allowed */

/* Debugging reference counting */
#ifdef DEBUG_COUNT_REFS
static unsigned block_count;
static uint8_t blocks_active[sizeof(unsigned)/8];

static void rc_set(unsigned refnum)
{
    unsigned cellno = refnum / 8;
    unsigned bitno = refnum % 8;
    blocks_active[cellno] |= (uint8_t)(1 << bitno);
}

static void rc_clear(unsigned refnum)
{
    unsigned cellno = refnum / 8;
    unsigned bitno = refnum % 8;
    blocks_active[cellno] &= (uint8_t)~(1 << bitno);
}

#endif /* DEBUG_COUNT_REFS */

/* Keep track of wtap_blocktype_t's via their id number */
static wtap_blocktype_t* blocktype_list[MAX_WTAP_BLOCK_TYPE_VALUE];

static if_filter_opt_t if_filter_dup(if_filter_opt_t* filter_src)
{
    if_filter_opt_t filter_dest;

    memset(&filter_dest, 0, sizeof(filter_dest));

    /* Deep copy. */
    filter_dest.type = filter_src->type;
    switch (filter_src->type) {

    case if_filter_pcap:
        /* pcap filter string */
        filter_dest.data.filter_str =
            g_strdup(filter_src->data.filter_str);
        break;

    case if_filter_bpf:
        /* BPF program */
        filter_dest.data.bpf_prog.bpf_prog_len =
            filter_src->data.bpf_prog.bpf_prog_len;
        filter_dest.data.bpf_prog.bpf_prog =
            (wtap_bpf_insn_t *)g_memdup2(filter_src->data.bpf_prog.bpf_prog,
                                        filter_src->data.bpf_prog.bpf_prog_len * sizeof (wtap_bpf_insn_t));
        break;

    default:
        break;
    }
    return filter_dest;
}

static void if_filter_free(if_filter_opt_t* filter_src)
{
    switch (filter_src->type) {

    case if_filter_pcap:
        /* pcap filter string */
        g_free(filter_src->data.filter_str);
        break;

    case if_filter_bpf:
        /* BPF program */
        g_free(filter_src->data.bpf_prog.bpf_prog);
        break;

    default:
        break;
    }
}

static packet_verdict_opt_t
packet_verdict_dup(packet_verdict_opt_t* verdict_src)
{
    packet_verdict_opt_t verdict_dest;

    memset(&verdict_dest, 0, sizeof(verdict_dest));

    /* Deep copy. */
    verdict_dest.type = verdict_src->type;
    switch (verdict_src->type) {

    case packet_verdict_hardware:
        /* array of octets */
        verdict_dest.data.verdict_bytes =
            g_byte_array_new_take((uint8_t *)g_memdup2(verdict_src->data.verdict_bytes->data,
                                                      verdict_src->data.verdict_bytes->len),
                                  verdict_src->data.verdict_bytes->len);
        break;

    case packet_verdict_linux_ebpf_tc:
        /* eBPF TC_ACT_ value */
        verdict_dest.data.verdict_linux_ebpf_tc =
            verdict_src->data.verdict_linux_ebpf_tc;
        break;

    case packet_verdict_linux_ebpf_xdp:
        /* xdp_action value */
        verdict_dest.data.verdict_linux_ebpf_xdp =
            verdict_src->data.verdict_linux_ebpf_xdp;
        break;

    default:
        break;
    }
    return verdict_dest;
}

void wtap_packet_verdict_free(packet_verdict_opt_t* verdict)
{
    switch (verdict->type) {

    case packet_verdict_hardware:
        /* array of bytes */
        g_byte_array_free(verdict->data.verdict_bytes, true);
        break;

    default:
        break;
    }
}

static packet_hash_opt_t
packet_hash_dup(packet_hash_opt_t* hash_src)
{
    packet_hash_opt_t hash_dest;

    memset(&hash_dest, 0, sizeof(hash_dest));

    /* Deep copy. */
    hash_dest.type = hash_src->type;
    /* array of octets */
    hash_dest.hash_bytes =
        g_byte_array_new_take((uint8_t *)g_memdup2(hash_src->hash_bytes->data,
                                                  hash_src->hash_bytes->len),
                              hash_src->hash_bytes->len);
    return hash_dest;
}

void wtap_packet_hash_free(packet_hash_opt_t* hash)
{
    /* array of bytes */
    g_byte_array_free(hash->hash_bytes, true);
}

void wtap_opttype_block_register(wtap_blocktype_t *blocktype)
{
    wtap_block_type_t block_type;
    static const wtap_opttype_t opt_comment = {
        "opt_comment",
        "Comment",
        WTAP_OPTTYPE_STRING,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };
    static const wtap_opttype_t opt_custom_string = {
        "opt_custom_string",
        "Custom string option",
        WTAP_OPTTYPE_CUSTOM_STRING,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };
    static const wtap_opttype_t opt_custom_binary = {
        "opt_custom_binary",
        "Custom binary option",
        WTAP_OPTTYPE_CUSTOM_BINARY,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };
    static const wtap_opttype_t opt_nocopy_custom_string = {
        "opt_nocopy_custom_string",
        "Uncopied custom string option",
        WTAP_OPTTYPE_CUSTOM_STRING,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };
    static const wtap_opttype_t opt_nocopy_custom_binary = {
        "opt_nocopy_custom_binary",
        "Uncopied custom binary option",
        WTAP_OPTTYPE_CUSTOM_BINARY,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };

    block_type = blocktype->block_type;

    /* Check input */
    ws_assert(block_type < MAX_WTAP_BLOCK_TYPE_VALUE);

    /* Don't re-register. */
    ws_assert(blocktype_list[block_type] == NULL);

    /* Sanity check */
    ws_assert(blocktype->name);
    ws_assert(blocktype->description);
    ws_assert(blocktype->create);

    /*
     * Initialize the set of supported options.
     * All blocks that support options at all support OPT_COMMENT,
     * OPT_CUSTOM_STR_COPY, OPT_CUSTOM_BIN_COPY, OPT_CUSTOM_STR_NO_COPY,
     * and OPT_CUSTOM_BIN_NO_COPY.
     *
     * XXX - there's no "g_uint_hash()" or "g_uint_equal()",
     * so we use "g_direct_hash()" and "g_direct_equal()".
     */
    blocktype->options = g_hash_table_new(g_direct_hash, g_direct_equal);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_COMMENT),
                        (void *)&opt_comment);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_CUSTOM_STR_COPY),
                        (void *)&opt_custom_string);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_CUSTOM_BIN_COPY),
                        (void *)&opt_custom_binary);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_CUSTOM_STR_NO_COPY),
                        (void *)&opt_nocopy_custom_string);
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(OPT_CUSTOM_BIN_NO_COPY),
                        (void *)&opt_nocopy_custom_binary);

    blocktype_list[block_type] = blocktype;
}

static void wtap_opttype_option_register(wtap_blocktype_t *blocktype, unsigned opttype, const wtap_opttype_t *option)
{
    g_hash_table_insert(blocktype->options, GUINT_TO_POINTER(opttype),
                        (void *) option);
}

wtap_block_type_t wtap_block_get_type(wtap_block_t block)
{
    return block->info->block_type;
}

void* wtap_block_get_mandatory_data(wtap_block_t block)
{
    return block->mandatory_data;
}

static wtap_optval_t *
wtap_block_get_option(wtap_block_t block, unsigned option_id)
{
    unsigned i;
    wtap_option_t *opt;

    if (block == NULL) {
        return NULL;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id)
            return &opt->value;
    }

    return NULL;
}

static wtap_optval_t *
wtap_block_get_nth_option(wtap_block_t block, unsigned option_id, unsigned idx)
{
    unsigned i;
    wtap_option_t *opt;
    unsigned opt_idx;

    if (block == NULL) {
        return NULL;
    }

    /*
     * Look for the idx'th option of this type.
     */
    opt_idx = 0;
    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id) {
            if (opt_idx == idx)
                return &opt->value;
            opt_idx++;
        }
    }

    return NULL;
}

wtap_block_t wtap_block_create(wtap_block_type_t block_type)
{
    wtap_block_t block;

    if (block_type >= MAX_WTAP_BLOCK_TYPE_VALUE)
        return NULL;

    block = g_new(struct wtap_block, 1);
    block->info = blocktype_list[block_type];
    block->options = g_array_new(false, false, sizeof(wtap_option_t));
    block->info->create(block);
    block->ref_count = 1;
#ifdef DEBUG_COUNT_REFS
    block->id = block_count++;
    rc_set(block->id);
    wtap_debug("Created #%d %s", block->id, block->info->name);
#endif /* DEBUG_COUNT_REFS */

    return block;
}

static void wtap_block_free_option(wtap_block_t block, wtap_option_t *opt)
{
    const wtap_opttype_t *opttype;

    if (block == NULL) {
        return;
    }

    opttype = GET_OPTION_TYPE(block->info->options, opt->option_id);
    switch (opttype->data_type) {

    case WTAP_OPTTYPE_STRING:
        g_free(opt->value.stringval);
        break;

    case WTAP_OPTTYPE_BYTES:
        g_bytes_unref(opt->value.byteval);
        break;

    case WTAP_OPTTYPE_CUSTOM_STRING:
        g_free(opt->value.custom_stringval.string);
        break;

    case WTAP_OPTTYPE_CUSTOM_BINARY:
        g_free(opt->value.custom_binaryval.data.custom_data);
        break;

    case WTAP_OPTTYPE_IF_FILTER:
        if_filter_free(&opt->value.if_filterval);
        break;

    case WTAP_OPTTYPE_PACKET_VERDICT:
        wtap_packet_verdict_free(&opt->value.packet_verdictval);
        break;

    case WTAP_OPTTYPE_PACKET_HASH:
        wtap_packet_hash_free(&opt->value.packet_hash);
        break;

    default:
        break;
    }
}

static void wtap_block_free_options(wtap_block_t block)
{
    unsigned i;
    wtap_option_t *opt;

    if (block == NULL || block->options == NULL) {
        return;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        wtap_block_free_option(block, opt);
    }
    g_array_remove_range(block->options, 0, block->options->len);
}

wtap_block_t wtap_block_ref(wtap_block_t block)
{
    if (block == NULL) {
        return NULL;
    }

    g_atomic_int_inc(&block->ref_count);
#ifdef DEBUG_COUNT_REFS
        wtap_debug("Ref     #%d %s", block->id, block->info->name);
#endif /* DEBUG_COUNT_REFS */
    return block;
}

void wtap_block_unref(wtap_block_t block)
{
    if (block != NULL)
    {
        if (g_atomic_int_dec_and_test(&block->ref_count)) {
#ifdef DEBUG_COUNT_REFS
            wtap_debug("Destroy #%d %s", block->id, block->info->name);
            rc_clear(block->id);
#endif /* DEBUG_COUNT_REFS */
            if (block->info->free_mand != NULL)
                block->info->free_mand(block);

            g_free(block->mandatory_data);
            wtap_block_free_options(block);
            g_array_free(block->options, true);
            g_free(block);
        }
#ifdef DEBUG_COUNT_REFS
        else {
            wtap_debug("Unref   #%d %s", block->id, block->info->name);
        }
#endif /* DEBUG_COUNT_REFS */
    }
}

void wtap_block_array_free(GArray* block_array)
{
    unsigned block;

    if (block_array == NULL)
        return;

    for (block = 0; block < block_array->len; block++) {
        wtap_block_unref(g_array_index(block_array, wtap_block_t, block));
    }
    g_array_free(block_array, true);
}

void wtap_block_array_ref(GArray* block_array)
{
    unsigned block;

    if (block_array == NULL)
        return;

    for (block = 0; block < block_array->len; block++) {
        wtap_block_ref(g_array_index(block_array, wtap_block_t, block));
    }
    g_array_ref(block_array);
}

void wtap_block_array_unref(GArray* block_array)
{
    unsigned block;

    if (block_array == NULL)
        return;

    for (block = 0; block < block_array->len; block++) {
        wtap_block_unref(g_array_index(block_array, wtap_block_t, block));
    }
    g_array_unref(block_array);
}

/*
 * Make a copy of a block.
 */
void
wtap_block_copy(wtap_block_t dest_block, wtap_block_t src_block)
{
    unsigned i;
    wtap_option_t *src_opt;
    const wtap_opttype_t *opttype;

    /*
     * Copy the mandatory data.
     */
    if (dest_block->info->copy_mand != NULL)
        dest_block->info->copy_mand(dest_block, src_block);

    /* Copy the options.  For now, don't remove any options that are in destination
     * but not source.
     */
    for (i = 0; i < src_block->options->len; i++)
    {
        src_opt = &g_array_index(src_block->options, wtap_option_t, i);
        opttype = GET_OPTION_TYPE(src_block->info->options, src_opt->option_id);

        switch(opttype->data_type) {

        case WTAP_OPTTYPE_UINT8:
            wtap_block_add_uint8_option(dest_block, src_opt->option_id, src_opt->value.uint8val);
            break;

        case WTAP_OPTTYPE_UINT32:
            wtap_block_add_uint32_option(dest_block, src_opt->option_id, src_opt->value.uint32val);
            break;

        case WTAP_OPTTYPE_UINT64:
            wtap_block_add_uint64_option(dest_block, src_opt->option_id, src_opt->value.uint64val);
            break;

        case WTAP_OPTTYPE_INT8:
            wtap_block_add_int8_option(dest_block, src_opt->option_id, src_opt->value.int8val);
            break;

        case WTAP_OPTTYPE_INT32:
            wtap_block_add_int32_option(dest_block, src_opt->option_id, src_opt->value.int32val);
            break;

        case WTAP_OPTTYPE_INT64:
            wtap_block_add_int64_option(dest_block, src_opt->option_id, src_opt->value.int64val);
            break;

        case WTAP_OPTTYPE_IPv4:
            wtap_block_add_ipv4_option(dest_block, src_opt->option_id, src_opt->value.ipv4val);
            break;

        case WTAP_OPTTYPE_IPv6:
            wtap_block_add_ipv6_option(dest_block, src_opt->option_id, &src_opt->value.ipv6val);
            break;

        case WTAP_OPTTYPE_STRING:
            wtap_block_add_string_option(dest_block, src_opt->option_id, src_opt->value.stringval, strlen(src_opt->value.stringval));
            break;

        case WTAP_OPTTYPE_BYTES:
            wtap_block_add_bytes_option_borrow(dest_block, src_opt->option_id, src_opt->value.byteval);
            break;

        case WTAP_OPTTYPE_CUSTOM_STRING:
            wtap_block_add_custom_string_option(dest_block, src_opt->option_id,
                                                src_opt->value.custom_stringval.pen,
                                                src_opt->value.custom_stringval.string,
                                                strlen(src_opt->value.custom_stringval.string));
            break;

        case WTAP_OPTTYPE_CUSTOM_BINARY:
            wtap_block_add_custom_binary_option(dest_block, src_opt->option_id,
                                                src_opt->value.custom_binaryval.pen,
                                                &src_opt->value.custom_binaryval.data);
            break;

        case WTAP_OPTTYPE_IF_FILTER:
            wtap_block_add_if_filter_option(dest_block, src_opt->option_id, &src_opt->value.if_filterval);
            break;

        case WTAP_OPTTYPE_PACKET_VERDICT:
            wtap_block_add_packet_verdict_option(dest_block, src_opt->option_id, &src_opt->value.packet_verdictval);
            break;

        case WTAP_OPTTYPE_PACKET_HASH:
            wtap_block_add_packet_hash_option(dest_block, src_opt->option_id, &src_opt->value.packet_hash);
            break;
        }
    }
}

wtap_block_t wtap_block_make_copy(wtap_block_t block)
{
    wtap_block_t block_copy;

    block_copy = wtap_block_create(block->info->block_type);
    wtap_block_copy(block_copy, block);
    return block_copy;
}

unsigned
wtap_block_count_option(wtap_block_t block, unsigned option_id)
{
    unsigned i;
    unsigned ret_val = 0;
    wtap_option_t *opt;

    if (block == NULL) {
        return 0;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id)
            ret_val++;
    }

    return ret_val;
}


bool wtap_block_foreach_option(wtap_block_t block, wtap_block_foreach_func func, void* user_data)
{
    unsigned i;
    wtap_option_t *opt;
    const wtap_opttype_t *opttype;

    if (block == NULL) {
        return true;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        opttype = GET_OPTION_TYPE(block->info->options, opt->option_id);
        if (func && !func(block, opt->option_id, opttype->data_type, &opt->value, user_data))
            return false;
    }
    return true;
}

static wtap_opttype_return_val
wtap_block_add_option_common(wtap_block_t block, unsigned option_id, wtap_opttype_e type, wtap_option_t **optp)
{
    wtap_option_t *opt;
    const wtap_opttype_t *opttype;
    unsigned i;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Is this an option of the specified data type?
     */
    if (opttype->data_type != type) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (!(opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED)) {
        /*
         * No. Is there already an instance of this option?
         */
        if (wtap_block_get_option(block, option_id) != NULL) {
            /*
             * Yes. Fail.
             */
            return WTAP_OPTTYPE_ALREADY_EXISTS;
        }
    }

    /*
     * Add an instance.
     */
    i = block->options->len;
    g_array_set_size(block->options, i + 1);
    opt = &g_array_index(block->options, wtap_option_t, i);
    opt->option_id = option_id;
    *optp = opt;
    return WTAP_OPTTYPE_SUCCESS;
}

static wtap_opttype_return_val
wtap_block_get_option_common(wtap_block_t block, unsigned option_id, wtap_opttype_e type, wtap_optval_t **optvalp)
{
    const wtap_opttype_t *opttype;
    wtap_optval_t *optval;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Is this an option of the specified data type?
     */
    if (opttype->data_type != type) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED) {
        /*
         * Yes.  You can't ask for "the" value.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    optval = wtap_block_get_option(block, option_id);
    if (optval == NULL) {
        /* Didn't find the option */
        return WTAP_OPTTYPE_NOT_FOUND;
    }

    *optvalp = optval;
    return WTAP_OPTTYPE_SUCCESS;
}

static wtap_opttype_return_val
wtap_block_get_nth_option_common(wtap_block_t block, unsigned option_id, wtap_opttype_e type, unsigned idx, wtap_optval_t **optvalp)
{
    const wtap_opttype_t *opttype;
    wtap_optval_t *optval;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Is this an option of the specified data type?
     */
    if (opttype->data_type != type) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (!(opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED)) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    optval = wtap_block_get_nth_option(block, option_id, idx);
    if (optval == NULL) {
        /* Didn't find the option */
        return WTAP_OPTTYPE_NOT_FOUND;
    }

    *optvalp = optval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_uint8_option(wtap_block_t block, unsigned option_id, uint8_t value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_UINT8, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.uint8val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_uint8_option_value(wtap_block_t block, unsigned option_id, uint8_t value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT8, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->uint8val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_uint8_option_value(wtap_block_t block, unsigned option_id, uint8_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT8, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->uint8val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_uint32_option(wtap_block_t block, unsigned option_id, uint32_t value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_UINT32, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.uint32val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_uint32_option_value(wtap_block_t block, unsigned option_id, uint32_t value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT32, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->uint32val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_uint32_option_value(wtap_block_t block, unsigned option_id, uint32_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT32, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->uint32val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_uint64_option(wtap_block_t block, unsigned option_id, uint64_t value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_UINT64, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.uint64val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_uint64_option_value(wtap_block_t block, unsigned option_id, uint64_t value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT64, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->uint64val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_uint64_option_value(wtap_block_t block, unsigned option_id, uint64_t *value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_UINT64, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->uint64val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_int8_option(wtap_block_t block, unsigned option_id, int8_t value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_INT8, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.int8val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_int8_option_value(wtap_block_t block, unsigned option_id, int8_t value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_INT8, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->int8val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_int8_option_value(wtap_block_t block, unsigned option_id, int8_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_INT8, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->int8val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_int32_option(wtap_block_t block, unsigned option_id, int32_t value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_INT32, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.int32val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_int32_option_value(wtap_block_t block, unsigned option_id, int32_t value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_INT32, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->int32val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_int32_option_value(wtap_block_t block, unsigned option_id, int32_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_INT32, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->int32val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_int64_option(wtap_block_t block, unsigned option_id, int64_t value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_INT64, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.int64val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_int64_option_value(wtap_block_t block, unsigned option_id, int64_t value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_INT64, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->int64val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_int64_option_value(wtap_block_t block, unsigned option_id, int64_t *value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_INT64, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->int64val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_ipv4_option(wtap_block_t block, unsigned option_id, uint32_t value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_IPv4, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.ipv4val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_ipv4_option_value(wtap_block_t block, unsigned option_id, uint32_t value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv4, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->ipv4val = value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_ipv4_option_value(wtap_block_t block, unsigned option_id, uint32_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv4, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->ipv4val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_ipv6_option(wtap_block_t block, unsigned option_id, ws_in6_addr *value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_IPv6, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.ipv6val = *value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_ipv6_option_value(wtap_block_t block, unsigned option_id, ws_in6_addr *value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv6, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    optval->ipv6val = *value;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_ipv6_option_value(wtap_block_t block, unsigned option_id, ws_in6_addr* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IPv6, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->ipv6val;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_string_option(wtap_block_t block, unsigned option_id, const char *value, size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_STRING, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.stringval = g_strndup(value, value_length);
    WS_UTF_8_CHECK(opt->value.stringval, -1);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_string_option_owned(wtap_block_t block, unsigned option_id, char *value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_STRING, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.stringval = value;
    WS_UTF_8_CHECK(opt->value.stringval, -1);
    return WTAP_OPTTYPE_SUCCESS;
}

static wtap_opttype_return_val
wtap_block_add_string_option_vformat(wtap_block_t block, unsigned option_id, const char *format, va_list va)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_STRING, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.stringval = ws_strdup_vprintf(format, va);
    WS_UTF_8_CHECK(opt->value.stringval, -1);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_string_option_format(wtap_block_t block, unsigned option_id, const char *format, ...)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;
    va_list va;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_STRING, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    va_start(va, format);
    opt->value.stringval = ws_strdup_vprintf(format, va);
    va_end(va);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_string_option_value(wtap_block_t block, unsigned option_id, const char *value, size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_STRING, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS) {
        if (ret == WTAP_OPTTYPE_NOT_FOUND) {
            /*
             * There's no instance to set, so just try to create a new one
             * with the value.
             */
            return wtap_block_add_string_option(block, option_id, value, value_length);
        }
        /* Otherwise fail. */
        return ret;
    }
    g_free(optval->stringval);
    optval->stringval = g_strndup(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_nth_string_option_value(wtap_block_t block, unsigned option_id, unsigned idx, const char *value, size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_STRING, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    g_free(optval->stringval);
    optval->stringval = g_strndup(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_string_option_value_format(wtap_block_t block, unsigned option_id, const char *format, ...)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;
    va_list va;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_STRING, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS) {
        if (ret == WTAP_OPTTYPE_NOT_FOUND) {
            /*
             * There's no instance to set, so just try to create a new one
             * with the formatted string.
             */
            va_start(va, format);
            ret = wtap_block_add_string_option_vformat(block, option_id, format, va);
            va_end(va);
            return ret;
        }
        /* Otherwise fail. */
        return ret;
    }
    g_free(optval->stringval);
    va_start(va, format);
    optval->stringval = ws_strdup_vprintf(format, va);
    va_end(va);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_nth_string_option_value_format(wtap_block_t block, unsigned option_id, unsigned idx, const char *format, ...)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;
    va_list va;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_STRING, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    g_free(optval->stringval);
    va_start(va, format);
    optval->stringval = ws_strdup_vprintf(format, va);
    va_end(va);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_string_option_value(wtap_block_t block, unsigned option_id, char** value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_STRING, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->stringval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_nth_string_option_value(wtap_block_t block, unsigned option_id, unsigned idx, char** value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_STRING, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->stringval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_bytes_option(wtap_block_t block, unsigned option_id, const uint8_t *value, size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_BYTES, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.byteval = g_bytes_new(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_bytes_option_borrow(wtap_block_t block, unsigned option_id, GBytes *value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_BYTES, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.byteval = g_bytes_ref(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_bytes_option_value(wtap_block_t block, unsigned option_id, const uint8_t *value, size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_BYTES, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS) {
        if (ret == WTAP_OPTTYPE_NOT_FOUND) {
            /*
             * There's no instance to set, so just try to create a new one
             * with the value.
             */
            return wtap_block_add_bytes_option(block, option_id, value, value_length);
        }
        /* Otherwise fail. */
        return ret;
    }
    g_bytes_unref(optval->byteval);
    optval->byteval = g_bytes_new(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_nth_bytes_option_value(wtap_block_t block, unsigned option_id, unsigned idx, GBytes *value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_BYTES, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    g_bytes_unref(optval->byteval);
    optval->byteval = g_bytes_ref(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_bytes_option_value(wtap_block_t block, unsigned option_id, GBytes** value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_BYTES, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->byteval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_nth_bytes_option_value(wtap_block_t block, unsigned option_id, unsigned idx, GBytes** value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_BYTES, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->byteval;
    return WTAP_OPTTYPE_SUCCESS;
}

static bool
custom_option_matches_with_pen(wtap_option_t *opt, unsigned option_id,
                               uint32_t pen)
{
    ws_assert(option_id == OPT_CUSTOM_STR_COPY ||
              option_id == OPT_CUSTOM_BIN_COPY ||
              option_id == OPT_CUSTOM_STR_NO_COPY ||
              option_id == OPT_CUSTOM_BIN_NO_COPY);

    if (opt->option_id != option_id)
        return false;  /* not the specified option type */
    if ((opt->option_id == OPT_CUSTOM_STR_COPY ||
        opt->option_id == OPT_CUSTOM_STR_NO_COPY) &&
        opt->value.custom_stringval.pen != pen)
        return false; /* custom option, but different PEN */
    if ((opt->option_id == OPT_CUSTOM_BIN_COPY ||
        opt->option_id == OPT_CUSTOM_BIN_NO_COPY) &&
        opt->value.custom_binaryval.pen != pen)
        return false; /* custom option, but different PEN */
    return true;
}

static wtap_optval_t *
wtap_block_get_nth_custom_option_with_pen(wtap_block_t block,
                                          unsigned option_id,
                                          uint32_t pen, unsigned idx)
{
    unsigned i;
    wtap_option_t *opt;
    unsigned opt_idx;

    ws_assert(option_id == OPT_CUSTOM_STR_COPY ||
              option_id == OPT_CUSTOM_BIN_COPY ||
              option_id == OPT_CUSTOM_STR_NO_COPY ||
              option_id == OPT_CUSTOM_BIN_NO_COPY);

    if (block == NULL) {
        return NULL;
    }

    /*
     * This is a custom option; look for the idx'th option of this
     * type *and* with the specified PEN.
     */
    opt_idx = 0;
    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (custom_option_matches_with_pen(opt, option_id, pen)) {
            if (opt_idx == idx)
                return &opt->value;
            opt_idx++;
        }
    }

    return NULL;
}

static wtap_opttype_return_val
wtap_block_get_nth_custom_option_with_pen_common(wtap_block_t block,
                                                 unsigned option_id,
                                                 uint32_t pen,
                                                 wtap_opttype_e type,
                                                 unsigned idx,
                                                 wtap_optval_t **optvalp)
{
    const wtap_opttype_t *opttype;
    wtap_optval_t *optval;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Is this an option of the specified data type?
     */
    if (opttype->data_type != type) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_TYPE_MISMATCH;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (!(opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED)) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    optval = wtap_block_get_nth_custom_option_with_pen(block, option_id,
                                                       pen, idx);
    if (optval == NULL) {
        /* Didn't find the option */
        return WTAP_OPTTYPE_NOT_FOUND;
    }

    *optvalp = optval;
    return WTAP_OPTTYPE_SUCCESS;
}

static wtap_opttype_return_val
wtap_block_add_custom_string_option_common(wtap_block_t block,
                                           unsigned option_id,
                                           uint32_t pen, wtap_option_t **optp)
{
    wtap_opttype_return_val ret;

    ret = wtap_block_add_option_common(block, option_id,
                                       WTAP_OPTTYPE_CUSTOM_STRING, optp);
    if (ret != WTAP_OPTTYPE_SUCCESS) {
        return ret;
    }

    (*optp)->value.custom_stringval.pen = pen;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_custom_string_option(wtap_block_t block, unsigned option_id,
                                    uint32_t pen, const char *value,
                                    size_t value_length)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_custom_string_option_common(block, option_id, pen, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.custom_stringval.string = g_strndup(value, value_length);
    return WTAP_OPTTYPE_SUCCESS;
}

static wtap_opttype_return_val
wtap_block_add_custom_binary_option_common(wtap_block_t block,
                                           unsigned option_id,
                                           uint32_t pen,
                                           wtap_option_t **optp)
{
    wtap_opttype_return_val ret;

    ret = wtap_block_add_option_common(block, option_id,
                                       WTAP_OPTTYPE_CUSTOM_BINARY, optp);
    if (ret != WTAP_OPTTYPE_SUCCESS) {
        return ret;
    }

    (*optp)->value.custom_binaryval.pen = pen;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_custom_binary_option(wtap_block_t block, unsigned option_id,
                                    uint32_t pen, binary_optdata_t *value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_custom_binary_option_common(block, option_id, pen, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.custom_binaryval.data.custom_data_len = value->custom_data_len;
    opt->value.custom_binaryval.data.custom_data = g_memdup2(value->custom_data, value->custom_data_len);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_custom_binary_option_from_data(wtap_block_t block,
                                              unsigned option_id,
                                              uint32_t pen,
                                              const void *data,
                                              size_t data_size)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_custom_binary_option_common(block, option_id, pen, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.custom_binaryval.data.custom_data_len = data_size;
    opt->value.custom_binaryval.data.custom_data = g_memdup2(data, data_size);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_nth_custom_binary_option_value(wtap_block_t block,
                                              unsigned option_id,
                                              uint32_t pen, unsigned idx,
                                              binary_optdata_t *value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_custom_option_with_pen_common(block, option_id,
                                                           pen,
                                                           WTAP_OPTTYPE_CUSTOM_BINARY,
                                                           idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->custom_binaryval.data;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_if_filter_option(wtap_block_t block, unsigned option_id, if_filter_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_IF_FILTER, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.if_filterval = if_filter_dup(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_if_filter_option_value(wtap_block_t block, unsigned option_id, if_filter_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;
    if_filter_opt_t prev_value;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IF_FILTER, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    prev_value = optval->if_filterval;
    optval->if_filterval = if_filter_dup(value);
    /* Free after memory is duplicated in case structure was manipulated with a "get then set" */
    if_filter_free(&prev_value);

    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_if_filter_option_value(wtap_block_t block, unsigned option_id, if_filter_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_option_common(block, option_id, WTAP_OPTTYPE_IF_FILTER, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->if_filterval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_packet_verdict_option(wtap_block_t block, unsigned option_id, packet_verdict_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_PACKET_VERDICT, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.packet_verdictval = packet_verdict_dup(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_set_nth_packet_verdict_option_value(wtap_block_t block, unsigned option_id, unsigned idx, packet_verdict_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;
    packet_verdict_opt_t prev_value;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_PACKET_VERDICT, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    prev_value = optval->packet_verdictval;
    optval->packet_verdictval = packet_verdict_dup(value);
    /* Free after memory is duplicated in case structure was manipulated with a "get then set" */
    wtap_packet_verdict_free(&prev_value);

    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_get_nth_packet_verdict_option_value(wtap_block_t block, unsigned option_id, unsigned idx, packet_verdict_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_optval_t *optval;

    ret = wtap_block_get_nth_option_common(block, option_id, WTAP_OPTTYPE_STRING, idx, &optval);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    *value = optval->packet_verdictval;
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_add_packet_hash_option(wtap_block_t block, unsigned option_id, packet_hash_opt_t* value)
{
    wtap_opttype_return_val ret;
    wtap_option_t *opt;

    ret = wtap_block_add_option_common(block, option_id, WTAP_OPTTYPE_PACKET_HASH, &opt);
    if (ret != WTAP_OPTTYPE_SUCCESS)
        return ret;
    opt->value.packet_hash = packet_hash_dup(value);
    return WTAP_OPTTYPE_SUCCESS;
}

wtap_opttype_return_val
wtap_block_remove_option(wtap_block_t block, unsigned option_id)
{
    const wtap_opttype_t *opttype;
    unsigned i;
    wtap_option_t *opt;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED) {
        /*
         * Yes.  You can't remove "the" value.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id) {
            /* Found it - free up the value */
            wtap_block_free_option(block, opt);
            /* Remove the option from the array of options */
            g_array_remove_index(block->options, i);
            return WTAP_OPTTYPE_SUCCESS;
        }
    }

    /* Didn't find the option */
    return WTAP_OPTTYPE_NOT_FOUND;
}

wtap_opttype_return_val
wtap_block_remove_nth_option_instance(wtap_block_t block, unsigned option_id,
                                      unsigned idx)
{
    const wtap_opttype_t *opttype;
    unsigned i;
    wtap_option_t *opt;
    unsigned opt_idx;

    if (block == NULL) {
        return WTAP_OPTTYPE_BAD_BLOCK;
    }

    opttype = GET_OPTION_TYPE(block->info->options, option_id);
    if (opttype == NULL) {
        /* There's no option for this block with that option ID */
        return WTAP_OPTTYPE_NO_SUCH_OPTION;
    }

    /*
     * Can there be more than one instance of this option?
     */
    if (!(opttype->flags & WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED)) {
        /*
         * No.
         */
        return WTAP_OPTTYPE_NUMBER_MISMATCH;
    }

    opt_idx = 0;
    for (i = 0; i < block->options->len; i++) {
        opt = &g_array_index(block->options, wtap_option_t, i);
        if (opt->option_id == option_id) {
            if (opt_idx == idx) {
                /* Found it - free up the value */
                wtap_block_free_option(block, opt);
                /* Remove the option from the array of options */
                g_array_remove_index(block->options, i);
                return WTAP_OPTTYPE_SUCCESS;
            }
            opt_idx++;
        }
    }

    /* Didn't find the option */
    return WTAP_OPTTYPE_NOT_FOUND;
}

static void shb_create(wtap_block_t block)
{
    wtapng_section_mandatory_t* section_mand = g_new(wtapng_section_mandatory_t, 1);

    section_mand->section_length = -1;

    block->mandatory_data = section_mand;
}

static void shb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_section_mandatory_t));
}

static void idb_create(wtap_block_t block)
{
    block->mandatory_data = g_new0(wtapng_if_descr_mandatory_t, 1);
}

static void idb_free_mand(wtap_block_t block)
{
    unsigned j;
    wtap_block_t if_stats;
    wtapng_if_descr_mandatory_t* mand = (wtapng_if_descr_mandatory_t*)block->mandatory_data;

    for(j = 0; j < mand->num_stat_entries; j++) {
        if_stats = g_array_index(mand->interface_statistics, wtap_block_t, j);
        wtap_block_unref(if_stats);
    }

    if (mand->interface_statistics)
        g_array_free(mand->interface_statistics, true);
}

static void idb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    unsigned j;
    wtap_block_t src_if_stats, dest_if_stats;
    wtapng_if_descr_mandatory_t *src_mand = (wtapng_if_descr_mandatory_t*)src_block->mandatory_data,
                                *dest_mand = (wtapng_if_descr_mandatory_t*)dest_block->mandatory_data;

    /* Need special consideration for copying of the interface_statistics member */
    if (dest_mand->num_stat_entries != 0)
        g_array_free(dest_mand->interface_statistics, true);

    memcpy(dest_mand, src_mand, sizeof(wtapng_if_descr_mandatory_t));
    if (src_mand->num_stat_entries != 0)
    {
        dest_mand->interface_statistics = g_array_new(false, false, sizeof(wtap_block_t));
        for (j = 0; j < src_mand->num_stat_entries; j++)
        {
            src_if_stats = g_array_index(src_mand->interface_statistics, wtap_block_t, j);
            dest_if_stats = wtap_block_make_copy(src_if_stats);
            dest_mand->interface_statistics = g_array_append_val(dest_mand->interface_statistics, dest_if_stats);
        }
    }
}

static void nrb_create(wtap_block_t block)
{
    block->mandatory_data = g_new0(wtapng_nrb_mandatory_t, 1);
}

static void nrb_free_mand(wtap_block_t block)
{
    wtapng_nrb_mandatory_t *mand = (wtapng_nrb_mandatory_t *)block->mandatory_data;
    g_list_free_full(mand->ipv4_addr_list, g_free);
    g_list_free_full(mand->ipv6_addr_list, g_free);
}

#if 0
static void *copy_hashipv4(const void *src, void *user_data _U_
{
    hashipv4_t *src_ipv4 = (hashipv4_t*)src;
    hashipv4_t *dst = g_new0(hashipv4_t, 1);
    dst->addr = src_ipv4->addr;
    (void) g_strlcpy(dst->name, src_ipv4->name, MAXDNSNAMELEN);
    return dst;
}

static void *copy_hashipv4(const void *src, void *user_data _U_
{
    hashipv6_t *src_ipv6 = (hashipv6_t*)src;
    hashipv6_t *dst = g_new0(hashipv6_t, 1);
    dst->addr = src_ipv4->addr;
    (void) g_strlcpy(dst->name, src_ipv4->name, MAXDNSNAMELEN);
    return dst;
}

static void nrb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    wtapng_nrb_mandatory_t *src = (wtapng_nrb_mandatory_t *)src_block->mandatory_data;
    wtapng_nrb_mandatory_t *dst = (wtapng_nrb_mandatory_t *)dest_block->mandatory_data;
    g_list_free_full(dst->ipv4_addr_list, g_free);
    g_list_free_full(dst->ipv6_addr_list, g_free);
    dst->ipv4_addr_list = g_list_copy_deep(src->ipv4_addr_list, copy_hashipv4, NULL);
    dst->ipv6_addr_list = g_list_copy_deep(src->ipv6_addr_list, copy_hashipv6, NULL);
}
#endif

static void isb_create(wtap_block_t block)
{
    block->mandatory_data = g_new0(wtapng_if_stats_mandatory_t, 1);
}

static void isb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    memcpy(dest_block->mandatory_data, src_block->mandatory_data, sizeof(wtapng_if_stats_mandatory_t));
}

static void dsb_create(wtap_block_t block)
{
    block->mandatory_data = g_new0(wtapng_dsb_mandatory_t, 1);
}

static void dsb_free_mand(wtap_block_t block)
{
    wtapng_dsb_mandatory_t *mand = (wtapng_dsb_mandatory_t *)block->mandatory_data;
    g_free(mand->secrets_data);
}

static void dsb_copy_mand(wtap_block_t dest_block, wtap_block_t src_block)
{
    wtapng_dsb_mandatory_t *src = (wtapng_dsb_mandatory_t *)src_block->mandatory_data;
    wtapng_dsb_mandatory_t *dst = (wtapng_dsb_mandatory_t *)dest_block->mandatory_data;
    dst->secrets_type = src->secrets_type;
    dst->secrets_len = src->secrets_len;
    g_free(dst->secrets_data);
    dst->secrets_data = (uint8_t *)g_memdup2(src->secrets_data, src->secrets_len);
}

static void pkt_create(wtap_block_t block)
{
    /* Commented out for now, there's no mandatory data that isn't handled by
     * Wireshark in other ways.
     */
    //block->mandatory_data = g_new0(wtapng_packet_mandatory_t, 1);

    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
}

static void ft_specific_event_create(wtap_block_t block)
{
    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
}

static void ft_specific_report_create(wtap_block_t block)
{
    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
}

static void sjeb_create(wtap_block_t block)
{
    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
}

static void cb_create(wtap_block_t block)
{
    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
}

static void ft_specific_information_create(wtap_block_t block)
{
    /* Ensure this is null, so when g_free is called on it, it simply returns */
    block->mandatory_data = NULL;
}

void wtap_opttypes_initialize(void)
{
    static wtap_blocktype_t shb_block = {
        WTAP_BLOCK_SECTION,     /* block_type */
        "SHB",                  /* name */
        "Section Header Block", /* description */
        shb_create,             /* create */
        NULL,                   /* free_mand */
        shb_copy_mand,          /* copy_mand */
        NULL                    /* options */
    };
    static const wtap_opttype_t shb_hardware = {
        "hardware",
        "SHB Hardware",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t shb_os = {
        "os",
        "SHB Operating System",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t shb_userappl = {
        "user_appl",
        "SHB User Application",
        WTAP_OPTTYPE_STRING,
        0
    };

    static wtap_blocktype_t idb_block = {
        WTAP_BLOCK_IF_ID_AND_INFO,     /* block_type */
        "IDB",                         /* name */
        "Interface Description Block", /* description */
        idb_create,                    /* create */
        idb_free_mand,                 /* free_mand */
        idb_copy_mand,                 /* copy_mand */
        NULL                           /* options */
    };
    static const wtap_opttype_t if_name = {
        "name",
        "IDB Name",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t if_description = {
        "description",
        "IDB Description",
        WTAP_OPTTYPE_STRING,
        0
    };
    // "ipv4addr"
    // "ipv6addr"
    // "macaddr"
    // "euiaddr"
    static const wtap_opttype_t if_speed = {
        "speed",
        "IDB Speed",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t if_tsresol = {
        "tsresol",
        "IDB Time Stamp Resolution",
        WTAP_OPTTYPE_UINT8, /* XXX - signed? */
        0
    };
    // "tzone"
    static const wtap_opttype_t if_filter = {
        "filter",
        "IDB Filter",
        WTAP_OPTTYPE_IF_FILTER,
        0
    };
    static const wtap_opttype_t if_os = {
        "os",
        "IDB Operating System",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t if_fcslen = {
        "fcslen",
        "IDB FCS Length",
        WTAP_OPTTYPE_UINT8,
        0
    };
    static const wtap_opttype_t if_tsoffset = {
        "tsoffset",
        "IDB Time Stamp Offset",
        WTAP_OPTTYPE_INT64,
        0
    };
    static const wtap_opttype_t if_hardware = {
        "hardware",
        "IDB Hardware",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t if_tx_speed = {
        "txspeed",
        "IDB Tx Speed",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t if_rx_speed = {
        "rxspeed",
        "IDB Rx Speed",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t if_iana_tzname = {
        "iana_tzname",
        "IDB IANA timezone name",
        WTAP_OPTTYPE_STRING,
        0
    };

    static wtap_blocktype_t nrb_block = {
        WTAP_BLOCK_NAME_RESOLUTION, /* block_type */
        "NRB",                      /* name */
        "Name Resolution Block",    /* description */
        nrb_create,                 /* create */
        nrb_free_mand,              /* free_mand */
        /* We eventually want to copy these, when dumper actually
         * writes them out. If we're actually processing packets,
         * as opposed to just reading and writing a file without
         * printing (e.g., editcap), do we still want to copy all
         * the pre-existing NRBs, or do we want to limit it to
         * the actually used addresses, as currently?
         */
#if 0
        nrb_copy_mand,              /* copy_mand */
#endif
        NULL,
        NULL                        /* options */
    };
    static const wtap_opttype_t ns_dnsname = {
        "dnsname",
        "NRB DNS server name",
        WTAP_OPTTYPE_STRING,
        0
    };
    static const wtap_opttype_t ns_dnsIP4addr = {
        "dnsIP4addr",
        "NRB DNS server IPv4 address",
        WTAP_OPTTYPE_IPv4,
        0
    };
    static const wtap_opttype_t ns_dnsIP6addr = {
        "dnsIP6addr",
        "NRB DNS server IPv6 address",
        WTAP_OPTTYPE_IPv6,
        0
    };

    static wtap_blocktype_t isb_block = {
        WTAP_BLOCK_IF_STATISTICS,     /* block_type */
        "ISB",                        /* name */
        "Interface Statistics Block", /* description */
        isb_create,                   /* create */
        NULL,                         /* free_mand */
        isb_copy_mand,                /* copy_mand */
        NULL                          /* options */
    };
    static const wtap_opttype_t isb_starttime = {
        "starttime",
        "ISB Start Time",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_endtime = {
        "endtime",
        "ISB End Time",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_ifrecv = {
        "ifrecv",
        "ISB Received Packets",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_ifdrop = {
        "ifdrop",
        "ISB Dropped Packets",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_filteraccept = {
        "filteraccept",
        "ISB Packets Accepted By Filter",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_osdrop = {
        "osdrop",
        "ISB Packets Dropped By The OS",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t isb_usrdeliv = {
        "usrdeliv",
        "ISB Packets Delivered To The User",
        WTAP_OPTTYPE_UINT64,
        0
    };

    static wtap_blocktype_t dsb_block = {
        WTAP_BLOCK_DECRYPTION_SECRETS,
        "DSB",
        "Decryption Secrets Block",
        dsb_create,
        dsb_free_mand,
        dsb_copy_mand,
        NULL
    };

    static wtap_blocktype_t pkt_block = {
        WTAP_BLOCK_PACKET,            /* block_type */
        "EPB/SPB/PB",                 /* name */
        "Packet Block",               /* description */
        pkt_create,                   /* create */
        NULL,                         /* free_mand */
        NULL,                         /* copy_mand */
        NULL                          /* options */
    };
    static const wtap_opttype_t pkt_flags = {
        "flags",
        "Link-layer flags",
        WTAP_OPTTYPE_UINT32,
        0
    };
    static const wtap_opttype_t pkt_hash = {
        "hash",
        "Hash of packet data",
        WTAP_OPTTYPE_PACKET_HASH,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };
    static const wtap_opttype_t pkt_dropcount = {
        "dropcount",
        "Packets Dropped since last packet",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t pkt_id = {
        "packetid",
        "Unique Packet Identifier",
        WTAP_OPTTYPE_UINT64,
        0
    };
    static const wtap_opttype_t pkt_queue = {
        "queue",
        "Queue ID in which packet was received",
        WTAP_OPTTYPE_UINT32,
        0
    };
    static const wtap_opttype_t pkt_verdict = {
        "verdict",
        "Packet Verdict",
        WTAP_OPTTYPE_PACKET_VERDICT,
        WTAP_OPTTYPE_FLAG_MULTIPLE_ALLOWED
    };
    static const wtap_opttype_t pkt_proc_id_thread_id = {
        "procidthreadid",
        "Process ID thread ID",
        WTAP_OPTTYPE_UINT64,
        0
    };

    static wtap_blocktype_t ft_specific_event_block = {
        WTAP_BLOCK_FT_SPECIFIC_EVENT, /* block_type */
        "FT_SPECIFIC_EVENT",          /* name */
        "File-type-specific event",   /* description */
        ft_specific_event_create,     /* create */
        NULL,                         /* free_mand */
        NULL,                         /* copy_mand */
        NULL                          /* options */
    };

    static wtap_blocktype_t ft_specific_report_block = {
        WTAP_BLOCK_FT_SPECIFIC_REPORT, /* block_type */
        "FT_SPECIFIC_REPORT",          /* name */
        "File-type-specific report",   /* description */
        ft_specific_report_create,     /* create */
        NULL,                          /* free_mand */
        NULL,                          /* copy_mand */
        NULL                           /* options */
    };

    static wtap_blocktype_t journal_block = {
        WTAP_BLOCK_SYSTEMD_JOURNAL_EXPORT, /* block_type */
        "SJEB",                         /* name */
        "systemd Journal Export Block", /* description */
        sjeb_create,                    /* create */
        NULL,                           /* free_mand */
        NULL,                           /* copy_mand */
        NULL                            /* options */
    };

    static wtap_blocktype_t cb_block = {
        WTAP_BLOCK_CUSTOM,            /* block_type */
        "CB",                         /* name */
        "Custom Block",               /* description */
        cb_create,                    /* create */
        NULL,                         /* free_mand */
        NULL,                         /* copy_mand */
        NULL                          /* options */
    };

    static wtap_blocktype_t ft_specific_information_block = {
        WTAP_BLOCK_FT_SPECIFIC_INFORMATION, /* block_type */
        "FT_SPECIFIC_INFORMATION",          /* name */
        "File-type specific information",   /* description */
        ft_specific_information_create,     /* create */
        NULL,                               /* free_mand */
        NULL,                               /* copy_mand */
        NULL                                /* options */
    };

    /*
     * Register the SHB and the options that can appear in it.
     */
    wtap_opttype_block_register(&shb_block);
    wtap_opttype_option_register(&shb_block, OPT_SHB_HARDWARE, &shb_hardware);
    wtap_opttype_option_register(&shb_block, OPT_SHB_OS, &shb_os);
    wtap_opttype_option_register(&shb_block, OPT_SHB_USERAPPL, &shb_userappl);

    /*
     * Register the IDB and the options that can appear in it.
     */
    wtap_opttype_block_register(&idb_block);
    wtap_opttype_option_register(&idb_block, OPT_IDB_NAME, &if_name);
    wtap_opttype_option_register(&idb_block, OPT_IDB_DESCRIPTION, &if_description);
    wtap_opttype_option_register(&idb_block, OPT_IDB_SPEED, &if_speed);
    wtap_opttype_option_register(&idb_block, OPT_IDB_TSRESOL, &if_tsresol);
    wtap_opttype_option_register(&idb_block, OPT_IDB_FILTER, &if_filter);
    wtap_opttype_option_register(&idb_block, OPT_IDB_OS, &if_os);
    wtap_opttype_option_register(&idb_block, OPT_IDB_FCSLEN, &if_fcslen);
    wtap_opttype_option_register(&idb_block, OPT_IDB_TSOFFSET, &if_tsoffset);
    wtap_opttype_option_register(&idb_block, OPT_IDB_HARDWARE, &if_hardware);
    wtap_opttype_option_register(&idb_block, OPT_IDB_TXSPEED, &if_tx_speed);
    wtap_opttype_option_register(&idb_block, OPT_IDB_TXSPEED, &if_rx_speed);
    wtap_opttype_option_register(&idb_block, OPT_IDB_IANA_TZNAME, &if_iana_tzname);

    /*
     * Register the NRB and the options that can appear in it.
     */
    wtap_opttype_block_register(&nrb_block);
    wtap_opttype_option_register(&nrb_block, OPT_NS_DNSNAME, &ns_dnsname);
    wtap_opttype_option_register(&nrb_block, OPT_NS_DNSIP4ADDR, &ns_dnsIP4addr);
    wtap_opttype_option_register(&nrb_block, OPT_NS_DNSIP6ADDR, &ns_dnsIP6addr);

    /*
     * Register the ISB and the options that can appear in it.
     */
    wtap_opttype_block_register(&isb_block);
    wtap_opttype_option_register(&isb_block, OPT_ISB_STARTTIME, &isb_starttime);
    wtap_opttype_option_register(&isb_block, OPT_ISB_ENDTIME, &isb_endtime);
    wtap_opttype_option_register(&isb_block, OPT_ISB_IFRECV, &isb_ifrecv);
    wtap_opttype_option_register(&isb_block, OPT_ISB_IFDROP, &isb_ifdrop);
    wtap_opttype_option_register(&isb_block, OPT_ISB_FILTERACCEPT, &isb_filteraccept);
    wtap_opttype_option_register(&isb_block, OPT_ISB_OSDROP, &isb_osdrop);
    wtap_opttype_option_register(&isb_block, OPT_ISB_USRDELIV, &isb_usrdeliv);

    /*
     * Register the DSB, currently no options are defined.
     */
    wtap_opttype_block_register(&dsb_block);

    /*
     * Register EPB/SPB/PB and the options that can appear in it/them.
     * NB: Simple Packet Blocks have no options.
     * NB: obsolete Packet Blocks have dropcount as a mandatory member instead
     * of an option.
     */
    wtap_opttype_block_register(&pkt_block);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_FLAGS, &pkt_flags);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_HASH, &pkt_hash);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_DROPCOUNT, &pkt_dropcount);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_PACKETID, &pkt_id);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_QUEUE, &pkt_queue);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_VERDICT, &pkt_verdict);
    wtap_opttype_option_register(&pkt_block, OPT_PKT_PROCIDTHRDID, &pkt_proc_id_thread_id);

    /*
     * Register the file-type specific event block; the options will be
     * dependent on the file type.
     */
    wtap_opttype_block_register(&ft_specific_event_block);

    /*
     * Register the file-type specific report block; the options will be
     * dependent on the file type.
     */
    wtap_opttype_block_register(&ft_specific_report_block);

    /*
     * Register the SJEB and the (no) options that can appear in it.
     */
    wtap_opttype_block_register(&journal_block);

    /*
     * Register the CB and the options that can appear in it.
     */
    wtap_opttype_block_register(&cb_block);

    /*
     * Register the file-type specific information block; the options will be
     * dependent on the file type.
     */
    wtap_opttype_block_register(&ft_specific_information_block);

#ifdef DEBUG_COUNT_REFS
    memset(blocks_active, 0, sizeof(blocks_active));
#endif
}

void wtap_opttypes_cleanup(void)
{
    unsigned block_type;
#ifdef DEBUG_COUNT_REFS
    unsigned i;
    unsigned cellno;
    unsigned bitno;
    uint8_t mask;
#endif /* DEBUG_COUNT_REFS */

    for (block_type = (unsigned)WTAP_BLOCK_SECTION;
         block_type < (unsigned)MAX_WTAP_BLOCK_TYPE_VALUE; block_type++) {
        if (blocktype_list[block_type]) {
            if (blocktype_list[block_type]->options)
                g_hash_table_destroy(blocktype_list[block_type]->options);
            blocktype_list[block_type] = NULL;
        }
    }

#ifdef DEBUG_COUNT_REFS
    for (i = 0 ; i < block_count; i++) {
        cellno = i / 8;
        bitno = i % 8;
        mask = 1 << bitno;

        if ((blocks_active[cellno] & mask) == mask) {
            wtap_debug("wtap_opttypes_cleanup: orphaned block #%d", i);
        }
    }
#endif /* DEBUG_COUNT_REFS */
}
