/* TODO:
    dissect_ndr_nt_SID_with_options    see comment.
*/
/* packet-dcerpc-nt.c
 * Routines for DCERPC over SMB packet disassembly
 * Copyright 2001-2003, Tim Potter <tpot@samba.org>
 * Copyright 2011-2013, Matthieu Patou <mat@matws.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tfs.h>

#include <wsutil/array.h>
#include <wsutil/ws_roundup.h>

#include "packet-dcerpc.h"
#include "packet-dcerpc-nt.h"
#include "packet-windows-common.h"


int hf_nt_cs_len;
int hf_nt_error;
int hf_nt_cs_size;
static int hf_lsa_String_name_len;
static int hf_lsa_String_name_size;
static int hf_nt_data_blob_len;
static int hf_nt_data_blob_data;
static int hf_nt_midl_blob_len;
static int hf_nt_midl_fill_bytes;
static int hf_nt_midl_version;
static int hf_nt_midl_hdr_len;

static int ett_nt_MIDL_BLOB;
static int ett_lsa_String;
static int ett_nt_data_blob;
static int ett_nt_counted_string;
static expert_field ei_dcerpc_nt_badsid;



/* This is used to safely walk the decode tree up, one item at a time safely.
   This is used by dcerpc dissectors that want to push the display of a string
   higher up in the tree for greater visibility.
*/
#define GET_ITEM_PARENT(x) \
	((x->parent!=NULL)?x->parent:x)

/*
 * This file contains helper routines that are used by the DCERPC over SMB
 * dissectors for wireshark.
 */

/*
 * Used by several dissectors.
 */
const value_string platform_id_vals[] = {
	{ 300, "DOS" },
	{ 400, "OS/2" },
	{ 500, "Windows NT" },
	{ 600, "OSF" },
	{ 700, "VMS" },
	{ 0,   NULL }
};

int
dissect_ndr_datablob(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hf_index,
			int use_remaining_space)
{
	proto_item *item;
	uint3264_t len;
	proto_tree *subtree;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_nt_data_blob, &item,
			proto_registrar_get_name(hf_index));

	if (use_remaining_space) {
		len = tvb_captured_length_remaining (tvb, offset);
	} else {
		offset = dissect_ndr_uint3264(tvb, offset, pinfo, subtree, di, drep,
				    hf_nt_data_blob_len, &len);
	}
	proto_tree_add_item(subtree, hf_nt_data_blob_data, tvb, offset, (int)len, ENC_NA);
	offset += (int)len;
	return offset;
}

int
dissect_null_term_string(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree,
				uint8_t *drep _U_, int hf_index, int levels _U_)
{
	unsigned len;

	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_index, tvb, offset, len, ENC_ASCII|ENC_NA);

	return offset + len;
}

int
dissect_null_term_wstring(tvbuff_t *tvb, int offset,
				packet_info *pinfo _U_, proto_tree *tree,
				uint8_t *drep _U_, int hf_index, int levels _U_)
{
	unsigned len;

	len = tvb_unicode_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_index, tvb, offset, len, ENC_UTF_16|ENC_LITTLE_ENDIAN);

	return offset + len;
}

/* Parse some common RPC structures */

/* Dissect a counted string as a callback to dissect_ndr_pointer_cb() */

int
dissect_ndr_counted_string_cb(tvbuff_t *tvb, int offset,
			      packet_info *pinfo, proto_tree *tree,
			      dcerpc_info *di, uint8_t *drep, int hf_index,
			      dcerpc_callback_fnct_t *callback,
			      void *callback_args)
{
	uint16_t len, size;

	/* Structure starts with short, but is aligned for pointer */

	ALIGN_TO_5_BYTES;

	if (di->conformant_run)
		return offset;

	/*
	   struct {
	       short len;
	       short size;
	       [size_is(size/2), length_is(len/2), ptr] unsigned short *string;
	   } UNICODE_STRING;

	 */

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep,
			hf_nt_cs_len, &len);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep,
			hf_nt_cs_size, &size);

	offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, di, drep,
			dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
			"Character Array", hf_index, callback, callback_args);

	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_5_BYTES;
	}

	return offset;
}

static int
dissect_ndr_counted_string_helper(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, uint8_t *drep, int hf_index, int levels,
				  bool add_subtree)
{
	proto_item *item;
	proto_tree *subtree = tree;

	if (add_subtree) {

		subtree = proto_tree_add_subtree(
			tree, tvb, offset, 0, ett_nt_counted_string, &item,
			proto_registrar_get_name(hf_index));
	}

	/*
	 * Add 2 levels, so that the string gets attached to the
	 * "Character Array" top-level item and to the top-level item
	 * added above.
	 */
	return dissect_ndr_counted_string_cb(
		tvb, offset, pinfo, subtree, di, drep, hf_index,
		cb_wstr_postprocess, GINT_TO_POINTER(2 + levels));
}

/* Dissect a counted string in-line. */

int
dissect_ndr_counted_string(tvbuff_t *tvb, int offset,
			   packet_info *pinfo, proto_tree *tree,
			   dcerpc_info *di, uint8_t *drep, int hf_index, int levels)
{
	return dissect_ndr_counted_string_helper(
		tvb, offset, pinfo, tree, di, drep, hf_index, levels, true);
}

/* Dissect a counted string as a callback to dissect_ndr_pointer().
   This doesn't add a adds a proto item and subtreee for the string as
   the pointer dissection already creates one. */

int
dissect_ndr_counted_string_ptr(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       dcerpc_info *di, uint8_t *drep)
{
	return dissect_ndr_counted_string_helper(
		tvb, offset, pinfo, tree, di, drep, di->hf_index, 0, false);
}

/* Dissect a counted byte_array as a callback to dissect_ndr_pointer_cb() */

static int ett_nt_counted_byte_array;

/* Dissect a counted byte array in-line. */

int
dissect_ndr_counted_byte_array_cb(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, uint8_t *drep, int hf_index,
				  dcerpc_callback_fnct_t *callback,
				  void *callback_args)
{
	proto_item *item;
	proto_tree *subtree;
	uint16_t len, size;

	/* Structure starts with short, but is aligned for pointer */

	ALIGN_TO_5_BYTES;

	if (di->conformant_run)
		return offset;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_nt_counted_byte_array, &item,
		proto_registrar_get_name(hf_index));

	/*
	   struct {
	       short len;
	       short size;
	       [size_is(size), length_is(len), ptr] unsigned char *string;
	   } WHATEVER_THIS_IS_CALLED;

	 */

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, di, drep,
			hf_nt_cs_len, &len);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, di, drep,
			hf_nt_cs_size, &size);

	offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, subtree, di, drep,
			dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
			"Byte Array", hf_index, callback, callback_args);

	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_5_BYTES;
	}

	return offset;
}

static void cb_byte_array_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, dcerpc_info *di _U_, tvbuff_t *tvb,
			int start_offset, int end_offset,
			void *callback_args)
{
	int options = GPOINTER_TO_INT(callback_args);
	int levels = CB_STR_ITEM_LEVELS(options);
	char *s;

	/* Align start_offset on 4-byte boundary. */

	start_offset = WS_ROUNDUP_4(start_offset);

	/* Get byte array value */

	if ((end_offset - start_offset) <= 12)
		return;

	s = tvb_bytes_to_str(pinfo->pool, tvb, start_offset + 12, (end_offset - start_offset - 12) );

	/* Append string to COL_INFO */

	if (options & CB_STR_COL_INFO) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", s);
	}

	/* Append string to upper-level proto_items */

	if (levels > 0 && item && s && s[0]) {
		proto_item_append_text(item, ": %s", s);
		item = GET_ITEM_PARENT(item);
		levels--;
		if (levels > 0) {
			proto_item_append_text(item, ": %s", s);
			item = GET_ITEM_PARENT(item);
			levels--;
			while (levels > 0) {
				proto_item_append_text(item, " %s", s);
				item = GET_ITEM_PARENT(item);
				levels--;
			}
		}
	}
}

int
dissect_ndr_counted_byte_array(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       dcerpc_info *di, uint8_t *drep, int hf_index, int levels)
{
	return dissect_ndr_counted_byte_array_cb(
		tvb, offset, pinfo, tree, di, drep, hf_index, cb_byte_array_postprocess, GINT_TO_POINTER(2 + levels));
}

/* Dissect a counted ascii string in-line. */
static int ett_nt_counted_ascii_string;

int
dissect_ndr_counted_ascii_string_cb(tvbuff_t *tvb, int offset,
				  packet_info *pinfo, proto_tree *tree,
				  dcerpc_info *di, uint8_t *drep, int hf_index,
				  dcerpc_callback_fnct_t *callback,
				  void *callback_args)
{
	proto_item *item;
	proto_tree *subtree;
	uint16_t len, size;

	/* Structure starts with short, but is aligned for pointer */

	ALIGN_TO_5_BYTES;

	if (di->conformant_run)
		return offset;

	subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_nt_counted_ascii_string, &item,
		proto_registrar_get_name(hf_index));

	/*
	   struct {
	       short len;
	       short size;
	       [size_is(size), length_is(len), ptr] unsigned char *string;
	   } WHATEVER_THIS_IS_CALLED;

	 */

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, di, drep,
			hf_nt_cs_len, &len);

	offset = dissect_ndr_uint16(tvb, offset, pinfo, subtree, di, drep,
			hf_nt_cs_size, &size);

	offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, subtree, di, drep,
			dissect_ndr_char_cvstring, NDR_POINTER_UNIQUE,
			"Ascii String", hf_index, callback, callback_args);

	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_5_BYTES;
	}

	return offset;
}

int
dissect_ndr_counted_ascii_string(tvbuff_t *tvb, int offset,
			       packet_info *pinfo, proto_tree *tree,
			       dcerpc_info *di, uint8_t *drep, int hf_index, int levels)
{
	return dissect_ndr_counted_ascii_string_cb(
		tvb, offset, pinfo, tree, di, drep, hf_index, cb_str_postprocess, GINT_TO_POINTER(2 + levels));
}

static int hf_nt_guid;

int
dissect_nt_GUID(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *tree,
			dcerpc_info *di, uint8_t *drep)
{
	offset=dissect_ndr_uuid_t(tvb, offset, pinfo, tree, di, drep, hf_nt_guid, NULL);

	return offset;
}

/* This function is used to dissect a lsa_String
	typedef [public] struct {
		[value(strlen_m_term(name)*2)] uint16 name_len;
		[value(strlen_m_term(name)*2)] uint16 name_size;
		[string,charset(UTF16)] uint16 *name;
	} lsa_String;
 */
int
dissect_ndr_lsa_String(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *parent_tree, dcerpc_info *di, uint8_t *drep, uint32_t param, int hfindex)
{
	proto_item *item;
	proto_tree *tree;
	int old_offset;
	header_field_info *hf_info;

	ALIGN_TO_5_BYTES;

	old_offset = offset;
	hf_info=proto_registrar_get_nth(hfindex);

	tree = proto_tree_add_subtree_format(parent_tree, tvb, offset, 0, ett_lsa_String, &item, "%s: ", hf_info->name);

	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_lsa_String_name_len, 0);

	offset = PIDL_dissect_uint16(tvb, offset, pinfo, tree, di, drep, hf_lsa_String_name_size, 0);

	offset = dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, NDR_POINTER_UNIQUE,
		hf_info->name, hfindex, cb_wstr_postprocess,
		GINT_TO_POINTER(param));

	proto_item_set_len(item, offset-old_offset);

	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_5_BYTES;
	}

	return offset;
}

/* This function is used to dissect a DCERPC encoded 64 bit time value. */
int
dissect_ndr_nt_NTTIME (tvbuff_t *tvb, int offset,
			packet_info *pinfo _U_, proto_tree *tree,
			dcerpc_info *di, uint8_t *drep, int hf_index)
{
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	ALIGN_TO_4_BYTES;

	dissect_nttime(tvb, tree, offset, hf_index,
	    (drep[0] & DREP_LITTLE_ENDIAN) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
	offset += 8;
	return offset;
}

int
dissect_ndr_nt_NTTIME_hyper (tvbuff_t *tvb, int offset,
			packet_info *pinfo _U_, proto_tree *tree,
			dcerpc_info *di, uint8_t *drep _U_, int hf_index)
{
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	ALIGN_TO_8_BYTES;

	dissect_nttime_hyper(tvb, tree, offset, hf_index,
	    (drep[0] & DREP_LITTLE_ENDIAN) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
	offset += 8;
	return offset;
}

int
dissect_ndr_nt_NTTIME_1sec (tvbuff_t *tvb, int offset,
			packet_info *pinfo _U_, proto_tree *tree,
			dcerpc_info *di, uint8_t *drep, int hf_index)
{
	if(di->conformant_run){
		/*just a run to handle conformant arrays, nothing to dissect */
		return offset;
	}

	ALIGN_TO_8_BYTES;

	dissect_nttime_hyper_1sec(tvb, tree, offset, hf_index,
	    (drep[0] & DREP_LITTLE_ENDIAN) ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
	offset += 8;
	return offset;
}

/* Define this symbol to display warnings about request/response and
   policy handle hash table collisions.	 This happens when a packet with
   the same conversation, smb fid and dcerpc call id occurs.  I think this
   is due to a bug in the dcerpc/smb fragment reassembly code. */

#undef DEBUG_HASH_COLL

/*
 * Policy handle hashing.
 *
 * We hash based on the policy handle value; the items in the hash table
 * are lists of policy handle information about one or more policy
 * handles with that value.  We have multiple values in case a given
 * policy handle is opened in frame N, closed in frame M, and re-opened
 * in frame O, where N < M < O.
 *
 * XXX - we really should also use a DCE RPC conversation/session handle
 * of some sort, in case two separate sessions have the same handle
 * value.  A transport-layer conversation might not be sufficient, as you
 * might, for example, have multiple pipes in a single SMB connection,
 * and you might have the same handle opened and closed separately on
 * those two pipes.
 *
 * The policy handle information has "first frame" and "last frame"
 * information; the entry should be used when dissecting a given frame
 * only if that frame is within the interval [first frame,last frame].
 * The list is sorted by "first frame".
 *
 * This doesn't handle the case of a handle being opened in frame N and
 * re-opened in frame M, where N < M, with no intervening close, but I'm
 * not sure anything can handle that if it's within the same DCE RPC
 * session (if it's not, the conversation/session handle would fix that).
 */

typedef struct {
	uint8_t policy_hnd[20];
} pol_hash_key;

typedef struct {
	pol_value *list;		 /* List of policy handle entries */
} pol_hash_value;

static wmem_map_t *pol_hash;

/* Hash function */

static unsigned pol_hash_fn(const void *k)
{
	const pol_hash_key *key = (const pol_hash_key *)k;

	/* Bytes 4-7 of the policy handle are a timestamp so should make a
	   reasonable hash value */

	return key->policy_hnd[4] + (key->policy_hnd[5] << 8) +
		(key->policy_hnd[6] << 16) + (key->policy_hnd[7] << 24);
}

/* Return true if a policy handle is all zeros */

static bool is_null_pol(e_ctx_hnd *policy_hnd)
{
	static uint8_t null_policy_hnd[20];

	return memcmp(policy_hnd, null_policy_hnd, 20) == 0;
}

/* Hash compare function */

static int pol_hash_compare(const void *k1, const void *k2)
{
	const pol_hash_key *key1 = (const pol_hash_key *)k1;
	const pol_hash_key *key2 = (const pol_hash_key *)k2;

	return memcmp(key1->policy_hnd, key2->policy_hnd,
		      sizeof(key1->policy_hnd)) == 0;
}

/*
 * Look up the instance of a policy handle value in whose range of frames
 * the specified frame falls.
 */
static pol_value *find_pol_handle(e_ctx_hnd *policy_hnd, uint32_t frame,
				  pol_hash_value **valuep)
{
	pol_hash_key key;
	pol_value *pol;

	memcpy(&key.policy_hnd, policy_hnd, sizeof(key.policy_hnd));
	if ((*valuep = (pol_hash_value *)wmem_map_lookup(pol_hash, &key))) {
		/*
		 * Look for the first value such that both:
		 *
		 *	1) the first frame in which it was seen is
		 *	   <= the specified frame;
		 *
		 *	2) the last frame in which it was seen is
		 *	   either unknown (meaning we haven't yet
		 *	   seen a close or another open of the
		 *	   same handle, which is assumed to imply
		 *	   an intervening close that wasn't captured)
		 *	   or is >= the specified frame.
		 *
		 * If there's more than one such frame, that's the
		 * case where a handle is opened in frame N and
		 * reopened in frame M, with no intervening close;
		 * there is no right answer for that, so the instance
		 * opened in frame N is as right as anything else.
		 */
		for (pol = (*valuep)->list; pol != NULL; pol = pol->next) {
			if (pol->first_frame <= frame &&
			    (pol->last_frame == 0 ||
			     pol->last_frame >= frame))
				break;	/* found one */
		}
		return pol;
	} else {
		/*
		 * The handle isn't in the hash table.
		 */
		return NULL;
	}
}

static void add_pol_handle(e_ctx_hnd *policy_hnd, uint32_t frame,
			   pol_value *pol, pol_hash_value *value)
{
	pol_hash_key *key;
	pol_value *polprev, *polnext;

	if (value == NULL) {
		/*
		 * There's no hash value; create one, put the new
		 * value at the beginning of its policy handle list,
		 * and put the hash value in the policy handle hash
		 * table.
		 */
		value = wmem_new(wmem_file_scope(), pol_hash_value);
		value->list = pol;
		pol->next = NULL;
		key = wmem_new(wmem_file_scope(), pol_hash_key);
		memcpy(&key->policy_hnd, policy_hnd, sizeof(key->policy_hnd));
		wmem_map_insert(pol_hash, key, value);
	} else {
		/*
		 * Put the new value in the hash value's policy handle
		 * list so that it's sorted by the first frame in
		 * which it appeared.
		 *
		 * Search for the first entry whose first frame number
		 * is greater than the current frame number, if any.
		 */
		for (polnext = value->list, polprev = NULL;
		    polnext != NULL && polnext->first_frame <= frame;
		    polprev = polnext, polnext = polnext->next)
			;

		/*
		 * "polprev" points to the entry in the list after
		 * which we should put the new entry; if it's null,
		 * that means we should put it at the beginning of
		 * the list.
		 */
		if (polprev == NULL)
			value->list = pol;
		else
			polprev->next = pol;

		/*
		 * "polnext" points to the entry in the list before
		 * which we should put the new entry; if it's null,
		 * that means we should put it at the end of the list.
		 */
		pol->next = polnext;
	}
}

/* Store the open and close frame numbers of a policy handle */

void dcerpc_smb_store_pol_pkts(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			       uint32_t param)
{
	pol_hash_value *value;
	pol_value *pol;

	/*
	 * By the time the first pass is done, the policy handle database
	 * has been completely constructed.  If we've already seen this
	 * frame, there's nothing to do.
	 */
	if (pinfo->fd->visited)
		return;

	if (is_null_pol(policy_hnd))
		return;

	/* Look up existing value */
	pol = find_pol_handle(policy_hnd, pinfo->num, &value);

	if (pol != NULL) {
		/*
		 * Update the existing value as appropriate.
		 */
		if (param & PIDL_POLHND_OPEN) {
			/*
			 * This is an open; we assume that we missed
			 * a close of this handle, so we set its
			 * "last frame" value and act as if we didn't
			 * see it.
			 *
			 * XXX - note that we might be called twice for
			 * the same operation (see "dissect_pipe_dcerpc()",
			 * which calls the DCE RPC dissector twice), so we
			 * must first check to see if this is a handle we
			 * just filled in.
			 *
			 * We check whether this handle's "first frame"
			 * frame number is this frame and its "last frame
			 * is 0; if so, this is presumably a duplicate call,
			 * and we don't do an implicit close.
			 */
			if (pol->first_frame == pinfo->num &&
			    pol->last_frame == 0)
				return;
			pol->last_frame = pinfo->num;
			pol = NULL;
		} else {
			if (param & PIDL_POLHND_CLOSE) {
				pol->close_frame = pinfo->num;
				pol->last_frame = pinfo->num;
			}
			return;
		}
	}

	/* Create a new value */

	pol = wmem_new(wmem_file_scope(), pol_value);

	pol->open_frame = (param & PIDL_POLHND_OPEN) ? pinfo->num : 0;
	pol->close_frame = (param & PIDL_POLHND_CLOSE) ? pinfo->num : 0;
	pol->first_frame = pinfo->num;
	pol->last_frame = pol->close_frame;	/* if 0, unknown; if non-0, known */
	pol->type=0;
	pol->name = NULL;

	add_pol_handle(policy_hnd, pinfo->num, pol, value);
}

/* Store the type of a policy handle */
static void dcerpc_store_polhnd_type(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			       uint32_t type)
{
	pol_hash_value *value;
	pol_value *pol;

	/*
	 * By the time the first pass is done, the policy handle database
	 * has been completely constructed.  If we've already seen this
	 * frame, there's nothing to do.
	 */
	if (pinfo->fd->visited)
		return;

	if (is_null_pol(policy_hnd))
		return;

	/* Look up existing value */
	pol = find_pol_handle(policy_hnd, pinfo->num, &value);

	if (pol != NULL) {
		/*
		 * Update the existing value as appropriate.
		 */
		pol->type=type;
	}
}

/* Store a text string with a policy handle */
void dcerpc_store_polhnd_name(e_ctx_hnd *policy_hnd, packet_info *pinfo,
			       const char *name)
{
	pol_hash_value *value;
	pol_value *pol;

	/*
	 * By the time the first pass is done, the policy handle database
	 * has been completely constructed.  If we've already seen this
	 * frame, there's nothing to do.
	 */
	if (pinfo->fd->visited)
		return;

	if (is_null_pol(policy_hnd))
		return;

	/* Look up existing value */
	pol = find_pol_handle(policy_hnd, pinfo->num, &value);

	if (pol != NULL) {
		/*
		 * This is the first pass; update the existing
		 * value as appropriate.
		 */
		if (pol->name && name) {
#ifdef DEBUG_HASH_COLL
			if (strcmp(pol->name, name) != 0)
				ws_warning("dcerpc_smb: pol_hash name collision %s/%s\n", value->name, name);
#endif
			/* pol->name is wmem_file_scope() allocated, don't free it now */
		}

		pol->name = wmem_strdup(wmem_file_scope(), name);

		return;
	}

	/* Create a new value */

	pol = wmem_new(wmem_file_scope(), pol_value);

	pol->open_frame = 0;
	pol->close_frame = 0;
	pol->first_frame = pinfo->num;
	pol->last_frame = 0;
	pol->type = 0;
	if (name)
		pol->name = wmem_strdup(wmem_file_scope(), name);
	else
		pol->name = wmem_strdup(wmem_file_scope(), "<UNKNOWN>");

	add_pol_handle(policy_hnd, pinfo->num, pol, value);
}

/*
 * Retrieve a policy handle.
 *
 * XXX - should this get a "param" argument, and match even closed
 * policy handles if the call closes the handle, so we can handle
 * retransmitted close operations?
 */

bool dcerpc_fetch_polhnd_data(e_ctx_hnd *policy_hnd,
			      char **name, uint32_t *type,
			      uint32_t *open_frame, uint32_t *close_frame,
			      uint32_t cur_frame)
{
	pol_hash_value *value;
	pol_value *pol;

	/* Prevent uninitialised return vars */

	if (name)
		*name = NULL;

	if (type)
		*type = 0;

	if (open_frame)
		*open_frame = 0;

	if (close_frame)
		*close_frame = 0;

	/* Look up existing value */
	pol = find_pol_handle(policy_hnd, cur_frame, &value);

	if (pol) {
		if (name)
			*name = pol->name;

		if (type)
			*type = pol->type;

		if (open_frame)
			*open_frame = pol->open_frame;

		if (close_frame)
			*close_frame = pol->close_frame;
	}

	return pol != NULL;
}

/* Dissect a NT status code */

int
dissect_ntstatus(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree, dcerpc_info *di, uint8_t *drep,
		 int hfindex, uint32_t *pdata)
{
	uint32_t status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hfindex, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str_ext(status, &NT_errors_ext,
					   "Unknown error 0x%08x"));
	if (pdata)
		*pdata = status;

	return offset;
}

/* Dissect a DOS status code */

int
dissect_doserror(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, dcerpc_info *di, uint8_t *drep,
	       int hfindex, uint32_t *pdata)
{
	uint32_t status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hfindex, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str_ext(status, &DOS_errors_ext,
					   "Unknown error 0x%08x"));
	if (pdata)
		*pdata = status;

	return offset;
}

int
dissect_werror(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, dcerpc_info *di, uint8_t *drep,
	       int hfindex, uint32_t *pdata)
{
	uint32_t status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hfindex, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str_ext(status, &WERR_errors_ext,
					   "Unknown error 0x%08x"));
	if (pdata)
		*pdata = status;

	return offset;
}

/* Dissect a HRESULT status code */

int
dissect_hresult(tvbuff_t *tvb, int offset, packet_info *pinfo,
	       proto_tree *tree, dcerpc_info *di, uint8_t *drep,
	       int hfindex, uint32_t *pdata)
{
	uint32_t status;

	offset = dissect_ndr_uint32(tvb, offset, pinfo, tree, di, drep,
				    hfindex, &status);

	if (status != 0)
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
				val_to_str_ext(status, &HRES_errors_ext,
					   "Unknown error 0x%08x"));
	if (pdata)
		*pdata = status;

	return offset;
}

/* Dissect a NT policy handle */

static int hf_nt_policy_open_frame;
static int hf_nt_policy_close_frame;

static int ett_nt_policy_hnd;

/* this function is used to dissect a "handle".
 * it will keep track of which frame a handle is opened from and in which
 * frame it is closed.
 * normally, this function would be used for tracking 20 byte policy handles
 * as used in dcerpc  but it has shown VERY useful to also use it for tracking
 * GUIDs such as for the file ids in smb2.
 */
typedef enum {
	HND_TYPE_CTX_HANDLE,
	HND_TYPE_GUID
} e_hnd_type;

static int
dissect_nt_hnd(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      uint32_t param, e_hnd_type type)
{
	proto_item *item=NULL;
	proto_tree *subtree;
	e_ctx_hnd hnd;
	uint32_t open_frame = 0, close_frame = 0;
	char *name;
	int old_offset = offset;
	if(di->conformant_run){
		/*
		 * just a run to handle conformant arrays, no scalars to
		 * dissect - and "dissect_ndr_ctx_hnd()" won't return
		 * a handle, so we can't do the hashing stuff in any
		 * case
		 */
		return offset;
	}

	/* Add to proto tree */

	switch(type){
	case HND_TYPE_CTX_HANDLE:
		if (!di->no_align) {
			offset = WS_ROUNDUP_4(offset);
		}
		subtree = proto_tree_add_subtree(tree, tvb, offset, sizeof(e_ctx_hnd),
					   ett_nt_policy_hnd, &item, "Policy Handle");

		offset = dissect_ndr_ctx_hnd(tvb, offset, pinfo, subtree, di, drep,
					     hfindex, &hnd);
		break;
	case HND_TYPE_GUID:
		subtree = proto_tree_add_subtree(tree, tvb, offset, 16,
					   ett_nt_policy_hnd, &item, "GUID handle");

		hnd.attributes=0;
		offset=dissect_ndr_uuid_t(tvb, offset, pinfo, subtree, di, drep, hfindex, &hnd.uuid);
		break;
	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return offset;
	}

	/*
	 * Create a new entry for this handle if it's not a null handle
	 * and no entry already exists, and, in any case, set the
	 * open, close, first, and last frame information as appropriate.
	 */
	dcerpc_smb_store_pol_pkts(&hnd, pinfo, param);

	/* Insert open/close/name information if known */
	if (dcerpc_fetch_polhnd_data(&hnd, &name, NULL, &open_frame,
			&close_frame, pinfo->num)) {

		if (open_frame) {
			proto_item *item_local;
			item_local=proto_tree_add_uint(
				subtree, hf_nt_policy_open_frame, tvb,
				old_offset, sizeof(e_ctx_hnd), open_frame);
			proto_item_set_generated(item_local);
		}
		if (close_frame) {
			proto_item *item_local;
			item_local=proto_tree_add_uint(
				subtree, hf_nt_policy_close_frame, tvb,
				old_offset, sizeof(e_ctx_hnd), close_frame);
			proto_item_set_generated(item_local);
		}

		/*
		 * Don't append the handle name if pitem is null; that's
		 * an indication that our caller will do so, as we're
		 * supplying a pointer to the item so that they can do
		 * so.
		 */
		if (name != NULL && pitem == NULL)
			proto_item_append_text(item, ": %s", name);
	}

	if (pdata)
		*pdata = hnd;

	if (pitem)
		*pitem = item;

	return offset;
}


int
dissect_nt_policy_hnd(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      uint32_t param)
{
	offset=dissect_nt_hnd(tvb, offset, pinfo,
		      tree, di, drep, hfindex,
		      pdata, pitem,
		      param, HND_TYPE_CTX_HANDLE);

	return offset;
}

/* This function is called from PIDL generated dissectors to dissect a
 * NT style policy handle (contect handle).
 *
 * param can be used to specify where policy handles are opened and closed
 * by setting PARAM_VALUE to
 *  PIDL_POLHND_OPEN where the policy handle is opened/created
 *  PIDL_POLHND_CLOSE where it is closed.
 * This enables policy handle tracking so that when a policy handle is
 * dissected it will be so as an expansion showing which frame it was
 * opened/closed in.
 *
 * See conformance file for winreg (epan/dissectors/pidl/winreg.cnf)
 * for examples.
 */
int
PIDL_dissect_policy_hnd(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, dcerpc_info* di, uint8_t *drep, int hfindex,
		      uint32_t param)
{
	e_ctx_hnd policy_hnd;

	offset=dissect_nt_hnd(tvb, offset, pinfo,
		      tree, di, drep, hfindex,
		      &policy_hnd, NULL,
		      param, HND_TYPE_CTX_HANDLE);

	/* If this was an open/create and we don't yet have a policy name
	 * then create one.
	 * XXX We do not yet have the infrastructure to know the name of the
	 * actual object  so just show it as <...> for the time being.
	 */
	if((param&PIDL_POLHND_OPEN)
	&& !pinfo->fd->visited
	&& !di->conformant_run){
		char *pol_string=NULL;
		const char *pol_name=NULL;
		dcerpc_call_value *dcv;

		dcv = (dcerpc_call_value *)di->call_data;
		pol_name = (const char *)dcv->private_data;
		if(!pol_name){
			pol_name="<...>";
		}
		pol_string=wmem_strdup_printf(pinfo->pool, "%s(%s)", di->dcerpc_procedure_name, pol_name);
		dcerpc_store_polhnd_name(&policy_hnd, pinfo, pol_string);
		dcerpc_store_polhnd_type(&policy_hnd, pinfo, param&PIDL_POLHND_TYPE_MASK);
	}

	/* Track this policy handle for the response */
	if(!pinfo->fd->visited
	&& !di->conformant_run){
		dcerpc_call_value *dcv;

		dcv = (dcerpc_call_value *)di->call_data;
		if(!dcv->pol){
			dcv->pol=(e_ctx_hnd *)wmem_memdup(wmem_file_scope(), &policy_hnd, sizeof(e_ctx_hnd));
		}
	}

	return offset;
}

/* this function must be called with   hfindex being HF_GUID */
int
dissect_nt_guid_hnd(tvbuff_t *tvb, int offset, packet_info *pinfo,
		      proto_tree *tree, dcerpc_info *di, uint8_t *drep, int hfindex,
		      e_ctx_hnd *pdata, proto_item **pitem,
		      uint32_t param)
{
	offset=dissect_nt_hnd(tvb, offset, pinfo,
		      tree, di, drep, hfindex,
		      pdata, pitem,
		      param, HND_TYPE_GUID);

	return offset;
}

/* Some helper routines to dissect a range of uint8 characters.	 I don't
   think these are "official" NDR representations and are probably specific
   to NT so for the moment they're put here instead of in packet-dcerpc.c
   and packet-dcerpc-ndr.c. */

int
dissect_dcerpc_uint8s(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		      proto_tree *tree, dcerpc_info *di _U_, uint8_t *drep _U_, int hfindex,
		      int length, const uint8_t **pdata)
{
	const uint8_t *data;

	data = (const uint8_t *)tvb_get_ptr(tvb, offset, length);

	/* This should be an FT_BYTES, so the byte order should not matter */
	proto_tree_add_item (tree, hfindex, tvb, offset, length, ENC_NA);

	if (pdata)
		*pdata = data;

	return offset + length;
}

int
dissect_ndr_uint8s(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, dcerpc_info *di, uint8_t *drep,
		   int hfindex, int length, const uint8_t **pdata)
{
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	/* no alignment needed */
	return dissect_dcerpc_uint8s(tvb, offset, pinfo,
				     tree, di, drep, hfindex, length, pdata);
}

int
dissect_dcerpc_uint16s(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
		       proto_tree *tree, uint8_t *drep, int hfindex,
		       int length)
{
	/* These are FT_BYTES fields, so the byte order should not matter;
	   however, perhaps there should be an FT_HEXADECTETS type,
	   or something such as that, with each pair of octets
	   displayed as a single unit, in which case the byte order
	   would matter, so we'll calculate the byte order here.  */
	proto_tree_add_item (tree, hfindex, tvb, offset, length * 2, DREP_ENC_INTEGER(drep));

	return offset + length * 2;
}

int
dissect_ndr_uint16s(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, dcerpc_info *di, uint8_t *drep,
		    int hfindex, int length)
{
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	if (offset % 2)
		offset++;

	return dissect_dcerpc_uint16s(tvb, offset, pinfo,
				      tree, drep, hfindex, length);
}

static void cb_str_postprocess_options(packet_info *pinfo,
				       proto_item *item,
				       dcerpc_info *di,
				       int options,
				       const char *s)
{
	int levels = CB_STR_ITEM_LEVELS(options);

	/* Append string to COL_INFO */

	if ((options & CB_STR_COL_INFO) && (!di->conformant_run)) {
		/*
		 * kludge, ugly, but this is called twice for all
		 * dcerpc interfaces due to how we chase pointers
		 * and putting the sid twice on the summary line
		 * looks even worse.
		 * Real solution would be to block updates to col_info
		 * while we just do a conformance run, this might
		 * have sideeffects so it needs some more thoughts first.
		 */
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", s);
	}

	/* Append string to upper-level proto_items */
	if (levels > 0 && item && s && s[0]) {
		proto_item_append_text(item, ": %s", s);
		item = GET_ITEM_PARENT(item);
		levels--;
		if (item && levels > 0) {
			proto_item_append_text(item, ": %s", s);
			item = GET_ITEM_PARENT(item);
			levels--;
			while (item && levels > 0) {
				proto_item_append_text(item, " %s", s);
				item = GET_ITEM_PARENT(item);
				levels--;
			}
		}
	}

	/* Save string to dcv->private_data */
	if (options & CB_STR_SAVE) {
		dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
		dcv->private_data = wmem_strdup(wmem_file_scope(), s);
	}
}

/*
 * Helper routines for dissecting NDR strings
 */
void cb_wstr_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, dcerpc_info *di, tvbuff_t *tvb,
			int start_offset, int end_offset,
			void *callback_args)
{
	int options = GPOINTER_TO_INT(callback_args);
	char *s;

	/* Align start_offset on 4-byte boundary. */

	start_offset = WS_ROUNDUP_4(start_offset);

	/* Get string value */

	if ((end_offset - start_offset) <= 12)
		return;		/* XXX: Use unistr2 dissector instead? */

	/*
	 * XXX - need to handle non-printable characters here.
	 *
	 * XXX - this is typically called after the string has already
	 * been fetched and processed by some other routine; is there
	 * some way we can get that string, rather than duplicating the
	 * efforts of that routine?
	 */
	s = tvb_get_string_enc(pinfo->pool,
		tvb, start_offset + 12, end_offset - start_offset - 12,
		ENC_UTF_16|ENC_LITTLE_ENDIAN);

	cb_str_postprocess_options(pinfo, item, di, options, s);
}

void cb_str_postprocess(packet_info *pinfo, proto_tree *tree _U_,
			proto_item *item, dcerpc_info *di, tvbuff_t *tvb,
			int start_offset, int end_offset,
			void *callback_args)
{
	int options = GPOINTER_TO_INT(callback_args);
	uint8_t *s;

	/* Align start_offset on 4-byte boundary. */

	start_offset = WS_ROUNDUP_4(start_offset);

	/* Get string value */

	if ((end_offset - start_offset) <= 12)
		return;		/* XXX: Use unistr2 dissector instead? */

	/*
	 * XXX - need to handle non-printable characters here.
	 *
	 * XXX - this is typically called after the string has already
	 * been fetched and processed by some other routine; is there
	 * some way we can get that string, rather than duplicating the
	 * efforts of that routine?
	 */
	s = tvb_get_string_enc(pinfo->pool,
		tvb, start_offset + 12, (end_offset - start_offset - 12), ENC_ASCII);

	cb_str_postprocess_options(pinfo, item, di, options, s);
}

/* Dissect a pointer to a NDR string and append the string value to the
   proto_item. */

int dissect_ndr_str_pointer_item(tvbuff_t *tvb, int offset,
				 packet_info *pinfo, proto_tree *tree,
				 dcerpc_info *di, uint8_t *drep, int type, const char *text,
				 int hf_index, int levels)
{
	return dissect_ndr_pointer_cb(
		tvb, offset, pinfo, tree, di, drep,
		dissect_ndr_wchar_cvstring, type, text, hf_index,
		cb_wstr_postprocess, GINT_TO_POINTER(levels + 1));
}

/* SID dissection routines */

static int hf_nt_count;
static int hf_nt_domain_sid;

/* That's a SID that is always 28 bytes long */
int
dissect_ndr_nt_SID28(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *tree, dcerpc_info *di, uint8_t *drep _U_, int hf_index)
{
	proto_item *item;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *sid_str=NULL;
	const char *name;
	int newoffset;

	if(hf_index > 0){
		name=proto_registrar_get_name(hf_index);
	} else {
		name="Domain";
	}
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	newoffset = dissect_nt_sid(tvb, pinfo, offset, tree, name, &sid_str,
				hf_nt_domain_sid);
	/* The dissected stuff can't be more than 28 bytes */
	if ((newoffset - offset) > 28) {
		item = proto_tree_get_parent(tree? tree->last_child : NULL);
		expert_add_info(pinfo, item, &ei_dcerpc_nt_badsid);

		/* The rest of the dissection will most probably wrong as we are not dissecting what we expect */
		return newoffset;
	}

	/* No matter how much we used for the real dissection of the SID consume 28 bytes */
	if (tree) {
		item = proto_tree_get_parent(tree->last_child);
		proto_item_set_len(item, 28);
	}
	offset += 28;
	/* dcv can be null, for example when this ndr structure is embedded
	 * inside non-dcerpc pdus, i.e. kerberos PAC structure
	 */
	if(dcv){
		/*
		 * sid_str has ephemeral storage duration;
		 * dcerpc_call_values have session duration,
		 * so we need to make its private data have
		 * session duration as well.
		 */
		dcv->private_data = wmem_strdup(wmem_file_scope(), sid_str);
	}

	return offset;
}

int
dissect_ndr_nt_SID(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, dcerpc_info *di, uint8_t *drep)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;
	char *sid_str=NULL;
	const char *name;

	if(di->hf_index > 0){
		name=proto_registrar_get_name(di->hf_index);
	} else {
		name="Domain";
	}
	if(di->conformant_run){
		/* just a run to handle conformant arrays, no scalars to dissect */
		return offset;
	}

	/* the SID contains a conformant array, first we must eat
	   the 4-byte max_count before we can hand it off */

	offset = dissect_ndr_uint3264 (tvb, offset, pinfo, tree, di, drep,
			hf_nt_count, NULL);

	offset = dissect_nt_sid(tvb, pinfo, offset, tree, name, &sid_str,
				hf_nt_domain_sid);

	/* dcv can be null, for example when this ndr structure is embedded
	 * inside non-dcerpc pdus, i.e. kerberos PAC structure
	 */
	if(dcv){
		/*
		 * sid_str has ephemeral storage duration;
		 * dcerpc_call_values have session duration,
		 * so we need to make its private data have
		 * session duration as well.
		 */
		dcv->private_data = wmem_strdup(wmem_file_scope(), sid_str);
	}

	return offset;
}

/* same as dissect_ndr_nt_SID() but takes the same options as counted strings
   do to prettify the dissect pane and the COL_INFO summary line
*/
/* Note this is in fact for dissecting the dom_sid2*/
int
dissect_ndr_nt_SID_with_options(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, dcerpc_info *di, uint8_t *drep, uint32_t options, int hf_index)
{
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	di->hf_index = hf_index;
	offset=dissect_ndr_nt_SID(tvb, offset, pinfo, tree, di, drep);

	if(dcv && dcv->private_data){
		char *s=(char *)dcv->private_data;
		proto_item *item=(proto_item *)tree;

		/*
		 * The string is already saved by dissect_ndr_nt_SID()
		 */
		options &= ~CB_STR_SAVE;

		cb_str_postprocess_options(pinfo,
					   item,
					   di,
					   options,
					   s);
	}

	return offset;
}

static int
dissect_ndr_nt_SID_hf_through_ptr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		   proto_tree *tree, dcerpc_info *di, uint8_t *drep)
{
	offset = dissect_ndr_nt_SID_with_options(tvb, offset, pinfo, tree,
						 di, drep,
						 CB_STR_ITEM_LEVELS(2),
						 di->hf_index);

	return offset;
}

static int ett_nt_sid_pointer;

int
dissect_ndr_nt_PSID_cb(tvbuff_t *tvb, int offset,
		       packet_info *pinfo, proto_tree *parent_tree,
		       dcerpc_info *di, uint8_t *drep,
		       dcerpc_callback_fnct_t *callback, void *callback_args)
{
	proto_item *item;
	proto_tree *tree;
	int old_offset=offset;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1,
			ett_nt_sid_pointer, &item, "SID pointer");

	offset = dissect_ndr_pointer_cb(tvb, offset, pinfo, tree, di, drep,
			dissect_ndr_nt_SID_hf_through_ptr, NDR_POINTER_UNIQUE,
			"SID pointer", hf_nt_domain_sid,
			callback, callback_args);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

int
dissect_ndr_nt_PSID(tvbuff_t *tvb, int offset,
		    packet_info *pinfo, proto_tree *parent_tree,
		    dcerpc_info *di, uint8_t *drep)
{
	return dissect_ndr_nt_PSID_cb(tvb, offset, pinfo, parent_tree,
				      di, drep, NULL, NULL);
}

static const true_false_string tfs_nt_acb_disabled = {
	"Account is DISABLED",
	"Account is NOT disabled"
};
static const true_false_string tfs_nt_acb_homedirreq = {
	"Homedir is REQUIRED",
	"Homedir is NOT required"
};
static const true_false_string tfs_nt_acb_pwnotreq = {
	"Password is NOT required",
	"Password is REQUIRED"
};
static const true_false_string tfs_nt_acb_tempdup = {
	"This is a TEMPORARY DUPLICATE account",
	"This is NOT a temporary duplicate account"
};
static const true_false_string tfs_nt_acb_normal = {
	"This is a NORMAL USER account",
	"This is NOT a normal user account"
};
static const true_false_string tfs_nt_acb_mns = {
	"This is a MNS account",
	"This is NOT a mns account"
};
static const true_false_string tfs_nt_acb_domtrust = {
	"This is a DOMAIN TRUST account",
	"This is NOT a domain trust account"
};
static const true_false_string tfs_nt_acb_wstrust = {
	"This is a WORKSTATION TRUST account",
	"This is NOT a workstation trust account"
};
static const true_false_string tfs_nt_acb_svrtrust = {
	"This is a SERVER TRUST account",
	"This is NOT a server trust account"
};
static const true_false_string tfs_nt_acb_pwnoexp = {
	"Passwords does NOT expire",
	"Password will EXPIRE"
};
static const true_false_string tfs_nt_acb_autolock = {
	"This account has been AUTO LOCKED",
	"This account has NOT been auto locked"
};

static int ett_nt_acct_ctrl;

static int hf_nt_acct_ctrl;
static int hf_nt_acb_disabled;
static int hf_nt_acb_homedirreq;
static int hf_nt_acb_pwnotreq;
static int hf_nt_acb_tempdup;
static int hf_nt_acb_normal;
static int hf_nt_acb_mns;
static int hf_nt_acb_domtrust;
static int hf_nt_acb_wstrust;
static int hf_nt_acb_svrtrust;
static int hf_nt_acb_pwnoexp;
static int hf_nt_acb_autolock;

int
dissect_ndr_nt_acct_ctrl(tvbuff_t *tvb, int offset, packet_info *pinfo,
			proto_tree *parent_tree, dcerpc_info *di, uint8_t *drep)
{
	uint32_t mask;
	static int * const flags[] = {
		&hf_nt_acb_autolock,
		&hf_nt_acb_pwnoexp,
		&hf_nt_acb_svrtrust,
		&hf_nt_acb_wstrust,
		&hf_nt_acb_domtrust,
		&hf_nt_acb_mns,
		&hf_nt_acb_normal,
		&hf_nt_acb_tempdup,
		&hf_nt_acb_pwnotreq,
		&hf_nt_acb_homedirreq,
		&hf_nt_acb_disabled,
		NULL
	};

	offset=dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep, -1, &mask);

	proto_tree_add_bitmask_value_with_flags(parent_tree, tvb, offset-4, hf_nt_acct_ctrl,
					ett_nt_acct_ctrl, flags, mask, BMT_NO_APPEND);

	return offset;
}

static int hf_logonhours_unknown_char;

static int
dissect_LOGON_HOURS_entry(tvbuff_t *tvb, int offset,
			  packet_info *pinfo, proto_tree *tree,
			  dcerpc_info *di, uint8_t *drep)
{
	offset = dissect_ndr_uint8(tvb, offset, pinfo, tree, di, drep,
			hf_logonhours_unknown_char, NULL);
	return offset;
}

static int ett_nt_logon_hours_hours;

static int
dissect_LOGON_HOURS_hours(tvbuff_t *tvb, int offset,
			  packet_info *pinfo, proto_tree *parent_tree,
			  dcerpc_info *di, uint8_t *drep)
{
	proto_item *item;
	proto_tree *tree;
	int old_offset=offset;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1,
			ett_nt_logon_hours_hours, &item, "LOGON_HOURS:");

	offset = dissect_ndr_ucvarray(tvb, offset, pinfo, tree, di, drep,
			dissect_LOGON_HOURS_entry);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int ett_nt_logon_hours;
static int hf_logonhours_divisions;

int
dissect_ndr_nt_LOGON_HOURS(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, uint8_t *drep)
{
	proto_item *item;
	proto_tree *tree;
	int old_offset=offset;

	ALIGN_TO_4_BYTES;  /* structure starts with short, but is aligned for longs */

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1,
			ett_nt_logon_hours, &item, "LOGON_HOURS:");

	offset = dissect_ndr_uint16(tvb, offset, pinfo, tree, di, drep,
				hf_logonhours_divisions, NULL);
	/* XXX - is this a bitmask like the "logon hours" field in the
	   Remote API call "NetUserGetInfo()" with an information level
	   of 11? */
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, di, drep,
			dissect_LOGON_HOURS_hours, NDR_POINTER_UNIQUE,
			"LOGON_HOURS", -1);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

static int
dissect_ndr_nt_PSID_no_hf(tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *parent_tree,
			     dcerpc_info *di, uint8_t *drep)
{
	offset=dissect_ndr_nt_PSID(tvb, offset, pinfo, parent_tree, di, drep);
	return offset;
}

static int
dissect_ndr_nt_PSID_ARRAY_sids (tvbuff_t *tvb, int offset,
			     packet_info *pinfo, proto_tree *tree,
			     dcerpc_info *di, uint8_t *drep)
{
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep,
			dissect_ndr_nt_PSID_no_hf);

	return offset;
}

static int ett_nt_sid_array;

int
dissect_ndr_nt_PSID_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, uint8_t *drep)
{
	uint32_t count;
	proto_item *item;
	proto_tree *tree;
	int old_offset=offset;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, -1,
			ett_nt_sid_array, &item, "SID array:");

	ALIGN_TO_5_BYTES;

	offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
			hf_nt_count, &count);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, di, drep,
			dissect_ndr_nt_PSID_ARRAY_sids, NDR_POINTER_UNIQUE,
			"PSID_ARRAY", -1);

	proto_item_set_len(item, offset-old_offset);

	if (di->call_data->flags & DCERPC_IS_NDR64) {
		ALIGN_TO_5_BYTES;
	}

	return offset;
}

static int ett_nt_sid_and_attributes;
static int ett_nt_se_group_attrs;
static int hf_nt_se_group_attrs;
static int hf_nt_se_group_attrs_mandatory;
static int hf_nt_se_group_attrs_enabled_by_default;
static int hf_nt_se_group_attrs_enabled;
static int hf_nt_se_group_attrs_owner;
static int hf_nt_se_group_attrs_resource_group;

static const true_false_string group_attrs_mandatory = {
    "The MANDATORY bit is SET",
    "The mandatory bit is NOT set",
};
static const true_false_string group_attrs_enabled_by_default = {
    "The ENABLED_BY_DEFAULT bit is SET",
    "The enabled_by_default bit is NOT set",
};
static const true_false_string group_attrs_enabled = {
    "The ENABLED bit is SET",
    "The enabled bit is NOT set",
};
static const true_false_string group_attrs_owner = {
    "The OWNER bit is SET",
    "The owner bit is NOT set",
};
static const true_false_string group_attrs_resource_group = {
    "The RESOURCE GROUP bit is SET",
    "The resource group bit is NOT set",
};

int
dissect_ndr_nt_SE_GROUP_ATTRIBUTES(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, uint8_t *drep)
{
    uint32_t mask;
    static int * const attr[] = {
        &hf_nt_se_group_attrs_mandatory,
        &hf_nt_se_group_attrs_enabled_by_default,
        &hf_nt_se_group_attrs_enabled,
        &hf_nt_se_group_attrs_owner,
        &hf_nt_se_group_attrs_resource_group,
        NULL
    };

    if(di->conformant_run){
        /*just a run to handle conformant arrays, nothing to dissect */
        return offset;
    }

    offset=dissect_ndr_uint32(tvb, offset, pinfo, NULL, di, drep,
                              -1, &mask);

    proto_tree_add_bitmask_value_with_flags(parent_tree, tvb, offset-4,
					    hf_nt_se_group_attrs, ett_nt_se_group_attrs,
					    attr, mask, BMT_NO_APPEND);
    return offset;
}

static void dissect_propagate_SID_to_parent_callback(packet_info *pinfo,
						     proto_tree *tree _U_,
						     proto_item *item _U_,
						     dcerpc_info *di,
						     tvbuff_t *tvb _U_,
						     int start_offset _U_,
						     int end_offset _U_,
						     void *callback_args)
{
	proto_item *parent_item = (proto_item *)callback_args;
	dcerpc_call_value *dcv = (dcerpc_call_value *)di->call_data;

	if (parent_item && dcv && dcv->private_data) {
		const char *s = (const char *)dcv->private_data;

		cb_str_postprocess_options(pinfo,
					   parent_item,
					   di,
					   CB_STR_ITEM_LEVELS(1),
					   s);
	}
}

int
dissect_ndr_nt_SID_AND_ATTRIBUTES(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, uint8_t *drep)
{
	proto_item *item;
	proto_tree *tree;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0,
			ett_nt_sid_and_attributes, &item, "SID_AND_ATTRIBUTES");

	offset = dissect_ndr_nt_PSID_cb(tvb, offset, pinfo, tree, di, drep,
					dissect_propagate_SID_to_parent_callback, item);

	offset = dissect_ndr_nt_SE_GROUP_ATTRIBUTES(tvb, offset, pinfo, tree, di, drep);

	return offset;
}

static int ett_nt_sid_and_attributes_array;

int
dissect_ndr_nt_SID_AND_ATTRIBUTES_ARRAY(tvbuff_t *tvb, int offset,
			packet_info *pinfo, proto_tree *parent_tree,
			dcerpc_info *di, uint8_t *drep)
{
	proto_item *item;
	proto_tree *tree;
	int old_offset=offset;

	tree = proto_tree_add_subtree(parent_tree, tvb, offset, 0,
			ett_nt_sid_and_attributes_array, &item, "SID_AND_ATTRIBUTES array:");

	/*offset = dissect_ndr_uint32 (tvb, offset, pinfo, tree, di, drep,
	  hf_samr_count, &count); */
	offset = dissect_ndr_ucarray(tvb, offset, pinfo, tree, di, drep,
			dissect_ndr_nt_SID_AND_ATTRIBUTES);

	proto_item_set_len(item, offset-old_offset);
	return offset;
}

/* This might be some sort of header that MIDL generates when creating
 * marshalling/unmarshalling code for blobs that are not to be transported
 * ontop of DCERPC and where the DREP fields specifying things such as
 * endianess and similar are not available.
 */
int
nt_dissect_MIDL_NDRHEADERBLOB(proto_tree *parent_tree, tvbuff_t *tvb, int offset, uint8_t *drep)
{
	proto_tree *tree;
	uint8_t val;

	tree=proto_tree_add_subtree(parent_tree, tvb, offset, 16, ett_nt_MIDL_BLOB, NULL, "MES header");

	/* modified DREP field that is used for stuff that is transporetd ontop
	 * of non dcerpc
	 */
	proto_tree_add_item(tree, hf_nt_midl_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	val = tvb_get_uint8(tvb, offset);
	proto_tree_add_uint(tree, hf_dcerpc_drep_byteorder, tvb, offset, 1, val>>4);

	offset++;

	if (drep) {
		*drep = val;
	}

	proto_tree_add_item(tree, hf_nt_midl_hdr_len, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset+=2;

	proto_tree_add_item(tree, hf_nt_midl_fill_bytes, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* length of blob that follows */
	proto_tree_add_item(tree, hf_nt_midl_blob_len, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	return offset;
}

/*
 * Register ett/hf values and perform DCERPC over SMB specific
 * initialisation.
 */
void dcerpc_smb_init(int proto_dcerpc)
{
	expert_module_t* expert_dcerpc_nt;
	static hf_register_info hf[] = {

		/* String handling */

		{ &hf_nt_cs_size,
		  { "Size", "dcerpc.nt.str.size", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Size of string in short integers",
		    HFILL }},

		{ &hf_nt_cs_len,
		  { "Length", "dcerpc.nt.str.len", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Length of string in short integers",
		    HFILL }},

		/* GUIDs */
		{ &hf_nt_guid,
		  { "GUID", "dcerpc.nt.guid", FT_GUID, BASE_NONE,
		    NULL, 0x0, "GUID (uuid for groups?)", HFILL }},

		/* Policy handles */

		{ &hf_nt_policy_open_frame,
		  { "Frame handle opened", "dcerpc.nt.open_frame",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_nt_policy_close_frame,
		  { "Frame handle closed", "dcerpc.nt.close_frame",
		    FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* ACBs */

		{ &hf_nt_acct_ctrl,
		  { "Acct Ctrl", "dcerpc.nt.acct_ctrl", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_nt_acb_disabled,
		  { "Account disabled", "dcerpc.nt.acb.disabled", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_disabled), 0x00000001,
		    "If this account is enabled or disabled", HFILL }},

		{ &hf_nt_acb_homedirreq,
		  { "Home dir required", "dcerpc.nt.acb.homedirreq", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_homedirreq), 0x00000002,
		    "Is homedirs required for this account?", HFILL }},

		{ &hf_nt_acb_pwnotreq,
		  { "Password required", "dcerpc.nt.acb.pwnotreq", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_pwnotreq), 0x00000004,
		    "If a password is required for this account?", HFILL }},

		{ &hf_nt_acb_tempdup,
		  { "Temporary duplicate account", "dcerpc.nt.acb.tempdup", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_tempdup), 0x00000008,
		    "If this is a temporary duplicate account", HFILL }},

		{ &hf_nt_acb_normal,
		  { "Normal user account", "dcerpc.nt.acb.normal", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_normal), 0x00000010,
		    "If this is a normal user account", HFILL }},

		{ &hf_nt_acb_mns,
		  { "MNS logon user account", "dcerpc.nt.acb.mns", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_mns), 0x00000020,
		    NULL, HFILL }},

		{ &hf_nt_acb_domtrust,
		  { "Interdomain trust account", "dcerpc.nt.acb.domtrust", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_domtrust), 0x00000040,
		    NULL, HFILL }},

		{ &hf_nt_acb_wstrust,
		  { "Workstation trust account", "dcerpc.nt.acb.wstrust", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_wstrust), 0x00000080,
		    NULL, HFILL }},

		{ &hf_nt_acb_svrtrust,
		  { "Server trust account", "dcerpc.nt.acb.svrtrust", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_svrtrust), 0x00000100,
		    NULL, HFILL }},

		{ &hf_nt_acb_pwnoexp,
		  { "Password expires", "dcerpc.nt.acb.pwnoexp", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_pwnoexp), 0x00000200,
		    "If this account expires or not", HFILL }},

		{ &hf_nt_acb_autolock,
		  { "Account is autolocked", "dcerpc.nt.acb.autolock", FT_BOOLEAN, 32,
		    TFS(&tfs_nt_acb_autolock), 0x00000400,
		    "If this account has been autolocked", HFILL }},

		{ &hf_nt_error,
		  { "Wrong string type", "dcerpc.nt.sting_error",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Non terminated string", HFILL }},

		/* SIDs */

		{ &hf_nt_domain_sid,
		  { "Domain SID", "dcerpc.nt.domain_sid",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The Domain SID", HFILL }},

		{ &hf_nt_count,
		  { "Count", "dcerpc.nt.count",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of elements in following array", HFILL }},

		/* Logon hours */

		{ &hf_logonhours_divisions,
		  { "Divisions", "dcerpc.nt.logonhours.divisions",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "Number of divisions for LOGON_HOURS", HFILL }},

		{ &hf_logonhours_unknown_char,
		  { "Unknown char", "dcerpc.nt.unknown.char",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    "Unknown char. If you know what this is, contact wireshark developers.", HFILL }},

		/* Misc */

		{ &hf_lsa_String_name_len,
		  { "Name Len", "dcerpc.lsa_String.name_len",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_lsa_String_name_size,
		  { "Name Size", "dcerpc.lsa_String.name_size",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_nt_data_blob_len,
		  { "Blob size", "dcerpc.nt.blob.size",
		    FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }},

		{ &hf_nt_data_blob_data,
		  { "Blob data", "dcerpc.nt.blob.data",
		    FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_nt_midl_blob_len, {
		  "Blob Length", "nt.midl_blob_len", FT_UINT64, BASE_DEC,
		  NULL, 0, "Length of NDR encoded data that follows", HFILL }},

		{ &hf_nt_midl_fill_bytes, {
		  "Fill bytes", "nt.midl.fill_bytes", FT_UINT32, BASE_HEX,
		  NULL, 0, "Just some fill bytes", HFILL }},

		{ &hf_nt_midl_version, {
		  "Version", "nt.midl.version", FT_UINT8, BASE_DEC,
		  NULL, 0, "Version of pickling", HFILL }},

		{ &hf_nt_midl_hdr_len, {
		  "HDR Length", "nt.midl.hdr_len", FT_UINT16, BASE_DEC,
		  NULL, 0, "Length of header", HFILL }},

		{ &hf_nt_se_group_attrs,
		  { "Group Attributes", "dcerpc.nt.groups.attrs",
		    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_nt_se_group_attrs_mandatory,
		   { "Mandatory", "dcerpc.nt.groups.attrs.mandatory",
		     FT_BOOLEAN, 32, TFS(&group_attrs_mandatory), 0x00000001,
		     "The group attributes MANDATORY flag", HFILL }},

		{ &hf_nt_se_group_attrs_enabled_by_default, {
		  "Enabled By Default", "dcerpc.nt.groups.attrs.enabled_by_default",
		  FT_BOOLEAN, 32, TFS(&group_attrs_enabled_by_default), 0x00000002,
		  "The group attributes ENABLED_BY_DEFAULT flag", HFILL }},

		{ &hf_nt_se_group_attrs_enabled, {
		  "Enabled", "dcerpc.nt.groups.attrs.enabled",
		  FT_BOOLEAN, 32, TFS(&group_attrs_enabled), 0x00000004,
		  "The group attributes ENABLED flag", HFILL }},

		{ &hf_nt_se_group_attrs_owner, {
		  "Owner", "dcerpc.nt.groups.attrs.owner",
		  FT_BOOLEAN, 32, TFS(&group_attrs_owner), 0x00000008,
		  "The group attributes OWNER flag", HFILL }},

		{ &hf_nt_se_group_attrs_resource_group, {
		  "Resource Group", "dcerpc.nt.groups.attrs.resource_group",
		  FT_BOOLEAN, 32, TFS(&group_attrs_resource_group), 0x20000000,
		  "The group attributes RESOURCE GROUP flag", HFILL }},

	};

	static int *ett[] = {
		&ett_nt_data_blob,
		&ett_nt_counted_string,
		&ett_nt_counted_byte_array,
		&ett_nt_policy_hnd,
		&ett_nt_sid_pointer,
		&ett_nt_acct_ctrl,
		&ett_nt_logon_hours,
		&ett_nt_logon_hours_hours,
		&ett_nt_sid_array,
		&ett_nt_sid_and_attributes_array,
		&ett_nt_sid_and_attributes,
		&ett_nt_se_group_attrs,
		&ett_nt_counted_ascii_string,
		&ett_lsa_String,
		&ett_nt_MIDL_BLOB,
	};
	static ei_register_info ei[] = {
		{ &ei_dcerpc_nt_badsid, { "dcerpc.nt.badsid", PI_MALFORMED, PI_ERROR, "Association rejected", EXPFILL }},
	};

	/* Register ett's and hf's */

	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_dcerpc, hf, array_length(hf));

	/* Initialise policy handle hash */
	expert_dcerpc_nt = expert_register_protocol(proto_dcerpc);
	expert_register_field_array(expert_dcerpc_nt, ei, array_length(ei));

	pol_hash = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), pol_hash_fn, pol_hash_compare);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
