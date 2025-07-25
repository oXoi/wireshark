/* packet-docsis-tlv.c
 *
 * Routines to Dissect Appendix C TLVs
 * Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 * Copyright 2017, Bruno Verstuyft <bruno.verstuyft@excentis.com>
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
#include <epan/reassemble.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>

#include "packet-docsis-tlv.h"

/* This module will dissect the Appendix C TLVs.  Please see:
 * http://www.cablemodem.com/specifications/specifications.html
 *
 * The main dissector is dissect_docsis_tlv.  This routine will dissect
 * top level TLVs and call sub-dissectors for the sub-TLVs.
 */

void proto_register_docsis_tlv(void);
void proto_reg_handoff_docsis_tlv(void);

/* Initialize the protocol and registered fields */
static dissector_handle_t docsis_vsif_handle;
static dissector_handle_t docsis_ucd_handle;
static dissector_handle_t docsis_rba_handle;

static int proto_docsis_tlv;
static int hf_docsis_tlv_down_freq;
static int hf_docsis_tlv_upstream_chid;
static int hf_docsis_tlv_net_access;
/* static int hf_docsis_tlv_cos; */
/* static int hf_docsis_tlv_mcap; */
static int hf_docsis_tlv_privacy_enable;
static int hf_docsis_tlv_max_cpe;
static int hf_docsis_tlv_max_classifiers;
static int hf_docsis_tlv_snmp_access;
static int hf_docsis_tlv_snmp_obj;
static int hf_docsis_tlv_svc_unavail;
static int hf_docsis_tlv_svc_unavail_classid;
static int hf_docsis_tlv_svc_unavail_type;
static int hf_docsis_tlv_svc_unavail_code;
static int hf_docsis_tlv_bpi;
/* static int hf_docsis_tlv_phs; */
static int hf_docsis_tlv_hmac_digest;
static int hf_docsis_tlv_tftp_server_timestamp;
static int hf_docsis_tlv_tftp_prov_modem_address;
/* static int hf_docsis_tlv_upclsfr; */
/* static int hf_docsis_tlv_downclsfr; */
/* static int hf_docsis_tlv_upsflow; */
/* static int hf_docsis_tlv_downsflow; */
/* static int hf_docsis_tlv_vendor_spec; */
static int hf_docsis_tlv_cm_mic;
static int hf_docsis_tlv_cmts_mic;
static int hf_docsis_tlv_auth_block;
static int hf_docsis_tlv_key_seq_num;
static int hf_docsis_tlv_snmpv3_kick;
static int hf_docsis_tlv_snmpv3_kick_name;
static int hf_docsis_tlv_snmpv3_kick_publicnum;
static int hf_docsis_tlv_mfgr_cvc;
static int hf_docsis_tlv_cosign_cvc;
static int hf_docsis_tlv_vendor_id;
static int hf_docsis_tlv_sw_file;
static int hf_docsis_tlv_sw_upg_srvr;
static int hf_docsis_tlv_cpe_ethernet;
static int hf_docsis_tlv_modem_addr;
static int hf_docsis_tlv_rng_tech;
static int hf_docsis_tlv_subs_mgmt_ctrl;
static int hf_docsis_tlv_subs_mgmt_ip_table;
static int hf_docsis_tlv_subs_mgmt_ip_entry;
static int hf_docsis_tlv_subs_mgmt_filter_grps;
static int hf_docsis_tlv_snmpv3_ntfy_rcvr;
static int hf_docsis_tlv_enable_20_mode;
static int hf_docsis_tlv_enable_test_modes;
/* static int hf_docsis_tlv_ds_ch_list; */
static int hf_docsis_tlv_mc_mac_address;
/* static int hf_docsis_tlv_dut_filter; */
/* static int hf_docsis_tlv_tcc; */
/* static int hf_docsis_tlv_sid_cl; */
/* static int hf_docsis_tlv_rcp; */
/* static int hf_docsis_tlv_rcc; */
/* static int hf_docsis_tlv_dsid; */
/* static int hf_docsis_tlv_sec_assoc; */
static int hf_docsis_tlv_init_ch_timeout;
/* static int hf_docsis_tlv_ch_asgn; */
static int hf_docsis_tlv_cm_init_reason;
static int hf_docsis_tlv_sw_upg_srvr_ipv6;
static int hf_docsis_tlv_tftp_prov_cm_ipv6_addr;
static int hf_docsis_tlv_us_drop_clfy;
static int hf_docsis_tlv_subs_mgmt_ipv6_lst;
static int hf_docsis_tlv_us_drop_clfy_group_id;
static int hf_docsis_tlv_subs_mgmt_ctrl_max_cpe_ipv6;
/* static int hf_docsis_tlv_cmts_mc_sess_enc; */

static int hf_docsis_tlv_cos_id;
static int hf_docsis_tlv_cos_sid;
static int hf_docsis_tlv_cos_max_down;
static int hf_docsis_tlv_cos_max_up;
static int hf_docsis_tlv_cos_up_chnl_pri;
static int hf_docsis_tlv_cos_min_grntd_up;
static int hf_docsis_tlv_cos_max_up_burst;
static int hf_docsis_tlv_cos_privacy_enable;

static int hf_docsis_tlv_mcap_concat;
static int hf_docsis_tlv_mcap_docs_ver;
static int hf_docsis_tlv_mcap_frag;
static int hf_docsis_tlv_mcap_phs;
static int hf_docsis_tlv_mcap_igmp;
static int hf_docsis_tlv_mcap_down_said;
static int hf_docsis_tlv_mcap_up_sid;
static int hf_docsis_tlv_mcap_privacy;
static int hf_docsis_tlv_mcap_8021P_filter;
static int hf_docsis_tlv_mcap_8021Q_filter;
static int hf_docsis_tlv_mcap_xmit_eq_taps_per_sym;
static int hf_docsis_tlv_mcap_xmit_eq_taps;
static int hf_docsis_tlv_mcap_dcc;
static int hf_docsis_tlv_mcap_ip_filters;
static int hf_docsis_tlv_mcap_llc_filters;
static int hf_docsis_tlv_mcap_exp_unicast_sid;
static int hf_docsis_tlv_mcap_rnghoff_cm;
static int hf_docsis_tlv_mcap_rnghoff_erouter;
static int hf_docsis_tlv_mcap_rnghoff_emta;
static int hf_docsis_tlv_mcap_rnghoff_estb;
static int hf_docsis_tlv_mcap_l2vpn;
static int hf_docsis_tlv_mcap_l2vpn_esafe;
static int hf_docsis_tlv_mcap_dut_filtering;
static int hf_docsis_tlv_mcap_us_freq_range;
static int hf_docsis_tlv_mcap_us_srate_160;
static int hf_docsis_tlv_mcap_us_srate_320;
static int hf_docsis_tlv_mcap_us_srate_640;
static int hf_docsis_tlv_mcap_us_srate_1280;
static int hf_docsis_tlv_mcap_us_srate_2560;
static int hf_docsis_tlv_mcap_us_srate_5120;
static int hf_docsis_tlv_mcap_sac;
static int hf_docsis_tlv_mcap_code_hop_mode2;
static int hf_docsis_tlv_mcap_mtc;
static int hf_docsis_tlv_mcap_512_msps_utc;
static int hf_docsis_tlv_mcap_256_msps_utc;
static int hf_docsis_tlv_mcap_total_sid_cluster;
static int hf_docsis_tlv_mcap_sid_per_sf;
static int hf_docsis_tlv_mcap_mrc;
static int hf_docsis_tlv_mcap_total_dsid;
static int hf_docsis_tlv_mcap_reseq_dsid;
static int hf_docsis_tlv_mcap_mc_dsid;
static int hf_docsis_tlv_mcap_mc_dsid_fwd;
static int hf_docsis_tlv_mcap_fctype_fwd;
static int hf_docsis_tlv_mcap_dpv_path;
static int hf_docsis_tlv_mcap_dpv_packet;
static int hf_docsis_tlv_mcap_ugs;
static int hf_docsis_tlv_mcap_map_ucd;
static int hf_docsis_tlv_mcap_udc;
static int hf_docsis_tlv_mcap_ipv6;
static int hf_docsis_tlv_mcap_ext_us_trans_power;
static int hf_docsis_tlv_mcap_em;
static int hf_docsis_tlv_mcap_em_1x1;
static int hf_docsis_tlv_mcap_em_light_sleep;
static int hf_docsis_tlv_mcap_cm_status_ack;
static int hf_docsis_tlv_mcap_em_pref;
static int hf_docsis_tlv_mcap_em_pref_1x1;
static int hf_docsis_tlv_mcap_em_pref_dls;
static int hf_docsis_tlv_mcap_ext_pkt_len_sup_cap;
static int hf_docsis_tlv_mcap_ofdm_mult_recv_chan_sup;
static int hf_docsis_tlv_mcap_ofdma_mult_trans_chan_sup;
static int hf_docsis_tlv_mcap_down_ofdm_prof_sup;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_reserved;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_qpsk;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_16qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_64qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_128qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_256qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_512qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_1024qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_2048qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_4096qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_8192qam;
static int hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_16384qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_reserved;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_qpsk;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_8qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_16qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_32qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_64qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_128qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_256qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_512qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_1024qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_2048qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_4096qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_8192qam;
static int hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_16384qam;
static int hf_docsis_tlv_mcap_down_lower_band_edge_conf;
static int hf_docsis_tlv_mcap_down_lower_band_edge_conf_108;
static int hf_docsis_tlv_mcap_down_lower_band_edge_conf_258;
static int hf_docsis_tlv_mcap_down_upper_band_edge_conf;
static int hf_docsis_tlv_mcap_down_upper_band_edge_conf_1218;
static int hf_docsis_tlv_mcap_down_upper_band_edge_conf_1794;
static int hf_docsis_tlv_mcap_down_upper_band_edge_conf_1002;
static int hf_docsis_tlv_mcap_dipl_up_upper_band_edge_conf;
static int hf_docsis_tlv_mcap_docsis_time_prot_mode;
static int hf_docsis_tlv_mcap_docsis_time_prot_perf_sup;
static int hf_docsis_tlv_mcap_pmax;
static int hf_docsis_tlv_mcap_dipl_down_lower_band_edge;
static int hf_docsis_tlv_mcap_dipl_down_lower_band_edge_108;
static int hf_docsis_tlv_mcap_dipl_down_lower_band_edge_258;
static int hf_docsis_tlv_mcap_dipl_down_upper_band_edge;
static int hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1218;
static int hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1794;
static int hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1002;
static int hf_docsis_tlv_mcap_dipl_up_upper_band_edge;
static int hf_docsis_tlv_mcap_dipl_up_upper_band_edge_42;
static int hf_docsis_tlv_mcap_dipl_up_upper_band_edge_65;
static int hf_docsis_tlv_mcap_dipl_up_upper_band_edge_85;
static int hf_docsis_tlv_mcap_dipl_up_upper_band_edge_117;
static int hf_docsis_tlv_mcap_dipl_up_upper_band_edge_204;
static int hf_docsis_tlv_mcap_advanced_band_plan;
static int hf_docsis_tlv_mcap_advanced_band_plan_fdx_l;
static int hf_docsis_tlv_mcap_advanced_band_plan_fdx;
static int hf_docsis_tlv_mcap_advanced_band_plan_fdd;
static int hf_docsis_tlv_mcap_advanced_band_plan_reserved;
static int hf_docsis_tlv_mcap_ext_sf_cluster_assign_sup;
static int hf_docsis_tlv_mcap_low_latency_sup;
static int hf_docsis_tlv_mcap_adv_down_lower_band_edge_conf;
static int hf_docsis_tlv_mcap_adv_down_upper_band_edge_conf;
static int hf_docsis_tlv_mcap_adv_up_upper_band_edge_conf;
static int hf_docsis_tlv_mcap_adv_down_lower_band_edge_option;
static int hf_docsis_tlv_mcap_adv_down_upper_band_edge_option;
static int hf_docsis_tlv_mcap_adv_up_upper_band_edge_option;
static int hf_docsis_tlv_mcap_extended_power_options;

static int hf_docsis_tlv_clsfr_ref;
static int hf_docsis_tlv_clsfr_id;
static int hf_docsis_tlv_clsfr_sflow_ref;
static int hf_docsis_tlv_clsfr_sflow_id;
static int hf_docsis_tlv_clsfr_rule_pri;
static int hf_docsis_tlv_clsfr_act_state;
static int hf_docsis_tlv_clsfr_dsc_act;
/* static int hf_docsis_tlv_clsfr_err; */
/* static int hf_docsis_tlv_ipclsfr; */
/* static int hf_docsis_tlv_ethclsfr; */
/* static int hf_docsis_tlv_dot1qclsfr; */

static int hf_docsis_tlv_clsfr_vendor_spc;

static int hf_docsis_tlv_clsfr_err_param;
static int hf_docsis_tlv_clsfr_err_code;
static int hf_docsis_tlv_clsfr_err_msg;

static int hf_docsis_tlv_ipclsfr_tosmask;
static int hf_docsis_tlv_ipclsfr_ipproto;
static int hf_docsis_tlv_ipclsfr_src;
static int hf_docsis_tlv_ipclsfr_dst;
static int hf_docsis_tlv_ipclsfr_srcmask;
static int hf_docsis_tlv_ipclsfr_dstmask;
static int hf_docsis_tlv_ipclsfr_sport_start;
static int hf_docsis_tlv_ipclsfr_sport_end;
static int hf_docsis_tlv_ipclsfr_dport_start;
static int hf_docsis_tlv_ipclsfr_dport_end;

static int hf_docsis_tlv_ip6clsfr_tc_low;
static int hf_docsis_tlv_ip6clsfr_tc_high;
static int hf_docsis_tlv_ip6clsfr_tc_mask;
static int hf_docsis_tlv_ip6clsfr_flow_label;
static int hf_docsis_tlv_ip6clsfr_next_header;
static int hf_docsis_tlv_ip6clsfr_src;
static int hf_docsis_tlv_ip6clsfr_src_prefix_length;
static int hf_docsis_tlv_ip6clsfr_dst;
static int hf_docsis_tlv_ip6clsfr_dst_prefix_length;

static int hf_docsis_tlv_ethclsfr_dmac;
static int hf_docsis_tlv_ethclsfr_smac;
static int hf_docsis_tlv_ethclsfr_ethertype;

static int hf_docsis_tlv_dot1qclsfr_user_pri;
static int hf_docsis_tlv_dot1qclsfr_vlanid;
static int hf_docsis_tlv_dot1qclsfr_vendorspec;

static int hf_docsis_tlv_sflow_ref;
static int hf_docsis_tlv_sflow_id;
static int hf_docsis_tlv_sflow_sid;
static int hf_docsis_tlv_sflow_classname;
static int hf_docsis_tlv_sflow_qos_param;
/* static int hf_docsis_tlv_sflow_err; */
static int hf_docsis_tlv_sflow_traf_pri;
static int hf_docsis_tlv_sflow_max_sus;
static int hf_docsis_tlv_sflow_max_burst;
static int hf_docsis_tlv_sflow_min_traf;
static int hf_docsis_tlv_sflow_ass_min_pkt_size;
static int hf_docsis_tlv_sflow_timeout_active;
static int hf_docsis_tlv_sflow_timeout_admitted;
static int hf_docsis_tlv_sflow_peak_traffic_rate;
static int hf_docsis_tlv_sflow_req_attr_mask;
static int hf_docsis_tlv_sflow_forb_attr_mask;
static int hf_docsis_tlv_sflow_attr_aggr_rule_mask;
static int hf_docsis_tlv_sflow_vendor_spec;
static int hf_docsis_tlv_sflow_max_concat_burst;
static int hf_docsis_tlv_sflow_sched_type;
static int hf_docsis_tlv_sflow_reqxmit_pol;
static int hf_docsis_tlv_sflow_reqxmit_all_cm_broadcast;
static int hf_docsis_tlv_sflow_reqxmit_priority_multicast;
static int hf_docsis_tlv_sflow_reqxmit_req_data_requests;
static int hf_docsis_tlv_sflow_reqxmit_req_data_data;
static int hf_docsis_tlv_sflow_reqxmit_piggy_back;
static int hf_docsis_tlv_sflow_reqxmit_concatenate_data;
static int hf_docsis_tlv_sflow_reqxmit_fragment;
static int hf_docsis_tlv_sflow_reqxmit_suppress_payload;
static int hf_docsis_tlv_sflow_reqxmit_drop_packets;
static int hf_docsis_tlv_sflow_nominal_polling;
static int hf_docsis_tlv_sflow_tolerated_jitter;
static int hf_docsis_tlv_sflow_ugs_size;
static int hf_docsis_tlv_sflow_nom_grant_intvl;
static int hf_docsis_tlv_sflow_tol_grant_jitter;
static int hf_docsis_tlv_sflow_grants_per_intvl;
static int hf_docsis_tlv_sflow_ip_tos_overwrite;
static int hf_docsis_tlv_sflow_ugs_timeref;
static int hf_docsis_tlv_sflow_cont_req_backoff_window_mult;
static int hf_docsis_tlv_sflow_num_of_bytes_requested_mult;
static int hf_docsis_tlv_sflow_max_down_latency;
static int hf_docsis_tlv_sflow_down_reseq;

static int hf_docsis_tlv_sflow_err_param;
static int hf_docsis_tlv_sflow_err_code;
static int hf_docsis_tlv_sflow_err_msg;

static int hf_docsis_tlv_phs_class_ref;
static int hf_docsis_tlv_phs_class_id;
static int hf_docsis_tlv_phs_sflow_ref;
static int hf_docsis_tlv_phs_sflow_id;
static int hf_docsis_tlv_phs_dsc_action;
/* static int hf_docsis_tlv_phs_err; */
static int hf_docsis_tlv_phs_phsf;
static int hf_docsis_tlv_phs_phsm;
/* static int hf_docsis_tlv_phs_phsv; */
static int hf_docsis_tlv_phs_phsi;
static int hf_docsis_tlv_phs_phss;
static int hf_docsis_tlv_phs_dbc_action;
static int hf_docsis_tlv_phs_vendorspec;

static int hf_docsis_tlv_phs_err_param;
static int hf_docsis_tlv_phs_err_code;
static int hf_docsis_tlv_phs_err_msg;

/* static int hf_docsis_tlv_ds_ch_list_single; */
/* static int hf_docsis_tlv_ds_ch_list_range; */
static int hf_docsis_tlv_ds_ch_list_default_timeout;

static int hf_docsis_tlv_single_ch_timeout;
static int hf_docsis_tlv_single_ch_freq;

static int hf_docsis_tlv_freq_rng_timeout;
static int hf_docsis_tlv_freq_rng_start;
static int hf_docsis_tlv_freq_rng_end;
static int hf_docsis_tlv_freq_rng_step;

static int hf_docsis_tlv_dut_filter_control;
static int hf_docsis_tlv_dut_filter_cmim;

static int hf_docsis_tlv_tcc_refid;
static int hf_docsis_tlv_tcc_us_ch_action;
static int hf_docsis_tlv_tcc_us_ch_id;
static int hf_docsis_tlv_tcc_new_us_ch_id;
static int hf_docsis_tlv_tcc_ucd;
static int hf_docsis_tlv_tcc_rng_sid;
static int hf_docsis_tlv_tcc_init_tech;
/* static int hf_docsis_tlv_tcc_rng_parms; */
static int hf_docsis_tlv_tcc_dyn_rng_win;
static int hf_docsis_tlv_tcc_p_16hi;
static int hf_docsis_tlv_tcc_oudp_iuc;
static int hf_docsis_tlv_tcc_extended_drw;
static int hf_docsis_tlv_tcc_extended_us_rng_pwr;
static int hf_docsis_tlv_tcc_oudp_sounding_sid;
/* static int hf_docsis_tlv_tcc_err; */

static int hf_docsis_rng_parms_us_ch_id;
static int hf_docsis_rng_parms_time_off_int;
static int hf_docsis_rng_parms_time_off_frac;
static int hf_docsis_rng_parms_power_off;
static int hf_docsis_rng_parms_freq_off;

static int hf_docsis_tcc_err_subtype;
static int hf_docsis_tcc_err_code;
static int hf_docsis_tcc_err_msg;

static int hf_docsis_sid_cl_sf_id;
/* static int hf_docsis_sid_cl_enc; */
/* static int hf_docsis_sid_cl_so_crit; */

static int hf_docsis_sid_cl_enc_id;
/* static int hf_docsis_sid_cl_enc_map; */

static int hf_docsis_sid_cl_map_us_ch_id;
static int hf_docsis_sid_cl_map_sid;
static int hf_docsis_sid_cl_map_action;

static int hf_docsis_sid_cl_so_max_req;
static int hf_docsis_sid_cl_so_max_out_bytes;
static int hf_docsis_sid_cl_so_max_req_bytes;
static int hf_docsis_sid_cl_so_max_time;

static int hf_docsis_tlv_rcp_id;
static int hf_docsis_tlv_rcp_name;
static int hf_docsis_tlv_rcp_freq_spc;
/* static int hf_docsis_tlv_rcp_rcv_mod_enc; */
/* static int hf_docsis_tlv_rcp_rcv_ch; */
/* static int hf_docsis_tlv_rcp_ven_spec; */

static int hf_docsis_rcv_mod_enc_idx;
static int hf_docsis_rcv_mod_enc_adj_ch;
/* static int hf_docsis_rcv_mod_enc_ch_bl_rng; */
static int hf_docsis_rcv_mod_enc_ctr_freq_asgn;
static int hf_docsis_rcv_mod_enc_rsq_ch_subs_cap;
static int hf_docsis_rcv_mod_enc_conn;
static int hf_docsis_rcv_mod_enc_phy_layr_parms;

static int hf_docsis_rcc_rcv_mod_enc_idx;
static int hf_docsis_rcc_rcv_mod_enc_ctr_freq_asgn;
static int hf_docsis_rcc_rcv_mod_enc_conn;

static int hf_docsis_ch_bl_rng_min_ctr_freq;
static int hf_docsis_ch_bl_rng_max_ctr_freq;

static int hf_docsis_rcv_ch_idx;
static int hf_docsis_rcv_ch_conn;
static int hf_docsis_rcv_ch_conn_off;
static int hf_docsis_rcv_ch_prim_ds_ch_ind;

static int hf_docsis_rcc_rcv_ch_idx;
static int hf_docsis_rcc_rcv_ch_conn;
static int hf_docsis_rcc_rcv_ch_ctr_freq_asgn;
static int hf_docsis_rcc_rcv_ch_prim_ds_ch_ind;

static int hf_docsis_tlv_rcc_id;
static int hf_docsis_tlv_rcc_partial_serv_down_chan_id;
static int hf_docsis_tlv_rcc_srcc_prim_ds_chan_assign_ds_ch_id;
static int hf_docsis_tlv_rcc_srcc_ds_chan_assign_ds_ch_id;
static int hf_docsis_tlv_rcc_srcc_ds_prof_assign_dcid;
static int hf_docsis_tlv_rcc_srcc_ds_prof_asssign_prof_list_prof_id;
static int hf_docsis_tlv_rcc_prim_down_chan;
/* static int hf_docsis_tlv_rcc_rcv_mod_enc; */
/* static int hf_docsis_tlv_rcc_rcv_ch; */
/* static int hf_docsis_tlv_rcc_part_serv_ds_ch; */
/* static int hf_docsis_tlv_rcc_ven_spec; */
/* static int hf_docsis_tlv_rcc_err; */

static int hf_docsis_tlv_rcc_err_mod_or_ch;
static int hf_docsis_tlv_rcc_err_idx;
static int hf_docsis_tlv_rcc_err_param;
static int hf_docsis_tlv_rcc_err_code;
static int hf_docsis_tlv_rcc_err_msg;

static int hf_docsis_tlv_dsid_id;
static int hf_docsis_tlv_dsid_action;
/* static int hf_docsis_tlv_dsid_ds_reseq; */
/* static int hf_docsis_tlv_dsid_mc; */

static int hf_docsis_ds_reseq_dsid;
static int hf_docsis_ds_reseq_ch_lst;
static int hf_docsis_ds_reseq_wait_time;
static int hf_docsis_ds_reseq_warn_thresh;
static int hf_docsis_ds_reseq_ho_timer;

/* static int hf_docsis_tlv_dsid_mc_addr; */
static int hf_docsis_tlv_dsid_mc_cmim;
static int hf_docsis_tlv_dsid_mc_group;
/* static int hf_docsis_tlv_dsid_mc_phs; */

static int hf_docsis_mc_addr_action;
static int hf_docsis_mc_addr_addr;

static int hf_docsis_tlv_sec_assoc_action;
static int hf_docsis_tlv_sec_assoc_desc;

static int hf_docsis_ch_asgn_us_ch_id;
static int hf_docsis_ch_asgn_rx_freq;

static int hf_docsis_cmts_mc_sess_enc_grp;
static int hf_docsis_cmts_mc_sess_enc_src;
static int hf_docsis_cmts_mc_sess_enc_cmim;

static int hf_docsis_tlv_em_mode_ind;

static int hf_docsis_tlv_em_id_list_for_cm_em_id;

static int hf_docsis_tlv_fdx_reset;

static int hf_docsis_tlv_fdx_tg_assignment_tg_id;
static int hf_docsis_tlv_fdx_tg_assignment_rba_type;

static int hf_docsis_tlv_unknown;
static int hf_docsis_tlv_unknown_type;
static int hf_docsis_tlv_unknown_length;
static int hf_docsis_tlv_unknown_value;


static int hf_docsis_ucd_fragments;
static int hf_docsis_ucd_fragment;
static int hf_docsis_ucd_fragment_overlap;
static int hf_docsis_ucd_fragment_overlap_conflict;
static int hf_docsis_ucd_fragment_multiple_tails;
static int hf_docsis_ucd_fragment_too_long_fragment;
static int hf_docsis_ucd_fragment_error;
static int hf_docsis_ucd_fragment_count;
static int hf_docsis_ucd_reassembled_in;
static int hf_docsis_ucd_reassembled_length;
static int hf_docsis_ucd_reassembled_data;

static int hf_docsis_ucd_reassembled;


/* Initialize the subtree pointers */
static int ett_docsis_tlv;
static int ett_docsis_tlv_cos;
static int ett_docsis_tlv_mcap;
static int ett_docsis_tlv_mcap_em;
static int ett_docsis_tlv_mcap_em_pref;
static int ett_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup;
static int ett_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup;
static int ett_docsis_tlv_mcap_down_lower_band_edge_conf;
static int ett_docsis_tlv_mcap_down_upper_band_edge_conf;
static int ett_docsis_tlv_mcap_dipl_down_lower_band_edge;
static int ett_docsis_tlv_mcap_dipl_down_upper_band_edge;
static int ett_docsis_tlv_mcap_dipl_up_upper_band_edge;
static int ett_docsis_tlv_mcap_advanced_band_plan;
static int ett_docsis_tlv_mcap_dipl_down_lower_band_edge_options_list;
static int ett_docsis_tlv_mcap_dipl_down_upper_band_edge_options_list;
static int ett_docsis_tlv_mcap_dipl_up_upper_band_edge_options_list;
static int ett_docsis_tlv_clsfr;
static int ett_docsis_tlv_clsfr_ip;
static int ett_docsis_tlv_clsfr_ip6;
static int ett_docsis_tlv_clsfr_ip6_tc;
static int ett_docsis_tlv_clsfr_eth;
static int ett_docsis_tlv_clsfr_err;
static int ett_docsis_tlv_phs;
static int ett_docsis_tlv_phs_err;
static int ett_docsis_tlv_clsfr_dot1q;
static int ett_docsis_tlv_reqxmitpol;
static int ett_docsis_tlv_sflow_err;
static int ett_docsis_tlv_svc_unavail;
static int ett_docsis_tlv_snmpv3_kick;
static int ett_docsis_tlv_ds_ch_list;
static int ett_docsis_tlv_ds_ch_list_single;
static int ett_docsis_tlv_ds_ch_list_range;
static int ett_docsis_tlv_ext_field;
static int ett_docsis_tlv_vendor_specific_cap;
static int ett_docsis_tlv_dut_filter;
static int ett_docsis_tlv_tcc;
static int ett_docsis_tlv_tcc_ucd;
static int ett_docsis_tlv_tcc_rng_parms;
static int ett_docsis_tlv_tcc_oudp;
static int ett_docsis_tlv_tcc_err;
static int ett_docsis_tlv_sid_cl;
static int ett_docsis_tlv_sid_cl_enc;
static int ett_docsis_tlv_sid_cl_enc_map;
static int ett_docsis_tlv_sid_cl_so;
static int ett_docsis_tlv_rcp;
static int ett_docsis_tlv_rcp_rcv_mod_enc;
static int ett_docsis_tlv_rcp_ch_bl_rng;
static int ett_docsis_tlv_rcp_rcv_ch;
static int ett_docsis_tlv_rcc;
static int ett_docsis_tlv_rcc_rcv_mod_enc;
static int ett_docsis_tlv_rcc_rcv_ch;
static int ett_docsis_tlv_rcc_partial_serv_down_chan;
static int ett_docsis_tlv_rcc_srcc;
static int ett_docsis_tlv_rcc_srcc_prim_ds_assign;
static int ett_docsis_tlv_rcc_srcc_ds_assign;
static int ett_docsis_tlv_rcc_srcc_ds_prof_assign;
static int ett_docsis_tlv_rcc_srcc_ds_prof_assign_prof_list;
static int ett_docsis_tlv_rcc_err;
static int ett_docsis_tlv_dsid;
static int ett_docsis_tlv_dsid_ds_reseq;
static int ett_docsis_tlv_dsid_mc;
static int ett_docsis_tlv_dsid_mc_addr;
static int ett_docsis_tlv_sec_assoc;
static int ett_docsis_tlv_ch_asgn;
static int ett_docsis_cmts_mc_sess_enc;
static int ett_docsis_em_id_list_for_cm;
static int ett_docsis_tlv_tg_assignment;
static int ett_docsis_tlv_unknown;
static int ett_docsis_ucd_fragments;
static int ett_docsis_ucd_fragment;
static int ett_docsis_ucd_reassembled;


static expert_field ei_docsis_tlv_tlvlen_bad;
static expert_field ei_docsis_tlv_tlvval_bad;


static const true_false_string ena_dis_tfs = {
  "Enable",
  "Disable"
};

static const value_string sup_unsup_vals[] = {
  {0, "Unsupported"},
  {1, "Supported"},
  {0, NULL},
};

static const true_false_string sup_unsup_tfs = {
  "Supported",
  "Unsupported"
};

static const value_string docs_ver_vals[] = {
  {0, "v1.0"},
  {1, "v1.1"},
  {2, "v2.0"},
  {3, "v3.0"},
  {4, "v3.1"},
  {5, "v4.0"},
  {0, NULL},
};

static const value_string dsc_act_vals[] = {
  {0, "DSC Add Classifier"},
  {1, "DSC Replace Classifier"},
  {2, "DSC Delete Classifier"},
  {0, NULL},
};

static const value_string qos_param_vals[] = {
  {0x01, "Apply to provisioned set only"},
  {0x02, "Perform admission control add apply to admitted set"},
  {0x03, "Apply to provisioned and admitted set; Perform admission control"},
  {0x04, "Perform admission control if needed and apply to active set"},
  {0x05,
   "Apply to provisioned and active sets; Admission control on admitted set in separate service flow, and activate service flow"},
  {0x06,
   "Perform admission control and activate; Apply to admitted and active sets"},
  {0x07,
   "Apply to Provisioned, Active and Admitted Sets; Admission Control and Activate Service Flow"},
  {0, NULL},
};

static const value_string sched_type_vals[] = {
  {0, "Reserved"},
  {1, "Undefined (CMTS Dependent)"},
  {2, "Best Effort Service"},
  {3, "Non-Real-Time Polling Service"},
  {4, "Real-Time Polling Service"},
  {5, "Unsolicited Grant Service w/Activity Detection"},
  {6, "Unsolicited Grant Service"},
  {0, NULL},
};

static const value_string action_vals[] = {
  {0, "Add PHS Rule"},
  {1, "Set PHS Rule"},
  {2, "Delete PHS Rule"},
  {3, "Delete all PHS Rules"},
  {0, NULL},
};

static const value_string dbc_action_vals[] = {
  {0, "Add PHS Rule"},
  {1, "Delete PHS Rule"},
  {0, NULL},
};

#if 0
static const true_false_string verify_tfs = {
  "Don't Verify",
  "Verify"
};
#endif

static const value_string rng_tech_vals[] = {
  {0, "Perform initial maintenance on new channel"},
  {1, "Perform only station maintenance on new channel"},
  {2, "Perform either initial maintenance or station maintenance on new channel"},
  {3, "Use the new channel directly without performing initial or station maintenance"},
  {0, NULL},
};


static const value_string docsis_conf_code[] = {
  {  0, "okay/success"},
  {  1, "Reject: Other/Auth failure (1.0)"},
  {  2, "Reject: Unrecognized configuration setting/COS failure (1.0)"},
  {  3, "Reject: Temporary/Reject resource"},
  {  4, "Reject: Permanent/Reject admin"},
  {  5, "Reject: Not owner"},
  {  6, "Reject: Service flow not found"},
  {  7, "Reject: Service flow exists"},
  {  8, "Reject: Required parameter not present"},
  {  9, "Reject: Header suppression"},
  { 10, "Reject: Unknown transaction ID"},
  { 11, "Reject: Authentication failure"},
  { 12, "Reject: Add aborted"},
  { 13, "Reject: Multiple errors"},
  { 14, "Reject: Classifier not found"},
  { 15, "Reject: Classifier exists"},
  { 16, "Reject: PHS rule not found"},
  { 17, "Reject: PHS rule exists"},
  { 18, "Reject: Duplicate reference ID or index in message"},
  { 19, "Reject: Multiple upstream service flows"},
  { 20, "Reject: Multiple downstream service flows"},
  { 21, "Reject: Classifier for another service flow"},
  { 22, "Reject: PHS for another service flow"},
  { 23, "Reject: Parameter invalid for context"},
  { 24, "Reject: Authorization failure"},
  { 25, "Reject: Temporary DCC"},
  { 26, "Reject: Downstream Inconsistency"},
  { 27, "Reject: Upstream Inconsistency"},
  { 28, "Reject: Insufficient SID Cluster Resources"},
  { 29, "Reject: Missing RCP"},
  { 30, "Partial Service"},
  { 31, "Reject: Temporary DBC"},
  { 32, "Reject: Unknown DSID"},
  { 33, "Reject: Unknown SID Cluster"},
  { 34, "Reject: Invalid Initialization Technique"},
  { 35, "Reject: No Change"},
  { 36, "Reject: Invalid DBC Request"},
  { 37, "Reject: Mode Switch"},
  { 38, "Reject: Insufficient Transmitters"},
  { 40, "Reject: Insufficient DSID Resources"},
  { 41, "Reject: Invalid DSID Encoding"},
  { 42, "Reject: Unknown Client MAC Address"},
  { 43, "Reject: Unknown SAID"},
  { 44, "Reject: Insufficient SA Resources"},
  { 45, "Reject: Invalid SA Encoding"},
  { 46, "Reject: Invalid SA Crypto Suite"},
  { 47, "Reject: TEK Exists"},
  { 48, "Reject: Invalid SID Cluster Encoding"},
  { 49, "Reject: Insufficient SID Resources"},
  { 50, "Reject: Unsupported Parameter Change"},
  { 51, "Reject: PHS Rule Fully Defined"},
  { 52, "Reject: No MAPs Or UCDs"},
  { 53, "Error: T3 Retries Exceeded"},
  { 54, "Error: T2 Timeout"},
  { 55, "Error: T4 Timeout"},
  { 56, "Error: Ranging Abort"},
  { 57, "Error: Initialization Channel Timeout"},
  { 58, "Error: DBC-REQ Incomplete"},
  { 59, "Reject: Too Many OFDMA Profiles"},
  { 60, "Reject: Too Many OFDM Profiles"},
  { 61, "Reject: EM Incorrect Primary DS"},
  { 62, "Reject: AQM Not Supported"},
  { 63, "Reject: Invalid DPD"},
  {100, "Reject: VLAD ID In Use"},
  {101, "Reject: Multipoint L2VPN"},
  {102, "Reject: Multipoint NSI"},
  {160, "Reject: Unknown RCP ID"},
  {161, "Reject: Multiple RCP IDs"},
  {162, "Reject: Missing Receive Module Index"},
  {163, "Reject: Invalid Receive Module Index"},
  {164, "Reject: Invalid Receive Channel Center Frequency"},
  {165, "Reject: Invalid Receive Module First Channel Center Frequency"},
  {166, "Reject: Missing Receive Module First Channel Center Frequency"},
  {167, "Reject: No Primary Downstream Channel Assigned"},
  {168, "Reject: Multiple Primary Downstream Channel Assigned"},
  {169, "Reject: Receive Module Connectivity Error"},
  {170, "Reject: Invalid Receive Channel Index"},
  {171, "Reject: Center Frequency Not Multiple of 62500 Hz"},
  {180, "Depart"},
  {181, "Arrive"},
  {182, "Reject: Already There"},
  {183, "Reject: Reject 2.0 Disable"},
  {200, "Reject: Major Service Flow Error"},
  {201, "Reject: Major Classifier Error"},
  {202, "Reject: Major PHS Rule Error"},
  {203, "Reject: Multiple Major Errors"},
  {204, "Reject: Message Syntax Error"},
  {205, "Reject: Primary Service Flow Error"},
  {206, "Reject: Message Too Big"},
  {207, "Reject: Invalid Modem Capabilities"},
  {208, "Reject: Bad RCC"},
  {209, "Reject: Bad TCC"},
  {210, "Reject: Dynamic Range Window Violation"},
  {211, "Reject: Unable to support Queue Depth"},
  {212, "Reject: Energy Management Parameters"},
  {213, "Reject: Invalid Backup Primary Downstream"},
  {0, NULL}
};

value_string_ext docsis_conf_code_ext = VALUE_STRING_EXT_INIT(docsis_conf_code);

static const value_string next_header_vals[] = {
  {0, "Hop-by-Hop"},
  {60, "Destination"},
  {43, "Routing"},
  {44, "Fragment"},
  {51, "Authentication"},
  {50, "Encapsulation"},
  {59, "No"},
  {256, "All IPv6 Traffic"},
  {257, "All UDP and TCP Traffic"},
  {0, NULL},
};

static const value_string us_ch_action_vals[] = {
  {0, "No Action"},
  {1, "Add"},
  {2, "Change"},
  {3, "Delete"},
  {4, "Replace"},
  {5, "Re-range"},
  {0, NULL},
};

static const value_string init_tech_vals[] = {
  {0, "reserved"},
  {1, "Perform broadcast initial ranging before normal ops"},
  {2, "Perform unicast ranging before normal ops"},
  {3, "Perform either broadcast or unicast ranging before normal ops"},
  {4, "Use new channel directly without reinitializing or ranging"},
  {5, "Perform probing before normal ops"},
  {6, "Perform unicast initial ranging before normal ops"},
  {7, "Perform station ranging before normal ops"},
  {8, "Use FDX channel directly"},
  {0, NULL},
};

static const value_string sid_ch_map_vals[] = {
  {0, "reserved"},
  {1, "Add"},
  {2, "Delete"},
  {0, NULL},
};

static const value_string mod_or_ch_vals[] = {
  {0, "reserved"},
  {1, "reserved"},
  {2, "reserved"},
  {3, "reserved"},
  {4, "Receive Module"},
  {5, "Receive Channel"},
  {0, NULL},
};

static const value_string dsid_action_vals[] = {
  {0, "Add"},
  {1, "Change"},
  {2, "Delete"},
  {0, NULL},
};

static const value_string add_del_vals[] = {
  {0, "Add"},
  {1, "Delete"},
  {0, NULL},
};

static const value_string init_reason_vals[] = {
  { 0, "reserved"},
  { 1, "Power On"},
  { 2, "T17 Lost Sync"},
  { 3, "All Upstream Failed"},
  { 4, "Bad DHCP Ack"},
  { 5, "Link Local Address in use"},
  { 6, "T6 Expired"},
  { 7, "REG-RSP not ok"},
  { 8, "BAD RCC/TCC"},
  { 9, "Failed Primary Downstream"},
  {10, "TCS failed on all upstreams"},
  {11, "reserved"},
  {12, "reserved"},
  {13, "reserved"},
  {14, "reserved"},
  {15, "MTCM Change"},
  {16, "T4 Expired"},
  {17, "No Primary SF on US Channel"},
  {18, "CM Control Init"},
  {19, "Dynamic Range Window Violation"},
  {20, "IP Provisioning Mode Override"},
  {21, "SW Upgrade Reboot"},
  {22, "SNMP Reset"},
  {23, "REG-RSP Missing RCC"},
  {24, "REG-RSP Missing TCC"},
  {25, "REG-RSP MTC Not Enabled"},
  {26, "DHCPv6 Bad Reply"},
  {27, "Reset Due To Diplexer Change"},
  {0, NULL},
};

static const value_string docsis_freq_rng_vals[] = {
  {0, "Standard Upstream Frequency Range (5-42 MHz)"},
  {1, "Selectable Between Standard (5-42 MHz) and Extended (5-85 MHz) Upstream Frequency Range"},
  {2, "Extended Upstream Frequency Range (5-85 MHz)"},
  {0, NULL},
};

static const value_string mc_dsid_fwd_vals[] = {
  {0, "No support for multicast DSID forwarding"},
  {1, "Support for GMAC explicit multicast DSID forwarding"},
  {2, "Support for GMAC promiscuous multicast DSID forwarding"},
  {0, NULL},
};

static const value_string fctype_fwd_vals[] = {
  {0, "Isolation Packet PDU Header (FC_Type of 10) is not forwarded"},
  {1, "Isolation Packet PDU Header (FC_Type of 10) is forwarded"},
  {0, NULL},
};

static const value_string em_mode_ind_vals[] = {
  {0, "Do not operate in any Energy Management Mode"},
  {1, "Operate in Energy Management 1x1 Mode"},
  {2, "Operate in DOCSIS Light Sleep (DLS) Mode"},
  {0, NULL},
};

static const value_string down_reseq_vals[] = {
  {0, "The CMTS is required to associate this service flow with a resequencing DSID if the service flow is assigned to a downstream bonding group."},
  {1, "The CMTS is required to not associate this service flow with a resequencing DSID."},
  {0, NULL},
};

static const value_string dipl_up_upper_band_edge_conf_vals[] = {
  {0, "Upstream Frequency Range up to 42 MHz"},
  {1, "Upstream Frequency Range up to 65 MHz"},
  {2, "Upstream Frequency Range up to 85 MHz"},
  {3, "Upstream Frequency Range up to 117 MHz"},
  {4, "Upstream Frequency Range up to 204 MHz"},
  {0, NULL},
};

static const value_string docsis_time_prot_mode_vals[] = {
  {0, "DTP operation is not supported"},
  {1, "DTP Slave capable only"},
  {2, "DTP Master capable only"},
  {3, "DTP Master or Slave capable"},
  {0, NULL},
};

static const value_string docsis_time_prot_perf_sup_vals[] = {
  {0, "DTP mode is not supported"},
  {1, "DTP support for DTP Level 1"},
  {2, "DTP support for DTP Level 2"},
  {3, "DTP support for DTP Level 3"},
  {4, "DTP support for DTP Level 4"},
  {5, "DTP support for DTP Level 5"},
  {6, "DTP supported but with no specified performance"},
  {0, NULL},
};

static const value_string rba_type_vals[] = {
  {0, "Use RBA-SW"},
  {1, "Use RBA-HW"},
  {0, NULL},
};

static const value_string fdx_reset_vals[] = {
  {0, "Do not reset FDX state"},
  {1, "Reset FDX state and restart FDX initialization"},
  {0, NULL},
};

static const value_string docsis_mcap_ext_sf_cluster_assign_sup_vals[] = {
  {0, "No support"},
  {1, "Support available"},
  {0, NULL},
};

static const value_string extended_power_options_vals[] = {
  {0, "No battery backup"},
  {1, "Battery backup"},
  {2, "Modem capacitance"},
  {0, NULL},
};

static void
fourth_db(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%.2f dB", value/4.0);
}

static void
fourth_dbmv(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%.2f dBmV", value/4.0);
}

static reassembly_table ucd_reassembly_table;

static const fragment_items ucd_frag_items = {
  &ett_docsis_ucd_fragment,
  &ett_docsis_ucd_fragments,
  &hf_docsis_ucd_fragments,
  &hf_docsis_ucd_fragment,
  &hf_docsis_ucd_fragment_overlap,
  &hf_docsis_ucd_fragment_overlap_conflict,
  &hf_docsis_ucd_fragment_multiple_tails,
  &hf_docsis_ucd_fragment_too_long_fragment,
  &hf_docsis_ucd_fragment_error,
  &hf_docsis_ucd_fragment_count,
  &hf_docsis_ucd_reassembled_in,
  &hf_docsis_ucd_reassembled_length,
  &hf_docsis_ucd_reassembled_data,
  "UCD fragments"
};


/* Dissection */
static void
dissect_unknown_tlv(tvbuff_t * tvb, packet_info *pinfo, proto_tree * tree, int start, uint16_t len) {
  unsigned type, length;
  proto_tree * unknown_tree;
  proto_item * unknown_item;

  unknown_item = proto_tree_add_item(tree, hf_docsis_tlv_unknown, tvb, start, len, ENC_NA);
  unknown_tree = proto_item_add_subtree(unknown_item, ett_docsis_tlv_unknown);

  if (len < 2)
    {
      expert_add_info_format(pinfo, unknown_item, &ei_docsis_tlv_tlvlen_bad, "Unknown TLV: total length < 2: %u", len);
      return;
    }

  proto_tree_add_item_ret_uint (unknown_tree, hf_docsis_tlv_unknown_type, tvb, start, 1, ENC_BIG_ENDIAN, &type);
  proto_tree_add_item_ret_uint (unknown_tree, hf_docsis_tlv_unknown_length, tvb, start + 1, 1, ENC_BIG_ENDIAN, &length);

  proto_item_append_text(unknown_item," (Type: %d, Length: %d)", type, length);

  if (length + 2 != len)
    {
      expert_add_info_format(pinfo, unknown_item, &ei_docsis_tlv_tlvlen_bad, "Unknown TLV: Wrong TLV length: %u", length);
      return;
    }

  proto_tree_add_item (unknown_tree, hf_docsis_tlv_unknown_value, tvb, start + 2, len - 2, ENC_NA);
}

static void
dissect_phs_err (tvbuff_t * tvb, packet_info *pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *err_tree;
  proto_item *err_item;
  int pos = start;

  err_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_sflow_err, &err_item,
                                  "5 Service Flow Error Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case PHS_ERR_PARAM:
            if (length == 1)
              {
                proto_tree_add_item (err_tree, hf_docsis_tlv_phs_err_param, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_ERR_CODE:
            if (length == 1)
              {
                proto_tree_add_item (err_tree, hf_docsis_tlv_phs_err_code, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_ERR_MSG:
            proto_tree_add_item (err_tree, hf_docsis_tlv_phs_err_msg, tvb, pos,
                                 length, ENC_ASCII);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, err_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_phs (tvbuff_t * tvb, packet_info *pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *phs_tree;
  proto_item *phs_item;
  int pos = start;

  phs_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_phs, &phs_item,
                                  "26 PHS Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case PHS_CLSFR_REF:
            if (length == 1)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_class_ref, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_CLSFR_ID:
            if (length == 2)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_class_id, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_SFLOW_REF:
            if (length == 2)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_sflow_ref, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_SFLOW_ID:
            if (length == 4)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_sflow_id, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_DSC_ACTION:
            if (length == 1)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_dsc_action,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_ERRORS:
            dissect_phs_err (tvb, pinfo, phs_tree, pos, length);
            break;
          case PHS_FIELD:
            proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phsf, tvb, pos,
                                 length, ENC_NA);
            break;
          case PHS_INDEX:
            if (length == 1)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phsi, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_MASK:
            proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phsm, tvb, pos,
                                 length, ENC_NA);
            break;
          case PHS_SUP_SIZE:
            if (length == 1)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phss, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_VERIFICATION:
            if (length == 1)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_phsf, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_DBC_ACTION:
            if (length == 1)
              {
                proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_dbc_action, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, phs_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case PHS_VENDOR_SPEC:
            proto_tree_add_item (phs_tree, hf_docsis_tlv_phs_vendorspec, tvb,
                                 pos, length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, phs_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static const true_false_string tfs_must_not_must = { "MUST NOT", "MUST" };
static const true_false_string tfs_must_must_not = { "MUST", "MUST NOT" };

static void
dissect_reqxmit_policy (tvbuff_t * tvb, proto_tree * tree, int start)
{
  static int * const requests[] = {
    &hf_docsis_tlv_sflow_reqxmit_all_cm_broadcast,
    &hf_docsis_tlv_sflow_reqxmit_priority_multicast,
    &hf_docsis_tlv_sflow_reqxmit_req_data_requests,
    &hf_docsis_tlv_sflow_reqxmit_req_data_data,
    &hf_docsis_tlv_sflow_reqxmit_piggy_back,
    &hf_docsis_tlv_sflow_reqxmit_concatenate_data,
    &hf_docsis_tlv_sflow_reqxmit_fragment,
    &hf_docsis_tlv_sflow_reqxmit_suppress_payload,
    &hf_docsis_tlv_sflow_reqxmit_drop_packets,
    NULL
  };
  proto_tree_add_bitmask(tree, tvb, start, hf_docsis_tlv_sflow_reqxmit_pol,
                         ett_docsis_tlv_reqxmitpol, requests, ENC_BIG_ENDIAN);
}

static void
dissect_sflow_err (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                   uint16_t len)
{
  uint8_t type, length;
  proto_tree *err_tree;
  proto_item *err_item;
  int pos = start;

  err_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_sflow_err, &err_item,
                                  "5 Service Flow Error Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SFW_ERR_PARAM:
            if (length == 1)
              {
                proto_tree_add_item (err_tree, hf_docsis_tlv_sflow_err_param,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_ERR_CODE:
            if (length == 1)
              {
                proto_tree_add_item (err_tree, hf_docsis_tlv_sflow_err_code,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_ERR_MSG:
            proto_tree_add_item (err_tree, hf_docsis_tlv_sflow_err_msg, tvb,
                                 pos, length, ENC_ASCII);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, err_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_downstream_sflow (tvbuff_t * tvb, packet_info* pinfo, proto_tree * sflow_tree,
                          proto_item* sflow_item, int start, uint16_t len)
{
  uint8_t type, length;
  int pos = start;

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
        case SFW_MAX_DOWN_LAT:
          if (length == 4)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_max_down_latency, tvb,
                                   pos, length, ENC_BIG_ENDIAN);
            }
          else
            {
              expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
            }
          break;
        case SFW_DOWN_RESEQ:
          if (length == 1)
            {
              proto_tree_add_item (sflow_tree,
                                   hf_docsis_tlv_sflow_down_reseq, tvb,
                                   pos, length, ENC_BIG_ENDIAN);
            }
          else
            {
              expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
            }
          break;
        default:
          dissect_unknown_tlv (tvb, pinfo, sflow_tree, pos - 2, length + 2);
          break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_upstream_sflow (tvbuff_t * tvb, packet_info* pinfo, proto_tree * sflow_tree,
                        proto_item* sflow_item, int start, uint16_t len)
{
  uint8_t type, length;
  int pos = start;

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SFW_MAX_CONCAT_BURST:
            if (length == 2)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_max_concat_burst, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_SCHEDULING_TYPE:
            if (length == 1)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_sched_type,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_REQ_XMIT_POL:
            dissect_reqxmit_policy (tvb, sflow_tree, pos);
            break;
          case SFW_NOM_POLL_INT:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_nominal_polling, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_POLL_JTTR_TOL:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_tolerated_jitter, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_UG_SIZE:
            if (length == 2)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_ugs_size,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_NOM_GRNT_INTV:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_nom_grant_intvl, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_GRNT_JTTR_TOL:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_tol_grant_jitter, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_GRNTS_PER_INTV:
            if (length == 1)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_grants_per_intvl, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_UG_TIME_REF:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_ugs_timeref, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_CONTENTION_REQ_BACKOFF_WINDOW_MULT:
            if (length == 1)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_cont_req_backoff_window_mult, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_NUM_OF_BYTES_REQUESTED_MULT:
            if (length == 1)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_num_of_bytes_requested_mult, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
                                uint8_t multiplier_val = tvb_get_uint8 (tvb, pos);
                                if (multiplier_val != 1 && multiplier_val != 2 && multiplier_val != 4 &&
                                    multiplier_val != 8 && multiplier_val != 16)
                                    {
                                      expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvval_bad,
                                                             "Wrong TLV value: %u (should be equal to 1,2,4,8 or 16)", multiplier_val);
                                    }
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, sflow_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_sflow (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len,
               uint8_t direction)
{
  uint8_t type, length;
  proto_tree *sflow_tree;
  proto_item *sflow_item;
  int pos = start;

  if (direction == 24)
    sflow_tree =
      proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr, &sflow_item,
                                    "24 Upstream Service Flow (Length = %u)", len);
  else if (direction == 25)
    sflow_tree =
      proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr, &sflow_item,
                                    "25 Downstream Service Flow (Length = %u)", len);
  else
    return;

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SFW_REF:
            if (length == 2)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_ref, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_ID:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_id, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_SID:
            if (length == 2)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_sid, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_SERVICE_CLASS_NAME:
            proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_classname, tvb,
                                 pos, length, ENC_ASCII);
            break;
          case SFW_ERRORS:
            dissect_sflow_err (tvb, pinfo, sflow_tree, pos, length);
            break;
          case SFW_QOS_SET_TYPE:
            if (length == 1)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_qos_param,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_TRAF_PRI:
            if (length == 1)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_traf_pri,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_MAX_SUSTAINED:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_max_sus,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_MAX_BURST:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_max_burst,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_MIN_RSVD_TRAF:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_min_traf,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_MIN_RSVD_PACKETSIZE:
            if (length == 2)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_ass_min_pkt_size, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_ACTIVE_QOS_TIMEOUT:
            if (length == 2)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_timeout_active, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_ADMITT_QOS_TIMEOUT:
            if (length == 2)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_timeout_admitted, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_IP_TOS_OVERWRITE:
            if (length == 2)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_ip_tos_overwrite, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_PEAK_TRAFFIC_RATE:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_peak_traffic_rate, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_REQUIRED_ATTRIBUTE_MASK:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_req_attr_mask, tvb,
                                     pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);

              }
            break;
          case SFW_FORBIDDEN_ATTRIBUTE_MASK:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_forb_attr_mask, tvb,
                                     pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_ATTRIBUTE_AGGREGATION_RULE_MASK:
            if (length == 4)
              {
                proto_tree_add_item (sflow_tree,
                                     hf_docsis_tlv_sflow_attr_aggr_rule_mask, tvb,
                                     pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, sflow_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SFW_VENDOR_SPEC:
            proto_tree_add_item (sflow_tree, hf_docsis_tlv_sflow_vendor_spec,
                                 tvb, pos, length, ENC_NA);
            break;
          default:
            if (direction == 24)
              dissect_upstream_sflow (tvb, pinfo, sflow_tree, sflow_item, pos - 2, length);
            else
              dissect_downstream_sflow (tvb, pinfo, sflow_tree, sflow_item, pos - 2, length);
            break;

        }                       /* switch (type) */
      pos = pos + length;
    }                           /* while(pos < start + len) */

}

static void
dissect_dot1q_clsfr (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                     uint16_t len)
{
  uint8_t type, length;
  proto_tree *dot1qclsfr_tree;
  proto_item *dot1qclsfr_item;
  int pos = start;

  dot1qclsfr_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_cos, &dot1qclsfr_item,
                                  "11 801.1P/Q Classifiers (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CFR_D1Q_USER_PRI:
            if (length == 2)
              {
                proto_tree_add_item (dot1qclsfr_tree,
                                     hf_docsis_tlv_dot1qclsfr_user_pri, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dot1qclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_D1Q_VLAN_ID:
            if (length == 2)
              {
                proto_tree_add_item (dot1qclsfr_tree,
                                     hf_docsis_tlv_dot1qclsfr_vlanid, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dot1qclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_D1Q_VENDOR_SPEC:
            proto_tree_add_item (dot1qclsfr_tree,
                                 hf_docsis_tlv_dot1qclsfr_vendorspec, tvb, pos,
                                 length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, dot1qclsfr_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_eth_clsfr (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                   uint16_t len)
{
  uint8_t type, length;
  proto_tree *ethclsfr_tree;
  proto_item *ethclsfr_item;
  int pos = start;

  ethclsfr_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr_eth, &ethclsfr_item,
                                  ".10 Ethernet Classifiers (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CFR_ETH_DST_MAC:
            if (length == 6)
              {
                proto_tree_add_item (ethclsfr_tree, hf_docsis_tlv_ethclsfr_dmac,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, ethclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_ETH_SRC_MAC:
            if (length == 6)
              {
                proto_tree_add_item (ethclsfr_tree, hf_docsis_tlv_ethclsfr_smac,
                                     tvb, pos, length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, ethclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_ETH_DSAP:
            if (length == 3)
              {
                proto_tree_add_item (ethclsfr_tree,
                                     hf_docsis_tlv_ethclsfr_ethertype, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ethclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, ethclsfr_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_clsfr_err (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                   uint16_t len)
{
  uint8_t type, length;
  proto_tree *err_tree;
  proto_tree *err_item;
  int pos = start;

  err_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr_err, &err_item,
                                  "8 Classifier Error Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CFR_ERR_PARAM:
            if (length == 1)
              proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_param, tvb,
                                   pos, length, ENC_BIG_ENDIAN);
            else if (length == 2)
              {
                proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_param,
                                     tvb, pos, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_param,
                                     tvb, pos + 1, 1, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_ERR_CODE:
            if (length == 1)
              {
                proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_code,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_ERR_MSG:
            proto_tree_add_item (err_tree, hf_docsis_tlv_clsfr_err_msg, tvb,
                                 pos, length, ENC_ASCII);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, err_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_ip_classifier (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                       uint16_t len)
{
  uint8_t type, length;
  proto_tree *ipclsfr_tree;
  proto_tree *ipclsfr_item;
  int pos = start;

  ipclsfr_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr_ip, &ipclsfr_item,
                                  ".9 IP Classifier (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CFR_IP_TOS_RANGE_MASK:
            if (length == 3)
              {
                proto_tree_add_item (ipclsfr_tree,
                                     hf_docsis_tlv_ipclsfr_tosmask, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_PROTO:
            if (length == 2)
              {
                proto_tree_add_item (ipclsfr_tree,
                                     hf_docsis_tlv_ipclsfr_ipproto, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_SOURCE_ADDR:
            if (length == 4)
              {
                proto_tree_add_item (ipclsfr_tree, hf_docsis_tlv_ipclsfr_src,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_SOURCE_MASK:
            if (length == 4)
              {
                proto_tree_add_item (ipclsfr_tree,
                                     hf_docsis_tlv_ipclsfr_srcmask, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_DEST_ADDR:
            if (length == 4)
              {
                proto_tree_add_item (ipclsfr_tree, hf_docsis_tlv_ipclsfr_dst,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_DEST_MASK:
            if (length == 4)
              {
                proto_tree_add_item (ipclsfr_tree,
                                     hf_docsis_tlv_ipclsfr_dstmask, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_SRCPORT_START:
            if (length == 2)
              {
                proto_tree_add_item (ipclsfr_tree,
                                     hf_docsis_tlv_ipclsfr_sport_start, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_SRCPORT_END:
            if (length == 2)
              {
                proto_tree_add_item (ipclsfr_tree,
                                     hf_docsis_tlv_ipclsfr_sport_end, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_DSTPORT_START:
            if (length == 2)
              {
                proto_tree_add_item (ipclsfr_tree,
                                     hf_docsis_tlv_ipclsfr_dport_start, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP_DSTPORT_END:
            if (length == 2)
              {
                proto_tree_add_item (ipclsfr_tree,
                                     hf_docsis_tlv_ipclsfr_dport_end, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ipclsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, ipclsfr_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_ip6_classifier_tc (tvbuff_t * tvb, proto_tree * tree, int start,
                       uint16_t len)
{
  proto_tree *ip6clsfr_tc_tree;
  proto_tree *ip6clsfr_tc_item;

  ip6clsfr_tc_tree = proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr_ip6_tc, &ip6clsfr_tc_item,
                                "..1 IPv6 Traffic Class Range and Mask");

  proto_tree_add_item(ip6clsfr_tc_tree, hf_docsis_tlv_ip6clsfr_tc_low, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ip6clsfr_tc_tree, hf_docsis_tlv_ip6clsfr_tc_high, tvb, start + 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ip6clsfr_tc_tree, hf_docsis_tlv_ip6clsfr_tc_mask, tvb, start + 2, 1, ENC_BIG_ENDIAN);

}

static void
dissect_ip6_classifier (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                       uint16_t len)
{
  uint8_t type, length;
  proto_tree *ip6clsfr_tree;
  proto_tree *ip6clsfr_item;
  int pos = start;


  ip6clsfr_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr_ip6, &ip6clsfr_item,
                                  ".12 IPv6 Classifier (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CFR_IP6_TRAFFIC_CLASS:
            if (length == 3)
              {
                dissect_ip6_classifier_tc(tvb, ip6clsfr_tree, pos, length);
              }
            else
              {
                expert_add_info_format(pinfo, ip6clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP6_FLOW_LABEL:
            if (length == 4)
              {
                proto_tree_add_item (ip6clsfr_tree,
                                     hf_docsis_tlv_ip6clsfr_flow_label, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ip6clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP6_NEXT_HEADER:
            if (length == 2)
              {
                proto_tree_add_item (ip6clsfr_tree,
                                     hf_docsis_tlv_ip6clsfr_next_header, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ip6clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP6_SOURCE_ADDR:
            if (length == 16)
              {
                proto_tree_add_item (ip6clsfr_tree,
                                     hf_docsis_tlv_ip6clsfr_src, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, ip6clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP6_SOURCE_PREFIX_LENGTH:
            if (length == 1)
              {
                proto_tree_add_item (ip6clsfr_tree,
                                     hf_docsis_tlv_ip6clsfr_src_prefix_length, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ip6clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP6_DESTINATION_ADDR:
            if (length == 16)
              {
                proto_tree_add_item (ip6clsfr_tree,
                                     hf_docsis_tlv_ip6clsfr_dst, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, ip6clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_IP6_DESTINATION_PREFIX_LENGTH:
            if (length == 1)
              {
                proto_tree_add_item (ip6clsfr_tree,
                                     hf_docsis_tlv_ip6clsfr_dst_prefix_length, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, ip6clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, ip6clsfr_tree, pos - 2, length + 2);
            break;
       }                       /* switch */
       pos = pos + length;
    }                           /* while */
}

static void
dissect_classifiers (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                     uint16_t len, uint8_t direction)
{
  uint8_t type, length;
  proto_tree *clsfr_tree;
  proto_item *clsfr_item;
  int pos = start;

  if (direction == 22)
    clsfr_tree =
      proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr, &clsfr_item,
                                    "22 Upstream Packet Classifier (Length = %u)",
                                    len);
  else if (direction == 23)
    clsfr_tree =
      proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_clsfr, &clsfr_item,
                                    "23 Downstream Packet Classifier (Length = %u)",
                                    len);
  else
    return;

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CFR_REF:
            if (length == 1)
              {
                proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_ref, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_ID:
            if (length == 2)
              {
                proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_id, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_SFLOW_REF:
            if (length == 2)
              {
                proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_sflow_ref,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_SFLOW_ID:
            if (length == 4)
              {
                proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_sflow_id,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_RULE_PRI:
            if (length == 1)
              {
                proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_rule_pri,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_ACT_STATE:
            if (length == 1)
              {
                proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_act_state,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_DSA_ACTION:
            if (length == 1)
              {
                proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_dsc_act,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, clsfr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CFR_ERROR:
            dissect_clsfr_err (tvb, pinfo, clsfr_tree, pos, length);
            break;
          case CFR_IP_CLASSIFIER:
            dissect_ip_classifier (tvb, pinfo, clsfr_tree, pos, length);
            break;
          case CFR_IP6_CLASSIFIER:
            dissect_ip6_classifier (tvb, pinfo, clsfr_tree, pos, length);
            break;
          case CFR_ETH_CLASSIFIER:
            dissect_eth_clsfr (tvb, pinfo, clsfr_tree, pos, length);
            break;
          case CFR_8021Q_CLASSIFIER:
            dissect_dot1q_clsfr (tvb, pinfo, clsfr_tree, pos, length);
            break;
          case CFR_VENDOR_SPEC:
            proto_tree_add_item (clsfr_tree, hf_docsis_tlv_clsfr_vendor_spc,
                                 tvb, pos, length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, clsfr_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_doc10cos (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                  uint16_t len)
{
  uint8_t type, length;
  proto_tree *doc10cos_tree;
  proto_tree *doc10cos_item;
  int pos = start;

  doc10cos_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_cos, &doc10cos_item,
                                  "1 Docsis 1.0 Class of Service (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case 1:
            if (length == 1)
              {
                proto_tree_add_item (doc10cos_tree, hf_docsis_tlv_cos_id, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, doc10cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case 2:
            if (length == 2)
              {
                proto_tree_add_item (doc10cos_tree, hf_docsis_tlv_cos_sid, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, doc10cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, doc10cos_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;

    }                           /* while */
}

static void
dissect_modemcap (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start,
                  uint16_t len)
{
  uint8_t type, length;
  uint32_t tlv_value;
  proto_tree *mcap_tree, *tlv_tree;
  proto_tree *mcap_item, *tlv_item;
  int pos = start;

  mcap_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_mcap, &mcap_item,
                                  "5 Modem Capabilities Type (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CAP_CONCAT:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_concat, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DOCSIS_VER:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_docs_ver,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_FRAG:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_frag, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_PHS:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_phs, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_IGMP:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_igmp, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_PRIVACY:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_privacy, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DOWN_SAID:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_down_said,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_UP_SID:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_up_sid, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_OPT_FILT:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_8021P_filter,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_8021Q_filter,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_XMIT_EQPERSYM:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree,
                                     hf_docsis_tlv_mcap_xmit_eq_taps_per_sym,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_NUM_XMIT_EQ_TAPS:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_xmit_eq_taps,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DCC:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_dcc, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_IP_FILTERS:
            if (length == 2)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_ip_filters, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_LLC_FILTERS:
            if (length == 2)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_llc_filters, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_EXP_UNICAST_SID:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_exp_unicast_sid, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_RNG_HOFF:
            if (length == 4)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_rnghoff_cm, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_rnghoff_erouter, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_rnghoff_emta, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_rnghoff_estb, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_L2VPN:
            proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_l2vpn, tvb,
                                 pos, length, ENC_NA);
            break;
          case CAP_L2VPN_ESAFE:
            proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_l2vpn_esafe, tvb,
                                 pos, length, ENC_NA);
            break;
          case CAP_DUT_FILTERING:
            proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_dut_filtering, tvb,
                                 pos, length, ENC_NA);
            break;
          case CAP_US_FREQ_RNG:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_us_freq_range, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_US_SRATE:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_us_srate_160, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_us_srate_320, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_us_srate_640, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_us_srate_1280, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_us_srate_2560, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_us_srate_5120, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_SAC:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_sac, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_CODE_HOP_M2:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_code_hop_mode2, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_MTC:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_mtc, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_512_MSPS_UTC:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_512_msps_utc, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_256_MSPS_UTC:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_256_msps_utc, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_TOTAL_SID_CLUST:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_total_sid_cluster, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_SID_PER_SF:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_sid_per_sf, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_MRC:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_mrc, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_TOTAL_DSID:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_total_dsid, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_RESEQ_DSID:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_reseq_dsid, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_MC_DSID:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_mc_dsid, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_MC_DSID_FWD:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_mc_dsid_fwd, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_FCTYPE_FWD:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_fctype_fwd, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DPV:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_dpv_path, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_dpv_packet, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_UGS:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_ugs, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_MAP_UCD:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_map_ucd, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_UDC:
            if (length == 2)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_udc, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_IPV6:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_ipv6, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_EXT_US_TRNS_PWR:
            if (length == 1)
              {
                unsigned power_raw;
                proto_item * power_cap_it = proto_tree_add_item_ret_uint (mcap_tree, hf_docsis_tlv_mcap_ext_us_trans_power,
                                                                          tvb, pos, length, ENC_BIG_ENDIAN, &power_raw);
                proto_item_append_text(power_cap_it, " (%.2f dB)", power_raw * 0.25);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_EM:
            if (length == 4)
              {
                static int * const cap_em[] = {
                  &hf_docsis_tlv_mcap_em_1x1,
                  &hf_docsis_tlv_mcap_em_light_sleep,
                  NULL
                };

                proto_tree_add_bitmask_with_flags(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_em, ett_docsis_tlv_mcap_em, cap_em, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_CM_STATUS_ACK:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_cm_status_ack, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_EM_PREF:
            if (length == 4)
              {
                static int * const em_pref[] = {
                  &hf_docsis_tlv_mcap_em_pref_1x1,
                  &hf_docsis_tlv_mcap_em_pref_dls,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_em_pref,
                         ett_docsis_tlv_mcap_em_pref, em_pref, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_EXT_PKT_LEN_SUP_CAP:
            if (length == 2)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_ext_pkt_len_sup_cap, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_OFDM_MULT_RECV_CHAN_SUP:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_ofdm_mult_recv_chan_sup, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_OFDMA_MULT_TRANS_CHAN_SUP:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_ofdma_mult_trans_chan_sup, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DOWN_OFDM_PROF_SUP:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_down_ofdm_prof_sup, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DOWN_OFDM_CHAN_SUBC_QAM_MOD_SUP:
            if (length == 2)
              {
                static int * const ofdm_qam_mod_sup[] = {
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_reserved,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_qpsk,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_16qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_64qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_128qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_256qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_512qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_1024qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_2048qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_4096qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_8192qam,
                  &hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_16384qam,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup,
                         ett_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup, ofdm_qam_mod_sup, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_UP_OFDMA_CHAN_SUBC_QAM_MOD_SUP:
            if (length == 2)
              {
                static int * const ofdma_qam_mod_sup[] = {
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_reserved,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_qpsk,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_8qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_16qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_32qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_64qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_128qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_256qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_512qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_1024qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_2048qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_4096qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_8192qam,
                  &hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_16384qam,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup,
                         ett_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup, ofdma_qam_mod_sup, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DOWN_LOWER_BAND_EDGE_CONF:
            if (length == 1)
              {
                static int * const down_lower_band_edge_conf[] = {
                  &hf_docsis_tlv_mcap_down_lower_band_edge_conf_108,
                  &hf_docsis_tlv_mcap_down_lower_band_edge_conf_258,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_down_lower_band_edge_conf,
                         ett_docsis_tlv_mcap_down_lower_band_edge_conf, down_lower_band_edge_conf, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DOWN_UPPER_BAND_EDGE_CONF:
            if (length == 1)
              {
                static int * const down_upper_band_edge_conf[] = {
                  &hf_docsis_tlv_mcap_down_upper_band_edge_conf_1218,
                  &hf_docsis_tlv_mcap_down_upper_band_edge_conf_1794,
                  &hf_docsis_tlv_mcap_down_upper_band_edge_conf_1002,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_down_upper_band_edge_conf,
                         ett_docsis_tlv_mcap_down_upper_band_edge_conf, down_upper_band_edge_conf, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DIPL_UP_UPPER_BAND_EDGE_CONF:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_dipl_up_upper_band_edge_conf, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DOCSIS_TIME_PROT_MODE:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_docsis_time_prot_mode, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DOCSIS_TIME_PROT_PERF_SUP:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_docsis_time_prot_perf_sup, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_PMAX:
            if (length == 2)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_pmax, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DIPL_DOWN_LOWER_BAND_EDGE:
            if (length == 1)
              {
                static int * const dipl_down_lower_band_edge[] = {
                  &hf_docsis_tlv_mcap_dipl_down_lower_band_edge_108,
                  &hf_docsis_tlv_mcap_dipl_down_lower_band_edge_258,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_dipl_down_lower_band_edge,
                         ett_docsis_tlv_mcap_dipl_down_lower_band_edge, dipl_down_lower_band_edge, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DIPL_DOWN_UPPER_BAND_EDGE:
            if (length == 1)
              {
                static int * const dipl_down_upper_band_edge[] = {
                  &hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1218,
                  &hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1794,
                  &hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1002,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_dipl_down_upper_band_edge,
                         ett_docsis_tlv_mcap_dipl_down_upper_band_edge, dipl_down_upper_band_edge, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_DIPL_UP_UPPER_BAND_EDGE:
            if (length == 1)
              {
                static int * const dipl_up_upper_band_edge[] = {
                  &hf_docsis_tlv_mcap_dipl_up_upper_band_edge_42,
                  &hf_docsis_tlv_mcap_dipl_up_upper_band_edge_65,
                  &hf_docsis_tlv_mcap_dipl_up_upper_band_edge_85,
                  &hf_docsis_tlv_mcap_dipl_up_upper_band_edge_117,
                  &hf_docsis_tlv_mcap_dipl_up_upper_band_edge_204,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_dipl_up_upper_band_edge,
                         ett_docsis_tlv_mcap_dipl_up_upper_band_edge, dipl_up_upper_band_edge, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_ADVANCED_BAND_PLAN:
            if (length == 1)
              {
                static int * const advanved_band_plan[] = {
                  &hf_docsis_tlv_mcap_advanced_band_plan_fdx_l,
                  &hf_docsis_tlv_mcap_advanced_band_plan_fdx,
                  &hf_docsis_tlv_mcap_advanced_band_plan_fdd,
                  &hf_docsis_tlv_mcap_advanced_band_plan_reserved,
                  NULL
                };

                proto_tree_add_bitmask(mcap_tree, tvb, pos, hf_docsis_tlv_mcap_advanced_band_plan,
                         ett_docsis_tlv_mcap_advanced_band_plan, advanved_band_plan, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_EXTENDED_SF_SID_CLUSTER_ASSIGN:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_ext_sf_cluster_assign_sup, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_LOW_LATENCY_SUP:
            if (length == 1)
              {
                tlv_item = proto_tree_add_item_ret_uint (mcap_tree, hf_docsis_tlv_mcap_low_latency_sup, tvb,
                                      pos, length, ENC_BIG_ENDIAN, &tlv_value);
                if (tlv_value > 0)
                  {
                    proto_item_append_text(tlv_item, " %s", (tlv_value == 1) ? "ASF" : "ASFs" );
                  }
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_ADVANCED_DOWN_LOWER_BAND_EDGE_CONF:
            if (length == 2)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_adv_down_lower_band_edge_conf, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_ADVANCED_DOWN_UPPER_BAND_EDGE_CONF:
            if (length == 2)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_adv_down_upper_band_edge_conf, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_ADVANCED_UP_UPPER_BAND_EDGE_CONF:
            if (length == 2)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_adv_up_upper_band_edge_conf, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_ADVANCED_DOWN_LOWER_BAND_EDGE_OPTIONS_LIST:
            if (length > 0 && length % 2 == 0)
              {
                tlv_tree = proto_tree_add_subtree_format(mcap_tree, tvb, pos, length,
                                  ett_docsis_tlv_mcap_dipl_down_lower_band_edge_options_list, &tlv_item,
                                  ".82 Advanced Diplexer Downstream Lower Band Edge Options List");

                for (uint8_t i = 0; i < length; i = i + 2)
                  {
                    proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_tlv_mcap_adv_down_lower_band_edge_option,
                                      tvb, pos + i, 2, ENC_BIG_ENDIAN, &tlv_value);
                    proto_item_append_text(tlv_item, "%s %d MHz", (i == 0) ? ":" : ",", tlv_value);
                  }
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_ADVANCED_DOWN_UPPER_BAND_EDGE_OPTIONS_LIST:
            if (length > 0 && length % 2 == 0)
              {
                tlv_tree = proto_tree_add_subtree_format(mcap_tree, tvb, pos, length,
                                  ett_docsis_tlv_mcap_dipl_down_upper_band_edge_options_list, &tlv_item,
                                  ".83 Advanced Diplexer Downstream Upper Band Edge Options List");

                for (uint8_t i = 0; i < length; i = i + 2)
                  {
                    proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_tlv_mcap_adv_down_upper_band_edge_option,
                                      tvb, pos + i, 2, ENC_BIG_ENDIAN, &tlv_value);
                    proto_item_append_text(tlv_item, "%s %d MHz", (i == 0) ? ":" : ",", tlv_value);
                  }
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CAP_ADVANCED_UP_UPPER_BAND_EDGE_OPTIONS_LIST:
            if (length > 0 && length % 2 == 0)
              {
                tlv_tree = proto_tree_add_subtree_format(mcap_tree, tvb, pos, length,
                                  ett_docsis_tlv_mcap_dipl_up_upper_band_edge_options_list, &tlv_item,
                                  ".84 Advanced Diplexer Upstream Upper Band Edge Options List");

                for (uint8_t i = 0; i < length; i = i + 2)
                  {
                    proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_tlv_mcap_adv_up_upper_band_edge_option,
                                      tvb, pos + i, 2, ENC_BIG_ENDIAN, &tlv_value);
                    proto_item_append_text(tlv_item, "%s %d MHz", (i == 0) ? ":" : ",", tlv_value);
                  }
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
            case CAP_EXTENDED_POWER_OPTIONS:
            if (length == 1)
              {
                proto_tree_add_item (mcap_tree, hf_docsis_tlv_mcap_extended_power_options, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, mcap_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, mcap_tree, pos - 2, length + 2);
            break;
        }                       /* switch (type) */
      pos = pos + length;
    }                           /* while (pos < pos+len) */
}

static void
dissect_cos (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *cos_tree;
  proto_tree *cos_item;
  int pos = start;

  cos_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_cos, &cos_item,
                                  "4 Class of Service Type (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case COS_CLASSID:
            if (length == 1)
              {
                proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case COS_MAX_DOWN:
            if (length == 4)
              {
                proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_max_down, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case COS_MAX_UP:
            if (length == 4)
              {
                proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_max_up, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case COS_UP_CH_PRIO:
            if (length == 1)
              {
                proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_up_chnl_pri,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case COS_MIN_UP_RATE:
            if (length == 4)
              {
                proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_min_grntd_up,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case COS_MAX_UP_BURST:
            if (length == 2)
              {
                proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_max_up_burst,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case COS_BP_ENABLE:
            if (length == 1)
              {
                proto_tree_add_item (cos_tree, hf_docsis_tlv_cos_privacy_enable,
                                     tvb, pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, cos_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, cos_tree, pos - 2, length + 2);
            break;
        }                       /* switch (type) */
      pos = pos + length;
    }                           /* while (pos < pos+len) */
}

static void
dissect_svc_unavail(tvbuff_t * tvb, proto_tree * tree, int pos, uint16_t length) {

  proto_item *svc_unavail_it;
  proto_tree *svc_unavail_tree;
  svc_unavail_it = proto_tree_add_item (tree,
                                        hf_docsis_tlv_svc_unavail,
                                        tvb, pos, length, ENC_NA);
  svc_unavail_tree = proto_item_add_subtree(svc_unavail_it, ett_docsis_tlv_svc_unavail );
  proto_tree_add_item (svc_unavail_tree,
                       hf_docsis_tlv_svc_unavail_classid, tvb,
                       pos, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (svc_unavail_tree,
                       hf_docsis_tlv_svc_unavail_type, tvb,
                       pos+1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (svc_unavail_tree,
                       hf_docsis_tlv_svc_unavail_code, tvb,
                       pos+2, 1, ENC_BIG_ENDIAN);

}

static void
dissect_snmpv3_kickstart(tvbuff_t * tvb, packet_info * pinfo, proto_tree *tree, int start, uint16_t len) {
  proto_item *snmpv3_it;
  proto_tree *snmpv3_tree;
  uint8_t type, length;
  int pos = start;

  snmpv3_it = proto_tree_add_item (tree,
                                   hf_docsis_tlv_snmpv3_kick,
                                   tvb, start, len, ENC_NA);
  snmpv3_tree = proto_item_add_subtree(snmpv3_it, ett_docsis_tlv_snmpv3_kick);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SNMPV3_SEC_NAME:
            proto_tree_add_item (snmpv3_tree,
                                 hf_docsis_tlv_snmpv3_kick_name, tvb,
                                 pos, length, ENC_ASCII);
            break;
          case SNMPV3_MGR_PUB_NUM:
            proto_tree_add_item (snmpv3_tree,
                                 hf_docsis_tlv_snmpv3_kick_publicnum, tvb,
                                 pos, length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, snmpv3_tree, pos - 2, length + 2);
            break;
        }  /* switch */
      pos += length;
    }   /* while */
}

static void
dissect_ds_ch_list_single (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree,
                           int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *single_tree;
  proto_item *single_item;
  int pos = start;

  single_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_ds_ch_list_single, &single_item,
                                  "1 Single Downstream Channel (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SINGLE_CH_TIMEOUT:
            if (length == 2)
              {
                proto_tree_add_item (single_tree, hf_docsis_tlv_single_ch_timeout, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, single_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SINGLE_CH_FREQ:
            if (length == 4)
              {
                proto_tree_add_item (single_tree, hf_docsis_tlv_single_ch_freq, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, single_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, single_tree, pos - 2, length + 2);
            break;
        }  /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_ds_ch_list_range (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree,
                          int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *range_tree;
  proto_item *range_item;
  int pos = start;

  range_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_ds_ch_list_range, &range_item,
                                  "2 Downstream Frequency Range (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case FREQ_RNG_TIMEOUT:
            if (length == 2)
              {
                proto_tree_add_item (range_tree, hf_docsis_tlv_freq_rng_timeout, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, range_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case FREQ_RNG_START:
            if (length == 4)
              {
                proto_tree_add_item (range_tree, hf_docsis_tlv_freq_rng_start, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, range_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case FREQ_RNG_END:
            if (length == 4)
              {
                proto_tree_add_item (range_tree, hf_docsis_tlv_freq_rng_end, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, range_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case FREQ_RNG_STEP:
            if (length == 4)
              {
                proto_tree_add_item (range_tree, hf_docsis_tlv_freq_rng_step, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, range_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, range_tree, pos - 2, length + 2);
            break;
        }                           /* switch */
      pos = pos + length;
    }                             /* while */
}

static void
dissect_dut_filter (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree,
                    int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *dut_tree;
  proto_item *dut_item;
  int pos = start;

  dut_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_dut_filter, &dut_item,
                                  "45 Downstream Unencrypted Traffic (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case DUT_CONTROL:
            if (length == 1)
              {
                proto_tree_add_item (dut_tree, hf_docsis_tlv_dut_filter_control, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dut_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case DUT_CMIM:
            proto_tree_add_item (dut_tree, hf_docsis_tlv_dut_filter_cmim, tvb,
                                 pos, length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, dut_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_ds_ch_list(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *dschlst_tree;
  proto_item *dschlst_item;
  int pos = start;

  dschlst_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_ds_ch_list, &dschlst_item,
                                  "41 Downstream Channel List (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case DS_CH_LIST_SINGLE:
            dissect_ds_ch_list_single(tvb, pinfo, dschlst_tree, pos, length);
            break;
          case DS_CH_LIST_RANGE:
            dissect_ds_ch_list_range(tvb, pinfo, dschlst_tree, pos, length);
            break;
          case DS_CH_LIST_DEFAULT_TIMEOUT:
            if (length == 2)
              {
                proto_tree_add_item (dschlst_tree,
                                     hf_docsis_tlv_ds_ch_list_default_timeout, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dschlst_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, dschlst_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_docsis_extension_field(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  proto_tree *ext_field_tree;
  proto_item *ext_field_item;
  tvbuff_t *vsif_tvb;

  ext_field_tree =
  proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_ext_field, &ext_field_item,
                                  "43 DOCSIS Extension Field (Length = %u)", len);

  vsif_tvb = tvb_new_subset_length (tvb, start, len);
  call_dissector (docsis_vsif_handle, vsif_tvb, pinfo, ext_field_tree);
}

static void
dissect_vendor_specific_capabilities(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  proto_tree *vend_spec_cap_tree;
  proto_item *vend_spec_cap_item;
  tvbuff_t *vsif_tvb;

  vend_spec_cap_tree =
  proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_vendor_specific_cap, &vend_spec_cap_item,
                                  "44 Vendor Specific Capabilities (Length = %u)", len);

  vsif_tvb = tvb_new_subset_length (tvb, start, len);
  call_dissector (docsis_vsif_handle, vsif_tvb, pinfo, vend_spec_cap_tree);
}

static void
dissect_tcc_err(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *tccerr_tree;
  proto_tree *tccerr_item;
  int pos = start;

  tccerr_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_tcc_err, &tccerr_item,
                                  "TCC Error Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TCC_ERR_SUBTYPE:
            proto_tree_add_item (tccerr_tree,
                                 hf_docsis_tcc_err_subtype, tvb,
                                 pos, length, ENC_NA);
            break;
          case TCC_ERR_CODE:
            if (length == 1)
              {
                proto_tree_add_item (tccerr_tree,
                                     hf_docsis_tcc_err_code, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tccerr_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TCC_ERR_MSG:
            proto_tree_add_item (tccerr_tree,
                                 hf_docsis_tcc_err_msg, tvb,
                                 pos, length, ENC_ASCII);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, tccerr_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_tcc_rng_parms(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rngparm_tree;
  proto_item *rngparm_item;
  int pos = start;

  rngparm_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_tcc_rng_parms, &rngparm_item,
                                  ".8 Ranging Parameters (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case RNG_PARMS_US_CH_ID:
            if (length == 1)
              {
                proto_tree_add_item (rngparm_tree,
                                     hf_docsis_rng_parms_us_ch_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rngparm_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RNG_PARMS_TIME_OFF_INT:
            if (length == 4)
              {
                proto_tree_add_item (rngparm_tree,
                                     hf_docsis_rng_parms_time_off_int, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rngparm_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RNG_PARMS_TIME_OFF_FRAC:
            if (length == 1)
              {
                proto_tree_add_item (rngparm_tree,
                                     hf_docsis_rng_parms_time_off_frac, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rngparm_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RNG_PARMS_POWER_OFF:
            if (length == 1)
              {
                proto_tree_add_item (rngparm_tree,
                                     hf_docsis_rng_parms_power_off, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rngparm_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RNG_PARMS_FREQ_OFF:
            if (length == 1)
              {
                proto_tree_add_item (rngparm_tree,
                                     hf_docsis_rng_parms_freq_off, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rngparm_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rngparm_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_tcc_oudp(tvbuff_t * tvb, proto_tree *tree, int start, uint16_t len)
{
  proto_tree *oudp_tree;
  proto_item *oudp_item;
  int pos = start;

  oudp_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_tcc_oudp, &oudp_item,
                                  ".11 Assigned OFDMA Upstream Data Profile (OUDP) IUC (Length = %u)", len);

  while (pos < (start + len))
    {
      proto_tree_add_item (oudp_tree, hf_docsis_tlv_tcc_oudp_iuc, tvb, pos, 1, ENC_BIG_ENDIAN);
      ++pos;
    }
}

static void
dissect_sid_cl_so_crit(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *crit_tree;
  proto_item *crit_item;
  int pos = start;

  crit_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_sid_cl_so, &crit_item,
                                  ".3 SID Cluster Switchover Criteria (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SID_CL_SO_MAX_REQ:
            if (length == 1)
              {
                proto_tree_add_item (crit_tree,
                                     hf_docsis_sid_cl_so_max_req, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, crit_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SID_CL_SO_MAX_OUT_BYTES:
            if (length == 4)
              {
                proto_tree_add_item (crit_tree,
                                     hf_docsis_sid_cl_so_max_out_bytes, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, crit_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SID_CL_SO_MAX_REQ_BYTES:
            if (length == 4)
              {
                proto_tree_add_item (crit_tree,
                                     hf_docsis_sid_cl_so_max_req_bytes, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, crit_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SID_CL_SO_MAX_TIME:
            if (length == 2)
              {
                proto_tree_add_item (crit_tree,
                                     hf_docsis_sid_cl_so_max_time, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, crit_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, crit_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sid_cl_enc_map(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *map_tree;
  proto_item *map_item;
  int pos = start;

  map_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_sid_cl_enc_map, &map_item,
                                  "..2 SID-to-Channel Mapping (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SID_CL_MAP_US_CH_ID:
            if (length == 1)
              {
                proto_tree_add_item (map_tree,
                                     hf_docsis_sid_cl_map_us_ch_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, map_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SID_CL_MAP_SID:
            if (length == 2)
              {
                proto_tree_add_item (map_tree,
                                     hf_docsis_sid_cl_map_sid, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, map_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SID_CL_MAP_ACTION:
            if (length == 1)
              {
                proto_tree_add_item (map_tree,
                                     hf_docsis_sid_cl_map_action, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, map_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, map_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sid_cl_enc(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *enc_tree;
  proto_item *enc_item;
  int pos = start;

  enc_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_sid_cl_enc, &enc_item,
                                  ".2 SID Cluster Encoding (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SID_CL_ENC_ID:
            if (length == 1)
              {
                proto_tree_add_item (enc_tree,
                                     hf_docsis_sid_cl_enc_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, enc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SID_CL_ENC_MAP:
            if (length == 10)
              dissect_sid_cl_enc_map(tvb, pinfo, enc_tree, pos, length);
            else
              expert_add_info_format(pinfo, enc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, enc_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sid_cl(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *sid_tree;
  proto_item *sid_item;
  int pos = start;

  sid_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_sid_cl, &sid_item,
                                  "47 Service Flow SID Cluster Assignments (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case SID_CL_SF_ID:
            if (length == 4)
              {
                proto_tree_add_item (sid_tree,
                                     hf_docsis_sid_cl_sf_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case SID_CL_ENC:
            dissect_sid_cl_enc(tvb, pinfo, sid_tree, pos, length);
            break;
          case SID_CL_SO_CRIT:
            dissect_sid_cl_so_crit(tvb, pinfo, sid_tree, pos, length);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, sid_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_tcc(tvbuff_t * tvb, packet_info * pinfo,
            proto_tree *tree, int start, uint16_t len, int* previous_channel_id)
{
  uint8_t type, length;
  proto_tree *tcc_tree, *reassembled_ucd_tree;
  proto_item *tcc_item, *reassembled_ucd_item;
  int pos = start;
  int channel_id = -1;

  fragment_head* reassembled_ucd = NULL;

  tcc_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_tcc, &tcc_item,
                                  "46 Transmit Channel Configuration (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TLV_TCC_REFID:
            if (length == 1)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_refid, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_US_CH_ACTION:
            if (length == 1)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_us_ch_action, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_US_CH_ID:
            if (length == 1)
              {
                proto_tree_add_item_ret_uint (tcc_tree,
                                     hf_docsis_tlv_tcc_us_ch_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN, &channel_id);
                /* Only perform reassembly on UCD if TLV is reassembled. fragment_end_seq_next added for the rare cases where UCD end is 254 long. */
                if(!pinfo->fragmented && *previous_channel_id != -1) {
                  fragment_end_seq_next(&ucd_reassembly_table, pinfo, *previous_channel_id, NULL);
                }
                *previous_channel_id = channel_id;

              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_NEW_US_CH_ID:
            if (length == 1)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_new_us_ch_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_UCD:
            proto_tree_add_item (tcc_tree, hf_docsis_tlv_tcc_ucd, tvb, pos, length, ENC_NA);
            if (channel_id == -1) {
              channel_id = *previous_channel_id;
            }

            /* Only perform reassembly on UCD if TLV is reassembled */
            if(!pinfo->fragmented) {
              reassembled_ucd_item = proto_tree_add_item(tcc_tree, hf_docsis_ucd_reassembled, tvb, 0, -1, ENC_NA);
              reassembled_ucd_tree = proto_item_add_subtree (reassembled_ucd_item, ett_docsis_ucd_reassembled );

              reassembled_ucd = fragment_add_seq_next(&ucd_reassembly_table,
                                  tvb, pos, pinfo,
                                  channel_id, NULL, /* ID for fragments belonging together */
                                  length, /* fragment length - to the end */
                                  (len == 254)); /* More fragments? */

              if (reassembled_ucd) {
                tvbuff_t *ucd_tvb = NULL;
                ucd_tvb = process_reassembled_data(tvb, pos , pinfo, ".5 Reassembled UCD", reassembled_ucd, &ucd_frag_items,
                                                NULL, reassembled_ucd_tree);

                if (ucd_tvb && tvb_reported_length(ucd_tvb) > 0) {
                  call_dissector (docsis_ucd_handle, ucd_tvb, pinfo, reassembled_ucd_tree);
                }
              }
            }

            break;
          case TLV_TCC_RNG_SID:
            if (length == 2)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_rng_sid, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_INIT_TECH:
            if (length == 1)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_init_tech, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_RNG_PARMS:
            dissect_tcc_rng_parms(tvb, pinfo, tcc_tree, pos, length);
            break;
          case TLV_TCC_DYN_RNG_WIN:
            if (length == 1)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_dyn_rng_win, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_P1_6HI:
            if (length == 1)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_p_16hi, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_ASSIGN_OFDMA_UP_DATA_PROF:
            dissect_tcc_oudp(tvb, tcc_tree, pos, length);
            break;
          case TLV_TCC_EXTENDED_DRW:
            if (length == 1)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_extended_drw, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_EXTENDED_US_RNG_PWR:
            if (length == 2)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_extended_us_rng_pwr, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_OUDP_SOUNDING_SID:
            if (length == 2)
              {
                proto_tree_add_item (tcc_tree,
                                     hf_docsis_tlv_tcc_oudp_sounding_sid, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_TCC_ERR:
            dissect_tcc_err(tvb, pinfo, tcc_tree, pos, length);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, tcc_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_ch_bl_rng(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *chblrng_tree;
  proto_item *chblrng_item;
  int pos = start;

  chblrng_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcp_ch_bl_rng, &chblrng_item,
                                  "..3 Receive Module Channel Block Range (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CH_BL_RNG_MIN_CTR_FREQ:
            if (length == 4)
              {
                proto_tree_add_item (chblrng_tree,
                                     hf_docsis_ch_bl_rng_min_ctr_freq, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, chblrng_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CH_BL_RNG_MAX_CTR_FREQ:
            if (length == 4)
              {
                proto_tree_add_item (chblrng_tree,
                                     hf_docsis_ch_bl_rng_max_ctr_freq, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, chblrng_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, chblrng_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcp_rcv_mod(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rcvmod_tree;
  proto_item *rcvmod_item;
  int pos = start;

  rcvmod_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcp_rcv_mod_enc, &rcvmod_item,
                                  ".4 Receive Module Capability (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case RCV_MOD_ENC_IDX:
            if (length == 1)
              {
                proto_tree_add_item (rcvmod_tree,
                                     hf_docsis_rcv_mod_enc_idx, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvmod_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_MOD_ENC_ADJ_CH:
            if (length == 1)
              {
                proto_tree_add_item (rcvmod_tree,
                                     hf_docsis_rcv_mod_enc_adj_ch, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvmod_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_MOD_ENC_CH_BL_RNG:
            dissect_ch_bl_rng(tvb, pinfo, rcvmod_tree, pos, length);
            break;
          case RCV_MOD_ENC_CTR_FREQ_ASGN:
            if (length == 4)
              {
                proto_tree_add_item (rcvmod_tree,
                                     hf_docsis_rcv_mod_enc_ctr_freq_asgn, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvmod_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_MOD_ENC_RSQ_CH_SUBS_CAP:
            proto_tree_add_item (rcvmod_tree,
                                 hf_docsis_rcv_mod_enc_rsq_ch_subs_cap, tvb, pos,
                                 length, ENC_NA);
            break;
          case RCV_MOD_ENC_CONN:
            proto_tree_add_item (rcvmod_tree,
                                 hf_docsis_rcv_mod_enc_conn, tvb, pos,
                                 length, ENC_NA);
            break;
          case RCV_MOD_ENC_PHY_LAYR_PARMS:
            proto_tree_add_item (rcvmod_tree,
                                 hf_docsis_rcv_mod_enc_phy_layr_parms, tvb, pos,
                                 length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rcvmod_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcp_rcv_ch(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rcvch_tree;
  proto_item *rcvch_item;
  int pos = start;

  rcvch_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcp_rcv_ch, &rcvch_item,
                                  ".5 Receive Channels (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case RCV_CH_IDX:
            if (length == 1)
              {
                proto_tree_add_item (rcvch_tree,
                                     hf_docsis_rcv_ch_idx, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvch_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_CH_CONN:
            proto_tree_add_item (rcvch_tree,
                                 hf_docsis_rcv_ch_conn, tvb, pos,
                                 length, ENC_NA);
            break;
          case RCV_CH_CONN_OFF:
            if (length == 1)
              {
                proto_tree_add_item (rcvch_tree,
                                     hf_docsis_rcv_ch_conn_off, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvch_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_CH_PRIM_DS_CH_IND:
            if (length == 1)
              {
                proto_tree_add_item (rcvch_tree,
                                     hf_docsis_rcv_ch_prim_ds_ch_ind, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvch_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rcvch_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}


static void
dissect_rcp(tvbuff_t * tvb, packet_info * pinfo,
            proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rcp_tree;
  proto_item *rcp_item;
  int pos = start;
  tvbuff_t *vsif_tvb;

  rcp_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcp, &rcp_item,
                                  "48 Receive Channel Profile (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TLV_RCP_ID:
            if (length == 5)
              {
                proto_tree_add_item (rcp_tree,
                                     hf_docsis_tlv_rcp_id, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, rcp_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_RCP_NAME:
            if (length <= 15)
              {
                proto_tree_add_item (rcp_tree,
                                     hf_docsis_tlv_rcp_name, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, rcp_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_RCP_FREQ_SPC:
            if (length == 1)
              {
                proto_tree_add_item (rcp_tree,
                                     hf_docsis_tlv_rcp_freq_spc, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcp_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_RCP_RCV_MOD_ENC:
            dissect_rcp_rcv_mod(tvb, pinfo, rcp_tree, pos, length);
            break;
          case TLV_RCP_RCV_CH:
            dissect_rcp_rcv_ch(tvb, pinfo, rcp_tree, pos, length);
            break;
          case TLV_RCP_VEN_SPEC:
            vsif_tvb = tvb_new_subset_length (tvb, pos, length);
            call_dissector (docsis_vsif_handle, vsif_tvb, pinfo, rcp_tree);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rcp_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc_rcv_mod(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rcvmod_tree;
  proto_item *rcvmod_item;
  int pos = start;

  rcvmod_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_rcv_mod_enc, &rcvmod_item,
                                  ".4 Receive Module Assignment (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case RCV_MOD_ENC_IDX:
            if (length == 1)
              {
                proto_tree_add_item (rcvmod_tree,
                                     hf_docsis_rcc_rcv_mod_enc_idx, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvmod_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_MOD_ENC_CTR_FREQ_ASGN:
            if (length == 4)
              {
                proto_tree_add_item (rcvmod_tree,
                                     hf_docsis_rcc_rcv_mod_enc_ctr_freq_asgn, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvmod_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_MOD_ENC_CONN:
            proto_tree_add_item (rcvmod_tree,
                                 hf_docsis_rcc_rcv_mod_enc_conn, tvb, pos,
                                 length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rcvmod_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc_rcv_ch(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rcvch_tree;
  proto_item *rcvch_item;
  int pos = start;

  rcvch_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_rcv_ch, &rcvch_item,
                                  ".5 Receive Channels (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case RCV_CH_IDX:
            if (length == 1)
              {
                proto_tree_add_item (rcvch_tree,
                                     hf_docsis_rcc_rcv_ch_idx, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvch_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_CH_CONN:
            proto_tree_add_item (rcvch_tree,
                                 hf_docsis_rcc_rcv_ch_conn, tvb, pos,
                                 length, ENC_NA);
            break;
          case RCV_CH_CTR_FREQ_ASGN:
            if (length == 4)
              {
                proto_tree_add_item (rcvch_tree,
                                     hf_docsis_rcc_rcv_ch_ctr_freq_asgn, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvch_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCV_CH_PRIM_DS_CH_IND:
            if (length == 1)
              {
                proto_tree_add_item (rcvch_tree,
                                     hf_docsis_rcc_rcv_ch_prim_ds_ch_ind, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcvch_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rcvch_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc_partial_serv_down_chan(tvbuff_t * tvb, proto_tree *tree, int start, uint16_t len)
{
  proto_tree *rcc_partial_serv_down_chan_tree;
  proto_item *rcc_partial_serv_down_chan_item;
  int pos = start;
  int i = 0;

  rcc_partial_serv_down_chan_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_partial_serv_down_chan, &rcc_partial_serv_down_chan_item,
                                  ".6 Partial Service Downstream Channels (Length = %u)", len);
  for (i=0; i< len; ++i)
    {
      proto_tree_add_item (rcc_partial_serv_down_chan_tree,
                           hf_docsis_tlv_rcc_partial_serv_down_chan_id, tvb, pos+i,
                           1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_rcc_srcc_prim_ds_ch_assign(tvbuff_t * tvb, proto_tree *tree, int start, uint16_t len)
{
  proto_tree *rcc_srcc_prim_ds_assign_tree;
  proto_item *rcc_srcc_prim_ds_assign_item;
  int pos = start;
  int i = 0;

  rcc_srcc_prim_ds_assign_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_srcc_prim_ds_assign, &rcc_srcc_prim_ds_assign_item,
                                  "..1 RCC SRCC Primary Downstream Channel Assignment (Length = %u)", len);
  for (i=0; i< len; ++i)
    {
      proto_tree_add_item (rcc_srcc_prim_ds_assign_tree,
                           hf_docsis_tlv_rcc_srcc_prim_ds_chan_assign_ds_ch_id, tvb, pos+i,
                           1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_rcc_srcc_ds_ch_assign(tvbuff_t * tvb, proto_tree *tree, int start, uint16_t len)
{
  proto_tree *rcc_srcc_ds_assign_tree;
  proto_item *rcc_srcc_ds_assign_item;
  int pos = start;
  int i = 0;

  rcc_srcc_ds_assign_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_srcc_ds_assign, &rcc_srcc_ds_assign_item,
                                  "..2 RCC SRCC Downstream Channel Assignment (Length = %u)", len);
  for (i=0; i< len; ++i)
    {
      proto_tree_add_item (rcc_srcc_ds_assign_tree,
                           hf_docsis_tlv_rcc_srcc_ds_chan_assign_ds_ch_id, tvb, pos+i,
                           1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_rcc_srcc_ds_prof_assign_prof_list(tvbuff_t * tvb, proto_tree *tree, int start, uint16_t len)
{
  proto_tree *rcc_srcc_ds_prof_assign_prof_list_tree;
  proto_item *rcc_srcc_ds_prof_assign_prof_list_item;
  int pos = start;
  int i = 0;

  rcc_srcc_ds_prof_assign_prof_list_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_srcc_ds_prof_assign_prof_list, &rcc_srcc_ds_prof_assign_prof_list_item,
                                  "....2 RCC SRCC Downstream Profile Assignment - Profile List (Length = %u)", len);
  for (i=0; i< len; ++i)
    {
      proto_tree_add_item (rcc_srcc_ds_prof_assign_prof_list_tree,
                           hf_docsis_tlv_rcc_srcc_ds_prof_asssign_prof_list_prof_id, tvb, pos+i,
                           1, ENC_BIG_ENDIAN);
    }
}

static void
dissect_rcc_srcc_ds_prof_assign(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rcc_srcc_ds_prof_assign_tree;
  proto_item *rcc_srcc_ds_prof_assign_item;
  int pos = start;

  rcc_srcc_ds_prof_assign_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_srcc_ds_prof_assign, &rcc_srcc_ds_prof_assign_item,
                                  "..3 RCC SRCC Downstream Profile Assignment(Length = %u)", len);
  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case RCC_SRCC_DS_PROF_ASSIGN_DCID:
            if (length == 1)
              {
                proto_tree_add_item (rcc_srcc_ds_prof_assign_tree,
                                     hf_docsis_tlv_rcc_srcc_ds_prof_assign_dcid, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, rcc_srcc_ds_prof_assign_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCC_SRCC_DS_PROF_ASSIGN_PROF_LIST:
            dissect_rcc_srcc_ds_prof_assign_prof_list(tvb, rcc_srcc_ds_prof_assign_tree, pos, length);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rcc_srcc_ds_prof_assign_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc_srcc(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rcc_srcc_tree;
  proto_item *rcc_srcc_item;
  int pos = start;

  rcc_srcc_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_srcc, &rcc_srcc_item,
                                  ".7 RCC Simplified Receive Channel Configuration (Length = %u)", len);
  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case RCC_SRCC_PRIM_DS_CHAN_ASSIGN:
            dissect_rcc_srcc_prim_ds_ch_assign(tvb, rcc_srcc_tree, pos, length);
            break;
          case RCC_SRCC_DS_CHAN_ASSIGN:
            dissect_rcc_srcc_ds_ch_assign(tvb, rcc_srcc_tree, pos, length);
            break;
          case RCC_SRCC_DS_PROF_ASSIGN:
            dissect_rcc_srcc_ds_prof_assign(tvb, pinfo, rcc_srcc_tree, pos, length);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rcc_srcc_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc_err(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *err_tree;
  proto_item *err_item;
  int pos = start;

  err_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc_rcv_ch, &err_item,
                                  ".254 RCC Error Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case RCC_ERR_MOD_OR_CH:
            if (length == 1)
              {
                proto_tree_add_item (err_tree,
                                     hf_docsis_tlv_rcc_err_mod_or_ch, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCC_ERR_IDX:
            if (length == 1)
              {
                proto_tree_add_item (err_tree,
                                     hf_docsis_tlv_rcc_err_idx, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCC_ERR_PARAM:
            if (length == 1)
              {
                proto_tree_add_item (err_tree,
                                     hf_docsis_tlv_rcc_err_param, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCC_ERR_CODE:
            if (length == 1)
              {
                proto_tree_add_item (err_tree,
                                     hf_docsis_tlv_rcc_err_code, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, err_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case RCC_ERR_MSG:
            proto_tree_add_item (err_tree,
                                 hf_docsis_tlv_rcc_err_msg, tvb, pos,
                                 length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, err_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_rcc(tvbuff_t * tvb, packet_info * pinfo,
            proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *rcc_tree;
  proto_item *rcc_item;
  int pos = start;
  tvbuff_t *vsif_tvb;

  rcc_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_rcc, &rcc_item,
                                  "49 Receive Channel Configuration (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TLV_RCP_ID:
            if (length == 5)
              {
                proto_tree_add_item (rcc_tree,
                                     hf_docsis_tlv_rcc_id, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, rcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_RCP_RCV_MOD_ENC:
            dissect_rcc_rcv_mod(tvb, pinfo, rcc_tree, pos, length);
            break;
          case TLV_RCP_RCV_CH:
            dissect_rcc_rcv_ch(tvb, pinfo, rcc_tree, pos, length);
            break;
          case TLV_RCP_VEN_SPEC:
            vsif_tvb = tvb_new_subset_length (tvb, pos, length);
            call_dissector (docsis_vsif_handle, vsif_tvb, pinfo, rcc_tree);
            break;
          case TLV_RCC_PARTIAL_SERV_DOWN_CHAN:
            dissect_rcc_partial_serv_down_chan(tvb, rcc_tree, pos, length);
            break;
          case TLV_RCC_SRCC:
            dissect_rcc_srcc(tvb, pinfo, rcc_tree, pos, length);
            break;
          case TLV_RCC_PRIM_DOWN_CHAN:
            if (length == 1)
              {
                proto_tree_add_item (rcc_tree,
                                     hf_docsis_tlv_rcc_prim_down_chan, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, rcc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_RCC_ERR:
            dissect_rcc_err(tvb, pinfo, rcc_tree, pos, length);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, rcc_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_dsid_ds_reseq(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *dsid_tree;
  proto_item *dsid_item;
  int pos = start;

  dsid_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_dsid_ds_reseq, &dsid_item,
                                  ".3 Resequencing DSID (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case DS_RESEQ_DSID:
            if (length == 1)
              {
                proto_tree_add_item (dsid_tree,
                                     hf_docsis_ds_reseq_dsid, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dsid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case DS_RESEQ_CH_LST:
            proto_tree_add_item (dsid_tree,
                                 hf_docsis_ds_reseq_ch_lst, tvb, pos,
                                 length, ENC_NA);
            break;
          case DS_RESEQ_WAIT_TIME:
            if (length == 1)
              {
                proto_tree_add_item (dsid_tree,
                                     hf_docsis_ds_reseq_wait_time, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dsid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case DS_RESEQ_WARN_THRESH:
            if (length == 1)
              {
                proto_tree_add_item (dsid_tree,
                                     hf_docsis_ds_reseq_warn_thresh, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dsid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case DS_RESEQ_HO_TIMER:
            if (length == 2)
              {
                proto_tree_add_item (dsid_tree,
                                     hf_docsis_ds_reseq_ho_timer, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dsid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, dsid_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_dsid_mc_addr(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *dsid_tree;
  proto_item *dsid_item;
  int pos = start;

  dsid_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_dsid_mc_addr, &dsid_item,
                                  "..1 Client MAC Address Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case MC_ADDR_ACTION:
            if (length == 1)
              {
                proto_tree_add_item (dsid_tree,
                                     hf_docsis_mc_addr_action, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, dsid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case MC_ADDR_ADDR:
            if (length == 6)
              {
                proto_tree_add_item (dsid_tree,
                                     hf_docsis_mc_addr_addr, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, dsid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
         default:
           dissect_unknown_tlv (tvb, pinfo, dsid_tree, pos - 2, length + 2);
           break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_dsid_mc(tvbuff_t * tvb, packet_info *pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *dsid_tree;
  int pos = start;

  dsid_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_dsid_mc, NULL,
                                  ".4 Multicast Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TLV_DSID_MC_ADDR:
            dissect_dsid_mc_addr(tvb, pinfo, dsid_tree, pos, length);
            break;
          case TLV_DSID_MC_CMIM:
            proto_tree_add_item (dsid_tree,
                                 hf_docsis_tlv_dsid_mc_cmim, tvb, pos,
                                 length, ENC_NA);
            break;
          case TLV_DSID_MC_GROUP:
            proto_tree_add_item (dsid_tree,
                                 hf_docsis_tlv_dsid_mc_group, tvb, pos,
                                 length, ENC_NA);
            break;
          case TLV_DSID_MC_PHS:
            dissect_phs(tvb, pinfo, dsid_tree, pos, length);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, dsid_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_dsid(tvbuff_t * tvb, packet_info *pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *dsid_tree;
  proto_item *dsid_item;
  int pos = start;

  dsid_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_dsid, &dsid_item,
                                  "50 DSID Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TLV_DSID_ID:
            if (length == 3)
              {
                proto_tree_add_item (dsid_tree,
                                     hf_docsis_tlv_dsid_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
               expert_add_info_format(pinfo, dsid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_DSID_ACTION:
            if (length == 1)
              {
                proto_tree_add_item (dsid_tree,
                                     hf_docsis_tlv_dsid_action, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
               expert_add_info_format(pinfo, dsid_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_DSID_DS_RESEQ:
            dissect_dsid_ds_reseq(tvb, pinfo, dsid_tree, pos, length);
            break;
          case TLV_DSID_MC:
            dissect_dsid_mc(tvb, pinfo, dsid_tree, pos, length);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, dsid_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_sec_assoc(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *sec_tree;
  proto_item *sec_item;
  int pos = start;

  sec_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_dsid, &sec_item,
                                  "51 Security Association Encodings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TLV_SEC_ASSOC_ACTION:
            if (length == 1)
              {
                proto_tree_add_item (sec_tree,
                                     hf_docsis_tlv_sec_assoc_action, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, sec_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_SEC_ASSOC_DESC:
            if (length == 14)
              {
                proto_tree_add_item (sec_tree,
                                     hf_docsis_tlv_sec_assoc_desc, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, sec_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, sec_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_ch_asgn(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *asgn_tree;
  proto_item *asgn_item;
  int pos = start;

  asgn_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_ch_asgn, &asgn_item,
                                  "56 Channel Assignment Configuration Settings (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TLV_CH_ASGN_US_CH_ID:
            if (length == 1)
              {
                proto_tree_add_item (asgn_tree,
                                     hf_docsis_ch_asgn_us_ch_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, asgn_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case TLV_CH_ASGN_RX_FREQ:
            if (length == 4)
              {
                proto_tree_add_item (asgn_tree,
                                     hf_docsis_ch_asgn_rx_freq, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, asgn_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, asgn_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_cmts_mc_sess_enc(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *mc_tree;
  proto_item *mc_item;
  int pos = start;

  mc_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_cmts_mc_sess_enc, &mc_item,
                                  "64 CMTS Static Multicast Session Encoding (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case CMTS_MC_SESS_ENC_GRP:
            if (length == 4 || length == 16)
              {
                proto_tree_add_item (mc_tree,
                                     hf_docsis_cmts_mc_sess_enc_grp, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, mc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CMTS_MC_SESS_ENC_SRC:
            if (length == 4 || length == 16)
              {
                proto_tree_add_item (mc_tree,
                                     hf_docsis_cmts_mc_sess_enc_src, tvb, pos,
                                     length, ENC_NA);
              }
            else
              {
                expert_add_info_format(pinfo, mc_item, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
              }
            break;
          case CMTS_MC_SESS_ENC_CMIM:
            proto_tree_add_item (mc_tree,
                                     hf_docsis_cmts_mc_sess_enc_cmim, tvb, pos,
                                     length, ENC_NA);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, mc_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static void
dissect_em_id_list_for_cm(tvbuff_t * tvb, proto_tree *tree, int start, uint16_t len)
{
  proto_tree *em_id_list_tree;
  proto_item *em_id_list_item;
  int pos = start;

  em_id_list_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_em_id_list_for_cm, &em_id_list_item,
                                  "78 Energy Management Identifier List for CM (Length = %u)", len);

  while (pos < (start + len))
    {
      proto_tree_add_item (em_id_list_tree, hf_docsis_tlv_em_id_list_for_cm_em_id, tvb, pos, 2, ENC_BIG_ENDIAN);
      pos+=2;
    }
}

static void
dissect_fdx_tg_assignment(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type, length;
  proto_tree *tg_assignment_tree;
  proto_item *tg_assignment_item;
  int pos = start;
  tvbuff_t *rba_tvb;

  tg_assignment_tree =
    proto_tree_add_subtree_format(tree, tvb, start, len, ett_docsis_tlv_tg_assignment, &tg_assignment_item,
                                  "85 FDX Transmission Group Assignment (Length = %u)", len);

  while (pos < (start + len))
    {
      type = tvb_get_uint8 (tvb, pos++);
      length = tvb_get_uint8 (tvb, pos++);
      switch (type)
        {
          case TLV_FDX_TG_ASSIGNMENT_TG_ID:
            if (length == 1)
              {
                proto_tree_add_item (tg_assignment_tree,
                                     hf_docsis_tlv_fdx_tg_assignment_tg_id, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tg_assignment_item, &ei_docsis_tlv_tlvlen_bad,
                                       "Wrong TLV length: %u", length);
              }
            break;
          case TLV_FDX_TG_ASSIGNMENT_RBA_TYPE:
            if (length == 1)
              {
                proto_tree_add_item (tg_assignment_tree,
                                     hf_docsis_tlv_fdx_tg_assignment_rba_type, tvb, pos,
                                     length, ENC_BIG_ENDIAN);
              }
            else
              {
                expert_add_info_format(pinfo, tg_assignment_item, &ei_docsis_tlv_tlvlen_bad,
                                       "Wrong TLV length: %u", length);
              }
            break;
          case TLV_FDX_TG_ASSIGNMENT_RBA_MESSAGE:
            rba_tvb = tvb_new_subset_length (tvb, pos, length);
            call_dissector (docsis_rba_handle, rba_tvb, pinfo, tg_assignment_tree);
            break;
          default:
            dissect_unknown_tlv (tvb, pinfo, tg_assignment_tree, pos - 2, length + 2);
            break;
        }                       /* switch */
      pos = pos + length;
    }                           /* while */
}

static int
dissect_docsis_tlv (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *tlv_tree;
  int pos = 0;
  int total_len;
  uint8_t type, length;
  uint16_t x;
  int previous_channel_id = -1;

  total_len = tvb_reported_length_remaining (tvb, 0);

  {
    it =
      proto_tree_add_protocol_format (tree, proto_docsis_tlv, tvb, 0,
                                      total_len, "TLV Data");
    tlv_tree = proto_item_add_subtree (it, ett_docsis_tlv);
    while (pos < total_len)
      {
        type = tvb_get_uint8 (tvb, pos++);
        length = tvb_get_uint8 (tvb, pos++);
        switch (type)
          {
            case TLV_DOWN_FREQ:
              /* This is ugly.  There are multiple type 1 TLVs that may appear
               * in the TLV data, the problem is that they are dependent on
               * message type.  */
              if (length == 4)
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_down_freq, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              else if (length == 1)
                proto_tree_add_item (tlv_tree, hf_docsis_tlv_rng_tech, tvb,
                                     pos, length, ENC_BIG_ENDIAN);
              else
                dissect_doc10cos (tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_CHNL_ID:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_upstream_chid,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_NET_ACCESS:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_net_access,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_COS:
              dissect_cos (tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_MODEM_CAP:
              dissect_modemcap (tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_CM_MIC:
              if (length == 16)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_cm_mic, tvb,
                                       pos, length, ENC_NA);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_CMTS_MIC:
              if (length == 16)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_cmts_mic, tvb,
                                       pos, length, ENC_NA);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_VENDOR_ID:
              if (length == 3)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_vendor_id, tvb,
                                       pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_SW_UPG_FILE:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_sw_file, tvb, pos,
                                   length, ENC_ASCII);
              break;
            case TLV_SNMP_WRITE_CTRL:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_snmp_access, tvb,
                                   pos, length, ENC_NA);
              break;
            case TLV_SNMP_OBJECT:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_snmp_obj, tvb,
                                   pos, length, ENC_NA);
              break;
            case TLV_MODEM_IP:
              if (length == 4)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_modem_addr,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_SVC_UNAVAIL:
              if (length == 3)
                {
                  dissect_svc_unavail(tvb, tlv_tree, pos, length);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_ETHERNET_MAC:
              if (length == 6)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_cpe_ethernet,
                                       tvb, pos, length, ENC_NA);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_TEL_SETTINGS:
              break;
            case TLV_BPI_CONFIG:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_bpi, tvb,
                                   pos, length, ENC_NA);
              break;
            case TLV_MAX_CPES:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_max_cpe, tvb,
                                       pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_TFTP_TIME:
              if (length == 4)
                {
                  proto_tree_add_item (tlv_tree,
                                       hf_docsis_tlv_tftp_server_timestamp,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_TFTP_MODEM_ADDRESS:
              if (length == 4)
                {
                  proto_tree_add_item (tlv_tree,
                                       hf_docsis_tlv_tftp_prov_modem_address,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_SW_UPG_SRVR:
              if (length == 4)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_sw_upg_srvr,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_UPSTREAM_CLASSIFIER:
            case TLV_DOWN_CLASSIFIER:
              dissect_classifiers (tvb, pinfo, tlv_tree, pos, length, type);
              break;
            case TLV_UPSTREAM_SERVICE_FLOW:
            case TLV_DOWN_SERVICE_FLOW:
              dissect_sflow (tvb, pinfo, tlv_tree, pos, length, type);
              break;
            case TLV_PHS:
              dissect_phs (tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_HMAC_DIGEST:
              if (length == 20)
                {
                  proto_tree_add_item (tlv_tree,
                                       hf_docsis_tlv_hmac_digest, tvb,
                                       pos, length, ENC_NA);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_MAX_CLASSIFIERS:
              if (length == 2)
                {
                  proto_tree_add_item (tlv_tree,
                                       hf_docsis_tlv_max_classifiers, tvb,
                                       pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_PRIVACY_ENABLE:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_privacy_enable,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_AUTH_BLOCK:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_auth_block,
                                   tvb, pos, length, ENC_NA);
              break;
            case TLV_KEY_SEQ_NUM:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_key_seq_num, tvb,
                                       pos, length, ENC_NA);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_MFGR_CVC:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_mfgr_cvc,
                                   tvb, pos, length, ENC_NA);
              break;
            case TLV_COSIGN_CVC:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_cosign_cvc,
                                   tvb, pos, length, ENC_NA);
              break;
            case TLV_SNMPV3_KICKSTART:
              dissect_snmpv3_kickstart(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_SUBS_MGMT_CTRL:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_subs_mgmt_ctrl,
                                   tvb, pos, length, ENC_NA);
              break;
            case TLV_SUBS_MGMT_CPE:
              if ((length % 4) == 0)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_subs_mgmt_ip_table,
                                       tvb, pos, length, ENC_NA);
                  for (x = 0; x < length; x+=4)
                    {
                      proto_tree_add_item (tlv_tree,
                                           hf_docsis_tlv_subs_mgmt_ip_entry,
                                           tvb, pos + x, 4, ENC_BIG_ENDIAN);
                    }
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_SUBS_MGMT_FLTR:
              proto_tree_add_item (tlv_tree,
                                   hf_docsis_tlv_subs_mgmt_filter_grps,
                                   tvb, pos, length, ENC_NA);
              break;
            case TLV_SNMPV3_NTFY_RCVR:
              proto_tree_add_item(tlv_tree,
                                  hf_docsis_tlv_snmpv3_ntfy_rcvr,
                                  tvb, pos, length, ENC_NA);
              break;
            case TLV_ENABLE_20_MODE:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_enable_20_mode,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_ENABLE_TEST_MODES:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_enable_test_modes,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_DS_CH_LIST:
              dissect_ds_ch_list(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_MC_MAC_ADDRESS:
              if (length == 6)
                {
                  proto_tree_add_item(tlv_tree, hf_docsis_tlv_mc_mac_address,
                                      tvb, pos, length, ENC_NA);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_DOCSIS_EXTENSION_FIELD:
              dissect_docsis_extension_field(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_VENDOR_SPEC:
              dissect_vendor_specific_capabilities(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_DUT_FILTER:
              dissect_dut_filter(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_TCC:
              dissect_tcc(tvb, pinfo, tlv_tree, pos, length, &previous_channel_id);
              break;
            case TLV_SID_CL:
              dissect_sid_cl(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_RCP:
              dissect_rcp(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_RCC:
              dissect_rcc(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_DSID:
              dissect_dsid(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_SEC_ASSOC:
              dissect_sec_assoc(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_INIT_CH_TIMEOUT:
              if (length == 2)
                {
                  proto_tree_add_item(tlv_tree, hf_docsis_tlv_init_ch_timeout,
                                      tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_CH_ASGN:
              dissect_ch_asgn(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_CM_INIT_REASON:
              if (length == 1)
                {
                  proto_tree_add_item(tlv_tree, hf_docsis_tlv_cm_init_reason,
                                      tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_SW_UPG_SRVR_IPV6:
              if (length == 16)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_sw_upg_srvr_ipv6,
                                       tvb, pos, length, ENC_NA);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_TFTP_PROV_CM_IPV6_ADDR:
              if (length == 16)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_tftp_prov_cm_ipv6_addr,
                                       tvb, pos, length, ENC_NA);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_US_DROP_CLFY:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_us_drop_clfy,
                                   tvb, pos, length, ENC_NA);
              break;
            case TLV_SUBS_MGMT_IPV6_LST:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_subs_mgmt_ipv6_lst,
                                   tvb, pos, length, ENC_NA);
              break;
            case TLV_US_DROP_CLFY_GROUP_ID:
              proto_tree_add_item (tlv_tree, hf_docsis_tlv_us_drop_clfy_group_id,
                                   tvb, pos, length, ENC_NA);
              break;
            case TLV_SUBS_MGMT_CTRL_MAX_CPE_IPV6:
              if (length == 2)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_subs_mgmt_ctrl_max_cpe_ipv6,
                                       tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_CMTS_MC_SESS_ENC:
              dissect_cmts_mc_sess_enc(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_EM_MODE_INDICATOR:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_em_mode_ind, tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_EM_ID_LIST_FOR_CM:
              dissect_em_id_list_for_cm(tvb, tlv_tree, pos, length);
              break;
            case TLV_FDX_TG_ASSIGNMENT:
              dissect_fdx_tg_assignment(tvb, pinfo, tlv_tree, pos, length);
              break;
            case TLV_FDX_RESET:
              if (length == 1)
                {
                  proto_tree_add_item (tlv_tree, hf_docsis_tlv_fdx_reset, tvb, pos, length, ENC_BIG_ENDIAN);
                }
              else
                {
                  expert_add_info_format(pinfo, it, &ei_docsis_tlv_tlvlen_bad, "Wrong TLV length: %u", length);
                }
              break;
            case TLV_END:
              break;
            default:
              dissect_unknown_tlv (tvb, pinfo, tlv_tree, pos - 2, length + 2);
              break;
          }                     /* switch(type) */

        pos = pos + length;
      }                         /* while (pos < total_len) */
  }                             /* if (tree) */

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_tlv (void)
{
  static hf_register_info hf[] = {
    {&hf_docsis_tlv_down_freq,
     {"1 Downstream Frequency", "docsis_tlv.downfreq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_upstream_chid,
     {"2 Upstream Channel ID", "docsis_tlv.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Service Identifier", HFILL}
    },
    {&hf_docsis_tlv_net_access,
     {"3 Network Access", "docsis_tlv.netaccess",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      "Network Access TLV", HFILL}
    },
#if 0
    {&hf_docsis_tlv_cos,
     {"4 COS Encodings", "docsis_tlv.cos",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_cos_id,
     {".1 Class ID", "docsis_tlv.cos.id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cos_sid,
     {".2 Service ID", "docsis_tlv.cos.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cos_max_down,
     {".2 Max Downstream Rate (bps)", "docsis_tlv.cos.maxdown",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cos_max_up,
     {".3 Max Upstream Rate (bps)", "docsis_tlv.cos.maxup",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cos_up_chnl_pri,
     {".4 Upstream Channel Priority", "docsis_tlv.cos.upchnlpri",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cos_min_grntd_up,
     {".5 Guaranteed Upstream Rate", "docsis_tlv.cos.mingrntdup",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Guaranteed Minimum Upstream Data Rate", HFILL}
    },
    {&hf_docsis_tlv_cos_max_up_burst,
     {".6 Maximum Upstream Burst", "docsis_tlv.cos.maxupburst",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cos_privacy_enable,
     {".7 COS Privacy Enable", "docsis_tlv.cos.privacy_enable",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      "Class of Service Privacy Enable", HFILL}
    },
#if 0
    {&hf_docsis_tlv_mcap,
     {"5 Modem Capabilities", "docsis_tlv.mcap",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_mcap_concat,
     {".1 Concatenation Support", "docsis_tlv.mcap.concat",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_docs_ver,
     {".2 Docsis Version", "docsis_tlv.map.docsver",
      FT_UINT8, BASE_DEC, VALS (docs_ver_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_frag,
     {".3 Fragmentation Support", "docsis_tlv.mcap.frag",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_phs,
     {".4 PHS Support", "docsis_tlv.mcap.phs",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_igmp,
     {".5 IGMP Support", "docsis_tlv.mcap.igmp",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_privacy,
     {".6 Privacy Support", "docsis_tlv.mcap.privacy",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_said,
     {".7 # Downstream SAIDs Supported", "docsis_tlv.mcap.downsaid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Downstream Said Support", HFILL}
    },
    {&hf_docsis_tlv_mcap_up_sid,
     {".8 # Upstream Service Flows Supported", "docsis_tlv.mcap.upsid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_8021P_filter,
     {".9 802.1P Filtering Support", "docsis_tlv.mcap.dot1pfiltering",
      FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_8021Q_filter,
     {".9 802.1Q Filtering Support", "docsis_tlv.mcap.dot1qfilt",
      FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x40,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_xmit_eq_taps_per_sym,
     {".10 Xmit Equalizer Taps/Sym", "docsis_tlv.mcap.tapspersym",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Transmit Equalizer Taps per Symbol", HFILL}
    },
    {&hf_docsis_tlv_mcap_xmit_eq_taps,
     {".11 # Xmit Equalizer Taps", "docsis_tlv.mcap.numtaps",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Number of Transmit Equalizer Taps", HFILL}
    },
    {&hf_docsis_tlv_mcap_dcc,
     {".12 DCC Support", "docsis_tlv.mcap.dcc",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ip_filters,
     {".13 IP Filters Support","docsis_tlv.mcap.ipfilters",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_llc_filters,
     {".14 LLC Filters Support","docsis_tlv.mcap.llcfilters",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_exp_unicast_sid,
     {".15 Expanded Unicast SID Space","docsis_tlv.mcap.exucsid",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_rnghoff_cm,
     {".16 Ranging Hold-Off (CM)","docsis_tlv.mcap.rnghoffcm",
      FT_BOOLEAN, 32, TFS(&tfs_on_off), 0x00000001,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_rnghoff_erouter,
     {".16 Ranging Hold-Off (ePS or eRouter)",
      "docsis_tlv.mcap.rnghofferouter",
      FT_BOOLEAN, 32, TFS(&tfs_on_off), 0x00000002,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_rnghoff_emta,
     {".16 Ranging Hold-Off (eMTA or EDVA)",
      "docsis_tlv.mcap.rnghoffemta",
      FT_BOOLEAN, 32, TFS(&tfs_on_off), 0x00000004,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_rnghoff_estb,
     {".16 Ranging Hold-Off (DSG/eSTB)",
      "docsis_tlv.mcap.rnghoffestb",
      FT_BOOLEAN, 32, TFS(&tfs_on_off), 0x00000008,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_l2vpn,
     {".17 L2VPN Capability","docsis_tlv.mcap.l2vpn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_l2vpn_esafe,
     {".18 L2VPN eSAFE Host Capability","docsis_tlv.mcap.l2vpnesafe",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dut_filtering,
     {".19 Downstream Unencrypted Traffic (DUT) Filtering",
      "docsis_tlv.mcap.dut",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_us_freq_range,
     {".20 Upstream Frequency Range Support",
      "docsis_tlv.mcap.usfreqrng",
      FT_UINT8, BASE_DEC, VALS (docsis_freq_rng_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_us_srate_160,
     {".21 Upstream Symbol Rate 160ksps supported",
      "docsis_tlv.mcap.srate160",
      FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_us_srate_320,
     {".21 Upstream Symbol Rate 320ksps supported",
      "docsis_tlv.mcap.srate320",
      FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_us_srate_640,
     {".21 Upstream Symbol Rate 640ksps supported",
      "docsis_tlv.mcap.srate640",
      FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_us_srate_1280,
     {".21 Upstream Symbol Rate 1280ksps supported",
      "docsis_tlv.mcap.srate1280",
      FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x08,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_us_srate_2560,
     {".21 Upstream Symbol Rate 2560ksps supported",
      "docsis_tlv.mcap.srate2560",
      FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x10,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_us_srate_5120,
     {".21 Upstream Symbol Rate 5120ksps supported",
      "docsis_tlv.mcap.srate5120",
      FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x20,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_sac,
     {".22 Selectable Active Code Mode 2 Support","docsis_tlv.mcap.sac",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_code_hop_mode2,
     {".23 Code Hopping Mode 2 Support","docsis_tlv.mcap.codehopm2",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_mtc,
     {".24 Multiple Transmit Channel Support","docsis_tlv.mcap.mtc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_512_msps_utc,
     {".25 5.12 Msps Upstream Transmit Channel Support",
      "docsis_tlv.mcap.512mspsutc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_256_msps_utc,
     {".26 2.56 Msps Upstream Transmit Channel Support",
      "docsis_tlv.mcap.256mspsutc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_total_sid_cluster,
     {".27 Total SID Cluster Support","docsis_tlv.mcap.totalsidcl",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_sid_per_sf,
     {".28 SID Clusters per Service Flow Support",
      "docsis_tlv.mcap.sidpersf",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_mrc,
     {".29 Multiple Receive Channel Support","docsis_tlv.mcap.mrc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_total_dsid,
     {".30 Total Downstream Service ID (DSID) Support",
      "docsis_tlv.mcap.totaldsid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_reseq_dsid,
     {".31 Resequencing Downstream Service ID (DSID) Support",
      "docsis_tlv.mcap.reseqdsid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_mc_dsid,
     {".32 Multicast Downstream Service ID (DSID) Support",
      "docsis_tlv.mcap.mcdsid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_mc_dsid_fwd,
     {".33 Multicast DSID Forwarding","docsis_tlv.mcap.mcdsidfwd",
      FT_UINT8, BASE_DEC, VALS (mc_dsid_fwd_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_fctype_fwd,
     {".34 Frame Control Type Forwarding Capability",
      "docsis_tlv.mcap.fctypefwd",
      FT_UINT8, BASE_DEC, VALS (fctype_fwd_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dpv_path,
     {".35 DPV Capability (per Path)","docsis_tlv.mcap.dpvpath",
      FT_UINT8, BASE_DEC, NULL, 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dpv_packet,
     {".35 DPV Capability (per Packet)","docsis_tlv.mcap.dpvpacket",
      FT_UINT8, BASE_DEC, NULL, 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ugs,
     {".36 Unsolicited Grant Service Support","docsis_tlv.mcap.ugs",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_map_ucd,
     {".37 MAP and UCD Receipt Support","docsis_tlv.mcap.mapucd",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_udc,
     {".38 Upstream Drop Classifier Support","docsis_tlv.mcap.udc",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ipv6,
     {".39 IPv6 Support","docsis_tlv.mcap.ipv6",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_on_off), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ext_us_trans_power,
     {".40 Extended Upstream Transmit Power Capability",
      "docsis_tlv.mcap.extustrpwr",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_em,
     {".44 Energy Management Capabilities", "docsis_tlv.mcap.em",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_em_1x1,
     {"Energy Management 1x1 Feature",
      "docsis_tlv.mcap.em.1x1",
      FT_BOOLEAN, 32, TFS (&sup_unsup_tfs), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_em_light_sleep,
     {"DOCSIS Light Sleep Mode",
      "docsis_tlv.mcap.em.light_sleep",
      FT_BOOLEAN, 32, TFS (&sup_unsup_tfs), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_cm_status_ack,
     {".46 CM-STATUS_ACK",
      "docsis_tlv.mcap.cm_status_ack",
      FT_UINT8, BASE_DEC, VALS(sup_unsup_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_em_pref,
     {".47 Energy Management Preference",
      "docsis_tlv.mcap.em_pref",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_em_pref_1x1,
     {"Energy Management 1x1 Feature",
      "docsis_tlv.mcap.em_pref.1x1",
      FT_BOOLEAN, 32, NULL, 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_em_pref_dls,
     {"DOCSIS Light Sleep Mode",
      "docsis_tlv.mcap.em_pref.dls",
      FT_BOOLEAN, 32, NULL, 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ext_pkt_len_sup_cap,
     {".48 Extended Packet Length Support Capability",
      "docsis_tlv.mcap.ext_pkt_len_sup_cap",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_mult_recv_chan_sup,
     {".49 OFDM Multiple Receive Channel Support",
      "docsis_tlv.mcap.ofdm_mult_recv_chan_sup",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_mult_trans_chan_sup,
     {".50 OFDMA Multiple Transmit Channel Support",
      "docsis_tlv.mcap.ofdma_mult_trans_chan_sup",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_ofdm_prof_sup,
     {".51 Downstream OFDM Profile Support",
      "docsis_tlv.mcap.down_ofdm_prof_sup",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup,
     {".52 Downstream OFDM channel subcarrier QAM modulation support",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_reserved,
     {"Reserved",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.reserved",
      FT_BOOLEAN, 16, NULL, 0x802B,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_qpsk,
     {"QPSK",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.qpsk",
      FT_BOOLEAN, 16, NULL, 0x0004,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_16qam,
     {"16-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.16qam",
      FT_BOOLEAN, 16, NULL, 0x0010,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_64qam,
     {"64-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.64qam",
      FT_BOOLEAN, 16, NULL, 0x0040,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_128qam,
     {"128-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.128qam",
      FT_BOOLEAN, 16, NULL, 0x0080,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_256qam,
     {"256-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.256qam",
      FT_BOOLEAN, 16, NULL, 0x0100,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_512qam,
     {"512-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.512qam",
      FT_BOOLEAN, 16, NULL, 0x0200,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_1024qam,
     {"1024-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.1024qam",
      FT_BOOLEAN, 16, NULL, 0x0400,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_2048qam,
     {"2048-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.2048qam",
      FT_BOOLEAN, 16, NULL, 0x0800,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_4096qam,
     {"4096-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.4096qam",
      FT_BOOLEAN, 16, NULL, 0x1000,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_8192qam,
     {"8192-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.8192qam",
      FT_BOOLEAN, 16, NULL, 0x2000,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup_16384qam,
     {"16384-QAM",
      "docsis_tlv.mcap.down_ofdm_chan_subc_qam_mod_sup.16384qam",
      FT_BOOLEAN, 16, NULL, 0x4000,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup,
     {".53 Upstream OFDMA channel subcarrier QAM modulation support",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_reserved,
     {"Reserved",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.reserved",
      FT_BOOLEAN, 16, NULL, 0x8003,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_qpsk,
     {"QPSK",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.qpsk",
      FT_BOOLEAN, 16, NULL, 0x0004,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_8qam,
     {"8-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.8qam",
      FT_BOOLEAN, 16, NULL, 0x0008,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_16qam,
     {"16-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.16qam",
      FT_BOOLEAN, 16, NULL, 0x0010,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_32qam,
     {"32-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.32qam",
      FT_BOOLEAN, 16, NULL, 0x0020,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_64qam,
     {"64-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.64qam",
      FT_BOOLEAN, 16, NULL, 0x0040,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_128qam,
     {"128-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.128qam",
      FT_BOOLEAN, 16, NULL, 0x0080,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_256qam,
     {"256-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.256qam",
      FT_BOOLEAN, 16, NULL, 0x0100,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_512qam,
     {"512-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.512qam",
      FT_BOOLEAN, 16, NULL, 0x0200,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_1024qam,
     {"1024-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.1024qam",
      FT_BOOLEAN, 16, NULL, 0x0400,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_2048qam,
     {"2048-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.2048qam",
      FT_BOOLEAN, 16, NULL, 0x0800,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_4096qam,
     {"4096-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.4096qam",
      FT_BOOLEAN, 16, NULL, 0x1000,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_8192qam,
     {"8192-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.8192qam",
      FT_BOOLEAN, 16, NULL, 0x2000,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup_16384qam,
     {"16384-QAM",
      "docsis_tlv.mcap.up_ofdma_chan_subc_qam_mod_sup.16384qam",
      FT_BOOLEAN, 16, NULL, 0x4000,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_lower_band_edge_conf,
     {".54 Downstream Lower Band Edge Configuration",
      "docsis_tlv.mcap.down_lower_band_edge_conf",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_lower_band_edge_conf_108,
     {"Downstream Frequency Range starting from 108 MHz",
      "docsis_tlv.mcap.down_lower_band_edge_conf.108mhz",
      FT_BOOLEAN, 8, NULL, 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_lower_band_edge_conf_258,
     {"Downstream Frequency Range starting from 258 MHz",
      "docsis_tlv.mcap.down_lower_band_edge_conf.258mhz",
      FT_BOOLEAN, 8, NULL, 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_upper_band_edge_conf,
     {".55 Downstream Upper Band Edge Configuration",
      "docsis_tlv.mcap.down_upper_band_edge_conf",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_upper_band_edge_conf_1218,
     {"Downstream Frequency Range up to 1218 MHz",
      "docsis_tlv.mcap.down_upper_band_edge_conf.1218mhz",
      FT_BOOLEAN, 8, NULL, 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_upper_band_edge_conf_1794,
     {"Downstream Frequency Range up to 1794 MHz",
      "docsis_tlv.mcap.down_upper_band_edge_conf.1794mhz",
      FT_BOOLEAN, 8, NULL, 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_down_upper_band_edge_conf_1002,
     {"Downstream Frequency Range up to 1002 MHz",
      "docsis_tlv.mcap.down_upper_band_edge_conf.1002mhz",
      FT_BOOLEAN, 8, NULL, 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_up_upper_band_edge_conf,
     {".56 Diplexer Upstream Upper Band Edge Configuration",
      "docsis_tlv.mcap.dipl_up_upper_band_edge_conf",
      FT_UINT8, BASE_DEC, VALS(dipl_up_upper_band_edge_conf_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_docsis_time_prot_mode,
     {".57 DOCSIS Time Protocol Mode",
      "docsis_tlv.mcap.docsis_time_prot_mode",
      FT_UINT8, BASE_DEC, VALS(docsis_time_prot_mode_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_docsis_time_prot_perf_sup,
     {".58 DOCSIS Time Protocol Performance Support",
      "docsis_tlv.mcap.docsis_time_prot_perf_sup",
      FT_UINT8, BASE_DEC, VALS(docsis_time_prot_perf_sup_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_pmax,
     {".59 Pmax",
      "docsis_tlv.mcap.pmax",
      FT_UINT16, BASE_CUSTOM, CF_FUNC(fourth_dbmv), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_down_lower_band_edge,
     {".60 Diplexer Downstream Lower Band Edge",
      "docsis_tlv.mcap.dipl_down_lower_band_edge",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_down_lower_band_edge_108,
     {"Downstream Frequency Range starting from 108 MHz",
      "docsis_tlv.mcap.dipl_down_lower_band_edge.108mhz",
      FT_BOOLEAN, 8, NULL, 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_down_lower_band_edge_258,
     {"Downstream Frequency Range starting from 258 MHz",
      "docsis_tlv.mcap.dipl_down_lower_band_edge.258mhz",
      FT_BOOLEAN, 8, NULL, 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_down_upper_band_edge,
     {".61 Diplexer Downstream Upper Band Edge",
      "docsis_tlv.mcap.dipl_down_upper_band_edge",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1218,
     {"Downstream Frequency Range up to 1218 MHz",
      "docsis_tlv.mcap.dipl_down_upper_band_edge.1218mhz",
      FT_BOOLEAN, 8, NULL, 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1794,
     {"Downstream Frequency Range up to 1794 MHz",
      "docsis_tlv.mcap.dipl_down_upper_band_edge.1794mhz",
      FT_BOOLEAN, 8, NULL, 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_down_upper_band_edge_1002,
     {"Downstream Frequency Range up to 1002 MHz",
      "docsis_tlv.mcap.dipl_down_upper_band_edge.1002mhz",
      FT_BOOLEAN, 8, NULL, 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_up_upper_band_edge,
     {".62 Diplexer Upstream Upper Band Edge",
      "docsis_tlv.mcap.dipl_up_upper_band_edge",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_up_upper_band_edge_42,
     {"Upstream Frequency Range up to 42 MHz",
      "docsis_tlv.mcap.dipl_up_upper_band_edge.42mhz",
      FT_BOOLEAN, 8, NULL, 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_up_upper_band_edge_65,
     {"Upstream Frequency Range up to 65 MHz",
      "docsis_tlv.mcap.dipl_up_upper_band_edge.65mhz",
      FT_BOOLEAN, 8, NULL, 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_up_upper_band_edge_85,
     {"Upstream Frequency Range up to 85 MHz",
      "docsis_tlv.mcap.dipl_up_upper_band_edge.85mhz",
      FT_BOOLEAN, 8, NULL, 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_up_upper_band_edge_117,
     {"Upstream Frequency Range up to 117 MHz",
      "docsis_tlv.mcap.dipl_up_upper_band_edge.117mhz",
      FT_BOOLEAN, 8, NULL, 0x08,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_dipl_up_upper_band_edge_204,
     {"Upstream Frequency Range up to 204 MHz",
      "docsis_tlv.mcap.dipl_up_upper_band_edge.204mhz",
      FT_BOOLEAN, 8, NULL, 0x10,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_advanced_band_plan,
     {".63 Advanced Band Plan",
      "docsis_tlv.mcap.advanced_band_plan",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_advanced_band_plan_fdx_l,
     {"FDX-L support",
      "docsis_tlv.mcap.advanced_band_plan.fdx_l",
      FT_BOOLEAN, 8, NULL, 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_advanced_band_plan_fdx,
     {"FDX support",
      "docsis_tlv.mcap.advanced_band_plan.fdx",
      FT_BOOLEAN, 8, NULL, 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_advanced_band_plan_fdd,
     {"FDD support",
      "docsis_tlv.mcap.advanced_band_plan.fdd",
      FT_BOOLEAN, 8, NULL, 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_advanced_band_plan_reserved,
     {"Reserved",
      "docsis_tlv.mcap.advanced_band_plan.reserved",
      FT_BOOLEAN, 8, NULL, 0xF8,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_ext_sf_cluster_assign_sup,
     {".74 Extended Service Flow SID Cluster Assignments Support",
      "docsis_tlv.mcap.ext_sf_cluster_assign_sup",
      FT_UINT8, BASE_DEC, VALS(docsis_mcap_ext_sf_cluster_assign_sup_vals), 0x0,
      "The ability of CM to handle TLV 89", HFILL}
    },
    {&hf_docsis_tlv_mcap_low_latency_sup,
     {".76 Low Latency Support",
      "docsis_tlv.mcap.low_latency_sup",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_adv_down_lower_band_edge_conf,
     {".79 Advanced Downstream Lower Band Edge Configuration",
      "docsis_tlv.mcap.adv_down_lower_band_edge_conf",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_adv_down_upper_band_edge_conf,
     {".80 Advanced Downstream Upper Band Edge Configuration",
      "docsis_tlv.mcap.adv_down_upper_band_edge_conf",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_adv_up_upper_band_edge_conf,
     {".81 Advanced Upstream Upper Band Edge Configuration",
      "docsis_tlv.mcap.adv_up_upper_band_edge_conf",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_adv_down_lower_band_edge_option,
     {"Advanced Diplexer Downstream Lower Band Edge Option",
      "docsis_tlv.mcap.adv_down_lower_band_edge_option",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_adv_down_upper_band_edge_option,
     {"Advanced Diplexer Downstream Upper Band Edge Option",
      "docsis_tlv.mcap.adv_down_upper_band_edge_option",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_adv_up_upper_band_edge_option,
     {"Advanced Diplexer Upstream Upper Band Edge Option",
      "docsis_tlv.mcap.adv_up_upper_band_edge_option",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mcap_extended_power_options,
     {".85 Extended Power Options",
      "docsis_tlv.mcap.extended_power_options",
      FT_UINT8, BASE_DEC, VALS(extended_power_options_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cm_mic,
     {"6 CM MIC", "docsis_tlv.cmmic",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Cable Modem Message Integrity Check", HFILL}
    },
    {&hf_docsis_tlv_cmts_mic,
     {"7 CMTS MIC", "docsis_tlv.cmtsmic",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "CMTS Message Integrity Check", HFILL}
    },
    {&hf_docsis_tlv_vendor_id,
     {"8 Vendor ID", "docsis_tlv.vendorid",
      FT_UINT24, BASE_OUI, NULL, 0x0,
      "Vendor Identifier", HFILL}
    },
    {&hf_docsis_tlv_sw_file,
     {"9 Software Upgrade File", "docsis_tlv.sw_upg_file",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_snmp_access,
     {"10 SNMP Write Access", "docsis_tlv.snmp_access",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_snmp_obj,
     {"11 SNMP Object", "docsis_tlv.snmp_obj",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_modem_addr,
     {"12 Modem IP Address", "docsis_tlv.modemaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_svc_unavail,
     {"13 Service Not Available Response", "docsis_tlv.svcunavail",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_svc_unavail_classid,
     {"Service Not Available: (Class ID)", "docsis_tlv.svcunavail.classid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_svc_unavail_type,
     {"Service Not Available (Type)", "docsis_tlv.svcunavail.type",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_svc_unavail_code,
     {"Service Not Available (Code)", "docsis_tlv.svcunavail.code",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cpe_ethernet,
     {"14 CPE Ethernet Addr", "docsis_tlv.cpe_ether",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_bpi,
     {"17 Baseline Privacy Encoding", "docsis_tlv.bpi",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_max_cpe,
     {"18 Max # of CPE's", "docsis_tlv.maxcpe",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Max Number of CPE's", HFILL}
    },
    {&hf_docsis_tlv_tftp_server_timestamp,
     {"19 TFTP Server Timestamp", "docsis_tlv.tftp_time",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tftp_prov_modem_address,
     {"20 TFTP Server Provisioned Modem Addr", "docsis_tlv.tftpmodemaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sw_upg_srvr,
     {"21 Software Upgrade Server", "docsis_tlv.sw_upg_srvr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_upclsfr,
     {"22 Upstream Classifier", "docsis_tlv.upclsfr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_downclsfr,
     {"23 Downstream Classifier", "docsis_tlv.downclsfr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_clsfr_ref,
     {".1 Classifier Ref", "docsis_tlv.clsfr.ref",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Classifier Reference", HFILL}
    },
    {&hf_docsis_tlv_clsfr_id,
     {".2 Classifier ID", "docsis_tlv.clsfr.id",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_clsfr_sflow_ref,
     {".3 Service Flow Ref", "docsis_tlv.clsfr.sflowref",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Flow Reference", HFILL}
    },
    {&hf_docsis_tlv_clsfr_sflow_id,
     {".4 Service Flow ID", "docsis_tlv.clsfr.sflowid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_clsfr_rule_pri,
     {".5 Rule Priority", "docsis_tlv.clsfr.rulepri",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_clsfr_act_state,
     {".6 Activation State", "docsis_tlv.clsfr.actstate",
      FT_BOOLEAN, BASE_NONE, TFS (&tfs_active_inactive), 0x0,
      "Classifier Activation State", HFILL}
    },
    {&hf_docsis_tlv_clsfr_dsc_act,
     {".7 DSC Action", "docsis_tlv.clsfr.dscact",
      FT_UINT8, BASE_DEC, VALS (dsc_act_vals), 0x0,
      "Dynamic Service Change Action", HFILL}
    },
#if 0
    {&hf_docsis_tlv_clsfr_err,
     {".8 Error Encodings", "docsis_tlv.clsfr.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_clsfr_err_param,
     {"..1 Param Subtype", "docsis_tlv.clsfr.err.param",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Parameter Subtype", HFILL}
    },
    {&hf_docsis_tlv_clsfr_err_code,
     {"..2 Error Code", "docsis_tlv.clsfr.err.code",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_clsfr_err_msg,
     {"..3 Error Message", "docsis_tlv.clsfr.err.msg",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_ipclsfr,
     {".9 IP Classifier Encodings", "docsis_tlv.clsfr.ip",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_ipclsfr_tosmask,
     {"..1 Type Of Service Mask", "docsis_tlv.clsfr.ip.tosmask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_ipproto,
     {"..2 IP Protocol", "docsis_tlv.clsfr.ip.ipproto",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_src,
     {"..3 Source Address", "docsis_tlv.clsfr.ip.src",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_dst,
     {"..4 Destination Address", "docsis_tlv.clsfr.ip.dst",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_srcmask,
     {"..5 Source Mask", "docsis_tlv.clsfr.ip.smask",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_dstmask,
     {"..6 Destination Mask", "docsis_tlv.clsfr.ip.dmask",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_sport_start,
     {"..7 Source Port Start", "docsis_tlv.clsfr.ip.sportstart",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TCP/UDP Source Port Start", HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_sport_end,
     {"..8 Source Port End", "docsis_tlv.clsfr.ip.sportend",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TCP/UDP Source Port End", HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_dport_start,
     {"..9 Dest Port Start", "docsis_tlv.clsfr.ip.dportstart",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TCP/UDP Destination Port Start", HFILL}
    },
    {&hf_docsis_tlv_ipclsfr_dport_end,
     {"..10 Dest Port End", "docsis_tlv.clsfr.ip.dportend",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TCP/UDP Destination Port End", HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_tc_low,
     {"tc-low", "docsis_tlv.clsfr.ip6.tc.low",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_tc_high,
     {"tc-high", "docsis_tlv.clsfr.ip6.tc.high",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_tc_mask,
     {"tc-mask", "docsis_tlv.clsfr.ip6.tc.mask",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_flow_label,
     {"..2 Flow Label", "docsis_tlv.clsfr.ip6.flowlabel",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_next_header,
     {"..3 Next Header", "docsis_tlv.clsfr.ip6.nextheader",
      FT_UINT16, BASE_DEC, VALS(next_header_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_src,
     {"..4 Source Address", "docsis_tlv.clsfr.ip6.src",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_src_prefix_length,
     {"..5 Source Prefix Length", "docsis_tlv.clsfr.ip6.src_prefix_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_dst,
     {"..6 Destination Address", "docsis_tlv.clsfr.ip6.dst",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ip6clsfr_dst_prefix_length,
     {"..7 Destination Prefix Length", "docsis_tlv.clsfr.ip6.dst_prefix_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_ethclsfr,
     {".10 Ethernet Classifier Encodings", "docsis_tlv.clsfr.eth",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_ethclsfr_dmac,
     {"..1 Dest MAC Address", "docsis_tlv.clsfr.eth.dmac",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      "Destination MAC Address", HFILL}
    },
    {&hf_docsis_tlv_ethclsfr_smac,
     {"..2 Source MAC Address", "docsis_tlv.clsfr.eth.smac",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ethclsfr_ethertype,
     {"..3 Ethertype", "docsis_tlv.clsfr.eth.ethertype",
      FT_UINT24, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_dot1qclsfr,
     {".11 802.1Q Classifier Encodings", "docsis_tlv.clsfr.dot1q",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_dot1qclsfr_user_pri,
     {"..1 User Priority", "docsis_tlv.clsfr.dot1q.userpri",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_dot1qclsfr_vlanid,
     {"..2 VLAN ID", "docsis_tlv.clsfr.dot1q.ethertype",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_dot1qclsfr_vendorspec,
     {"..43 Vendor Specific Encodings", "docsis_tlv.clsfr.dot1q.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_clsfr_vendor_spc,
     {".43 Vendor Specific Encodings", "docsis_tlv.clsfr.vendor",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_upsflow,
     {"24 Upstream Service Flow", "docsis_tlv.upsflow",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_downsflow,
     {"25 Downstream Service Flow", "docsis_tlv.downsflow",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_sflow_ref,
     {".1 Service Flow Ref", "docsis_tlv.sflow.ref",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Service Flow Reference", HFILL}
    },
    {&hf_docsis_tlv_sflow_id,
     {".2 Service Flow ID", "docsis_tlv.sflow.id",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_sid,
     {".3 Service Identifier", "docsis_tlv.sflow.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_classname,
     {".4 Service Class Name", "docsis_tlv.sflow.cname",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_sflow_err,
     {".5 Error Encodings", "docsis_tlv.sflow.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_sflow_err_param,
     {"..1 Param Subtype", "docsis_tlv.sflow.err.param",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Parameter Subtype", HFILL}
    },
    {&hf_docsis_tlv_sflow_err_code,
     {"..2 Error Code", "docsis_tlv.sflow.err.code",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_err_msg,
     {"..3 Error Message", "docsis_tlv.sflow.err.msg",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_qos_param,
     {".6 QOS Parameter Set", "docsis_tlv.sflow.qos",
      FT_UINT8, BASE_HEX, VALS (qos_param_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_traf_pri,
     {".7 Traffic Priority", "docsis_tlv.sflow.trafpri",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_max_sus,
     {".8 Maximum Sustained Traffic Rate (bps)", "docsis_tlv.sflow.maxtrafrate",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_max_burst,
     {".9 Maximum Burst (bps)", "docsis_tlv.sflow.maxburst",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_min_traf,
     {".10 Minimum Traffic Rate (bps)", "docsis_tlv.sflow.mintrafrate",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_ass_min_pkt_size,
     {".11 Assumed Min Reserved Packet Size", "docsis_tlv.sflow.assumed_min_pkt_size",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Assumed Minimum Reserved Packet Size", HFILL}
    },
    {&hf_docsis_tlv_sflow_timeout_active,
     {".12 Timeout for Active Params (secs)", "docsis_tlv.sflow.act_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_timeout_admitted,
     {".13 Timeout for Admitted Params (secs)", "docsis_tlv.sflow.adm_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_max_down_latency,
     {".14 Maximum Downstream Latency (usec)", "docsis_tlv.sflow.max_down_lat",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_max_concat_burst,
     {".14 Max Concat Burst", "docsis_tlv.sflow.maxconcat",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Max Concatenated Burst", HFILL}
    },
    {&hf_docsis_tlv_sflow_sched_type,
     {".15 Scheduling Type", "docsis_tlv.sflow.schedtype",
      FT_UINT32, BASE_HEX, VALS (sched_type_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_down_reseq,
     {".17 Downstream Resequencing", "docsis_tlv.sflow.down_reseq",
      FT_UINT8, BASE_DEC, VALS(down_reseq_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_pol,
     {".16 Request/Transmission Policy", "docsis_tlv.sflow.reqxmitpol",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_all_cm_broadcast,
     {"Service flow use \"all CMs\" broadcast request opportunities", "docsis_tlv.sflow.reqxmitpol.all_cm_broadcast",
      FT_BOOLEAN, 32, TFS(&tfs_must_not_must), 0x00000001,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_priority_multicast,
     {"Service flow use priority multicast request opportunities", "docsis_tlv.sflow.reqxmitpol.priority_multicast",
      FT_BOOLEAN, 32, TFS(&tfs_must_not_must), 0x00000002,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_req_data_requests,
     {"Service flow use Request/Data opportunities for requests", "docsis_tlv.sflow.reqxmitpol.req_data_requests",
      FT_BOOLEAN, 32, TFS(&tfs_must_not_must), 0x00000004,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_req_data_data,
     {"Service flow use Request/Data opportunities for data", "docsis_tlv.sflow.reqxmitpol.req_data_data",
      FT_BOOLEAN, 32, TFS(&tfs_must_not_must), 0x00000008,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_piggy_back,
     {"Service flow use piggy back requests with data", "docsis_tlv.sflow.reqxmitpol.piggy_back",
      FT_BOOLEAN, 32, TFS(&tfs_must_not_must), 0x00000010,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_concatenate_data,
     {"Service flow concatenate data", "docsis_tlv.sflow.reqxmitpol.concatenate_data",
      FT_BOOLEAN, 32, TFS(&tfs_must_not_must), 0x00000020,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_fragment,
     {"Service flow fragment data", "docsis_tlv.sflow.reqxmitpol.fragment",
      FT_BOOLEAN, 32, TFS(&tfs_must_not_must), 0x00000040,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_suppress_payload,
     {"Service flow suppress payload headers", "docsis_tlv.sflow.reqxmitpol.suppress_payload",
      FT_BOOLEAN, 32, TFS(&tfs_must_not_must), 0x00000080,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_reqxmit_drop_packets,
     {"Service flow drop packets that do not fit in the UGS size", "docsis_tlv.sflow.reqxmitpol.drop_packets",
      FT_BOOLEAN, 32, TFS(&tfs_must_must_not), 0x00000100,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_nominal_polling,
     {".17 Nominal Polling Interval(usec)", "docsis_tlv.sflow.nominal_polling",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_tolerated_jitter,
     {".18 Tolerated Poll Jitter (usec)", "docsis_tlv.sflow.toler_jitter",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_ugs_size,
     {".19 Unsolicited Grant Size (bytes)", "docsis_tlv.sflow.ugs_size",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_nom_grant_intvl,
     {".20 Nominal Grant Interval (usec)", "docsis_tlv.sflow.nom_grant_intvl",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_tol_grant_jitter,
     {".21 Tolerated Grant Jitter (usec)", "docsis_tlv.sflow.tol_grant_jitter",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_grants_per_intvl,
     {".22 Grants Per Interval", "docsis_tlv.sflow.grnts_per_intvl",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_ip_tos_overwrite,
     {".23 IP TOS Overwrite", "docsis_tlv.sflow.iptos_overwrite",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_ugs_timeref,
     {".24 UGS Time Reference", "docsis_tlv.sflow.ugs_timeref",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_cont_req_backoff_window_mult,
     {".25 Multiplier to Contention Request Backoff Window", "docsis_tlv.sflow.cont_req_backoff_window_mult",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_num_of_bytes_requested_mult,
     {".26 Multiplier to Number of Bytes Requested", "docsis_tlv.sflow.num_of_bytes_requested_mult",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_peak_traffic_rate,
     {".27 Peak Traffic Rate", "docsis_tlv.sflow.peak_traffic_rate",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_req_attr_mask,
     {".31 Required Attribute Mask", "docsis_tlv.sflow.req_attr_mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_forb_attr_mask,
     {".32 Forbidden Attribute Mask", "docsis_tlv.sflow.forb_attr_mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_attr_aggr_rule_mask,
     {".33 Attribute Aggregation Rule Mask", "docsis_tlv.sflow.attr_aggr_rule_mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sflow_vendor_spec,
     {".43 Vendor Specific Encodings", "docsis_tlv.sflow.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_phs,
     {"26 PHS Rules", "docsis_tlv.phs",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_phs_class_ref,
     {".1 Classifier Reference", "docsis_tlv.phs.classref",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_class_id,
     {".2 Classifier ID", "docsis_tlv.phs.classid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_sflow_ref,
     {".3 Service flow reference", "docsis_tlv.phs.sflowref",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_sflow_id,
     {".4 Service flow ID", "docsis_tlv.phs.sflowid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_dsc_action,
     {".5 DSC Action", "docsis_tlv.phs.dscaction",
      FT_UINT8, BASE_DEC, VALS (action_vals), 0x0,
      "Dynamic Service Change Action", HFILL}
    },
#if 0
    {&hf_docsis_tlv_phs_err,
     {".6 Error Encodings", "docsis_tlv.phs.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_phs_err_param,
     {"..1 Param Subtype", "docsis_tlv.phs.err.param",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Parameter Subtype", HFILL}
    },
    {&hf_docsis_tlv_phs_err_code,
     {"..2 Error Code", "docsis_tlv.phs.err.code",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_err_msg,
     {"..3 Error Message", "docsis_tlv.phs.err.msg",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_phsf,
     {".7 PHS Field", "docsis_tlv.phs.phsf",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_phsi,
     {".8 PHS Index", "docsis_tlv.phs.phsi",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_phsm,
     {".9 PHS Mask", "docsis_tlv.phs.phsm",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_phss,
     {".10 PHS Size", "docsis_tlv.phs.phss",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_phs_dbc_action,
     {".13 PHS Dynamic Bonding Change Action", "docsis_tlv.phs.dbc_action",
      FT_UINT8, BASE_DEC, VALS (dbc_action_vals), 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_phs_phsv,
     {".11 PHS Verify", "docsis_tlv.phs.phsv",
      FT_BOOLEAN, BASE_NONE, TFS (&verify_tfs), 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_phs_vendorspec,
     {".43 PHS Vendor Specific", "docsis_tlv.phs.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_hmac_digest,
     {"27 HMAC Digest", "docsis_tlv.hmac_digest",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_max_classifiers,
     {"28 Max # of Classifiers", "docsis_tlv.maxclass",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_privacy_enable,
     {"29 Privacy Enable", "docsis_tlv.bpi_en",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_auth_block,
     {"30 Auth Block", "docsis_tlv.auth_block",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_key_seq_num,
     {"31 Key Sequence Number", "docsis_tlv.key_seq",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mfgr_cvc,
     {"32 Manufacturer CVC", "docsis_tlv.mfgr_cvc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cosign_cvc,
     {"33 Co-Signer CVC", "docsis_tlv.cosign_cvc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_snmpv3_kick,
     {"34 SNMPv3 Kickstart Value", "docsis_tlv.snmpv3",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_snmpv3_kick_name,
     {".1 SNMPv3 Kickstart Security Name", "docsis_tlv.snmpv3.secname",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_snmpv3_kick_publicnum,
     {".2 SNMPv3 Kickstart Manager Public Number", "docsis_tlv.snmpv3.publicnum",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_subs_mgmt_ctrl,
     {"35 Subscriber Management Control", "docsis_tlv.subsmgmtctrl",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_subs_mgmt_ip_table,
     {"36 Subscriber Management CPE IP Table", "docsis_tlv.subsiptable",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_subs_mgmt_ip_entry,
     {"Subscriber Management CPE IP Entry", "docsis_tlv.subsipentry",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_subs_mgmt_filter_grps,
     {"37 Subscriber Management Filter Groups", "docsis_tlv.subsfltrgrps",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_snmpv3_ntfy_rcvr,
     {"38 SNMPv3 Notification Receiver", "docsis_tlv.snmpv3ntfy",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_enable_20_mode,
     {"39 Enable 2.0 Mode", "docsis_tlv.enable20mode",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_enable_test_modes,
     {"40 Enable Test Modes", "docsis_tlv.enabletestmodes",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_ds_ch_list,
     {"41 Downstream Channel List", "docsis_tlv.dschlist",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ds_ch_list_single,
     {".1 Single Downstream Channel", "docsis_tlv.dschlist.single",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_single_ch_timeout,
     {"..1 Timeout", "docsis_tlv.dschlist.single.timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_single_ch_freq,
     {"..2 Timeout", "docsis_tlv.dschlist.single.freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_ds_ch_list_range,
     {".2 Downstream Frequency Range", "docsis_tlv.dschlist.range",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_freq_rng_timeout,
     {"..1 Timeout", "docsis_tlv.dschlist.range.timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_freq_rng_start,
     {"..2 Frequency Start", "docsis_tlv.dschlist.range.start",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_freq_rng_end,
     {"..3 Frequency End", "docsis_tlv.dschlist.range.end",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_freq_rng_step,
     {"..4 Frequency Step Size", "docsis_tlv.dschlist.range.step",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_ds_ch_list_default_timeout,
     {".3 Default Scanning Timeout", "docsis_tlv.dschlist.defaulttimeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_mc_mac_address,
     {"42 Static Multicast MAC Address", "docsis_tlv.mcmac",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_vendor_spec,
     {"43 Vendor Specific Encodings", "docsis_tlv.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_rng_tech,
     {"Ranging Technique", "docsis_tlv.rng_tech",
      FT_UINT8, BASE_DEC, VALS (rng_tech_vals), 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_dut_filter,
     {"45 Downstream Unencrypted Traffic Filtering Encoding", "docsis_tlv.dut",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_dut_filter_control,
     {".1 DUT Control", "docsis_tlv.dut.control",
      FT_BOOLEAN, BASE_NONE, TFS (&ena_dis_tfs), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_dut_filter_cmim,
     {".2 DUT CMIM", "docsis_tlv.dut.cmim",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_tcc,
     {"46 Transmit Channel Configuration", "docsis_tlv.tcc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_tcc_refid,
     {".1 TCC Reference ID", "docsis_tlv.tcc.refid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_us_ch_action,
     {".2 Upstream Channel Action", "docsis_tlv.tcc.uschact",
      FT_UINT8, BASE_DEC, VALS (us_ch_action_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_us_ch_id,
     {".3 Upstream Channel ID", "docsis_tlv.tcc.uschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_new_us_ch_id,
     {".4 New Upstream Channel ID", "docsis_tlv.tcc.newuschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_ucd,
     {".5 Upstream Channel Descriptor", "docsis_tlv.tcc.ucd",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_rng_sid,
     {".6 Ranging SID", "docsis_tlv.tcc.rngsid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_init_tech,
     {".7 Initialization Technique", "docsis_tlv.tcc.inittech",
      FT_UINT8, BASE_DEC, VALS (init_tech_vals), 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_tcc_rng_parms,
     {".8 Ranging Parameters", "docsis_tlv.tcc.rngparms",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    /* TODO: wrong label? */
    {&hf_docsis_rng_parms_us_ch_id,
     {"..1 Ranging Reference Channel ID", "docsis_tlv.tcc.rngparms.uschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
    },
    {&hf_docsis_rng_parms_time_off_int,
     {"..2 Timing Offset, Integer Part", "docsis_tlv.tcc.rngparms.timeoffint",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rng_parms_time_off_frac,
     {"..3 Timing Offset, Fractional Part", "docsis_tlv.tcc.rngparms.timeofffrac",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rng_parms_power_off,
     {"..4 Power Offset", "docsis_tlv.tcc.rngparms.poweroff",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rng_parms_freq_off,
     {"..5 Frequency Offset", "docsis_tlv.tcc.rngparms.freqoff",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_dyn_rng_win,
     {".9 Dynamic Range Window", "docsis_tlv.tcc.dynrngwin",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(fourth_db), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_p_16hi,
     {".10 P1.6hi", "docsis_tlv.tcc.p16hi",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(fourth_dbmv), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_oudp_iuc,
     {"OUDP IUC", "docsis_tlv.tcc.oudp_iuc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_extended_drw,
     {".14 Extended Dynamic Range Window", "docsis_tlv.tcc.extended_dynrngwin",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(fourth_db), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_extended_us_rng_pwr,
     {".15 Extended US Ranging Power", "docsis_tlv.tcc.extended_us_rng_pwr",
      FT_UINT16, BASE_CUSTOM, CF_FUNC(fourth_db), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tcc_oudp_sounding_sid,
     {".16 OUDP Sounding SID", "docsis_tlv.tcc.oudp_sounding_sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_tcc_err,
     {".10 TCC Error Encodings", "docsis_tlv.tcc.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tcc_err_subtype,
     {"..1 TCC Subtype", "docsis_tlv.tcc.err.subtype",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tcc_err_code,
     {"..2 Error Code", "docsis_tlv.tcc.err.code",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tcc_err_msg,
     {"..3 Error Message", "docsis_tlv.tcc.err.msg",
      FT_STRINGZ, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_sid_cl,
     {"47 Service Flow SID Cluster Assignments", "docsis_tlv.sid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_sid_cl_sf_id,
     {".1 Service Flow ID", "docsis_tlv.sid.sfid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_sid_cl_enc,
     {".2 SID Cluster Encodings", "docsis_tlv.sid.enc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_sid_cl_enc_id,
     {"..1 SID Cluster ID", "docsis_tlv.sid.enc.id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_sid_cl_enc_map,
     {"..2 SID-to-Channel Mapping", "docsis_tlv.sid.enc.map",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_sid_cl_map_us_ch_id,
     {"...1 Upstream Channel ID", "docsis_tlv.sid.enc.map.uschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_sid_cl_map_sid,
     {"...2 SID", "docsis_tlv.sid.enc.map.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_sid_cl_map_action,
     {"...3 SID-to-Channel Mapping Action", "docsis_tlv.sid.enc.map.action",
      FT_UINT8, BASE_DEC, VALS (sid_ch_map_vals), 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_sid_cl_so_crit,
     {".3 SID Cluster Switchover Criteria", "docsis_tlv.sid.socrit",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_sid_cl_so_max_req,
     {"..1 Maximum Requests per SID Cluster", "docsis_tlv.sid.socrit.maxreq",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_sid_cl_so_max_out_bytes,
     {"..2 Maximum Outstanding Bytes per SID Cluster", "docsis_tlv.sid.socrit.maxoutbytes",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_sid_cl_so_max_req_bytes,
     {"..3 Maximum Total Bytes Requested per SID Cluster", "docsis_tlv.sid.socrit.maxreqbytes",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_sid_cl_so_max_time,
     {"..4 Maximum Time in the SID Cluster", "docsis_tlv.sid.socrit.maxtime",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_rcp,
     {"48 Receive Channel Profile", "docsis_tlv.rcp",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_rcp_id,
     {".1 RCP-ID", "docsis_tlv.rcp.id",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcp_name,
     {".2 RCP Name", "docsis_tlv.rcp.name",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcp_freq_spc,
     {".3 RCP Center Frequency Spacing", "docsis_tlv.rcp.freq_spc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_rcp_rcv_mod_enc,
     {".4 Receive Module Capability", "docsis_tlv.rcp.rcv_mod_enc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Receive Module Encoding", HFILL}
    },
#endif
    {&hf_docsis_rcv_mod_enc_idx,
     {"..1 Receive Module Index", "docsis_tlv.rcp.rcv_mod_enc.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcv_mod_enc_adj_ch,
     {"..2 Adjacent Channels", "docsis_tlv.rcp.rcv_mod_enc.adj_ch",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_rcv_mod_enc_ch_bl_rng,
     {"..3 Channel Block Range", "docsis_tlv.rcp.rcv_mod_enc.ch_bl_rng",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_rcv_mod_enc_ctr_freq_asgn,
     {"..4 First Channel Center Frequency Assignment", "docsis_tlv.rcv_mod_enc.ctr_freq_asgn",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ch_bl_rng_min_ctr_freq,
     {"...1 Minimum Center Frequency", "docsis_tlv.rcp.rcv_mod_enc.ch_bl_rng.min_ctr_freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ch_bl_rng_max_ctr_freq,
     {"...2 Maximum Center Frequency", "docsis_tlv.rcp.rcv_mod_enc.ch_bl_rng.max_ctr_freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcv_mod_enc_rsq_ch_subs_cap ,
     {"..5 Resequencing Channel Subset Capability", "docsis_tlv.rcp.rcv_mod_enc.rsq_ch_subs_cap",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcv_mod_enc_conn ,
     {"..6 Receive Module Connectivity", "docsis_tlv.rcp.rcv_mod_enc.conn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcv_mod_enc_phy_layr_parms,
     {"..7 Physical Layer Parameter", "docsis_tlv.rcp.rcv_mod_enc.phy_layr_parms",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_rcp_rcv_ch,
     {".5 Receive Channel", "docsis_tlv.rcp.rcv_ch",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_rcv_ch_idx,
     {"..1 Receive Channel Index", "docsis_tlv.rcp.rcv_ch.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcv_ch_conn,
     {"..2 Receive Channel Connectivity", "docsis_tlv.rcp.rcv_ch.conn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcv_ch_conn_off,
     {"..3 Receive Channel Connected Offset", "docsis_tlv.rcp.rcv_ch.conn_off",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcv_ch_prim_ds_ch_ind,
     {"..5 Primary Downstream Channel Indicator", "docsis_tlv.rcp.rcv_ch.prim_ds_ch_ind",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_rcp_ven_spec,
     {".43 Vendor Specific Encodings", "docsis_tlv.rcp.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc,
     {"49 Receive Channel Configuration", "docsis_tlv.rcc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_rcc_id,
     {".1 Assigned RCP-ID", "docsis_tlv.rcc.id",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_rcc_rcv_mod_enc,
     {".4 Receive Module Assignment", "docsis_tlv.rcc.rcv_mod_enc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_rcc_rcv_mod_enc_idx,
     {"..1 Receive Module Index", "docsis_tlv.rcc.rcc_rcv_mod_enc.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcc_rcv_mod_enc_ctr_freq_asgn,
     {"..4 First Channel Center Frequency Assignment", "docsis_tlv.rcc.rcv_mod_enc.ctr_freq_asgn",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcc_rcv_mod_enc_conn ,
     {"..6 Receive Module Connectivity", "docsis_tlv.rcc.rcv_mod_enc.conn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_rcc_rcv_ch,
     {".5 Receive Channel", "docsis_tlv.rcc.rcv_ch",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_rcc_rcv_ch_idx,
     {"..1 Receive Channel Index", "docsis_tlv.rcc.rcv_ch.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcc_rcv_ch_conn,
     {"..2 Receive Channel Connectivity", "docsis_tlv.rcc.rcv_ch.conn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcc_rcv_ch_ctr_freq_asgn,
     {"..4 Receive Channel Center Frequency Assignment", "docsis_tlv.rcc.rcv_ch.ctr_freq_asgn",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rcc_rcv_ch_prim_ds_ch_ind,
     {"..5 Primary Downstream Channel Indicator", "docsis_tlv.rcc.rcv_ch.prim_ds_ch_ind",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_rcc_part_serv_ds_ch,
     {".6 Partial Service Downstream Channels", "docsis_tlv.rcc.part_serv_ds_ch",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_ven_spec,
     {".43 Vendor Specific Encodings", "docsis_tlv.rcc.vendorspec",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_err,
     {".254 RCC Error Encodings", "docsis_tlv.rcc.err",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_rcc_partial_serv_down_chan_id,
     {"Downstream Channel ID", "docsis_tlv.rcc.partial_serv_down_chan.ds_ch_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_srcc_prim_ds_chan_assign_ds_ch_id,
     {"Downstream Channel ID", "docsis_tlv.rcc.srcc.prim_ds_chann_assign.ds_ch_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_srcc_ds_chan_assign_ds_ch_id,
     {"Downstream Channel ID", "docsis_tlv.rcc.srcc.ds_chann_assign.ds_ch_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_srcc_ds_prof_assign_dcid,
     {"....1 DCID", "docsis_tlv.rcc.srcc.ds_prof_assign.prof_list.dcid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_srcc_ds_prof_asssign_prof_list_prof_id,
     {"Profile ID", "docsis_tlv.rcc.srcc.ds_prof_assign.prof_list.prof_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_prim_down_chan,
     {".8 Primary Downstream Channel", "docsis_tlv.rcc.prim_down_chan",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_err_mod_or_ch,
     {".1 Receive Modul or Receive Channel", "docsis_tlv.rcc.err.mod_or_ch",
      FT_UINT8, BASE_DEC, VALS (mod_or_ch_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_err_idx,
     {".2 Receive Modul/Channel Index", "docsis_tlv.rcc.err.idx",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_err_param,
     {".3 Reported Parameter", "docsis_tlv.rcc.err.param",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_err_code,
     {".4 Error Code", "docsis_tlv.rcc.err.code",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_rcc_err_msg,
     {".5 Error Message", "docsis_tlv.rcc.err.msg",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_dsid,
     {"50 DSID Encodings", "docsis_tlv.dsid",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_dsid_id,
     {".1 Downstream Service Identifier (DSID)", "docsis_tlv.dsid.id",
      FT_UINT24, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_dsid_action,
     {".2 DSID Action", "docsis_tlv.dsid.action",
      FT_UINT8, BASE_DEC, VALS (dsid_action_vals), 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_dsid_ds_reseq,
     {".3 Downstream Resequencing Encodings", "docsis_tlv.dsid.ds_reseq",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_ds_reseq_dsid,
     {"..1 Resequencing DSID", "docsis_tlv.dsid.ds_reseq.dsid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ds_reseq_ch_lst,
     {"..2 Downstream Resequencing Channel List", "docsis_tlv.dsid.ds_reseq.ch_lst",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ds_reseq_wait_time,
     {"..3 Downstream Resequencing Wait Time", "docsis_tlv.dsid.ds_reseq.wait_time",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ds_reseq_warn_thresh,
     {"..4 Resequencing Warn Threshold", "docsis_tlv.dsid.ds_reseq.warn_thresh",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ds_reseq_ho_timer,
     {"..5 CM-Status max. Event Hold-Off Timer (Out-of-Range Events)", "docsis_tlv.dsid.ds_reseq.ho_timer",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_dsid_mc,
     {".4 Multicast Encodings", "docsis_tlv.dsid.mc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_dsid_mc_addr,
     {"..1 Client MAC Address Encodings", "docsis_tlv.dsid.mc.addr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_mc_addr_action,
     {"...1 Client MAC Address Action", "docsis_tlv.dsid.mc.addr.action",
      FT_UINT8, BASE_DEC, VALS (add_del_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mc_addr_addr,
     {"...2 Client MAC Address", "docsis_tlv.dsid.mc.addr.addr",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_dsid_mc_cmim,
     {"..2 Multicast CM Interface Mask", "docsis_tlv.dsid.mc.cmim",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_dsid_mc_group,
     {"..3 Multicast Group MAC Addresses", "docsis_tlv.dsid.mc.group",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_dsid_mc_phs,
     {"..26 Payload Header Suppression Encodings", "docsis_tlv.dsid.mc.phs",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sec_assoc,
     {"51 Security Association Encodings", "docsis_tlv.sec_assoc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_tlv_sec_assoc_action,
     {".1 SA Action", "docsis_tlv.sec_assoc.action",
      FT_UINT8, BASE_DEC, VALS (add_del_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sec_assoc_desc,
     {".23 SA Descriptor", "docsis_tlv.sec_assoc.desc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_init_ch_timeout,
     {"52 Initializing Channel Timeout", "docsis_tlv.init_ch_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_ch_asgn,
     {"56 Channel Assignment Configuration Settings", "docsis_tlv.ch_asgn",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_ch_asgn_us_ch_id,
     {".1 Upstream Channel ID", "docsis_tlv.ch_asgn.us_ch_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ch_asgn_rx_freq,
     {".2 Rx Frequency", "docsis_tlv.ch_asgn.rx_freq",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_cm_init_reason,
     {"57 CM Initialization Reason", "docsis_tlv.cm_init_reason",
      FT_UINT16, BASE_DEC, VALS (init_reason_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_sw_upg_srvr_ipv6,
     {"58 Software Upgrade Server IPv6", "docsis_tlv.sw_upg_srvr_ipv6",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_tftp_prov_cm_ipv6_addr,
     {"59 TFTP Server Provisioned Modem IPv6 Address", "docsis_tlv.tftp_prov_cm_ipv6_addr",
      FT_IPv6, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_us_drop_clfy,
     {"60 Upstream Drop Packet Classification Encoding", "docsis_tlv.us_drop_clfy",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_subs_mgmt_ipv6_lst,
     {"61 Subscriber Management CPE IPv6 Prefix List", "docsis_tlv.subs_mgmt_ipv6_lst",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_us_drop_clfy_group_id,
     {"62 Upstream Drop Classifier Group ID", "docsis_tlv.us_drop_clfy_group_id",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_subs_mgmt_ctrl_max_cpe_ipv6,
     {"63 Subscriber Management Control Max CPE IPv6 Prefix", "docsis_tlv.subs_mgmt_ctrl_max_cpe_ipv6",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
#if 0
    {&hf_docsis_tlv_cmts_mc_sess_enc,
     {"64 CMTS Static Multicast Session Encoding", "docsis_tlv.cmts_mc_sess_enc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
#endif
    {&hf_docsis_cmts_mc_sess_enc_grp,
     {".1 Multicast Group Address", "docsis_tlv.cmts_mc_sess_enc.grp",
      FT_IPXNET, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmts_mc_sess_enc_src,
     {".2 Source IP Address", "docsis_tlv.cmts_mc_sess_enc.src",
      FT_IPXNET, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmts_mc_sess_enc_cmim,
     {".3 CMIM", "docsis_tlv.cmts_mc_sess_enc.cmim",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_em_mode_ind,
      {"75 Energy Management Mode Indicator", "docsis_tlv.em_mode_ind",
       FT_UINT8, BASE_DEC, VALS(em_mode_ind_vals), 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_tlv_em_id_list_for_cm_em_id,
      {"Energy Management Identifier", "docsis_tlv.em_id_list_for_cm.em_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_tlv_fdx_tg_assignment_tg_id,
      {"Transmission Group ID", "docsis_tlv.fdx_tg_assignment_tg_id",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_tlv_fdx_tg_assignment_rba_type,
      {"RBA Type", "docsis_tlv.fdx_tg_assignment_rba_type",
       FT_UINT8, BASE_DEC, VALS (rba_type_vals), 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_tlv_fdx_reset,
     {"86 FDX Reset", "docsis_tlv.fdx_reset",
      FT_UINT8, BASE_DEC, VALS (fdx_reset_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_tlv_unknown,
      {"Unknown TLV", "docsis_tlv.unknown",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_tlv_unknown_type,
      {"Type", "docsis_tlv.unknown.type",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_tlv_unknown_length,
      {"Length", "docsis_tlv.unknown.length",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_tlv_unknown_value,
      {"Value", "docsis_tlv.unknown.value",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_ucd_fragment_overlap,
     { "Fragment overlap", "docsis_tlv.ucd.fragment.overlap",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Fragment overlaps with other fragments", HFILL}
    },
    { &hf_docsis_ucd_fragment_overlap_conflict,
     { "Conflicting data in fragment overlap", "docsis_tlv.ucd.fragment.overlap.conflict",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Overlapping fragments contained conflicting data", HFILL}
    },
    { &hf_docsis_ucd_fragment_multiple_tails,
     { "Multiple tail fragments found", "docsis_tlv.ucd.fragment.multipletails",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Several tails were found when defragmenting the packet", HFILL}
    },
    { &hf_docsis_ucd_fragment_too_long_fragment,
     { "Fragment too long", "docsis_tlv.ucd.fragment.toolongfragment",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Fragment contained data past end of packet", HFILL}
    },
    { &hf_docsis_ucd_fragment_error,
     { "Defragmentation error", "docsis_tlv.ucd.fragment.error",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "Defragmentation error due to illegal fragments", HFILL}
    },
    { &hf_docsis_ucd_fragment_count,
     { "Fragment count", "docsis_tlv.ucd.fragment.count",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_ucd_fragment,
     { "UCD Fragment", "docsis_tlv.ucd.fragment",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_ucd_fragments,
     { "UCD Fragments", "docsis_tlv.ucd.fragments",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_ucd_reassembled_in,
     { "Reassembled UCD in frame", "docsis_tlv.ucd.reassembled_in",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "This UCD packet is reassembled in this frame", HFILL}
    },
    { &hf_docsis_ucd_reassembled_length,
     { "Reassembled UCD length", "docsis_tlv.ucd.reassembled.length",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       "The total length of the reassembled payload", HFILL}
    },
    { &hf_docsis_ucd_reassembled_data,
     { "Reassembled UCD data", "docsis_tlv.ucd.reassembled.data",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       "The reassembled payload", HFILL}
    },
    { &hf_docsis_ucd_reassembled,
     { ".5 Reassembled UCD", "docsis_tlv.ucd.reassembled",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       "The reassembled UCD", HFILL}
    },

  };

  static int *ett[] = {
    &ett_docsis_tlv,
    &ett_docsis_tlv_cos,
    &ett_docsis_tlv_mcap,
    &ett_docsis_tlv_mcap_em,
    &ett_docsis_tlv_mcap_em_pref,
    &ett_docsis_tlv_mcap_ofdm_chan_subc_qam_mod_sup,
    &ett_docsis_tlv_mcap_ofdma_chan_subc_qam_mod_sup,
    &ett_docsis_tlv_mcap_down_lower_band_edge_conf,
    &ett_docsis_tlv_mcap_down_upper_band_edge_conf,
    &ett_docsis_tlv_mcap_dipl_down_lower_band_edge,
    &ett_docsis_tlv_mcap_dipl_down_upper_band_edge,
    &ett_docsis_tlv_mcap_dipl_up_upper_band_edge,
    &ett_docsis_tlv_mcap_advanced_band_plan,
    &ett_docsis_tlv_mcap_dipl_down_lower_band_edge_options_list,
    &ett_docsis_tlv_mcap_dipl_down_upper_band_edge_options_list,
    &ett_docsis_tlv_mcap_dipl_up_upper_band_edge_options_list,
    &ett_docsis_tlv_clsfr,
    &ett_docsis_tlv_clsfr_ip,
    &ett_docsis_tlv_clsfr_ip6,
    &ett_docsis_tlv_clsfr_ip6_tc,
    &ett_docsis_tlv_clsfr_eth,
    &ett_docsis_tlv_clsfr_err,
    &ett_docsis_tlv_clsfr_dot1q,
    &ett_docsis_tlv_reqxmitpol,
    &ett_docsis_tlv_sflow_err,
    &ett_docsis_tlv_phs,
    &ett_docsis_tlv_phs_err,
    &ett_docsis_tlv_svc_unavail,
    &ett_docsis_tlv_snmpv3_kick,
    &ett_docsis_tlv_ds_ch_list,
    &ett_docsis_tlv_ds_ch_list_single,
    &ett_docsis_tlv_ds_ch_list_range,
    &ett_docsis_tlv_ext_field,
    &ett_docsis_tlv_vendor_specific_cap,
    &ett_docsis_tlv_dut_filter,
    &ett_docsis_tlv_tcc,
    &ett_docsis_tlv_tcc_ucd,
    &ett_docsis_tlv_tcc_rng_parms,
    &ett_docsis_tlv_tcc_oudp,
    &ett_docsis_tlv_tcc_err,
    &ett_docsis_tlv_sid_cl,
    &ett_docsis_tlv_sid_cl_enc,
    &ett_docsis_tlv_sid_cl_enc_map,
    &ett_docsis_tlv_sid_cl_so,
    &ett_docsis_tlv_rcp,
    &ett_docsis_tlv_rcp_rcv_mod_enc,
    &ett_docsis_tlv_rcp_ch_bl_rng,
    &ett_docsis_tlv_rcp_rcv_ch,
    &ett_docsis_tlv_rcc,
    &ett_docsis_tlv_rcc_rcv_mod_enc,
    &ett_docsis_tlv_rcc_rcv_ch,
    &ett_docsis_tlv_rcc_partial_serv_down_chan,
    &ett_docsis_tlv_rcc_srcc,
    &ett_docsis_tlv_rcc_srcc_prim_ds_assign,
    &ett_docsis_tlv_rcc_srcc_ds_assign,
    &ett_docsis_tlv_rcc_srcc_ds_prof_assign,
    &ett_docsis_tlv_rcc_srcc_ds_prof_assign_prof_list,
    &ett_docsis_tlv_rcc_err,
    &ett_docsis_tlv_dsid,
    &ett_docsis_tlv_dsid_ds_reseq,
    &ett_docsis_tlv_dsid_mc,
    &ett_docsis_tlv_dsid_mc_addr,
    &ett_docsis_tlv_sec_assoc,
    &ett_docsis_tlv_ch_asgn,
    &ett_docsis_cmts_mc_sess_enc,
    &ett_docsis_em_id_list_for_cm,
    &ett_docsis_tlv_tg_assignment,
    &ett_docsis_tlv_unknown,
    &ett_docsis_ucd_fragment,
    &ett_docsis_ucd_fragments,
    &ett_docsis_ucd_reassembled,
  };

  static ei_register_info ei[] = {
    {&ei_docsis_tlv_tlvlen_bad, { "docsis_tlv.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
    {&ei_docsis_tlv_tlvval_bad, { "docsis_tlv.tlvvalbad", PI_PROTOCOL, PI_WARN, "Wrong TLV value", EXPFILL}},
  };

  expert_module_t* expert_docsis_tlv;

  proto_docsis_tlv = proto_register_protocol ("DOCSIS Appendix C TLVs", "DOCSIS TLVs", "docsis_tlv");

  proto_register_field_array (proto_docsis_tlv, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_tlv = expert_register_protocol(proto_docsis_tlv);
  expert_register_field_array(expert_docsis_tlv, ei, array_length(ei));

  register_dissector ("docsis_tlv", dissect_docsis_tlv, proto_docsis_tlv);
}

void
proto_reg_handoff_docsis_tlv (void)
{
#if 0
  dissector_handle_t docsis_tlv_handle;

  docsis_tlv_handle = find_dissector ("docsis_tlv");
  dissector_add_uint ("docsis", 0xFF, docsis_tlv_handle);
#endif

  docsis_vsif_handle = find_dissector("docsis_vsif");
  docsis_ucd_handle = find_dissector("docsis_ucd");
  docsis_rba_handle = find_dissector("docsis_rba");

  reassembly_table_register(&ucd_reassembly_table,
                        &addresses_reassembly_table_functions);


}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
