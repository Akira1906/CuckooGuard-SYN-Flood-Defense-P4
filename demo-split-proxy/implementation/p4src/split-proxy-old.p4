/*
    SmartCookie: Blocking Large-Scale SYN Floods with a Split-Proxy Defense on Programmable Data Planes
    
    Copyright (C) 2023 Sophia Yoo, Xiaoqi Chen, Princeton University
    sy6 [at] princeton.edu
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <core.p4>
#include <v1model.p4>

// Testbed parameters
const bit<9> SERVER_PORT=12; 
const bit<32> SERVER_IP=0x0c000003;//12.0.0.3

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_SIPH_INTM = 16w0xff00;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const bit<16> PORT_TIMEDELTA_UPDATE = 5555; //for time delta

const bit<4> CALLBACK_TYPE_SYNACK=1;
const bit<4> CALLBACK_TYPE_TAGACK=2; 

//siphash-related consts
#define DEFAULT_SIP_KEY_0 0x33323130
#define DEFAULT_SIP_KEY_1 0x42413938
// moved this here from SwitchIngress
// use timestamp values that are actually available in bmv2 instead
#define TIMESTAMP_NOW_TICK_16 ((bit<32>) standard_metadata.ingress_global_timestamp[47:16])

const bit<32> const_0 = 0x70736575;
const bit<32> const_1 = 0x6e646f6d;
const bit<32> const_2 = 0x6e657261;
const bit<32> const_3 = 0x79746573;

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
}

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header sip_meta_h {
    bit<32> v_0;
    bit<32> v_1;
    bit<32> v_2;
    bit<32> v_3;
    bit<8> round;
    bit<4> __padding1;
    bit<4> callback_type;
    bit<7> __padding2;
    bit<9> egr_port; // This will be mapped to standard_metadata.egress_spec
    bit<32> cookie_time;
    bit<32> ack_verify_timediff;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    //
    bit<1> flag_cwr;
    bit<1> flag_ece; 
    //
    bit<1> flag_urg;
    bit<1> flag_ack;
    bit<1> flag_psh;
    bit<1> flag_rst;
    bit<1> flag_syn;
    bit<1> flag_fin;
    //
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header udp_payload_h {
    bit<32> timestamp;
}

struct header_t {
    ethernet_h ethernet;
    sip_meta_h sip_meta;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    udp_payload_h udp_payload;
}

struct metadata_t {
    // Ingress
    // commbined ig _medadata_t and eg_metadata_t into one since that's what bmv2 supports
    // siphash calc related
    bit<32> a_0;
    bit<32> a_1;
    bit<32> a_2;
    bit<32> a_3;

    // new introduced metadata
    bit<1> sip_meta_valid;
    bit<1> tcp_valid;
    bit<1> udp_payload_valid;
    
    bit<32> timestamp_now_copy;
    bit<32> timestamp_minus_servertime;
    bit<32> msg_var;
    
    bit<1> bloom_read_1;
    bit<1> bloom_read_2;
    // new introduced metadata
    bit<32> bloom_hash_1;
    bit<32> bloom_hash_2;

    // bool bloom_read_passed;
    // bool ingress_is_server_port;
    bit<1> bloom_read_passed;
    bit<1> ingress_is_server_port;
    bit<1> ack_verify_timediff_exceeded_limit;
    
    bit<1> flag_ece;
    bit<1> flag_ack;
    bit<1> flag_syn;
    
    bit<16> tcp_total_len;//always 20
    bit<1> redo_checksum;

    // Egress
    
    bit<32> cookie_val;
    bit<32> incoming_ack_minus_1;
    bit<32> incoming_seq_plus_1;

    bit<1> tb_output_stage;

    // newly introduced ot bypass egress
    bit<1> bypass_egress;

    standard_metadata_t standard_metadata;
}

parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {


    state start {
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_SIPH_INTM: parse_sip_meta;
            // default : reject;
            default : accept;
        }
    }
    
    state parse_sip_meta {
        pkt.extract(hdr.sip_meta);
        meta.sip_meta_valid = 1;
        transition parse_ipv4;
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }
    
    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.tcp_valid = 1;
        transition select(hdr.ipv4.total_len) {
            default : accept;
        }
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            PORT_TIMEDELTA_UPDATE: parse_udp_payload;
            default: accept;
        }
    }
    
    state parse_udp_payload {
        pkt.extract(hdr.udp_payload);
        meta.udp_payload_valid = 1;
        transition accept;
    }
}

// // ---------------------------------------------------------------------------
// // Ingress Deparser
// // ---------------------------------------------------------------------------
// control SwitchIngressDeparser(
//         packet_out pkt,
//         inout header_t hdr,
//         in ig_metadata_t ig_md,
//         in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    

//     apply {

//         // maybe we need to set some headers valid or invalid based on metadata

//         pkt.emit(hdr.ethernet);
//         pkt.emit(hdr.sip_meta);
//         pkt.emit(hdr.ipv4);
//         pkt.emit(hdr.tcp);
//         pkt.emit(hdr.udp);
//     }

// }

// // ---------------------------------------------------------------------------
// // Egress parser
// // ---------------------------------------------------------------------------
// parser SwitchEgressParser(
//         packet_in pkt,
//         out header_t hdr,
//         out eg_metadata_t eg_md,
//         out egress_intrinsic_metadata_t eg_intr_md) {
//     state start {
//         pkt.extract(eg_intr_md);
//         transition parse_ethernet;
//     }
    
//     state parse_ethernet {
//         pkt.extract(hdr.ethernet);
//         transition select (hdr.ethernet.ether_type) {
//             ETHERTYPE_IPV4 : parse_ipv4;
//             ETHERTYPE_SIPH_INTM: parse_sip_meta;
//             default : reject;
//         }
//     }
    
//     state parse_sip_meta {
//         pkt.extract(hdr.sip_meta);
//         transition parse_ipv4;
//     }
    
//     state parse_ipv4 {
//         pkt.extract(hdr.ipv4);
//         transition select(hdr.ipv4.protocol) {
//             IP_PROTOCOLS_TCP : parse_tcp;
//             IP_PROTOCOLS_UDP : parse_udp;
//             default : accept;
//         }
//     }
    
//     state parse_tcp {
//         pkt.extract(hdr.tcp);
//         transition select(hdr.ipv4.total_len) {
//             default : accept;
//         }
//     }
    
//     state parse_udp {
//         pkt.extract(hdr.udp);
//         transition select(hdr.udp.dst_port) {
//             default: accept;
//         }
//     }
// }

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        in header_t hdr) {
   	
    // Checksum() ip_checksum;
    // Checksum() tcp_checksum;    
    
    apply {
        // // Perform checksum update if required
        // if (meta.redo_checksum == 1) {
        //     // Update IPv4 header checksum
        //     update_checksum(
        //         hdr.ipv4.isValid(),
        //         { hdr.ipv4.version,
        //         hdr.ipv4.ihl,
        //         hdr.ipv4.diffserv,
        //         hdr.ipv4.total_len,
        //         hdr.ipv4.identification,
        //         hdr.ipv4.flags,
        //         hdr.ipv4.frag_offset,
        //         hdr.ipv4.ttl,
        //         hdr.ipv4.protocol,
        //         hdr.ipv4.src_addr,
        //         hdr.ipv4.dst_addr },
        //         hdr.ipv4.hdr_checksum,
        //         HashAlgorithm.csum16
        //     );

        //     // Update TCP checksum (includes pseudo-header fields)
        //     update_checksum(
        //         hdr.tcp.isValid(),
        //         { hdr.ipv4.src_addr,
        //         hdr.ipv4.dst_addr,
        //         8w0,  // Zero padding
        //         hdr.ipv4.protocol,
        //         meta.tcp_total_len,  // Total TCP length from metadata
        //         hdr.tcp.src_port,
        //         hdr.tcp.dst_port,
        //         hdr.tcp.seq_no,
        //         hdr.tcp.ack_no,
        //         hdr.tcp.data_offset,
        //         hdr.tcp.res,
        //         hdr.tcp.flag_cwr, 
        //         hdr.tcp.flag_ece,
        //         hdr.tcp.flag_urg,
        //         hdr.tcp.flag_ack,
        //         hdr.tcp.flag_psh,
        //         hdr.tcp.flag_rst,
        //         hdr.tcp.flag_syn,
        //         hdr.tcp.flag_fin,
        //         hdr.tcp.window,
        //         hdr.tcp.urgent_ptr },
        //         hdr.tcp.checksum,
        //         HashAlgorithm.csum16
        //     );
        // }

        // Emit headers
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.sip_meta);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
// @pa_container_size("ingress","ig_md.a_0",32)
// @pa_container_size("ingress","ig_md.a_1",32)
// @pa_container_size("ingress","ig_md.a_2",32)
// @pa_container_size("ingress","ig_md.a_3",32)
// @pa_container_size("ingress","hdr.sip_meta.v_0",32)
// @pa_container_size("ingress","hdr.sip_meta.v_1",32)
// @pa_container_size("ingress","hdr.sip_meta.v_2",32)
// @pa_container_size("ingress","hdr.sip_meta.v_3",32)
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {
        
    action bypass_egress(){
        // standard_metadata.egress_spec = 511; // BMv2 uses 511 as a drop port
        meta.bypass_egress = 1;
        // TODO: we do not really use this fuction what is even the functionality in the original implementation?
    }
    action dont_bypass_egress(){
        meta.bypass_egress = 0;
    }
     
    action drop() {
        mark_to_drop(standard_metadata);
        bypass_egress();
    }
    action dont_drop(){
        //  Do nothing 
    }
    
    
    action nop() {
    }
    action route_to(bit<9> port){
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_addr=1; 
        hdr.ethernet.dst_addr=(bit<48>) port; 
    }
    action reflect(){
        //send you back to where you're from
        route_to(standard_metadata.ingress_port);
    }
    
    action do_recirc(){
    //    route_to(68);
    }
    
    
    //siphash init
    action sip_init(bit<32> key_0, bit<32> key_1){
        hdr.sip_meta.setValid();
        hdr.ethernet.ether_type = ETHERTYPE_SIPH_INTM;
        hdr.sip_meta.round = 0;   
            
        hdr.sip_meta.v_0 = key_0 ^ const_0;
        hdr.sip_meta.v_1 = key_1 ^ const_1;
        hdr.sip_meta.v_2 = key_0 ^ const_2;
        hdr.sip_meta.v_3 = key_1 ^ const_3;
        
        meta.msg_var = hdr.ipv4.src_addr;
    }
    
    action sip_init_default_key(){
        bit<32> key_0 = DEFAULT_SIP_KEY_0;
        bit<32> key_1 = DEFAULT_SIP_KEY_1;
        hdr.sip_meta.setValid();
        hdr.ethernet.ether_type=ETHERTYPE_SIPH_INTM;
        hdr.sip_meta.round = 0;   
            
        hdr.sip_meta.v_0 = key_0 ^ const_0;
        hdr.sip_meta.v_1 = key_1 ^ const_1;
        hdr.sip_meta.v_2 = key_0 ^ const_2;
        hdr.sip_meta.v_3 = key_1 ^ const_3;
        
        meta.msg_var = hdr.ipv4.src_addr;
    }
    
    action sip_continue_round4(){
        meta.msg_var = hdr.tcp.src_port ++ hdr.tcp.dst_port; // will this work? or do I need to use that super complex syntax?
    }
    action sip_continue_round8(){
        meta.msg_var = 0;
    }
    action sip_end_round12_tagack_verify(){
        //do nothing for now, use next stage to check ack_verify_timediff
    }
    
    @pragma stage 0
    table tb_maybe_sip_init {
        key = {
            meta.sip_meta_valid: exact;
            // hdr.sip_meta.isValid(): exact;
            // hdr.tcp.isValid(): exact;
            meta.tcp_valid: exact;
            hdr.sip_meta.round: ternary;
        }
        actions = {
            //sip_init;
            sip_init_default_key;
            sip_continue_round4;
            sip_continue_round8;
            sip_end_round12_tagack_verify;
            nop;
        }
        default_action = nop; 
        size = 16;
        // const entries={
        //     (false, true, _): sip_init_default_key(); //change key from control plane
        //     (true, true, 4): sip_continue_round4();
        //     (true, true, 8): sip_continue_round8();
        //     (true, true, 12): sip_end_round12_tagack_verify();
        // }
    }
    
    action sip_1_odd(){
        //i_3 = i_3 ^ message
        hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ meta.msg_var;
    }
    action sip_1_a(){
        //a_0 = i_0 + i_1
        meta.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
        //a_2 = i_2 + i_3
        meta.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
        //a_1 = i_1 << 5
        // @in_hash {
        meta.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27];
    }
    action sip_1_b(){
        //a_3 = i_3 << 8
        meta.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];
    }
    action sip_2_a(){
        //b_1 = a_1 ^ a_0
        hdr.sip_meta.v_1 = meta.a_1 ^ meta.a_0;
        //b_3 = a_3 ^ a_2
        hdr.sip_meta.v_3 = meta.a_3 ^ meta.a_2;
        // b_0 = a_0 << 16
        hdr.sip_meta.v_0 = meta.a_0[15:0] ++ meta.a_0[31:16];
        //b_2 = a_2
        hdr.sip_meta.v_2 = meta.a_2;
    }
    action sip_3_a(){
        //c_2 = b_2 + b_1
        meta.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_1;
        //c_0 = b_0 + b_3
        meta.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_3;
        //c_1 = b_1 << 13
        // @in_hash { 
        meta.a_1 = hdr.sip_meta.v_1[18:0] ++ hdr.sip_meta.v_1[31:19];
    }
    action sip_3_b(){
        //c_3 = b_3 << 7
        // @in_hash { 
        meta.a_3 = hdr.sip_meta.v_3[24:0] ++ hdr.sip_meta.v_3[31:25];
    }

    action sip_4_a(){
        //d_1 = c_1 ^ c_2
        hdr.sip_meta.v_1 = meta.a_1 ^ meta.a_2;
        //d_3 = c_3 ^ c_0 i
        hdr.sip_meta.v_3 = meta.a_3 ^ meta.a_0;
        //d_2 = c_2 << 16
        hdr.sip_meta.v_2 = meta.a_2[15:0] ++ meta.a_2[31:16];
    }
    action sip_4_b_odd(){
        //d_0 = c_0
        hdr.sip_meta.v_0 = meta.a_0;
    }
    action sip_4_b_even(){
        //d_0 = c_0 ^ message
        hdr.sip_meta.v_0 = meta.a_0 ^ meta.msg_var;
    }
  
    // time-delta 

    // register req_timedelta {
    //     bit<32>;
    // }
    register< bit<32> >(1) reg_timedelta;

    // Register<bit<32>,_ >(1) reg_timedelta;
    // RegisterAction<bit<32>, _, bit<32>>(reg_timedelta) regact_timedelta_write = 
    // {
    //     void apply(inout bit<32> value, out bit<32> ret){
    //         value = ig_md.timestamp_minus_servertime;
    //         ret = 0;
    //     }
    // };
    // RegisterAction<bit<32>, _, bit<32>>(reg_timedelta) regact_timedelta_read = 
    // {
    //     void apply(inout bit<32> value, out bit<32> ret){
    //         ret = value;
    //     }
    // };
        
    //#define TIMESTAMP_NOW_USEC ((bit<32>) ig_intr_md.ingress_mac_tstamp[41:10])
    // #define TIMESTAMP_NOW_TICK_16 ((bit<32>) meta.ingress_mac_tstamp[47:16])
	action timedelta_step0(){
        meta.timestamp_now_copy = TIMESTAMP_NOW_TICK_16;
    }
    action timedelta_step1_write(){
        meta.timestamp_minus_servertime = meta.timestamp_now_copy - hdr.udp_payload.timestamp;
    }
    action timedelta_step2_write(){
        // regact_timedelta_write.execute(0);
        // register_write(reg_timedelta, 0, meta.timestamp_minus_servertime);
        reg_timedelta.write((bit<32>) 0, meta.timestamp_minus_servertime);

    }
    action timedelta_step1_read(){
        // meta.timestamp_minus_servertime = regact_timedelta_read.execute(0);
        reg_timedelta.read(meta.timestamp_minus_servertime, (bit<32>) 0);
        // port_pkt_ip_bytes_in.write(istd.ingress_port, tmp);maybe this is enough
        // tmp = port_pkt_ip_bytes_in.read(istd.ingress_port); no mentioning of the offset
    }
    action timedelta_step2_read(){
        hdr.sip_meta.cookie_time = meta.timestamp_now_copy - meta.timestamp_minus_servertime;
	}
	action timedelta_step3_read(){
  		hdr.sip_meta.cookie_time= hdr.sip_meta.cookie_time >> 12;
    }
        
    
    // bloom filter for flows
	// register<bit<1>,_ >(32w4096) reg_bloom_1;
    register<bit<1>>(32w4096) reg_bloom_1;
    // RegisterAction<bit<1>, _, bit<1>>(reg_bloom_1) regact_bloom_1_get = 
    // {
    //     void apply(inout bit<1> value, out bit<1> ret){
    //         ret = value;
    //     }
    // };
    // RegisterAction<bit<1>, _, bit<1>>(reg_bloom_1) regact_bloom_1_set = 
    // {
    //     void apply(inout bit<1> value, out bit<1> ret){
    //         value = 1;
    //         ret = 0;
    //     }
    // };
    // register<bit<1>,_ >(32w4096) reg_bloom_2;
    register<bit<1>>(32w4096) reg_bloom_2;
    // RegisterAction<bit<1>, _, bit<1>>(reg_bloom_2) regact_bloom_2_get = 
    // {
    //     void apply(inout bit<1> value, out bit<1> ret){
    //         ret = value;
    //     }
    // };
    // RegisterAction<bit<1>, _, bit<1>>(reg_bloom_2) regact_bloom_2_set = 
    // {
    //     void apply(inout bit<1> value, out bit<1> ret){
    //         value = 1;
    //         ret = 0;
    //     }
    // };

    // Hash<bit<12>>(HashAlgorithm.crc16) hash_1;
    // Hash<bit<12>>(HashAlgorithm.crc32) hash_2;

// NOTES:
// this would be worth a shot, if the bloom filter complains about too large values or something
// bit<12> index = meta.bloom_hash_1[11:0]; // Extracts only the lower 12 bits
// req_bloom_1.write(index, (bit<1>)1);


    action set_bloom_1_a(){
        // bit<12> index = hash_1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port});
        hash(meta.bloom_hash_1, HashAlgorithm.crc16, (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, 
            (bit<32>)4095);
        reg_bloom_1.write(meta.bloom_hash_1, (bit<1>) 1);
        // regact_bloom_1_set.execute(hash_1.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port,hdr.tcp.dst_port }));
    }
    action set_bloom_2_a(){
        // regact_bloom_2_set.execute(hash_2.get({ 3w1, hdr.ipv4.src_addr, 3w1,  hdr.ipv4.dst_addr,  3w1, hdr.tcp.src_port,  3w1, hdr.tcp.dst_port }));
        // bit<12> index = hash_2.get({3w1, hdr.ipv4.src_addr, 3w1, hdr.ipv4.dst_addr, 3w1, hdr.tcp.src_port, 3w1, hdr.tcp.dst_port});
        hash(meta.bloom_hash_2, HashAlgorithm.crc32, (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, 
            (bit<32>)4095);
        reg_bloom_2.write(meta.bloom_hash_2, (bit<1>) 1);
    }
    action get_bloom_1_a(){
        // ig_md.bloom_read_1=regact_bloom_1_get.execute(hash_1.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port,hdr.tcp.dst_port }));
        hash(meta.bloom_hash_1, HashAlgorithm.crc16, (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, 
            (bit<32>)4095);

        // bit<12> index = hash_1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port});
        reg_bloom_1.read(meta.bloom_read_1, meta.bloom_hash_1);
    }
    action get_bloom_2_a(){
        // ig_md.bloom_read_2=regact_bloom_2_get.execute(hash_2.get({ 3w1, hdr.ipv4.src_addr, 3w1,  hdr.ipv4.dst_addr,  3w1, hdr.tcp.src_port,  3w1, hdr.tcp.dst_port }));
        // bit<12> index = hash_2.get({3w1, hdr.ipv4.src_addr, 3w1, hdr.ipv4.dst_addr, 3w1, hdr.tcp.src_port, 3w1, hdr.tcp.dst_port});
        hash(meta.bloom_hash_2, HashAlgorithm.crc32, (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, 
            (bit<32>)4095);
        reg_bloom_2.read(meta.bloom_read_2, meta.bloom_hash_2);
    }
    
    // packet in-out related

    action naive_routing(){
        standard_metadata.egress_spec = (bit<9>) hdr.ipv4.dst_addr[31:24];
        hdr.ethernet.src_addr=1;
        hdr.ethernet.dst_addr[47:8] = 0; 
        hdr.ethernet.dst_addr[7:0] = hdr.ipv4.dst_addr[31:24];
    }
    
    action craft_onward_ack(){
        hdr.tcp.seq_no = hdr.tcp.seq_no - 1;
        hdr.tcp.data_offset = 5;
        //add setup tag
        hdr.tcp.flag_ece = 1;
    }

    // finally, decide next step for all types of packets
    // traffic, stop at first pass
    action client_to_server_nonsyn_ongoing(){
        route_to(SERVER_PORT);
        bypass_egress();
        // dont_drop();
        hdr.sip_meta.setInvalid();
        hdr.ethernet.ether_type=ETHERTYPE_IPV4; 
    }
    action server_to_client_normal_traffic(){
        hdr.sip_meta.setInvalid();
        hdr.ethernet.ether_type=ETHERTYPE_IPV4;
        naive_routing();
        bypass_egress();
        // dont_drop();
    }
    action non_tcp_traffic(){
        naive_routing();
        bypass_egress();
        // dont_drop();
    }
    // hash calc
    action start_sipcalc_synack(){
        hdr.sip_meta.callback_type=CALLBACK_TYPE_SYNACK;
        hdr.sip_meta.egr_port=standard_metadata.ingress_port; // meta or standard_metadata ? 
        
        hdr.sip_meta.round=2;
        // resubmit();
        // do_recirc();
        dont_bypass_egress(); 
        // dont_drop();
    }
    action start_sipcalc_tagack(){
        hdr.sip_meta.callback_type=CALLBACK_TYPE_TAGACK;
        hdr.sip_meta.egr_port=SERVER_PORT; 
        
        hdr.sip_meta.round=2;
        // resubmit();
        // do_recirc();
        dont_bypass_egress();
        // dont_drop();
    }
    action continue_sipcalc_round4to6(){
        hdr.sip_meta.round=6;
        // resubmit();
        // do_recirc();
        dont_bypass_egress();
        // dont_drop();
    }
    action pre_finalize_synack(){
        hdr.sip_meta.round=10;
        route_to(hdr.sip_meta.egr_port);
        dont_bypass_egress();
        // dont_drop();
    }
    action pre_finalize_tagack(){
        hdr.sip_meta.round=10;
        // resubmit();
        // do_recirc();
        dont_bypass_egress();
        // dont_drop();
    }
    
    action finalize_tagack(){
        route_to(hdr.sip_meta.egr_port);
        //don't bypass egress, perform checksum update in egress deparser 
        dont_bypass_egress();
        hdr.sip_meta.round=99; //DO_CHECKSUM
        // if failed cookie check, drop
        // ig_intr_dprsr_md.drop_ctl = (bit<3>) meta.ack_verify_timediff_exceeded_limit;

        if (meta.ack_verify_timediff_exceeded_limit == 1) {
        mark_to_drop(standard_metadata);
        }
        // not sure if this should be here or the the dropping happens in craft_onward_ack()
        craft_onward_ack();
        //move this logic to egress 
        // remove sip_meta header
        //hdr.sip_meta.setInvalid();  hdr.ethernet.ether_type=ETHERTYPE_IPV4;
    }
    // TODO check whether egress is vital to the calculatio of siphash or anything, if yes then we can't use resubmit() and instead need to use some other mechanism
    // to recirculate the packets when necessary
    @pragma stage 11
    table tb_triage_pkt_types_nextstep {
        key = {
            hdr.sip_meta.round: exact;
            meta.tcp_valid: exact;
            meta.udp_payload_valid: exact;
            
            meta.ingress_is_server_port: ternary;
            
            meta.flag_syn: ternary;
            meta.flag_ack: ternary;
            meta.flag_ece: ternary; 
            
            hdr.sip_meta.callback_type: ternary;
            
            meta.bloom_read_passed: ternary;
        }
        actions = {
            drop;
            start_sipcalc_synack;
            start_sipcalc_tagack;
            client_to_server_nonsyn_ongoing;
            server_to_client_normal_traffic;
            non_tcp_traffic;
            
            continue_sipcalc_round4to6;
            pre_finalize_synack;
            pre_finalize_tagack;
            finalize_tagack;
        }
        default_action = drop();
        // TODO the table entrie types have to be changed as well
        // const entries = {//all types of packets, from linker_config.json in Lucid
             
        //      //"event" : "udp_from_server_time"
        //      (0,false,true,   true,    _,_,_,  _, _): drop(); //already saved time delta
        //      //"event" : "iptcp_to_server_syn"
        //      (0,true,false,   false,   1,0,_,  _, _ ): start_sipcalc_synack();
        //      //"event" : "iptcp_to_server_non_syn"
        //      (0,true,false,   false,   0,_,_,  _, false): start_sipcalc_tagack();
        //      (0,true,false,   false,   0,_,_,  _, true): client_to_server_nonsyn_ongoing();
             
        //      //"event" : "iptcp_from_server_tagged"
        //      (0,true,false,   true,    _,_,1,  _, _): drop(); //already added to bf
        //      //"event" : "iptcp_from_server_non_tagged"
        //      (0,true,false,   true,    _,_,0,  _, _): server_to_client_normal_traffic();
        //      //"event" : "non_tcp_in"
        //      (0,false,true, false,     _,_,_,  _, _): non_tcp_traffic();
        //      (0,false,false, _,     _,_,_,  _, _): non_tcp_traffic();
             
        //      //continue calculation, after initial round
        //      //round 4->6
        //      (4,true,false,  _,     _,_,_,  _, _): continue_sipcalc_round4to6();
        //      //round 8->10
        //      (8,true,false,  _,     _,_,_,  CALLBACK_TYPE_TAGACK, _): pre_finalize_tagack(); //round 8->10, tagack needs one last recirc, after 3rd pass (12 round) come back to ingress again for final determination
        //      (8,true,false,  _,     _,_,_,  CALLBACK_TYPE_SYNACK, _): pre_finalize_synack(); //round 8->10, route to client
        //      //round 12, tagack
        //      (12,true,false, _,     _,_,_,  CALLBACK_TYPE_TAGACK, _): finalize_tagack(); //route to server, drop if bad cookie 
        // }
        size = 32;
    }
        // TODO: continue here, also figure out the issue about recirculation
	// Random< bit<1> >() rng; why th do we need this

    apply {    
        //stage 0
        tb_maybe_sip_init.apply();
       
        //calculate all other cases in parallel
        timedelta_step0();
        if(meta.udp_payload_valid == 1 && standard_metadata.ingress_port==SERVER_PORT){
            timedelta_step1_write();
            timedelta_step2_write();
            //drop(); //for full parallelization, postpone to triage table
        }else{
            timedelta_step1_read();
            timedelta_step2_read();
            timedelta_step3_read();
        }
        
        if(meta.tcp_valid == 1 && standard_metadata.ingress_port == SERVER_PORT && hdr.tcp.flag_ece==1){
            set_bloom_1_a();
            set_bloom_2_a();
            meta.bloom_read_passed=0;
            //drop(); //for full parallelization, postpone to triage table
        }else{
            get_bloom_1_a();
            get_bloom_2_a();
            if(meta.bloom_read_1==1 && meta.bloom_read_2==1){
                meta.bloom_read_passed=1;
            }else{
                meta.bloom_read_passed=0;
            }
        }
        
        //pre-calculate conditions and save in metadata. used in final stage triage.
        if(standard_metadata.ingress_port==SERVER_PORT){
            meta.ingress_is_server_port = 1;
        }else{
            meta.ingress_is_server_port = 0;
        }

        if(hdr.sip_meta.ack_verify_timediff==0 || hdr.sip_meta.ack_verify_timediff==1 || hdr.sip_meta.ack_verify_timediff==2){
            meta.ack_verify_timediff_exceeded_limit=0;
        }else{
            meta.ack_verify_timediff_exceeded_limit=1;
        }
        
        
        //calculate siphash 2 round
        sip_1_odd(); //v3^=msg
        //first SipRound
        sip_1_a();
        sip_1_b();
        sip_2_a();
        sip_3_a();
        sip_3_b();
        sip_4_a();
        sip_4_b_odd();
        //second SipRound
        sip_1_a();
        sip_1_b();
        sip_2_a();
        sip_3_a();
        sip_3_b();
        sip_4_a(); 
        sip_4_b_even(); //v0^=msg
        
        // hdr.sip_meta.round=hdr.sip_meta.round+2; // increment round as part of final-stage triage table

        if(meta.tcp_valid == 1){
            meta.flag_syn=hdr.tcp.flag_syn;
            meta.flag_ack=hdr.tcp.flag_ack;
            meta.flag_ece=hdr.tcp.flag_ece;
        }
        else{
            meta.flag_syn=0;
            meta.flag_ack=0;
            meta.flag_ece=0;
        }


        // // Generate a pseudo-random bit
        bit<1> rnd;
        hash(rnd, HashAlgorithm.crc16, (bit<32>)0, {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, (bit<32>)1);
        if (rnd == 1) {
            route_to(68);
        } else {
            route_to(68+128);
        }
        // why do we need this?
        // bit<1> rnd = rng.get();
        // if(rnd==1){
        //     route_to(68);
        // }
        // else{
        //     route_to(68+128);
        // }
        tb_triage_pkt_types_nextstep.apply();
    }
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
// @pa_container_size("egress","eg_md.a_0",32)
// @pa_container_size("egress","eg_md.a_1",32)
// @pa_container_size("egress","eg_md.a_2",32)
// @pa_container_size("egress","eg_md.a_3",32)
// @pa_container_size("egress","hdr.sip_meta.v_0",32)
// @pa_container_size("egress","hdr.sip_meta.v_1",32)
// @pa_container_size("egress","hdr.sip_meta.v_2",32)
// @pa_container_size("egress","hdr.sip_meta.v_3",32)
control SwitchEgress(
        inout header_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {
    
   
    action sip_1_odd(){
        //i_3 = i_3 ^ message
        hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ meta.msg_var;
    }
    action sip_1_a(){
        //a_0 = i_0 + i_1
        meta.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
        //a_2 = i_2 + i_3
        meta.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
        //a_1 = i_1 << 5
        meta.a_1 = (hdr.sip_meta.v_1 << 5) | (hdr.sip_meta.v_1 >> (32 - 5));
        // @in_hash { eg_md.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
    }
    action sip_1_b(){
        //a_3 = i_3 << 8
        // meta.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];
        meta.a_3 = (hdr.sip_meta.v_3 << 8) | (hdr.sip_meta.v_3 >> 24);
    }
    action sip_2_a(){
        //b_1 = a_1 ^ a_0
        hdr.sip_meta.v_1 = meta.a_1 ^ meta.a_0;
        //b_3 = a_3 ^ a_2
        hdr.sip_meta.v_3 = meta.a_3 ^ meta.a_2;
        // b_0 = a_0 << 16
        hdr.sip_meta.v_0 = (meta.a_0 << 16) | (meta.a_0 >> (32 - 16));
        // hdr.sip_meta.v_0 = eg_md.a_0[15:0] ++ eg_md.a_0[31:16];
        //b_2 = a_2
        hdr.sip_meta.v_2 = meta.a_2;
    }
    action sip_3_a(){
        //c_2 = b_2 + b_1
        meta.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_1;
        //c_0 = b_0 + b_3
        meta.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_3;
        //c_1 = b_1 << 13
        meta.a_1 = (hdr.sip_meta.v_1 << 13) | (hdr.sip_meta.v_1 >> (32 - 13));
        // @in_hash { eg_md.a_1 = hdr.sip_meta.v_1[18:0] ++ hdr.sip_meta.v_1[31:19]; }
    }
    action sip_3_b(){
        //c_3 = b_3 << 7
        // @in_hash { eg_md.a_3 = hdr.sip_meta.v_3[24:0] ++ hdr.sip_meta.v_3[31:25]; }
        meta.a_3 = (hdr.sip_meta.v_3 << 7) | (hdr.sip_meta.v_3 >> (32 - 7)); // Left rotate by 7
    }

    action sip_4_a(){
        //d_1 = c_1 ^ c_2
        hdr.sip_meta.v_1 = meta.a_1 ^ meta.a_2;
        //d_3 = c_3 ^ c_0 i
        hdr.sip_meta.v_3 = meta.a_3 ^ meta.a_0;
        //d_2 = c_2 << 16
        // hdr.sip_meta.v_2 = eg_md.a_2[15:0] ++ eg_md.a_2[31:16];
        hdr.sip_meta.v_2 = (meta.a_2 << 16) | (meta.a_2 >> (32 - 16)); // Left rotate by 16
    }
    action sip_4_b_odd(){
        //d_0 = c_0
        hdr.sip_meta.v_0 = meta.a_0;
    }
    action sip_4_b_even(){
        //d_0 = c_0 ^ message
        hdr.sip_meta.v_0 = meta.a_0 ^ meta.msg_var;
    }
    
    

    action clean_up(){
        // hdr.sip_meta.setInvalid(); not supported we need to ignore this during parsing
        meta.sip_meta_valid = 0;
        hdr.ethernet.ether_type=ETHERTYPE_IPV4; 
    }
 

    action sip_final_xor_with_time(){
        hdr.tcp.seq_no = hdr.sip_meta.cookie_time ^ hdr.sip_meta.v_0 ^ hdr.sip_meta.v_1 ^ hdr.sip_meta.v_2 ^ hdr.sip_meta.v_3;
        clean_up();
    }

    action sip_final_xor_with_ackm1(){
        meta.cookie_val = meta.incoming_ack_minus_1 ^ hdr.sip_meta.v_0 ^ hdr.sip_meta.v_1 ^ hdr.sip_meta.v_2 ^ hdr.sip_meta.v_3;
    }
    
	action verify_timediff(){
	    hdr.sip_meta.ack_verify_timediff = hdr.sip_meta.cookie_time - meta.cookie_val; // should be 0 or 1
	}

    action craft_synack_reply(){
        hdr.tcp.ack_no=meta.incoming_seq_plus_1;
        //move this call to a separate table call to avoid too many hashes in one action/table 
	   //sip_final_xor_with_time(); // cookie_val = time ^ hash, -> synack
	
        //swap IP
        bit<32> tmp_ip = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_ip;
       
    	//swap port 
    	bit<16> tmp_port = hdr.tcp.src_port;  
        hdr.tcp.src_port=hdr.tcp.dst_port;
        hdr.tcp.dst_port=tmp_port;
	
        //packet crafting 
        hdr.tcp.data_offset=5;
        
        hdr.tcp.flag_ack=1;
        hdr.tcp.flag_syn=1;

        hdr.ipv4.ihl=5;
        hdr.ipv4.total_len=40; 

        //necessary for checksum update 
        meta.redo_checksum=1;
        meta.tcp_total_len=20; 

        //routing done in ingress
    }

    action drop(){
        mark_to_drop(standard_metadata);
    }
    action dont_drop(){
        // packet is automatically forwarded
    }

    action nop() {
    }

    table tb_decide_output_type_1 {
        key = {
            meta.sip_meta_valid: exact;
            meta.tcp_valid: exact;
            hdr.sip_meta.round: exact;
            hdr.sip_meta.callback_type: ternary;
            //eg_md.tb_output_stage: exact; 
        }
        actions = {
            craft_synack_reply; 
            sip_final_xor_with_ackm1;
            clean_up;
            nop;
        }
        default_action = nop;
        size = 16;
        // const entries={
        //     (true, true, 12, CALLBACK_TYPE_SYNACK): craft_synack_reply();
        //     (true, true, 12, CALLBACK_TYPE_TAGACK): sip_final_xor_with_ackm1();  // cookie_val = (ack-1) ^ hash, ==? time(+1)
        //     (true, true, 12, _): clean_up();
        // }
    }
    
    table tb_decide_output_type_2 {
        key = {
            meta.sip_meta_valid: exact;
            meta.tcp_valid: exact;
            hdr.sip_meta.round: exact;
            hdr.sip_meta.callback_type: ternary;
        }
        actions = {
            sip_final_xor_with_time;
            verify_timediff;
            nop;
        }
        default_action = nop;
        size = 16;
        // const entries={
        //     (true, true, 12, CALLBACK_TYPE_SYNACK): sip_final_xor_with_time();//need second stage to not have two hash copies in one action 
        //     (true, true, 12, CALLBACK_TYPE_TAGACK): verify_timediff(); //need second stage to complete case for CALLBACK_TYPE_TAGACK 
        // }
    }

    apply {
        if(meta.bypass_egress == 0){
            //stage 0
            if(hdr.sip_meta.round==2){
                meta.msg_var = hdr.ipv4.dst_addr;
            }else
            if(hdr.sip_meta.round==6 && hdr.sip_meta.callback_type==CALLBACK_TYPE_SYNACK){
                meta.msg_var = hdr.tcp.seq_no;
            }else 
            if(hdr.sip_meta.round==6 && hdr.sip_meta.callback_type==CALLBACK_TYPE_TAGACK){
                meta.msg_var = hdr.tcp.seq_no - 1;
            }else 
            if(hdr.sip_meta.round==10){ 
                meta.msg_var = 0;  //final compression rounds is 8,9,10,11
            }

            if(hdr.sip_meta.round != 99){
                //v3^=m
                sip_1_odd();
                //first SipRound
                sip_1_a();
                sip_1_b();
                sip_2_a();
                sip_3_a();
                sip_3_b();
                sip_4_a();
                sip_4_b_odd();
                //second SipRound
                sip_1_a();
                sip_1_b();
                sip_2_a();
                sip_3_a();
                sip_3_b();
                sip_4_a();
                //v0^=m
                sip_4_b_even();
                hdr.sip_meta.round=hdr.sip_meta.round+2;

                meta.incoming_ack_minus_1=hdr.tcp.ack_no - 1;
                meta.incoming_seq_plus_1=hdr.tcp.seq_no + 1;
                meta.tcp_total_len=20;
                
                meta.redo_checksum=0;
            
                tb_decide_output_type_1.apply(); 	 
                tb_decide_output_type_2.apply(); 
            }//endif round!=99
            else{ //round==99, here from ingress to perform checksum update in deparser  
            //don't do any further modification of packet 

                //necessary for checksum update 
                hdr.ipv4.ihl=5;
                hdr.ipv4.total_len=40; 

                meta.redo_checksum=1;
                meta.tcp_total_len=20; 
                // remove sip_meta header
                // hdr.sip_meta.setInvalid();
                meta.sip_meta_valid = 0;
                hdr.ethernet.ether_type=ETHERTYPE_IPV4;
            }
        }
    }//apply
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout header_t hdr, inout metadata_t meta) {
    apply {
     verify_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr},
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout header_t hdr, inout metadata_t meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);

        update_checksum_with_payload(
	    hdr.tcp.isValid() && hdr.ipv4.isValid(),
            { hdr.ipv4.src_addr,
	      hdr.ipv4.dst_addr,
              8w0,
              hdr.ipv4.protocol,
              meta.tcp_total_len,
              hdr.tcp.src_port,
              hdr.tcp.dst_port,
              hdr.tcp.seq_no,
              hdr.tcp.ack_no,
              hdr.tcp.data_offset,
              hdr.tcp.res,
              hdr.tcp.flag_cwr,
              hdr.tcp.flag_ece,
              hdr.tcp.flag_urg,
              hdr.tcp.flag_ack,
              hdr.tcp.flag_psh,
              hdr.tcp.flag_rst,
              hdr.tcp.flag_syn,
              hdr.tcp.flag_fin,
              hdr.tcp.window,
              hdr.tcp.urgent_ptr
              },
            hdr.tcp.checksum,
            HashAlgorithm.csum16);

    }
}


V1Switch(
    SwitchIngressParser(),
    MyVerifyChecksum(),
    SwitchIngress(),
    //  SwitchIngressDeparser(),
    //  SwitchEgressParser(),
    SwitchEgress(),
    MyComputeChecksum(),
    SwitchEgressDeparser()
) main;

// Switch(pipe) main;