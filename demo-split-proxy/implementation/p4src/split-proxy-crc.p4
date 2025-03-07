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
const bit<9> SERVER_PORT=3; 
const bit<32> SERVER_IP=0x0c000003;//12.0.0.3


typedef bit<48> mac_addr_t;
const mac_addr_t SERVER_MAC = 0x00010A000101;//00:01:0a:00:01:01
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
    bit<32> cookie_hash;
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

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        in header_t hdr) {
    
    apply {
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
        // hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        // hdr.ethernet.src_addr=1; replaced with code below
        hdr.ethernet.src_addr = SERVER_MAC;
        hdr.ethernet.dst_addr = (bit<48>) port; 
    }
    action reflect(){
        //send you back to where you're from
        route_to(standard_metadata.ingress_port);
    }
    
    action do_recirc(){
    //    route_to(68);
    }
    
    
  
    // time-delta 

    // register req_timedelta {
    //     bit<32>;
    // }
    register< bit<32> >(1) reg_timedelta;
        
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
  		hdr.sip_meta.cookie_time = hdr.sip_meta.cookie_time >> 12;
    }
        
    
    // bloom filter for flows
    register<bit<1>>(32w4096) reg_bloom_1;
    register<bit<1>>(32w4096) reg_bloom_2;

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
        // hdr.ethernet.src_addr=1; this is changed
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
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
        meta.sip_meta_valid = 0;
        hdr.ethernet.ether_type=ETHERTYPE_IPV4; 
    }
    action server_to_client_normal_traffic(){
        hdr.sip_meta.setInvalid();
        meta.sip_meta_valid = 0;
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
    action start_crc_calc_synack() {
        hdr.sip_meta.setValid(); // added to fix behaviour
        meta.sip_meta_valid = 1;
        hdr.sip_meta.callback_type = CALLBACK_TYPE_SYNACK;
        hdr.sip_meta.egr_port = standard_metadata.ingress_port; 
        route_to(hdr.sip_meta.egr_port);

        // Compute CRC32 hash and store in metadata
        hash(meta.cookie_hash, HashAlgorithm.crc32, (bit<32>) 0, 
            { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no }, 
            (bit<32>) 65535);
        
        
    }

    action start_crc_calc_tagack() {
        hdr.sip_meta.setValid(); // added to fix behaviour
        meta.sip_meta_valid = 1;
        hdr.sip_meta.callback_type = CALLBACK_TYPE_TAGACK;
        hdr.sip_meta.egr_port = SERVER_PORT; 

        // Compute CRC32 hash and store in metadata
        hash(meta.cookie_hash, HashAlgorithm.crc32, (bit<32>) 0, 
            { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no }, 
            (bit<32>) 65535);
    }

    action pre_finalize_synack(){
        // hdr.sip_meta.round=10;
        // route_to(hdr.sip_meta.egr_port);
        // dont_bypass_egress();
        // // dont_drop();
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
            start_crc_calc_synack;
            start_crc_calc_tagack;
            client_to_server_nonsyn_ongoing;
            server_to_client_normal_traffic;
            non_tcp_traffic;
            
            pre_finalize_synack;
            pre_finalize_tagack;
            finalize_tagack;
        }
        default_action = drop();
        // const entries = {//all types of packets, from linker_config.json in Lucid
             
        //      //"event" : "udp_from_server_time"
        //      (0,false,true,   true,    _,_,_,  _, _): drop(); //already saved time delta
        //      //"event" : "iptcp_to_server_syn"
        //      (0,true,false,   false,   1,0,_,  _, _ ): start_crc_calc_synack();
        //      //"event" : "iptcp_to_server_non_syn"
        //      (0,true,false,   false,   0,_,_,  _, false): start_crc_calc_tagack();
        //      (0,true,false,   false,   0,_,_,  _, true): client_to_server_nonsyn_ongoing();
             
        //      //"event" : "iptcp_from_server_tagged"
        //      (0,true,false,   true,    _,_,1,  _, _): drop(); //already added to bf
        //      //"event" : "iptcp_from_server_non_tagged"
        //      (0,true,false,   true,    _,_,0,  _, _): server_to_client_normal_traffic();
        //      //"event" : "non_tcp_in"
        //      (0,false,true, false,     _,_,_,  _, _): non_tcp_traffic();
        //      (0,false,false, _,     _,_,_,  _, _): non_tcp_traffic();
             
        //      //round 8->10
        //      (8,true,false,  _,     _,_,_,  CALLBACK_TYPE_TAGACK, _): pre_finalize_tagack(); //round 8->10, tagack needs one last recirc, after 3rd pass (12 round) come back to ingress again for final determination
        //      (8,true,false,  _,     _,_,_,  CALLBACK_TYPE_SYNACK, _): pre_finalize_synack(); //round 8->10, route to client
        //      //round 12, tagack
        //      (12,true,false, _,     _,_,_,  CALLBACK_TYPE_TAGACK, _): finalize_tagack(); //route to server, drop if bad cookie 
        // }
        size = 32;
    }

    apply {    
        //stage 0
        // tb_maybe_sip_init.apply();
       
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


        // send the packet to be recirculated by default, either 68 or 68+128 to saturate bandwidth in both directions
        // bit<1> rnd;
        // hash(rnd, HashAlgorithm.crc16, (bit<32>)0, {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, (bit<32>)1);
        // if (rnd == 1) {
        //     route_to(68);
        // } else {
        //     route_to(68+128);
        // }

        route_to(68); // send the packet to 68 for debugging
        

        tb_triage_pkt_types_nextstep.apply();
    }
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {
    
    action clean_up(){
        meta.sip_meta_valid = 0;
        hdr.sip_meta.setInvalid();
        hdr.ethernet.ether_type=ETHERTYPE_IPV4; 
    }
 
    action sip_final_xor_with_time(){
        // hdr.tcp.seq_no = hdr.sip_meta.cookie_time ^ hdr.sip_meta.v_0 ^ hdr.sip_meta.v_1 ^ hdr.sip_meta.v_2 ^ hdr.sip_meta.v_3;
        hdr.tcp.seq_no = meta.cookie_hash ^ hdr.sip_meta.cookie_time;
        clean_up();
    }
    
	action verify_timediff(){
	    hdr.sip_meta.ack_verify_timediff = hdr.sip_meta.cookie_time - meta.cookie_val; // should be 0 or 1
	}

    action sip_final_xor_with_ackm1(){
        // meta.cookie_val = meta.incoming_ack_minus_1 ^ hdr.sip_meta.v_0 ^ hdr.sip_meta.v_1 ^ hdr.sip_meta.v_2 ^ hdr.sip_meta.v_3;
        meta.cookie_val = meta.incoming_ack_minus_1 ^ meta.cookie_hash; // correct?
        verify_timediff();
    }

    action craft_synack_reply(){
        hdr.tcp.ack_no=meta.incoming_seq_plus_1;
        //dont't anymore: move this call to a separate table call to avoid too many hashes in one action/table 
	   sip_final_xor_with_time(); // cookie_val = time ^ hash, -> synack
	
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
    
    // table tb_decide_output_type_2 {
    //     key = {
    //         meta.sip_meta_valid: exact;
    //         meta.tcp_valid: exact;
    //         hdr.sip_meta.round: exact;
    //         hdr.sip_meta.callback_type: ternary;
    //     }
    //     actions = {
    //         sip_final_xor_with_time;
    //         verify_timediff;
    //         nop;
    //     }
    //     default_action = nop;
    //     size = 16;
    //     // const entries={
    //     //     (true, true, 12, CALLBACK_TYPE_SYNACK): sip_final_xor_with_time();//need second stage to not have two hash copies in one action 
    //     //     (true, true, 12, CALLBACK_TYPE_TAGACK): verify_timediff(); //need second stage to complete case for CALLBACK_TYPE_TAGACK 
    //     // }
    // }

    apply {
        if(meta.bypass_egress == 0){

            if(hdr.sip_meta.round != 99){
                hdr.sip_meta.round = hdr.sip_meta.round + 2;

                meta.incoming_ack_minus_1 = hdr.tcp.ack_no - 1;
                meta.incoming_seq_plus_1 = hdr.tcp.seq_no + 1;
                meta.tcp_total_len = 20;
                
                meta.redo_checksum = 0;

                hdr.sip_meta.round = 12;

                tb_decide_output_type_1.apply(); 	 
                // tb_decide_output_type_2.apply(); 
            }//endif round!=99
            else{ //round==99, here from ingress to perform checksum update in deparser  
            //don't do any further modification of packet 

                //necessary for checksum update 
                hdr.ipv4.ihl=5;
                hdr.ipv4.total_len=40; 

                meta.redo_checksum=1;
                meta.tcp_total_len=20; 
                // remove sip_meta header
                hdr.sip_meta.setInvalid();
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