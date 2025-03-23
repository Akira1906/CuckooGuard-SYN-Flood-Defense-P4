#include <core.p4>
#include <v1model.p4>

#ifndef FILTER_SIZE
#define FILTER_SIZE 32w4096
#endif

#ifndef FILTER_SIZE_MINUS_ONE
#define FILTER_SIZE_MINUS_ONE 4095
#endif

#ifndef N_BUCKETS
#define N_BUCKETS 3
#endif

#define N_HASH_FUNCTIONS N_BUCKETS
#define STAGE_SIZE_MINUS_ONE FILTER_SIZE_MINUS_ONE
#define BLOOM_STAGE_SIZE FILTER_SIZE

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_SIPH_INTM = 16w0xff00;

// Testbed parameters
const bit<9> SERVER_PORT=3; 

typedef bit<8> ip_protocol_t;
typedef bit<9> egress_spec_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const bit<16> PORT_TIMEDELTA_UPDATE = 5555; //for time delta

const bit<4> CALLBACK_TYPE_SYNACK=1;
const bit<4> CALLBACK_TYPE_TAGACK=2; 

struct paired_32bit {
    bit<32> lo;
    bit<32> hi;
}

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
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
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    udp_payload_h udp_payload;
}

struct metadata_t {
    // Header validity bits for use in tables
    bit<1> tcp_valid;
    bit<1> udp_payload_valid;
    
    // Timestamping
    bit<32> timestamp_now_copy;
    bit<32> timestamp_minus_servertime;
    
    // Bloom Filter
    bit<1> bloom_read;
    // new introduced metadata
    bit<32> bloom_hash;
    bit<32> bloom_hash_1;
    bit<32> bloom_hash_2;
    // bit<1> active_bloom_filter;
    bit<1> bloom_read_passed;
    

    // Packet metadata
    bit<1> ingress_is_server_port;

    bit<32> incoming_ack_minus_1;
    bit<32> incoming_seq_plus_1;
    
    bit<16> tcp_len;

    // Cookie-related
    bit<32> cookie_hash;
    bit<32> cookie_val;
    bit<32> cookie_time;
    bit<32> ack_verify_timediff;
    bit<1> ack_verify_timediff_exceeded_limit;

    // Cookie control flow
    bit<4> callback_type;
    bit<1> bypass_egress;
    bit<1> skip_routing;
    bit<9> egr_port;

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
            default : accept;
        }
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


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {
        
    action bypass_egress(){
        // bypass final step "egress"
        meta.bypass_egress = 1;
    }
    action dont_bypass_egress(){
        // don't bypass final step "egress"
        meta.bypass_egress = 0;
    }

    action skip_routing(){
        // skip table based IPv4 forwarding
        meta.skip_routing = 1;
    }
     
    action drop() {
        // drops the packet as quick as possible
        mark_to_drop(standard_metadata);
        bypass_egress();
        skip_routing();
    }

  
    // time-delta 

    register< bit<32> >(1) reg_timedelta;
        
	action timedelta_step0(){
        meta.timestamp_now_copy = (bit<32>) standard_metadata.ingress_global_timestamp[47:16];
    }

    // to specify the time delta between server and proxy application
    action timedelta_step1_write(){
        meta.timestamp_minus_servertime = meta.timestamp_now_copy - hdr.udp_payload.timestamp;
    }

    action timedelta_step2_write(){
        reg_timedelta.write((bit<32>) 0, meta.timestamp_minus_servertime);

    }

    // calculate the actual cookie time as it would be at the server itself
    action timedelta_step1_read(){
        reg_timedelta.read(meta.timestamp_minus_servertime, (bit<32>) 0);
    }

    action timedelta_step2_read(){
       meta.cookie_time = meta.timestamp_now_copy - meta.timestamp_minus_servertime;
       if (meta.cookie_time == 0) { // DEBUG
        meta.cookie_time = 0;
       }
	}

	action timedelta_step3_read(){
  		meta.cookie_time = meta.cookie_time >> 7; // before it was 12, but that's very granular? 7 -> 1 == 10 sec
        reg_timedelta.write((bit<32>) 0, meta.cookie_time);
    }
    
    // Bloom Filter for flows
    // Bloom Filter #0
    register<bit<1>>(BLOOM_STAGE_SIZE) reg_bloom_0_1;
    // register<bit<1>>(BLOOM_STAGE_SIZE) reg_bloom_0_2;

    // Bloom Filter #1
    register<bit<1>>(BLOOM_STAGE_SIZE) reg_bloom_1_1;
    // register<bit<1>>(BLOOM_STAGE_SIZE) reg_bloom_1_2;


    action calc_bloom_hash_1(){
        hash(meta.bloom_hash_1, HashAlgorithm.crc16, (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, 
            (bit<32>)STAGE_SIZE_MINUS_ONE);
    }

    action calc_bloom_hash_2(){
        hash(meta.bloom_hash_2, HashAlgorithm.crc32, (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, 
            (bit<32>)STAGE_SIZE_MINUS_ONE);
    }

    action calc_bloom_hash_3(){
        meta.bloom_hash = meta.bloom_hash_2 + meta.bloom_hash_1;
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }
    action calc_bloom_hash_4() {
        meta.bloom_hash = meta.bloom_hash_2 + (2 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_5() {
        meta.bloom_hash = meta.bloom_hash_2 + (3 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_6() {
        meta.bloom_hash = meta.bloom_hash_2 + (4 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_7() {
        meta.bloom_hash = meta.bloom_hash_2 + (5 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_8() {
        meta.bloom_hash = meta.bloom_hash_2 + (6 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_9() {
        meta.bloom_hash = meta.bloom_hash_2 + (7 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_10() {
        meta.bloom_hash = meta.bloom_hash_2 + (8 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_11() {
        meta.bloom_hash = meta.bloom_hash_2 + (9 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_12() {
        meta.bloom_hash = meta.bloom_hash_2 + (10 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_13() {
        meta.bloom_hash = meta.bloom_hash_2 + (11 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action calc_bloom_hash_14() {
        meta.bloom_hash = meta.bloom_hash_2 + (12 * meta.bloom_hash_1);
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
        if (meta.bloom_hash > STAGE_SIZE_MINUS_ONE) {
            meta.bloom_hash = meta.bloom_hash - BLOOM_STAGE_SIZE;
        }
    }

    action set_bloom_1_a(){
        calc_bloom_hash_1();
        reg_bloom_0_1.write(meta.bloom_hash_1, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash_1, (bit<1>) 1);
    }

    action set_bloom_2_a(){
        calc_bloom_hash_2();
        reg_bloom_0_1.write(meta.bloom_hash_2, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash_2, (bit<1>) 1);
    }

    action set_bloom_3_a(){
        calc_bloom_hash_3();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_4_a(){
        calc_bloom_hash_4();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_5_a(){
        calc_bloom_hash_5();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_6_a(){
        calc_bloom_hash_6();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_7_a(){
        calc_bloom_hash_7();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_8_a(){
        calc_bloom_hash_8();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_9_a(){
        calc_bloom_hash_9();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_10_a(){
        calc_bloom_hash_10();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_11_a(){
        calc_bloom_hash_11();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_12_a(){
        calc_bloom_hash_12();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
    }

    action set_bloom_13_a(){
        calc_bloom_hash_13();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
        }

    action set_bloom_14_a(){
        calc_bloom_hash_14();
        reg_bloom_0_1.write(meta.bloom_hash, (bit<1>) 1);
        reg_bloom_1_1.write(meta.bloom_hash, (bit<1>) 1);
        }

    action get_bloom_1_a(){
        calc_bloom_hash_1();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash_1);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash_1);
        }
    }

    action get_bloom_2_a(){
        calc_bloom_hash_2();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash_2);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash_2);
        }
    }

    action get_bloom_3_a(){
        calc_bloom_hash_3();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_4_a(){
        calc_bloom_hash_4();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
        }

    action get_bloom_5_a(){
        calc_bloom_hash_5();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_6_a(){
        calc_bloom_hash_6();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_7_a(){
        calc_bloom_hash_7();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_8_a(){
        calc_bloom_hash_8();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_9_a(){
        calc_bloom_hash_9();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_10_a(){
        calc_bloom_hash_10();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_11_a(){
        calc_bloom_hash_11();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_12_a(){
        calc_bloom_hash_12();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_13_a(){
        calc_bloom_hash_13();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    action get_bloom_14_a(){
        calc_bloom_hash_14();
        reg_bloom_0_1.read(meta.bloom_read, meta.bloom_hash);
        if (meta.bloom_read == 0) {
            reg_bloom_1_1.read(meta.bloom_read, meta.bloom_hash);
        }
    }

    // tb_triage_pkt_types_nextstep actions
    // decide the next step for packets

    action client_to_server_nonsyn_ongoing(){
        bypass_egress();
    }

    action server_to_client_normal_traffic(){
        bypass_egress();
    }

    action non_tcp_traffic(){
        bypass_egress();
    }

    // Hash Calculation

    // create cookie hash
    action start_crc_calc_synack() {
        meta.callback_type = CALLBACK_TYPE_SYNACK;
        // reroute to ingress port
        meta.egr_port = standard_metadata.ingress_port; 

        // Compute CRC32 hash and store in metadata
        hash(meta.cookie_hash, HashAlgorithm.crc32, (bit<32>) 0, 
            { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no }, 
            (bit<32>) 65535);
        
    }

    // create cookie hash for later verification
    action start_crc_calc_tagack() {
        meta.callback_type = CALLBACK_TYPE_TAGACK;
        // reroute to server port
        meta.egr_port = SERVER_PORT;
        bit<32> seq_no_minusone = hdr.tcp.seq_no - 1;

        // Compute CRC32 hash and store in metadata
        hash(meta.cookie_hash, HashAlgorithm.crc32, (bit<32>) 0, 
            { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, seq_no_minusone }, 
            (bit<32>) 65535);
    }

    

    table tb_triage_pkt_types_nextstep {
        key = {
            meta.tcp_valid: exact;
            meta.udp_payload_valid: exact;
            
            meta.ingress_is_server_port: ternary;
            
            hdr.tcp.flag_syn: ternary;
            hdr.tcp.flag_ack: ternary;
            hdr.tcp.flag_ece: ternary; 
            
            meta.callback_type: ternary;
            
            meta.bloom_read_passed: ternary;
        }
        actions = {
            drop;

            start_crc_calc_synack;
            start_crc_calc_tagack;

            client_to_server_nonsyn_ongoing;
            server_to_client_normal_traffic;

            non_tcp_traffic;
            
        }
        default_action = drop();
        // const entries = {//all types of packets, from linker_config.json in Lucid
             
        //      //"event" : "udp_from_server_time"
        //      (false,true,   true,    _,_,_,  _, _): drop(); //already saved time delta
        //      //"event" : "iptcp_to_server_syn"
        //      (true,false,   false,   1,0,_,  _, _ ): start_crc_calc_synack();
        //      //"event" : "iptcp_to_server_non_syn"
        //      (true,false,   false,   0,_,_,  _, false): start_crc_calc_tagack();
        //      (true,false,   false,   0,_,_,  _, true): client_to_server_nonsyn_ongoing();
             
        //      //"event" : "iptcp_from_server_tagged"
        //      (true,false,   true,    _,_,1,  _, _): drop(); //already added to bf
        //      //"event" : "iptcp_from_server_non_tagged"
        //      (true,false,   true,    _,_,0,  _, _): server_to_client_normal_traffic();
        //      //"event" : "non_tcp_in"
        //      (false,true, false,     _,_,_,  _, _): non_tcp_traffic();
        //      (false,false, _,     _,_,_,  _, _): non_tcp_traffic();
        size = 32;
    }

    // forward packet to the appropriate port
    action ipv4_forward(mac_addr_t dst_addr, egress_spec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_addr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // we have one table responsible for forwarding packets
    table tb_ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;   // maximum number of entries in the table
        default_action = drop();
    }
 
    action final_xor_with_time(){
        hdr.tcp.seq_no = meta.cookie_hash ^ meta.cookie_time;
    }
    
	action verify_timediff(){
	    meta.ack_verify_timediff = meta.cookie_time - meta.cookie_val; // should be 0 or 1
	}

    action final_xor_with_ackm1(){
        meta.cookie_val = meta.incoming_ack_minus_1 ^ meta.cookie_hash;
    }

    action verify_ack(){
        final_xor_with_ackm1();
        verify_timediff();
    }

    action craft_synack_reply(){
        hdr.tcp.ack_no = meta.incoming_seq_plus_1;

	   final_xor_with_time(); // cookie_val = time ^ hash, -> synack
	
        //swap IP
        bit<32> tmp_ip = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp_ip;
       
    	//swap port 
    	bit<16> tmp_port = hdr.tcp.src_port;  
        hdr.tcp.src_port=hdr.tcp.dst_port;
        hdr.tcp.dst_port=tmp_port;
	
        //packet crafting 
        hdr.tcp.data_offset=5; //ignore tcp options by default
        
        hdr.tcp.flag_ack=1;
        hdr.tcp.flag_syn=1;

        hdr.ipv4.ihl=5;
    }

    table tb_decide_output_type {
        key = {
            // meta.sip_meta_valid: exact;
            meta.tcp_valid: exact;
            // hdr.sip_meta.round: exact;
            meta.callback_type: ternary;
        }
        actions = {
            craft_synack_reply; 
            verify_ack;
            // clean_up;
            NoAction;
        }
        default_action = NoAction;
        size = 16;
        // const entries={
        //     (true, CALLBACK_TYPE_SYNACK): craft_synack_reply();
        //     (true, CALLBACK_TYPE_TAGACK): verify_ack();  // cookie_val = (ack-1) ^ hash, ==? time(+1)
        // }
    }

    action craft_onward_ack(){
        hdr.tcp.seq_no = hdr.tcp.seq_no - 1;
        hdr.tcp.data_offset = 5;
        //add setup tag
        hdr.tcp.flag_ece = 1;
    }

    action finalize_tagack(){
        if (meta.ack_verify_timediff_exceeded_limit == 1) {
            mark_to_drop(standard_metadata);
        }
        craft_onward_ack();
    }

    action compute_tcp_length(){
        bit<16> tcpLength;
        bit<16> ipv4HeaderLength = ((bit<16>) hdr.ipv4.ihl) * 4;
        // this gives the size of IPv4 header in bytes, since ihl value represents
        // the number of 32-bit words including the options field
        tcpLength = hdr.ipv4.total_len - ipv4HeaderLength;
        // save this value to metadata to be used later in checksum computation
        meta.tcp_len = tcpLength;
    }

    apply {

        // Timedelta verification and setup
        timedelta_step0();
        if(hdr.udp.isValid() && standard_metadata.ingress_port == SERVER_PORT){
            timedelta_step1_write();
            timedelta_step2_write();
        }else{
            timedelta_step1_read();
            timedelta_step2_read();
            timedelta_step3_read();
        }

        // Check if Bloom Filter time-decaying mechanism has to run

        // Bloom Filter set and get
        
        if(hdr.tcp.isValid() && standard_metadata.ingress_port == SERVER_PORT && hdr.tcp.flag_ece==1){
            if (N_HASH_FUNCTIONS >= 1) {
                set_bloom_1_a();
                if (N_HASH_FUNCTIONS >= 2) {
                    set_bloom_2_a();
                    if (N_HASH_FUNCTIONS >= 3) {
                        set_bloom_3_a();
                        if (N_HASH_FUNCTIONS >= 4) {
                            set_bloom_4_a();
                            if (N_HASH_FUNCTIONS >= 5) {
                                set_bloom_5_a();
                                if (N_HASH_FUNCTIONS >= 6) {
                                    set_bloom_6_a();
                                    if (N_HASH_FUNCTIONS >= 7) {
                                        set_bloom_7_a();
                                        if (N_HASH_FUNCTIONS >= 8) {
                                            set_bloom_8_a();
                                            if (N_HASH_FUNCTIONS >= 9) {
                                                set_bloom_9_a();
                                                if (N_HASH_FUNCTIONS >= 10) {
                                                    set_bloom_10_a();
                                                    if (N_HASH_FUNCTIONS >= 11) {
                                                        set_bloom_11_a();
                                                        if (N_HASH_FUNCTIONS >= 12) {
                                                            set_bloom_12_a();
                                                            if (N_HASH_FUNCTIONS >= 13) {
                                                                set_bloom_13_a();
                                                                if (N_HASH_FUNCTIONS >= 14) {
                                                                    set_bloom_14_a();
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            meta.bloom_read_passed=0;
        }else{
            if (N_HASH_FUNCTIONS >= 1) {
                get_bloom_1_a();
                if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 2) {
                    get_bloom_2_a();
                    if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 3) {
                        get_bloom_3_a();
                        if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 4) {
                            get_bloom_4_a();
                            if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 5) {
                                get_bloom_5_a();
                                if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 6) {
                                    get_bloom_6_a();
                                    if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 7) {
                                        get_bloom_7_a();
                                        if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 8) {
                                            get_bloom_8_a();
                                            if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 9) {
                                                get_bloom_9_a();
                                                if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 10) {
                                                    get_bloom_10_a();
                                                    if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 11) {
                                                        get_bloom_11_a();
                                                        if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 12) {
                                                            get_bloom_12_a();
                                                            if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 13) {
                                                                get_bloom_13_a();
                                                                if (meta.bloom_read == 1 && N_HASH_FUNCTIONS >= 14) {
                                                                    get_bloom_14_a();
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            if(meta.bloom_read==1){
                meta.bloom_read_passed=1;
            }else{
                meta.bloom_read_passed=0;
            }
        }
        
        // pre-calculate conditions and save in metadata. used in final stage triage.
        if(standard_metadata.ingress_port==SERVER_PORT){
            meta.ingress_is_server_port = 1;
        }else{
            meta.ingress_is_server_port = 0;
        }

        tb_triage_pkt_types_nextstep.apply();


        // final packet processing stage: "egress"

        if(meta.bypass_egress == 0){
            meta.incoming_ack_minus_1 = hdr.tcp.ack_no - 1;
            meta.incoming_seq_plus_1 = hdr.tcp.seq_no + 1;

            tb_decide_output_type.apply(); 
            
            if(meta.callback_type == CALLBACK_TYPE_TAGACK){

                if(meta.ack_verify_timediff==0){  // before: || meta.ack_verify_timediff==1 || meta.ack_verify_timediff==2
                // == 0 is very strict this means it can't be older than 10 seconds, it should be more tolerant
                    meta.ack_verify_timediff_exceeded_limit=0;
                }else{
                    meta.ack_verify_timediff_exceeded_limit=1;
                    mark_to_drop(standard_metadata);
                    skip_routing();
                }

                if(hdr.tcp.isValid() && !hdr.udp.isValid() && meta.callback_type == CALLBACK_TYPE_TAGACK){
                    finalize_tagack();
                }
                // necessary for checksum update 
                hdr.ipv4.ihl=5;
                hdr.ipv4.total_len=40;
            }
        
        }
        
        compute_tcp_length();

        // Normal forwarding scenario after processing based on the scenario
        if (meta.skip_routing == 0 && hdr.ipv4.isValid()) {
            tb_ipv4_lpm.apply();
        }
    }
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout header_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t standard_metadata) {

    apply {}
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
              meta.tcp_len,
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

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        in header_t hdr) {
    
    apply {
        // Emit headers
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
    }
}


V1Switch(
    SwitchIngressParser(),
    MyVerifyChecksum(),
    SwitchIngress(),
    SwitchEgress(),
    MyComputeChecksum(),
    SwitchEgressDeparser()
) main;