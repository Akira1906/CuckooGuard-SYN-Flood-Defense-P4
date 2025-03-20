#include <core.p4>
#include <v1model.p4>

#ifndef FILTER_SIZE //CUCKOO_N_FINGERPRINTS
#define FILTER_SIZE 32w316
#endif
#define CUCKOO_N_FINGERPRINTS FILTER_SIZE


// #ifndef FILTER_SIZE_MINUS_ONE //N_FINGERPRINTS_MINUS_ONE
// #define FILTER_SIZE_MINUS_ONE 315
// #endif
// #define N_FINGERPRINTS_MINUS_ONE FILTER_SIZE_MINUS_ONE

#ifndef FINGERPRINT_SIZE
#define FINGERPRINT_SIZE 10
#endif

const bit<6> fp_bit_index = 32 - FINGERPRINT_SIZE;

#ifndef N_BUCKETS
#define N_BUCKETS 79
#endif

#ifndef N_BUCKETS_MINUS_ONE
#define N_BUCKETS_MINUS_ONE 78
#endif

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
// cuckoo fingeprint size
typedef bit<FINGERPRINT_SIZE> cuckoo_fingerprint_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_CUCKOO = 16w0xff00;

// Cuckoo Filter Parameters
// Determine constants using formula
// const bit<32> CAPACITY = 79; // size of the filter
const bit<32> bucket_size = 4;
const bit<32> max_kicks = 500;

// Testbed parameters
const bit<9> SERVER_PORT=3; 

typedef bit<8> ip_protocol_t;
typedef bit<9> egress_spec_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

const bit<16> PORT_TIMEDELTA_UPDATE = 5555; // for time delta

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

// header cuckoo_h {
//     cuckoo_fingerprint_t fingerprint;
//     bit<32> index;
//     bit<16> loop_count;
// }

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
    // cuckoo_h cuckoo;
    ipv4_h ipv4;
    tcp_h tcp;
    udp_h udp;
    udp_payload_h udp_payload;
}

struct metadata_t {
    // Header validity bits for use in tables
    bit<1> tcp_valid;
    bit<1> udp_payload_valid;
    bit<1> cuckoo_valid;
    
    // Timestamping
    bit<32> timestamp_now_copy;
    bit<32> timestamp_minus_servertime;
    
    // // Bloom Filter
    // bit<1> bloom_read_1;
    // bit<1> bloom_read_2;
    // // new introduced metadata
    // bit<32> bloom_hash_1;
    // bit<32> bloom_hash_2;

    // bit<1> bloom_read_passed;

    // Cuckoo Metadata to be preserved after recirculation
    @field_list(1)
    cuckoo_fingerprint_t cuckoo_fingerprint;
    @field_list(1)
    bit<32> cuckoo_index;
    @field_list(1)
    bit<16> cuckoo_loop_count; // inidicates the round number 1....501

    // Cuckoo Filter
    bit<32> cuckoo_index1;
    bit<32> cuckoo_index2;
    bit<1> cuckoo_insert_success;
    bit<1> cuckoo_delete_success;
    bit<1> cuckoo_check_passed;
    bit<4> pseudo_random_bits;
    bit<1> cuckoo_insert_failed;

    

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
            // ETHERTYPE_CUCKOO : parse_cuckoo;
            default : accept;
        }
    }

    // state parse_cuckoo {
    //     pkt.extract(hdr.cuckoo);
    //     meta.cuckoo_valid = 1;
    //     transition parse_ipv4;
    // }
    
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

    // action recirculate() {
    //     standard_metadata.egress_spec = 68;
    // }

  
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
            meta.cuckoo_loop_count: ternary;
            
            meta.ingress_is_server_port: ternary;
            
            hdr.tcp.flag_syn: ternary;
            hdr.tcp.flag_ack: ternary;
            hdr.tcp.flag_ece: ternary; 
            hdr.tcp.flag_psh: ternary;
            
            // meta.callback_type: ternary;
            
            meta.cuckoo_check_passed: ternary;
        }
        actions = {
            drop;

            start_crc_calc_synack;
            start_crc_calc_tagack;

            client_to_server_nonsyn_ongoing;
            server_to_client_normal_traffic;
            
            NoAction;
            non_tcp_traffic;
            
        }
        default_action = drop();
        // const entries = {//all types of packets, from linker_config.json in Lucid
             
        //      //"event" : "udp_from_server_time"
        //      (0, 1, 0, 1, _, _, _, _, _): drop(); //already saved time delta
        //      //"event" : "iptcp_to_server_syn"
        //      (1, 0, 0, 0, 1, 0, _, 0, _): start_crc_calc_synack();
        //      //"event" : "iptcp_to_server_non_syn"
        //      (1, 0, 0, 0, 0, _, _, 0, 0): start_crc_calc_tagack();
        //      (1, 0, 0, 0, 0, _, _, 0, 1): client_to_server_nonsyn_ongoing();
             
        //      //"event" : "iptcp_from_server_tagged"
        //      (1, 0, 0, 1, _, _, 1, _, _): drop(); //already added to cuckoo filter
        //      //"event" : "iptcp_from_server_non_tagged"
        //      (1, 0, 0, 1, _, _, 0, _, _): server_to_client_normal_traffic();
        //      //"event" : "non_tcp_in"
        //      (0, 1, 0, 0, _, _, _, _, _): non_tcp_traffic();
        //      (0, 1, 0, _, _, _, _, _, _): non_tcp_traffic();
        //      commented out: (1, 0, _, _, _, _, _, _, _): NoAction();
        //      (1, 0, 0, 0, _, 1, _, _, 0): drop(); // drop ack packets that come from an unexpected source
        //      commented out:(true, false,0,_, _, _, _, _, _, 0): drop();
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

    // CUCKOO Filter
    // e.g. fingerprint: 10 bits, 79 * 4 = 316 entries
    // e.g. capacity is 79
    register<cuckoo_fingerprint_t>(CUCKOO_N_FINGERPRINTS) reg_cuckoo;

    action cuckoo_bucket_insert(bit<32> bucket_index) {
        // check all 4 possible bucket values and insert if any of them is empty

        // bucket index -> entry index in register
        bit<32> entry_index = bucket_index << 2; // * 4
        
        cuckoo_fingerprint_t curr_fingerprint = 0;

        reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index);
        bit<2> insert_pos = 0;

        if (curr_fingerprint != 0) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 1);
            insert_pos = 1;
        }

        if (curr_fingerprint != 0) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 2);
            insert_pos = 2;
        }

        if (curr_fingerprint != 0) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 3);
            insert_pos = 3;
        }

        // If found free entry in bucket[bucket_index] then insert
        if (curr_fingerprint == 0) {
            meta.cuckoo_insert_success = 1;
            entry_index = entry_index + (bit<32>) insert_pos;

            reg_cuckoo.write((bit<32>) entry_index, meta.cuckoo_fingerprint);            
        }
    }

    action cuckoo_calc_index_pair() {
        // calculate index1, index_hash(item)
        hash(meta.cuckoo_index1, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port},
        (bit<32>) N_BUCKETS_MINUS_ONE);

        // index2, index_hash(fingerprint)
        hash(meta.cuckoo_index2, HashAlgorithm.crc32, (bit<32>)0, {meta.cuckoo_fingerprint},
        (bit<32>) N_BUCKETS_MINUS_ONE);

        bit<32> temp_index;

        temp_index = meta.cuckoo_index1 ^ meta.cuckoo_index2;
        if(temp_index >= N_BUCKETS){
            temp_index = temp_index - N_BUCKETS;
        }
        meta.cuckoo_index2 = temp_index;
    }

    action cuckoo_calc_fingerprint() {
        bit<32> index_hash;
        hash(index_hash, HashAlgorithm.crc32, (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port}, 
            (bit<32>)4294967295);

        meta.cuckoo_fingerprint = index_hash[31:fp_bit_index];
        meta.pseudo_random_bits = index_hash[3:0];
    }

    action cuckoo_insert_init() {
        cuckoo_calc_fingerprint();
        cuckoo_calc_index_pair();

        // meta.cuckoo_index1, meta.cuckoo_index2

        // check if bucket at index1 is empty

        cuckoo_bucket_insert(meta.cuckoo_index1);

        if (meta.cuckoo_insert_success == 0){
            cuckoo_bucket_insert(meta.cuckoo_index2);
        }

        // If unsuccessfull then start the insertion-kick loop
        if (meta.cuckoo_insert_success == 0){

            // Choose a random out of the indices to save to header
            bit<1> random_bit;
            random(random_bit, 0, 1);

            if (random_bit == 1) {
                meta.cuckoo_index = meta.cuckoo_index1;
            }
            else {
                meta.cuckoo_index = meta.cuckoo_index2;
            }
            // all necessary metadata is now set
            meta.cuckoo_loop_count = 1;
             // this is a marker for the Cuckoo algorithm to start the kicking process

        }


        // reg_cuckoo.read(stored_fingerprint, (bit<32>) );

    }

    action cuckoo_swap_fingerprint() {
        bit<2> random_entry;
        random(random_entry, 0, 3);

        bit<32> entry_index;
        entry_index = meta.cuckoo_index << 2;
        entry_index = entry_index + (bit<32>) random_entry;

        // swap fingerprint in meta and in the random entry in the bucket
        cuckoo_fingerprint_t temp;
        reg_cuckoo.read(temp, (bit<32>) entry_index);
        reg_cuckoo.write((bit<32>) entry_index, meta.cuckoo_fingerprint);
        meta.cuckoo_fingerprint = temp;
    }

    action cuckoo_insert_kick_round() {

        cuckoo_swap_fingerprint();

        bit<32> index_hash;
        hash(index_hash, HashAlgorithm.crc32, (bit<32>)0, {meta.cuckoo_fingerprint},
        (bit<32>) N_BUCKETS_MINUS_ONE);
        index_hash = meta.cuckoo_index ^ index_hash;
        if (index_hash >= N_BUCKETS) {
            index_hash = index_hash - N_BUCKETS; // workaround for modulo
        }
        meta.cuckoo_index = index_hash;

        cuckoo_bucket_insert(meta.cuckoo_index);

        meta.cuckoo_loop_count = meta.cuckoo_loop_count + 1;
    }

    // NOTE: maybe register reading could be optimized by using registers of size 4 * fingerprint = bucke size
    //       this way we can only need to read once from register and then do bit splicing to check
    // TODO

    action cuckoo_check_index(bit<32> index) {

        cuckoo_fingerprint_t curr_fingerprint;
        bit<32> entry_index = index << 2;

        // Checky entry 0
        reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index);

        // Checky entry 1
        if (curr_fingerprint != meta.cuckoo_fingerprint) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 1);
        }
        
        // Checky entry 2
        if (curr_fingerprint != meta.cuckoo_fingerprint) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 2);
        }
        
        // Checky entry 3
        if (curr_fingerprint != meta.cuckoo_fingerprint) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 3);
        }

        if (curr_fingerprint == meta.cuckoo_fingerprint) {
            meta.cuckoo_check_passed = 1;
        }
    }

    action cuckoo_check() {
        cuckoo_calc_fingerprint();
        cuckoo_calc_index_pair();
        
        cuckoo_check_index(meta.cuckoo_index1);
        if(meta.cuckoo_check_passed == 0){
            cuckoo_check_index(meta.cuckoo_index2);
        }
        // check if this exact fingerprint is in one of the two buckets
    }

    action cuckoo_bucket_delete(bit<32> bucket_index) {
        bit<32> entry_index = bucket_index << 2;

        cuckoo_fingerprint_t curr_fingerprint = 0;

        reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index);

        bit<2> delete_pos = 0;

        if (curr_fingerprint != meta.cuckoo_fingerprint) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 1);
            delete_pos = 1;
        }

        if (curr_fingerprint != meta.cuckoo_fingerprint) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 2);
            delete_pos = 2;
        }

        if (curr_fingerprint != meta.cuckoo_fingerprint) {
            reg_cuckoo.read(curr_fingerprint, (bit<32>) entry_index + 3);
            delete_pos = 3;
        }

        // If found fingerprint to delete in bucket[bucket_index] then nullify
        if (curr_fingerprint == meta.cuckoo_fingerprint) {
            meta.cuckoo_delete_success = 1;
            entry_index = entry_index + (bit<32>) delete_pos;

            reg_cuckoo.write((bit<32>) entry_index, (cuckoo_fingerprint_t) 0);            
        }
    }

    action cuckoo_delete() {
        // first: swap src, dst addr and port
        bit<32> temp_ip = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = temp_ip;

        bit<16> temp_port = hdr.tcp.src_port;
        hdr.tcp.src_port = hdr.tcp.dst_port;
        hdr.tcp.dst_port = temp_port;

        cuckoo_calc_fingerprint();
        cuckoo_calc_index_pair();

        // Try to delete from one of both buckets

        cuckoo_bucket_delete(meta.cuckoo_index1);

        if (meta.cuckoo_delete_success == 0){
            cuckoo_bucket_delete(meta.cuckoo_index2);
        }

        // swap it back
        hdr.ipv4.dst_addr = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = temp_ip;

        hdr.tcp.dst_port = hdr.tcp.src_port;
        hdr.tcp.src_port = temp_port;
    }

    action cuckoo_insert_kick_success(){

    }

    action cuckoo_insert_kick_fail(){

    }

    register< bit<32> >(1) reg_debug;
    register< bit<32> >(2) reg_debug2;

    action debug_write_loop_count(){
        reg_debug.write((bit<32>) 0, (bit<32>) meta.cuckoo_loop_count);
    }

    action debug_write_final_loop_count(){
        reg_debug2.write((bit<32>) 0, (bit<32>) meta.cuckoo_loop_count);
        reg_debug2.write((bit<32>) 1, (bit<32>) hdr.tcp.src_port);
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

        // Cuckoo Filter set and get

        // More realistic cuckoo_delete conditions:
        // 1. FIN Flag is set, technically have to wait for FIN acknowledgment, maybe server is enough?
        // RST Flag from one of both sides


        if (hdr.tcp.isValid() && standard_metadata.ingress_port == SERVER_PORT && hdr.tcp.flag_ece == 1 && meta.cuckoo_loop_count == 0){
            if(hdr.tcp.flag_urg == 1){
                cuckoo_delete();
                // set the flags back to normal so ACK packet can reach client
                hdr.tcp.flag_urg = 0;
                hdr.tcp.flag_ece = 0;
            }
            else{
                cuckoo_insert_init(); // sets loop_count to 1 if no place found yet
                // if possible immediately add element to cuckoo filter if not
                // set up cuckoo header up with metadata to start kicking process
            }

        
        }

        if(meta.cuckoo_loop_count != 0){
            cuckoo_insert_kick_round(); // increments loop_count

            if (meta.cuckoo_loop_count == 501) {
                cuckoo_insert_kick_fail(); // DEBUGGING
                drop();
            }
            // this is gonna be the final loop
            // this case has to be handled later, but it should technically not happen
            // swap the fingerprint with one entry from bucket[index]
            // if not successfull recirculate the packet
            // increment the circulation counter of the packet
            // if circulation counter too high drop packet
            // keep a counter about how many elements were already added to the cuckoo filter
            debug_write_loop_count();

            if(meta.cuckoo_insert_success == 0){
                // recirculate();
                resubmit_preserving_field_list(1); // marks the packet for resubmission
                bypass_egress();
                skip_routing();
            }
            else{
                cuckoo_insert_kick_success(); // DEBUGGING
                debug_write_final_loop_count();
                drop();
            }
        }else{ // standard case
            cuckoo_check();
            // check cuckoo filter if element is added already
            // sets meta.cuckoo_check_passed bit
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
        // pkt.emit(hdr.cuckoo);
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