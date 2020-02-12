/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

#include "include/headers.p4"
#include "include/parsers.p4"

#define COUNTER_WIDTH 16
#define BUCKET_SIZE 6

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

  register<bit<COUNTER_WIDTH>>(1) bucket_counter;
  register<bit<16>>(65536) server_timestamps;
  register<bit<1>>(65536) server_to_transition_state;
  register<bit<16>>(1) debug_hash;
  bit<16> counter_value; 
  bit<16> server_id; 
  bit<1> server_timestamp_state;
  bit<16> server_timestamp;
  bit<16> bucket_id;
  bit<16> cookie;

  action compute_packet_hash(bit<32> ip_addr_one, 
                             bit<16> tcp_port_one, 
                             bit<16> tcp_port_two,
                             bit<8> ip_protocol){
    hash(meta.packet_hash, HashAlgorithm.crc16,
              (bit<16>)0,
              { ip_addr_one, tcp_port_one, tcp_port_two, ip_protocol},
              (bit<16>)65535);
    debug_hash.write(0,meta.packet_hash);
  }

  action fwd(bit<16> egress_port, bit<32> dip, bit<48> mac_server){
    hdr.ipv4.dstAddr = dip;
    hdr.ethernet.dstAddr = mac_server;
    standard_metadata.egress_spec = (bit<9>)egress_port;
  }

  action fwd_2(bit<16> egress_port, bit<32> dip, bit<48> mac_server){
    hdr.ipv4.dstAddr = dip;
    hdr.ethernet.dstAddr = mac_server;
    standard_metadata.egress_spec = (bit<9>)egress_port;
  }

  action get_server_id(bit<16> server_id_input){
    server_id = server_id_input;
  }

  table get_server_from_bucket {
    key = {
      meta.bucket_id: exact;
    }
    actions = {
      fwd;
    }
    size = 65536;
  }

  table get_server_from_ip {
    key = {
      hdr.ipv4.srcAddr: exact;
    }
    actions = {
      get_server_id;
    }
    size = 65536;
  }

  table get_server_from_id {
    key = {
      meta.server_id: exact;
    }
    actions = {
      fwd_2;
    }
    size = 65536;
  }

    apply {
      server_id = 0;
        if(hdr.ipv4.isValid()){
          //VIP is 10.0.0.254, which is 0x0a0000fe
          if(hdr.ipv4.dstAddr==0x0a0000fe){
            // incoming packet from client
            if(hdr.tcp.isValid()){

              if(hdr.tcp.syn == 0){
                //old connection, extract cookie and obtain server_id
                compute_packet_hash(hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.ipv4.protocol);
                server_id = meta.packet_hash ^ hdr.timestamp.tsecr_lsb;
                //old connection,
                //fixing the timestamp now
                get_server_from_id.apply();
                server_to_transition_state.read(server_timestamp_state, (bit<32>)server_id);
                server_timestamps.read(server_timestamp, (bit<32>)server_id);
                debug_hash.write(0,server_timestamp);
                if(hdr.timestamp.tsecr_msb >= 32768 && server_timestamp_state == 1){
                  hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                  hdr.timestamp.tsecr_msb = server_timestamp;
                }else if(hdr.timestamp.tsecr_msb >= 32768 && server_timestamp_state == 0){
                  hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                  hdr.timestamp.tsecr_msb = server_timestamp -1;
                }else{
                  hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                  hdr.timestamp.tsecr_msb = server_timestamp;
                }
              }else{
                // new connection, get a server
                bucket_counter.read(meta.bucket_id, 0);
              
                get_server_from_bucket.apply();
              
                // new connection, update counter
                meta.bucket_id = meta.bucket_id + 1;
                if (meta.bucket_id == BUCKET_SIZE){
                  meta.bucket_id = 0;
                }
                bucket_counter.write(0, meta.bucket_id);
              }
            }
          }else{
            //incoming packet from server, we need to add the cookie
            if(hdr.tcp.isValid()){

              get_server_from_ip.apply();
              server_timestamps.write((bit<32>)server_id, hdr.timestamp.tsval_msb);
              hdr.timestamp.tsval_msb = hdr.timestamp.tsval_lsb;
              compute_packet_hash(hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort,hdr.ipv4.protocol);
              //debug_hash.write(0,server_id);
              cookie = server_id ^ meta.packet_hash;
              //debug_hash.write(0,cookie);
              hdr.timestamp.tsval_lsb = cookie;
              if (hdr.timestamp.tsval_msb >= 32768){
                server_to_transition_state.write((bit<32>)server_id, 1);
              }else{
                server_to_transition_state.write((bit<32>)server_id, 0);
              }
              //send to client interface on port 1
              standard_metadata.egress_spec = (bit<9>)1;
              hdr.ethernet.dstAddr = 0x00000a000001;
              hdr.ipv4.srcAddr = 0x0a0000fe;
            }
          }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
