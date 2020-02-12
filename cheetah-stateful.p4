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
#define STATEFUL_SIZE 10

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
  register<bit<16>>(1) debug_hash;
  register<bit<16>>(20) index_to_hash;
  register<bit<16>>(20) index_to_server_id;
  register<bit<16>>(20) free_indices;
  bit<16> free_index_value;
  register<bit<16>>(2) push_index;
  bit<16> push_index_value;
  register<bit<16>>(2) pop_index;
  bit<16> pop_index_value;
  //register<bit<16>>(65536) index_to_timestamp;
  //register<bit<16>>(65536) index_to_transition_state;
  bit<16> counter_value; 
  bit<16> server_id; 
  bit<1> server_timestamp_state;
  bit<16> server_timestamp;
  bit<16> bucket_id;
  bit<16> cookie;
  bit<16> stored_hash;

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

  action fwd(bit<16> egress_port, bit<32> dip, bit<48> mac_server, bit<16> server_id_input){
    hdr.ipv4.dstAddr = dip;
    hdr.ethernet.dstAddr = mac_server;
    standard_metadata.egress_spec = (bit<9>)egress_port;
    server_id = server_id_input;
  }

  action fwd_2(bit<16> egress_port, bit<32> dip, bit<48> mac_server){
    hdr.ipv4.dstAddr = dip;
    hdr.ethernet.dstAddr = mac_server;
    standard_metadata.egress_spec = (bit<9>)egress_port;
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
      bit<16> offset = 0;
      bit<16> offset_unit = 0;
      server_id = 0;
        if(hdr.ipv4.isValid()){
          //VIP is 10.0.0.254, which is 0x0a0000fe
          if(hdr.ipv4.dstAddr==0x0a0000fe){
            // incoming packet from client
            if(hdr.tcp.isValid()){
              compute_packet_hash(hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.ipv4.protocol);
              if(((bit<1>)meta.packet_hash) == 1){
                offset = STATEFUL_SIZE;
                offset_unit = 1;
              }
              if(hdr.tcp.syn == 0){
                //old connection, extract cookie and obtain server_id
                index_to_hash.read(stored_hash,(bit<32>)(hdr.timestamp.tsecr_lsb + offset));
                if(meta.packet_hash != stored_hash){
                  mark_to_drop();
                }else{
                  index_to_server_id.read(meta.server_id,(bit<32>)(hdr.timestamp.tsecr_lsb+ offset));
                  //old connection,
                  //fixing the timestamp now
                  get_server_from_id.apply();
                  if(hdr.tcp.fin == 1){
                    push_index.read(push_index_value,(bit<32>)offset_unit);
                    free_indices.write((bit<32>)(push_index_value+ offset), hdr.timestamp.tsecr_lsb);
                    push_index_value=push_index_value + 1;
                    if(push_index_value == (10+ offset)){
                      push_index_value = offset;
                      //TODO: we should also check if we are overlapping with the pop index
                    }
                    push_index.write((bit<32>)offset_unit,push_index_value);
                    index_to_hash.write((bit<32>)(hdr.timestamp.tsecr_lsb+ offset),0xffff);
                    index_to_server_id.write((bit<32>)(hdr.timestamp.tsecr_lsb+ offset),0xffff);
                  }
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

                pop_index.read(pop_index_value,(bit<32>)offset_unit);
                free_indices.read(free_index_value,(bit<32>)(pop_index_value+ offset));
                free_indices.write((bit<32>)(pop_index_value+ offset), 0xffff);
                pop_index_value=pop_index_value + 1;
                if(pop_index_value == (10+ offset)){
                  pop_index_value = offset;
                }
                pop_index.write((bit<32>)offset_unit,pop_index_value);
                index_to_hash.write((bit<32>)(free_index_value+ offset),meta.packet_hash);
                index_to_server_id.write((bit<32>)(free_index_value+ offset),server_id);
                hdr.timestamp.tsecr_lsb = free_index_value;
              }
            }
          }else{
            //incoming packet from server, we need to add the cookie
            if(hdr.tcp.isValid()){
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
