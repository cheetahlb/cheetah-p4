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

  //Counter for the WRR
  register<bit<COUNTER_WIDTH>>(1) bucket_counter;

  //Register table to remeber each server's current MSB
  register<bit<16>>(65536) server_timestamps;

  //Version of each server's current timestamp
  register<bit<1>>(65536) server_to_transition_state;

  //A register for debugging, internal use only
  //register<bit<16>>(1) debug_hash;

  //IP Address of the VIP
  register<bit<32>>(1) vip_ip;

  //Various transient state variables
  bit<16> counter_value; 
  bit<16> server_id; 
  bit<1> server_timestamp_state;
  bit<16> server_timestamp;
  bit<16> bucket_id;
  bit<16> cookie;
  bit<32> vip;

  //Computes the hash of the packet, used for obfuscation
  action compute_packet_hash(bit<32> ip_addr_one, 
                             bit<16> tcp_port_one, 
                             bit<16> tcp_port_two,
                             bit<8> ip_protocol){
    hash(meta.packet_hash, HashAlgorithm.crc16,
              (bit<16>)0,
              { ip_addr_one, tcp_port_one, tcp_port_two, ip_protocol},
              (bit<16>)65535);
//    debug_hash.write(0,meta.packet_hash);
  }

  //Forwarding action for server bucket (new connection, the WRR table in practice)
  action fwd(bit<16> egress_port, bit<32> dip, bit<48> mac_server){
    hdr.ipv4.dstAddr = dip;
    hdr.ethernet.dstAddr = mac_server;
    standard_metadata.egress_spec = (bit<9>)egress_port;
  }

  //Forwarding action for the server id (for existing connections)
  action fwd_2(bit<16> egress_port, bit<32> dip, bit<48> mac_server){
    hdr.ipv4.dstAddr = dip;
    hdr.ethernet.dstAddr = mac_server;
    standard_metadata.egress_spec = (bit<9>)egress_port;
  }

  //Action to extract the server id from its IP
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


  // Incremental checksum fix adapted from the pseudocode at https://p4.org/p4-spec/docs/PSA-v1.1.0.html#appendix-internetchecksum-implementation
  action ones_complement_sum(in bit<16> x, in bit<16> y, out bit<16> sum) {
      bit<17> ret = (bit<17>) x + (bit<17>) y;
      if (ret[16:16] == 1) {
          ret = ret + 1;
      }
      sum = ret[15:0];
  }

  // Restriction: data is a multiple of 16 bits long
  action subtract(inout bit<16> sum, bit<16> d) {
        ones_complement_sum(sum, ~d, sum);
  }

  action subtract32(inout bit<16> sum, bit<32> d) {
        ones_complement_sum(sum, ~(bit<16>)d[15:0], sum);
        ones_complement_sum(sum, ~(bit<16>)d[31:16], sum);
  }

  action add(inout bit<16> sum, bit<16> d) {
        ones_complement_sum(sum, d, sum);
  }

  action add32(inout bit<16> sum, bit<32> d) {
        ones_complement_sum(sum, (bit<16>)(d[15:0]), sum);
        ones_complement_sum(sum, (bit<16>)(d[31:16]), sum);
  }

  apply {
      server_id = 0;
        if(hdr.ipv4.isValid()){

          vip_ip.read(vip, 0);
          if(hdr.ipv4.dstAddr==vip){ //If destination is the VIP, then this packets goes towards the server
            // incoming packet from client
            if(hdr.tcp.isValid() && hdr.timestamp.isValid()){

              //Two cases: either it is a new connection (SYN is true), or it is an established one
              if(hdr.tcp.syn == 0){

                bit <16> sum = 0;
                subtract(sum, hdr.tcp.checksum);
                subtract32(sum, hdr.ipv4.dstAddr);
                subtract(sum, hdr.timestamp.tsecr_msb);
                subtract(sum, hdr.timestamp.tsecr_lsb);

                //old connection, extract cookie and obtain server_id
                compute_packet_hash(hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.ipv4.protocol);

                //The serverID is the xor of the hash, abd the LSB of the timestamp
                server_id = meta.packet_hash ^ hdr.timestamp.tsecr_lsb;

                //Find the server's IP from its ID
                get_server_from_id.apply();

                //Now fix the timestamp
                server_to_transition_state.read(server_timestamp_state, (bit<32>)server_id);

                //The read the correct one
                server_timestamps.read(server_timestamp, (bit<32>)server_id);

                //Debugging stuff
                //debug_hash.write(0,server_timestamp);

                //If the MSB is 1, and the state is 1, it is the current timestamp
                if(hdr.timestamp.tsecr_msb >= 32768 && server_timestamp_state == 1){
                  hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                  hdr.timestamp.tsecr_msb = server_timestamp;
                //If the MSB is 1, but the state is 0, it is the old timestamp
                }else if(hdr.timestamp.tsecr_msb >= 32768 && server_timestamp_state == 0){
                  hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                  hdr.timestamp.tsecr_msb = server_timestamp -1;
                }else{ //If the MSB is 0, it is the current timestamp
                  hdr.timestamp.tsecr_lsb = hdr.timestamp.tsecr_msb;
                  hdr.timestamp.tsecr_msb = server_timestamp;
                }

                add32(sum, hdr.ipv4.dstAddr);
                add(sum, hdr.timestamp.tsecr_msb);
                add(sum, hdr.timestamp.tsecr_lsb);
                hdr.tcp.checksum = ~sum;
              } else {
                // new connection, get a server
                bucket_counter.read(meta.bucket_id, 0);

                bit<16> sum = 0;
                subtract(sum, hdr.tcp.checksum);
                subtract32(sum, hdr.ipv4.dstAddr);

                // we use the bucket index to find the server
                get_server_from_bucket.apply();
              
                // new connection, update counter
                meta.bucket_id = meta.bucket_id + 1;

                //Do the wrapping
                if (meta.bucket_id == BUCKET_SIZE) {
                    meta.bucket_id = 0;
                }
                bucket_counter.write(0, meta.bucket_id);
              }
            }
          }else{
            //incoming packet from server, we need to add the cookie
            if(hdr.tcp.isValid()){
              //We need to find the server id from its IP
              get_server_from_ip.apply();

              //Remember the server's original MSB
              server_timestamps.write((bit<32>)server_id, hdr.timestamp.tsval_msb);

              //Move the LSB to the MSB
              hdr.timestamp.tsval_msb = hdr.timestamp.tsval_lsb;

              //Compute the hash
              compute_packet_hash(hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort,hdr.ipv4.protocol);

              //Debugging stuffs
              //debug_hash.write(0,server_id);

              //The cookie is the xor of the server and hash
              cookie = server_id ^ meta.packet_hash;

              //Debugging stuffs
              //debug_hash.write(0,cookie);

              //Set the cookie in the LSB
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
