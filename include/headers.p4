/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// Parsing of TCP options taken from Andy Fingerhut: 
// https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser.p4
// parsing of TCP timestamp option added by Marco Chiesa

typedef bit<48>  EthernetAddress;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header Tcp_option_end_h {
    bit<8> kind;
}
header Tcp_option_nop_h {
    bit<8> kind;
}
header Tcp_option_sz_h {
    bit<8> length;
}
header Tcp_option_ss_h {
    bit<8>  kind;
    bit<8> length;
    bit<32> maxSegmentSize;
}
header Tcp_option_s_h {
    bit<8>  kind;
    bit<24> scale;
}
header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}
header Tcp_option_timestamp_h {
    bit<8>         kind;
    bit<8>         length;
    bit<16>        tsval_msb;
    bit<16>        tsval_lsb;
    bit<16>        tsecr_msb;
    bit<16>        tsecr_lsb;
}

//Versions without the kind for hop by hop
header Tcp_option_ss_e {
    bit<8> length;
    bit<16> maxSegmentSize;
}

header Tcp_option_sack_e {
    varbit<256>    sack;
}
header Tcp_option_timestamp_e {
    bit<8>         length;
    bit<16>        tsval_msb;
    bit<16>        tsval_lsb;
    bit<16>        tsecr_msb;
    bit<16>        tsecr_lsb;
}

//Unused (does not compile yet)
header_union Tcp_option_h {
    Tcp_option_end_h  end;
    Tcp_option_nop_h  nop;
    Tcp_option_ss_h   ss;
    Tcp_option_s_h    s;
    Tcp_option_sack_h sack;
    //Tcp_option_timestamp_h timestamp;
}

// Defines a stack of 10 tcp options
typedef Tcp_option_h[10] Tcp_option_stack;

header Tcp_option_padding_h {
    varbit<256> padding;
}

struct headers {
    ethernet_t       ethernet;
    ipv4_t           ipv4;
    tcp_t            tcp;
    //Tcp_option_stack tcp_options_vec;
    //Tcp_option_padding_h tcp_options_padding;
    //Linux established nop nop ts
    Tcp_option_nop_h nop1;
    Tcp_option_nop_h nop2;
    //Linux MSS SACK TS
    Tcp_option_ss_e ss;
    Tcp_option_nop_h nop3;
    Tcp_option_sz_h sackw;
    Tcp_option_sack_e sack;
    Tcp_option_nop_h nop4;
    Tcp_option_timestamp_e timestamp;
}

struct fwd_metadata_t {
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    bit<16> bucket_id;
    bit<16> packet_hash;
    bit<16> server_id;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

struct Tcp_option_sack_top
{
    bit<8> kind;
    bit<8> length;
}


