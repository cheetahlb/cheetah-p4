/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

// Parsing of TCP options taken from Andy Fingerhut: 
// https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser.p4
// However most of that code is unused as of now, as the compilation is still tricky with the ETH VM.
// Jump to line 100 for real stuffs.
// parsing of TCP timestamp option added by Marco Chiesa, more layouts by Tom Barbette

parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         out Tcp_option_stack vec,
                         out Tcp_option_padding_h padding)
{
    bit<7> tcp_hdr_bytes_left;
    
    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        // always true here: 0 <= tcp_hdr_bytes_left <= 40
        transition next_option;
    }
    state next_option {
        transition select(tcp_hdr_bytes_left) {
            0 : accept;  // no TCP header bytes left
            default : next_option_part2;
        }
    }
    state next_option_part2 {
        // precondition: tcp_hdr_bytes_left >= 1
        transition select(b.lookahead<bit<8>>()) {
            0: parse_tcp_option_end;
            1: parse_tcp_option_nop;
            2: parse_tcp_option_ss;
            3: parse_tcp_option_s;
            5: parse_tcp_option_sack;
           // 8: parse_tcp_option_timestamp;
        }
    }
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        // TBD: This code is an example demonstrating why it would be
        // useful to have sizeof(vec.next.end) instead of having to
        // put in a hard-coded length for each TCP option.
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition consume_remaining_tcp_hdr_and_accept;
    }
    state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(padding, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
    state parse_tcp_option_nop {
        b.extract(vec.next.nop);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition next_option;
    }
    state parse_tcp_option_ss {
        verify(tcp_hdr_bytes_left >= 5, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 5;
        b.extract(vec.next.ss);
        transition next_option;
    }
    state parse_tcp_option_s {
        verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 4;
        b.extract(vec.next.s);
        transition next_option;
    }
    /*state parse_tcp_option_timestamp {
        verify(tcp_hdr_bytes_left >= 10, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
        b.extract(vec.next.timestamp);
        transition next_option;
    }*/
    state parse_tcp_option_sack {
        bit<8> n_sack_bytes = b.lookahead<Tcp_option_sack_top>().length;
        // I do not have global knowledge of all TCP SACK
        // implementations, but from reading the RFC, it appears that
        // the only SACK option lengths that are legal are 2+8*n for
        // n=1, 2, 3, or 4, so set an error if anything else is seen.
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<7>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<7>) n_sack_bytes;
        b.extract(vec.next.sack, (bit<32>) (8 * n_sack_bytes - 16));
        transition next_option;
    }
}

//The real stuff now.
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
    	transition parse_ethernet;
    }

    state parse_ethernet {
    	packet.extract(hdr.ethernet);
    	transition select(hdr.ethernet.etherType){
    		0x0800: parse_ipv4;
    		default: accept;
    	}
    }

    state parse_ipv4 {
    	packet.extract(hdr.ipv4);
    	transition select(hdr.ipv4.protocol){
    		6: parse_tcp;
    		default: accept;
    	}
    }

    //Let's start the fun! We consider "nop" as actually a kind field, that we parse and then analyse to see what 
    // option we actually just parsed and "finish" the parsing that started.
    state parse_tcp {
    	packet.extract(hdr.tcp);
        //P4 16 is slightly getting there... But this is still not compiling, so
        // we must manually parse a few known layouts...
        //Tcp_option_parser.apply(packet, hdr.tcp.dataOffset,
        //                        hdr.tcp_options_vec, hdr.tcp_options_padding);
        packet.extract(hdr.nop1);
        transition select(hdr.nop1.kind){
		1: parse_nop;
            2: parse_ss;
            4: parse_sack;
            8: parse_ts;
		default: accept;
	}
    }

    state parse_nop {
        packet.extract(hdr.nop2);
         transition select(hdr.nop2.kind){
            1: parse_nop2;
            8: parse_ts;
		default: accept;
	}
    }
    state parse_nop2 {
        packet.extract(hdr.nop3);
         transition select(hdr.nop3.kind){
            8: parse_ts;
		default: accept;
	}
    }
    state parse_ss {
        //Finish parsing SS
        packet.extract(hdr.ss);
        packet.extract(hdr.nop3);
        transition select(hdr.nop3.kind){
            4: parse_sack;
            8: parse_ts;
		default: accept;
	}
    }

    state parse_sack {
        //Finish parsing sack
        packet.extract(hdr.sackw);
        packet.extract(hdr.sack, (bit<32>)hdr.sackw.length - 2);
        packet.extract(hdr.nop4);
        transition select(hdr.nop4.kind){
            8: parse_ts;
		default: accept;
	}
    }

    state parse_ts {
        //Finish parsing ts
        packet.extract(hdr.timestamp);
        transition accept;
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.nop1);
        packet.emit(hdr.nop2);
        packet.emit(hdr.ss);
        packet.emit(hdr.nop3);
        packet.emit(hdr.sackw);
        packet.emit(hdr.sack);
        packet.emit(hdr.nop4);
        packet.emit(hdr.timestamp);
    }
}
