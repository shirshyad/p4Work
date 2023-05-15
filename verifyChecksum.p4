
// {C} Copyright 2023 AMD Inc. All rights reserved

parser Parser (packet_in packet,
               inout intr_global_h intr_global,
               out ingress_headers hdr,
               out metadata_t metadata) {

    // Offsets and length of first layer of headers in the packet.
    bit<16> l3_1_hdr_offset;    // L3 offset
    bit<16> l4_1_hdr_offset;    // L4 offset
    bit<16> icmp_1_hdr_offset;  // Icmp offset
    bit<16> ipv4_1_len;         // v4 len
    bit<16> l4_1_len;           // L4 len

    // Offsets and length of second layer of headers in the packet.
    bit<16> l3_2_hdr_offset;    // L3 offset
    bit<16> l4_2_hdr_offset;    // L4 offset
    bit<16> icmp_2_hdr_offset;  // Icmp offset
    bit<16> ipv4_2_len;         // v4 len
    bit<16> l4_2_len;           // L4 len

    // In order to highlight checksum, only relevant portions
    // if parser states are listed below not from the begining of start() state.

    /******************************************************************************
     * Layer 1 headers of a packet.
     *****************************************************************************/

    state parse_ipv4_1 {
        metadata.offset_metadata.l3_1 = packet.state_byte_offset()[7:0];
        bit<8>  ver_len = packet.lookahead<bit<8>>();
        bit<16> flags_fragoffset = (packet.lookahead<bit<64>>())[15:0];
        transition select(ver_len, flags_fragoffset) {
            (0x40 &&& 0xFC, 0x0 &&& 0x0000) : accept;
            (0x44 &&& 0xFF, 0x0 &&& 0x0000) : accept;
            (0x45 &&& 0xFF, 0x0 &&& 0x3FFF) : parse_ipv4_base_1;
            default                         : accept;
        }
    }
                                                                                                                                                                                                                [239/5896]
    state parse_ipv4_base_1 {
        l3_1_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.ip_u_1.ipv4);
        ipv4_1_len = ((bit<16>) hdr.ip_u_1.ipv4.ihl << 2);
        l4_1_len =  hdr.ip_u_1.ipv4.totalLen - ipv4_1_len;
        transition parse_ipv4_checksum_1;
    }

    state parse_ipv4_checksum_1 {
        metadata.offset_metadata.l4_1 = packet.state_byte_offset()[7:0];

        // Verify ipv4 checksum
        ipv4HdrCsum_1.update_len(l3_1_hdr_offset, ipv4_1_len);
        ipv4HdrCsum_1.validate(hdr.ip_u_1.ipv4.hdrChecksum);

        // Provide pseudo header fields
        tcpCsum_1.update_pseudo_header_offset(hdr.ip_u_1.ipv4, l3_1_hdr_offset);
        udpCsum_1.update_pseudo_header_offset(hdr.ip_u_1.ipv4, l3_1_hdr_offset);
        tcpCsum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv4,
                {hdr.ip_u_1.ipv4.srcAddr, hdr.ip_u_1.ipv4.dstAddr, l4_1_len});
        udpCsum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv4,
                {hdr.ip_u_1.ipv4.srcAddr, hdr.ip_u_1.ipv4.dstAddr, l4_1_len});

        transition select(hdr.ip_u_1.ipv4.protocol) {
            IP_PROTO_ICMP       : parse_icmp_1;
            IP_PROTO_TCP        : parse_tcp_1;
            IP_PROTO_UDP        : parse_udp_1;
            default             : accept;
        }
    }

    state parse_ipv6_1 {
        metadata.offset_metadata.l3_1 = packet.state_byte_offset()[7:0];
        packet.extract(hdr.ip_u_1.ipv6);

        l4_1_len        =  hdr.ip_u_1.ipv6.payloadLen;

        tcpCsum_1.update_pseudo_header_offset(hdr.ip_u_1.ipv6, l3_1_hdr_offset);
        udpCsum_1.update_pseudo_header_offset(hdr.ip_u_1.ipv6, l3_1_hdr_offset);
        tcpCsum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv6,
                                              {hdr.ip_u_1.ipv6.srcAddr, hdr.ip_u_1.ipv6.dstAddr, l4_1_len});
        udpCsum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv6,
                                              {hdr.ip_u_1.ipv6.srcAddr, hdr.ip_u_1.ipv6.dstAddr, l4_1_len});
        icmpv6Csum_1.update_pseudo_header_offset(hdr.ip_u_1.ipv6, l3_1_hdr_offset);
        icmpv6Csum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv6,
                {hdr.ip_u_1.ipv6.srcAddr, hdr.ip_u_1.ipv6.dstAddr, l4_1_len});
        icmpv6Csum_1.update_pseudo_hdr_constant(IP_PROTO_ICMPV6);

        transition select(hdr.ip_u_1.ipv6.nextHdr) {
                    IPV6_PROTO_EXTN_NO_HDR : accept;
            default: parse_ipv6_1_ulp_no_options;
        }
    }

    state parse_ipv6_1_ulp_no_options {
        metadata.offset_metadata.l4_1 = packet.state_byte_offset()[7:0];
        metadata.control_metadata.ipv6_proto_1 = hdr.ip_u_1.ipv6.nextHdr;

        transition select(hdr.ip_u_1.ipv6.nextHdr) {
            IP_PROTO_ICMPV6   : parse_icmp6_1;
            IP_PROTO_TCP      : parse_tcp_1;
            IP_PROTO_UDP      : parse_udp_1;
            default : accept;
        }
    }

    state parse_icmp_1 {
        metadata.control_metadata.icmp_valid = TRUE;
        icmp_1_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.l4_u.icmpv4);
        metadata.key_metadata.dport = hdr.l4_u.icmpv4.typeCode;
        icmpv4Csum_1.update_len(icmp_1_hdr_offset, l4_1_len);
        icmpv4Csum_1.validate(hdr.l4_u.icmpv4.hdrChecksum);
        transition select(hdr.l4_u.icmpv4.typeCode) {
            ICMP_ECHO_REQ_TYPE_CODE : parse_icmp_echo;
            ICMP_ECHO_REPLY_TYPE_CODE : parse_icmp_echo;
            default : accept;
        }
    }

    state parse_icmp6_1 {
        metadata.control_metadata.icmp_valid = TRUE;
        icmp_1_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.l4_u.icmpv6);
        metadata.key_metadata.dport = hdr.l4_u.icmpv6.typeCode;
        icmpv6Csum_1.update_len(icmp_1_hdr_offset, l4_1_len);
        icmpv6Csum_1.validate(hdr.l4_u.icmpv6.hdrChecksum);
        transition select(hdr.l4_u.icmpv6.typeCode) {
            ICMP6_ECHO_REQ_TYPE_CODE : parse_icmp_echo;
            ICMP6_ECHO_REPLY_TYPE_CODE : parse_icmp_echo;
            default : accept;
        }
    }

    state parse_icmp_echo {
        packet.extract(hdr.icmp_echo);
        metadata.key_metadata.sport = hdr.icmp_echo.identifier;
        transition accept;
    }
                                                                                                                                                                                                                [139/5896]
    state parse_tcp_1 {
        l4_1_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.l4_u.tcp);

        metadata.key_metadata.sport = hdr.l4_u.tcp.srcPort;
        metadata.key_metadata.dport = hdr.l4_u.tcp.dstPort;
        tcpCsum_1.update_pseudo_hdr_constant(IP_PROTO_TCP);
        tcpCsum_1.update_len(l4_1_hdr_offset, l4_1_len);
        tcpCsum_1.validate(hdr.l4_u.tcp.checksum);
        transition accept;
    }

    state parse_udp_1 {
        l4_1_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.udp_1);
        metadata.key_metadata.sport = hdr.udp_1.srcPort;
        metadata.key_metadata.dport = hdr.udp_1.dstPort;
        l4_1_len = hdr.udp_1.len;
        udpCsum_1.update_pseudo_hdr_constant(IP_PROTO_UDP);
        udpCsum_1.update_len(l4_1_hdr_offset, l4_1_len);
        udpCsum_1.validate(hdr.udp_1.checksum);
        transition select(hdr.udp_1.dstPort) {
            UDP_PORT_VXLAN : parse_vxlan_1;
            default : accept;
        }
    }

    state parse_vxlan_1 {
        packet.extract(hdr.encap_u_1.vxlan);
        transition parse_ethernet_2;
    }

    /******************************************************************************
     * Layer 2 headers of a packet
     *****************************************************************************/

    state parse_ethernet_2 {
        packet.extract(hdr.ethernet_2);
        transition select(hdr.ethernet_2.etherType) {
            ETHERTYPE_CTAG : parse_ctag_2;
            ETHERTYPE_IPV4 : parse_ipv4_len_chk_2;
            ETHERTYPE_IPV6 : parse_ipv6_len_chk_2;
            default : accept;
        }
    }

    state parse_ctag_2 {
            packet.extract(hdr.ctag_2);
        transition select(hdr.ctag_2.etherType) {
            ETHERTYPE_IPV4 : parse_ipv4_2;
            ETHERTYPE_IPV6 : parse_ipv6_2;
            default : accept;
        }
    }

    state parse_ipv4_2 {
        bit<16>  totalLen = packet.lookahead<bit<32>>()[15:0];
        l3_2_hdr_offset = packet.state_byte_offset();
        bit<8>  ver_len = packet.lookahead<bit<8>>();
        bit<16> flags_fragoffset = (packet.lookahead<bit<64>>())[15:0];
        transition select(ver_len, flags_fragoffset) {
            (0x40 &&& 0xFC, 0x0 &&& 0x0000) : accept;
            (0x44 &&& 0xFF, 0x0 &&& 0x0000) : accept;
            (0x45 &&& 0xFF, 0x0 &&& 0x3FFF) : parse_ipv4_base_2;
            (0x40 &&& 0xF0, 0x0 &&& 0x3FFF) : parse_ipv4_with_options_2;
            default                         : accept;
        }
    }

    state parse_ipv4_base_2 {
        packet.extract(hdr.ip_u_2.ipv4);
        ipv4_2_len = ((bit<16>) hdr.ip_u_2.ipv4.ihl << 2);

        transition parse_ipv4_checksum_2;
    }

    state parse_ipv4_with_options_2 {
        packet.extract(hdr.ip_u_2.ipv4);

        bit<16>     ip_u_2_option_len;
        ipv4_2_len = ((bit<16>) hdr.ip_u_2.ipv4.ihl << 2);
        ip_u_2_option_len  = ipv4_2_len - 20;
        packet.extract_bytes(hdr.ipv4_option_2, ip_u_2_option_len);
        transition parse_ipv4_checksum_2;
    }

    state parse_ipv4_checksum_2 {
        l4_2_len =  hdr.ip_u_2.ipv4.totalLen - ipv4_2_len;
        ipv4HdrCsum_2.update_len(l3_2_hdr_offset, ipv4_2_len);
        ipv4HdrCsum_2.validate(hdr.ip_u_2.ipv4.hdrChecksum);
        tcpCsum_2.update_pseudo_header_offset(hdr.ip_u_2.ipv4, l3_2_hdr_offset);
        udpCsum_2.update_pseudo_header_offset(hdr.ip_u_2.ipv4, l3_2_hdr_offset);
        tcpCsum_2.update_pseudo_header_fields(hdr.ip_u_2.ipv4,
                {hdr.ip_u_2.ipv4.srcAddr, hdr.ip_u_2.ipv4.dstAddr, l4_2_len});
        udpCsum_2.update_pseudo_header_fields(hdr.ip_u_2.ipv4,
                {hdr.ip_u_2.ipv4.srcAddr, hdr.ip_u_2.ipv4.dstAddr, l4_2_len});
                        transition select(hdr.ip_u_2.ipv4.protocol) {
            IP_PROTO_ICMP       : parse_icmp_2;
            IP_PROTO_TCP        : parse_tcp_2;
            IP_PROTO_UDP        : parse_udp_2;
            default             : accept;
        }
    }

    state parse_ipv6_2 {
        l3_2_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.ip_u_2.ipv6);
        l4_2_len        =  hdr.ip_u_2.ipv6.payloadLen;
        tcpCsum_2.update_pseudo_header_offset(hdr.ip_u_2.ipv6, l3_2_hdr_offset);
        udpCsum_2.update_pseudo_header_offset(hdr.ip_u_2.ipv6, l3_2_hdr_offset);
        tcpCsum_2.update_pseudo_header_fields(hdr.ip_u_2.ipv6,
                                              {hdr.ip_u_2.ipv6.srcAddr, hdr.ip_u_2.ipv6.dstAddr, l4_2_len});
        udpCsum_2.update_pseudo_header_fields(hdr.ip_u_2.ipv6,
                                              {hdr.ip_u_2.ipv6.srcAddr, hdr.ip_u_2.ipv6.dstAddr, l4_2_len});
        icmpv6Csum_2.update_pseudo_header_offset(hdr.ip_u_2.ipv6, l3_2_hdr_offset);
        icmpv6Csum_2.update_pseudo_header_fields(hdr.ip_u_2.ipv6,
                {hdr.ip_u_2.ipv6.srcAddr, hdr.ip_u_2.ipv6.dstAddr, l4_2_len});
        icmpv6Csum_2.update_pseudo_hdr_constant(IP_PROTO_ICMPV6);

        transition select(hdr.ip_u_2.ipv6.nextHdr) {
            default: parse_ipv6_2_ulp_no_options;
        }
    }

    state parse_ipv6_2_ulp_no_options {
        metadata.control_metadata.ipv6_proto_2 = hdr.ip_u_2.ipv6.nextHdr;

        transition select(hdr.ip_u_2.ipv6.nextHdr) {
            IP_PROTO_ICMPV6   : parse_icmp6_2;
            IP_PROTO_TCP      : parse_tcp_2;
            IP_PROTO_UDP      : parse_udp_2;
            default : accept;
        }
    }

    state parse_icmp_2 {
        metadata.control_metadata.icmp_valid = TRUE;
        icmp_2_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.l4_u.icmpv4);
        metadata.key_metadata.dport = hdr.l4_u.icmpv4.typeCode;
        icmpv4Csum_2.update_len(icmp_2_hdr_offset, l4_2_len);
        icmpv4Csum_2.validate(hdr.l4_u.icmpv4.hdrChecksum);
        transition select(hdr.l4_u.icmpv4.typeCode) {
            ICMP_ECHO_REQ_TYPE_CODE : parse_icmp_echo;
            ICMP_ECHO_REPLY_TYPE_CODE : parse_icmp_echo;
            default : accept;
        }
    }

    state parse_icmp6_2 {
        metadata.control_metadata.icmp_valid = TRUE;
        icmp_2_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.l4_u.icmpv6);
        metadata.key_metadata.dport = hdr.l4_u.icmpv6.typeCode;
        icmpv6Csum_2.update_len(icmp_2_hdr_offset, l4_2_len);
        icmpv6Csum_2.validate(hdr.l4_u.icmpv6.hdrChecksum);
        transition select(hdr.l4_u.icmpv6.typeCode) {
            ICMP6_ECHO_REQ_TYPE_CODE : parse_icmp_echo;
            ICMP6_ECHO_REPLY_TYPE_CODE : parse_icmp_echo;
            default : accept;
        }
    }

    state parse_tcp_2 {
        l4_2_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.l4_u.tcp);

        metadata.key_metadata.sport = hdr.l4_u.tcp.srcPort;
        metadata.key_metadata.dport = hdr.l4_u.tcp.dstPort;
        tcpCsum_2.update_pseudo_hdr_constant(IP_PROTO_TCP);
        tcpCsum_2.update_len(l4_2_hdr_offset, l4_2_len);
        tcpCsum_2.validate(hdr.l4_u.tcp.checksum);
        transition accept;
    }

    state parse_udp_2 {
        l4_2_hdr_offset = packet.state_byte_offset();
        packet.extract(hdr.l4_u.udp);
        l4_2_len = hdr.l4_u.udp.len;
        metadata.key_metadata.sport = hdr.l4_u.udp.srcPort;
        metadata.key_metadata.dport = hdr.l4_u.udp.dstPort;
        udpCsum_2.update_pseudo_hdr_constant(IP_PROTO_UDP);
        udpCsum_2.update_len(l4_2_hdr_offset, l4_2_len);
        udpCsum_2.validate(hdr.l4_u.udp.checksum);
        transition accept;
    }
}
