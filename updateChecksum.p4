// {C} Copyright 2023 AMD Inc. All rights reserved

checksum16() l2CsumEg;
checksum16() ipv4HdrCsum_0;
checksum16() ipv4HdrCsum_1;
checksum16() ipv4HdrCsum_2;
checksum16() udpCsum_1;
checksum16() icmpv4Csum_1;
checksum16() icmpv6Csum_1;
checksum16() tcpCsum_1;
checksum16() udpCsum_2;

control P4Deparser(packet_out packet,
                       inout intr_global_h intr_global,
                       inout headers hdr,
                   in metadata_t metadata) {
    apply {
        packet.emit(hdr.ethernet_0);
        packet.emit(hdr.ip_u_0.ipv4);
        packet.emit(hdr.ip_u_0.ipv6);
        packet.emit(hdr.udp_0);
        packet.emit(hdr.encap_u_0.vxlan);

        // compute IPv4 checksum of the encapsulating header.
        ipv4HdrCsum_0.update_len(hdr.ip_u_0.ipv4,
                                      metadata.csum.ip_hdr_len_0 );
        hdr.ip_u_0.ipv4.hdrChecksum = ipv4HdrCsum_0.get();

        // l2 csum
        l2CsumEg.compute_complete_checksum_after(hdr.ethernet_1 , metadata.csum.l2_csum_len);
        l2CsumEg.include_checksum_result(hdr.ip_u_1.ipv4);
        l2CsumEg.include_checksum_result(hdr.l4_u.udp);
        l2CsumEg.include_checksum_result(hdr.l4_u.icmpv4);
        l2CsumEg.include_checksum_result(hdr.l4_u.icmpv6);
        l2CsumEg.include_checksum_result(hdr.l4_u.tcp);
        hdr.punt_header.csum = l2CsumEg.get(); // filled inside header provided for driver to consume L2 checksum

        // Emit original 2 layered packet as shown in verifyChecksum.p4 example.
        // along with fully computing all checksum values.
        packet.emit(hdr.ethernet_1);
        packet.emit(hdr.ctag_1);
        packet.emit(hdr.ctag2_1);
        packet.emit(hdr.ip_u_1.ipv4);
        packet.emit(hdr.ip_u_1.ipv6);
        packet.emit(hdr.udp_1);
        packet.emit(hdr.encap_u_1.vxlan);

        // Compute full ipv4 checksum
        ipv4HdrCsum_1.update_len(hdr.ip_u_1.ipv4, metadata.csum.ip_hdr_len_1);
        hdr.ip_u_1.ipv4.hdrChecksum = ipv4HdrCsum_1.get();

        // Compute full UDP checksum (udp encapsualted packet).
        // Also ensure checksum computed values to include results of inner checksums.
        if (hdr.udp_1.isValid()) {
            udpCsum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv4, {hdr.ip_u_1.ipv4.srcAddr,
                                                       hdr.ip_u_1.ipv4.dstAddr, metadata.csum.udp_len_1});
            udpCsum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv6, {hdr.ip_u_1.ipv6.srcAddr,
                                                       hdr.ip_u_1.ipv6.dstAddr, metadata.csum.udp_len_1});
            udpCsum_1.update_len(hdr.udp_1, metadata.csum.udp_len_1);
            udpCsum_1.update_pseudo_hdr_constant(IP_PROTO_UDP);

            udpCsum_1.include_checksum_result(hdr.ip_u_2.ipv4);
            udpCsum_1.include_checksum_result(hdr.l4_u.icmpv4);
            udpCsum_1.include_checksum_result(hdr.l4_u.icmpv6);
            udpCsum_1.include_checksum_result(hdr.l4_u.tcp);
            udpCsum_1.include_checksum_result(hdr.l4_u.udp);

            hdr.udp_1.checksum = udpCsum_1.get();
        }

        packet.emit(hdr.ethernet_2);
        packet.emit(hdr.ctag_2);
        packet.emit(hdr.ip_u_2.ipv4);
        packet.emit(hdr.ip_u_2.ipv6);
        packet.emit(hdr.ipv4_option_2);
        packet.emit(hdr.ipv6_option_2);

        ipv4HdrCsum_2.update_len(hdr.ip_u_2.ipv4, metadata.csum.ip_hdr_len_2);
        hdr.ip_u_2.ipv4.hdrChecksum = ipv4HdrCsum_2.get();

        if (hdr.l4_u.icmpv4.isValid()) {
            packet.emit(hdr.l4_u.icmpv4);
            icmpv4Csum_1.update_len(hdr.l4_u.icmpv4, metadata.csum.icmp_len_1);
            hdr.l4_u.icmpv4.hdrChecksum = icmpv4Csum_1.get();
        } else if (hdr.l4_u.icmpv6.isValid()) {
            packet.emit(hdr.l4_u.icmpv6);
            icmpv6Csum_1.update_len(hdr.l4_u.icmpv6, metadata.csum.icmp_len_1);
            icmpv6Csum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv6, {hdr.ip_u_1.ipv6.srcAddr,
                    hdr.ip_u_1.ipv6.dstAddr, metadata.csum.icmp_len_1});
            icmpv6Csum_1.update_pseudo_header_fields(hdr.ip_u_2.ipv6, {hdr.ip_u_2.ipv6.srcAddr,
                    hdr.ip_u_2.ipv6.dstAddr, metadata.csum.icmp_len_1});
            icmpv6Csum_1.update_pseudo_hdr_constant(IP_PROTO_ICMPV6);
            hdr.l4_u.icmpv6.hdrChecksum = icmpv6Csum_1.get();
        } else if (hdr.l4_u.tcp.isValid()) {
                    packet.emit(hdr.l4_u.icmpv6);
            icmpv6Csum_1.update_len(hdr.l4_u.icmpv6, metadata.csum.icmp_len_1);
            icmpv6Csum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv6, {hdr.ip_u_1.ipv6.srcAddr,
                    hdr.ip_u_1.ipv6.dstAddr, metadata.csum.icmp_len_1});
            icmpv6Csum_1.update_pseudo_header_fields(hdr.ip_u_2.ipv6, {hdr.ip_u_2.ipv6.srcAddr,
                    hdr.ip_u_2.ipv6.dstAddr, metadata.csum.icmp_len_1});
            icmpv6Csum_1.update_pseudo_hdr_constant(IP_PROTO_ICMPV6);
            hdr.l4_u.icmpv6.hdrChecksum = icmpv6Csum_1.get();
        } else if (hdr.l4_u.tcp.isValid()) {
            packet.emit(hdr.l4_u.tcp);
            tcpCsum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv4, {hdr.ip_u_1.ipv4.srcAddr,
                    hdr.ip_u_1.ipv4.dstAddr, metadata.csum.tcp_len_1});
            tcpCsum_1.update_pseudo_header_fields(hdr.ip_u_1.ipv6, {hdr.ip_u_1.ipv6.srcAddr,
                    hdr.ip_u_1.ipv6.dstAddr, metadata.csum.tcp_len_1});
            tcpCsum_1.update_pseudo_header_fields(hdr.ip_u_2.ipv4, {hdr.ip_u_2.ipv4.srcAddr,
                    hdr.ip_u_2.ipv4.dstAddr, metadata.csum.tcp_len_1});
            tcpCsum_1.update_pseudo_header_fields(hdr.ip_u_2.ipv6, {hdr.ip_u_2.ipv6.srcAddr,
                    hdr.ip_u_2.ipv6.dstAddr, metadata.csum.tcp_len_1});
            tcpCsum_1.update_len(hdr.l4_u.tcp, metadata.csum.tcp_len_1);
            tcpCsum_1.update_pseudo_hdr_constant(IP_PROTO_TCP);
            hdr.l4_u.tcp.checksum = tcpCsum_1.get();
        } else if (hdr.l4_u.udp.isValid()) {
            packet.emit(hdr.l4_u.udp);
            udpCsum_2.update_pseudo_header_fields(hdr.ip_u_2.ipv4, {hdr.ip_u_2.ipv4.srcAddr,
                    hdr.ip_u_2.ipv4.dstAddr, metadata.csum.udp_len_2});
            udpCsum_2.update_pseudo_header_fields(hdr.ip_u_2.ipv6, {hdr.ip_u_2.ipv6.srcAddr,
                    hdr.ip_u_2.ipv6.dstAddr, metadata.csum.udp_len_2});
            udpCsum_2.update_len(hdr.l4_u.udp, metadata.csum.udp_len_2);
            udpCsum_2.update_pseudo_hdr_constant(IP_PROTO_UDP);
            hdr.l4_u.udp.checksum = udpCsum_2.get();
        }
     }
}
        
