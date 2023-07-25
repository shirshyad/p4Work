
// {C} Copyright 2023 AMD Inc. All rights reserved
// Example code snippets.

Checksum16()          ipv4HdrCsum;​
Checksum16()          udpCsum;​
parser  p(packet_in packet, out headers hdr,.. ) {​
  bit<16>                         l3_hdr_offset;​
  bit<16>                         l4_hdr_offset;​
  bit<16>                        l4_len​

  state parse_ipv4 {​
    l3_hdr_offset = packet.state_byte_offset();​
    packet.extract(hdr.ipv4);​
    transition parse_ipv4_checksum;​
  }​
  state parse_ipv4_checksum {​
    bit<16>     ip_header_len;​
    ip_header_len = ((bit<16>) hdr.ipv4.ihl << 2);​
    ipv4HdrCsum.checksum_over(l3_hdr_offset, ip_header_len);​
    ipv4HdrCsum.validate(hdr.ipv4.checksum);​
    bit<16> ip_total_len  = hdr.ipv4.totalLen;
    l4_len        = ip_total_len - ip_header_len;​
    transition parse_udp;
  }​

  state parse_udp {​
    packet.extract(hdr.udp);​
    l4_hdr_offset = packet.state_byte_offset();​
    udpCsum.checksum_over(l4_hdr_offset, l4_len);​
    udpCsum.add_fields({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, l4_len});​
    udpCsum.add(IP_PROTO_UDP);​
    udpCsum.validate(hdr.udp.checksum);​
  } ​
}
​
