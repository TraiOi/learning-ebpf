# NETWORK HEADER

## Layer 2

![ethernet-frame-format-ieee-802.3](/docs/img/ethernet-frame-format-ieee-802.3.png)

`#include <linux/if_ether.h>`
* `__u8 h_dest[ETH_ALEN]`: Destination Address.
* `__u8 h_source[ETH_ALEN]`: Source Address.
* `__u16 h_proto`: Packet type ID field.

## Layer 3

![ipv4-header](/docs/img/ipv4-header.png)

`#include <linux/ip.h>`
* `__u8 ihl`: IHL (Header Length).
* `__u8 version`: Version - Version of IP protocol (4 or 6).
* `__u8 tos`: Type of Service (TOS).
* `__u16 tot_len`: Total Length.
* `__u16 id`: Identification.
* `__u16 frag_off`: IP Flags.
* `__u8 ttl`: Time To Live (TTL).
* `__u8 protocol`: Protocol.
* `__u16 check`: Header Checksum.
* `__u32 saddr`: Source Address.
* `__u32 daddr`: Destination Address.

## Layer 4

![tcp-header](/docs/img/tcp-header.png)

`#include <linux/tcp.h>`
* `__u16 source`: Source port.
* `__u16 dest`: Destination port.
* `__u32 seq`: Sequence number.
* `__u32 ack_seq`: Acknowlegment number.
* some tcp flags ...
* `__u16 window`: Window size.
* `__u16 check`: TCP checksum.
* `__u16 urg_ptr`: Urgent pointers.
