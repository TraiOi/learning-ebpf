#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "bpf_helpers.h"


BPF_MAP_DEF(matches) = {
	.map_type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 255,
}
BPF_MAP_ADD(matches);

SEC("xdp")
int drop(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end) {
		return XDP_ABORTED;
	}

	if (eth->h_proto != htons(ETH_P_IP)) {
		return XDP_PASS;
	}
    		
	data += sizeof(*eth);
	struct iphdr *ip = data;
	if (data + sizeof(*ip) > data_end) {
		return XDP_ABORTED;
   	}

    	__u32 proto_index = ip->protocol;
	if (proto_index == IPPROTO_ICMP) {
   		__u64 *counter = bpf_map_lookup_elem(&matches, &proto_index);
		if (counter) {
			(*counter)++;
		}
		return XDP_DROP;
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPLv2";
