#include <arpa/inet.h>
#include <linux/if_ether.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

BPF_MAP_DEF(matches) = {
	.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u64),
	.max_entries = 128,
};
BPF_MAP_ADD(matches);

struct macaddr {
	__u8 octet1;
	__u8 octet2;
	__u8 octet3;
	__u8 octet4;
	__u8 octet5;
	__u8 octet6;
};

struct eth_header {
	struct macaddr dest;
	struct macaddr src;
	__u16 proto;
};

SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u64 packet_size = data_end - data;

	// Layer 2
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end) {
		return XDP_ABORTED;
	}
	data += sizeof(*eth);
	struct eth_header evt = {
		.dest = {
			.octet1 = eth->h_dest[0],
			.octet2 = eth->h_dest[1],
			.octet3 = eth->h_dest[2],
			.octet4 = eth->h_dest[3],
			.octet5 = eth->h_dest[4],
			.octet6 = eth->h_dest[5],
		},
		.src = {
			.octet1 = eth->h_source[0],
			.octet2 = eth->h_source[1],
			.octet3 = eth->h_source[2],
			.octet4 = eth->h_source[3],
			.octet5 = eth->h_source[4],
			.octet6 = eth->h_source[5],
		},
		.proto = bpf_ntohs(eth->h_proto),
	};
	__u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
	bpf_perf_event_output(ctx, &matches, flags, &evt, sizeof(evt));

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
