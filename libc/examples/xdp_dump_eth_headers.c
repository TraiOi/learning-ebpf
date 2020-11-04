#include <linux/if_ether.h>
#include "bpf_helpers.h"

BPF_MAP_DEF(matches) = {
	.map_type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 128,
};
BPF_MAP_ADD(matches);

struct perf_event_item {
	__u32 proto;
}

SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// Layer 2
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end) {
		return XDP_ABORTED;
	}
	data += sizeof(*eth);
	struct perf_event_item evt = {
		.proto = eth->h_proto,
	};

	bpf_perf_event_output(ctx, &matches, &evt, sizeof(evt));

	return XDP_PASS;
}

char _license[] SEC("license") = "GPLv2";
