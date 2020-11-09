# 0x02: Perf Events

> **Description:** Hiểu hơn cách tracing BPF program bằng Perf Events thông qua ví dụ dump Ethernet headers.  
> **Author:** TraiOi  
> **Userspace:** [xdp\_dump\_eth\_headers.go](/src/examples/xdp_dump_eth_headers.go)  
> **Kernelspace:** [xdp\_dump\_eth\_headers.c](/libc/examples/xdp_dump_eth_headers.c)  

## 1. Create a map

Tạp 1 map với `.map_type` là `BPF_MAP_TYPE_PERF_EVENT_ARRAY` để sử dụng Perf Events.

```
BPF_MAP_DEF(matches) = {
	.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u64),
	.max_entries = 128,
};
BPF_MAP_ADD(matches);
```

## 2. Define custom struct

```
struct eth_header { // (1)
	struct macaddr dest; // (2)
	struct macaddr src; // (2)
	__u16 proto; // (3)
}
```

Do `bpf_perf_event_output()` chỉ hỗ trợ các custom structs để share data với userspace.
* **(1)** Define 1 struct với tên là `eth_header` bao gồm các thông tin cần thiết về Ethernet header để chia sẻ với userspace.
* **(2)** Thông tin về dest MAC và source MAC của packets,  tương ứng với struct:
```
struct macaddr {
	__u8 octet1;
	__u8 octet2;
	__u8 octet3;
	__u8 octet4;
	__u8 octet5;
	__u8 octet6;
};
```
* **(3)** Thông tin về protocol hay EtherType. Tham khảo thêm tại [EtherType](https://en.wikipedia.org/wiki/EtherType).

## 3. Define example function

```
SEC("xdp")
int xdp_dump(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u64 packet_size = data_end - data; // (1)

	// Layer 2
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end) {
		return XDP_ABORTED;
	}
	data += sizeof(*eth);
	struct eth_header evt = { // (2)
		.dest = {
			.octet1 = eth->h_dest[0], // (3)
			.octet2 = eth->h_dest[1], // (3)
			.octet3 = eth->h_dest[2], // (3)
			.octet4 = eth->h_dest[3], // (3)
			.octet5 = eth->h_dest[4], // (3)
			.octet6 = eth->h_dest[5], // (3)
		},
		.src = {
			.octet1 = eth->h_source[0], // (3)
			.octet2 = eth->h_source[1], // (3)
			.octet3 = eth->h_source[2], // (3)
			.octet4 = eth->h_source[3], // (3)
			.octet5 = eth->h_source[4], // (3)
			.octet6 = eth->h_source[5], // (3)
		},
		.proto = bpf_ntohs(eth->h_proto), // (4)
	};
	__u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32); // (5)
	bpf_perf_event_output(ctx, &matches, flags, &evt, sizeof(evt)); // (6)

	return XDP_PASS;
}
```

Tạo 1 function `xdp_dump()` để kernelspace và userspace có thể share data bằng Perf Events.
* **(2)** Khai báo và gán các data tương ứng với `struct eth_header` cho biến `evt`.
* **(3)** Source/Dest MAC sẽ bao gồm 6 bytes được khai báo trong 1 mảng 6 unint8 `h_dest[6]` và `h_source[6]` (Tham khảo tại [Ethernet Header](/docs/network-headers.md#layer-2)). Mỗi bytes trong mảng sẽ tương ứng với 1 octet trong `struct macaddr`.
* **(4)** Sử dụng hàm `bpf_ntohs()` được define trong `bpf_endian.h` để convert từ thứ tự network bytes sang thứ tự host bytes.
* **(5)** `flags` (sẽ được giải thích trong **(6)**), có giá trị bằng `BPF_F_CURRENT_CPU | (packet_size << 32)`. Trong đó:
	* `BPF_F_CURRENT_CPU` được define trong `linux/bpf.h` chỉ ra index của CPU core hiện tại đang sử dụng trong event map.
	* `(packet_size << 32)` sẽ dịch 32 bit của `packet_size` sang phải.
	* ***Ví dụ:*** Xác định `flag` trên NIC đang sử dụng CPU thứ 6 và có `packet_size` là 680.
		* `packet_size`=680 ban đầu sẽ tương ứng với 32 dưới của `flag`.
		* `__u64`: `00000000 00000000 00000000 00000000 | 00000000 00000000 00000010 10101000`.
		* Dấu `|` tượng trưng cho ngăn cách giữa 32 bit trên và 32 bit dưới trong `flag`.
		* `<< 32` tương ứng với việc chuyển 32 bit dưới lên 32 bit trên.
		* `__u64`: `00000000 00000000 00000010 10101000 | 00000000 00000000 00000000 00000000`.
		* NIC đang sử dụng CPU thứ 6 sẽ tương ứng `110` được đặt ở 32 bit dưới.
		* `__u64`: `00000000 00000000 00000010 10101000 | 00000000 00000000 00000000 00000110`.
		* Lúc này phía userspace sẽ dựa vào 32 bit dưới để lấy ra CPU_ID đang map với packet và 32 bit trên để lấy ra packet size cũng như payload của packet.
* **(6)** Function `bpf_perf_event_output()` được define trong `bpf_helpers.h`, được dùng để gửi output (hay share data) cho userspace thông qua custome struct với map type tương ứng với `BPF_MAP_TYPE_PERF_EVENT_ARRAY`. Function có cú pháp là 
```long bpf_perf_event_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)```
	* `struct bpf_map *map`: Tên struct được define tương ứng với map type `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.
	* `u64 flags`: Phía userspace sẽ gọi function `perf_event_output()` và dựa vào flag để lấy ra các thông tin cần thiết từ packet `*ctx`. **(5)**. Flag sẽ bao gồm 64 bit và được chia làm 2 phần, mỗi phần gồm 32 bit.
		* `0-31 bit`: Index của eBPF map hoặc `BPF_F_CURRENT_CPU` tương ứng với CPU_ID như là eBPF map index.
		* `32-63 bit`: Data của packet `*ctx` được biểu diễn qua `packet_size`.
	* `void *data`: Thông tin data cần share giữa kernelspace và userspace, tuowng ứng với data được gán trong custom struct (`&evt`).
	* `u64 size`: Size của `&evt`, tương ứng với `sizeof(evt)`.

## 4. Demo

![0x02.gif](/docs/gif/0x02.gif)
