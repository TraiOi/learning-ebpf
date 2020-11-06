# 0x01: Familar with XDP

> **Description:** Làm quen với XDP và eBPF.  
> **Author:** TraiOi  
> **Userspace:** [xdp\_drop\_icmp.go](/src/examples/xdp_drop_icmp.go)  
> **Kernelspace:** [xdp\_drop\_icmp.c](/libc/examples/xdp_drop_icmp.c)  

## 1. Create a map

```
BPF_MAP_DEF(matches) = { // (1)
	.map_type = BPF_MAP_TYPE_ARRAY, // (2)
	.key_size = sizeof(__u32), // (3)
	.value_size = sizeof(__u64), // (4)
	.max_entries = 255, // (5)
}
BPF_MAP_ADD(matches); // (6)
```

Để tạo 1 map thì cần 2 bpf syscall quan trọng là:
* `BPF_MAP_DEF` **(1)**: để định nghĩa tên và các attribute của map.
* `BPF_MAP_ADD` **(6)**: để thêm map vào hệ thống.

Một map sẽ bao gồm các attribute cơ bản:
* `.map_type` **(2)**: Một trong những **bpf_map_type**. Tham khảo thêm ở [bpf map types](/docs/bpf_map_types.md).
* `.key_size` **(3)**: Size của key (tính bằng bytes).
* `.value_size` **(4)**: Size của value (tính bằng bytes).
* `.max_entries` **(5)**: Max số lượng bản ghi trong 1 map.

## 2. Define example function

```
SEC("xdp")
int drop(struct xdp_md *ctx) { // (1)
	void *data_end = (void *)(long)ctx->data_end; // (2)
	void *data = (void *)(long)ctx->data; // (2)

	struct ethhdr *eth = data; // (3)
	if (data + sizeof(*eth) > data_end) { // (4)
		return XDP_ABORTED; // (4)
	}

	if (eth->h_proto != htons(ETH_P_IP)) { // (5)
		return XDP_PASS; // (5)
	}
    		
	data += sizeof(*eth); // (6)
	struct iphdr *ip = data; // (7)
	if (data + sizeof(*ip) > data_end) { // (8)
		return XDP_ABORTED; // (8)
   	}

    	__u32 proto_index = ip->protocol; // (9)
	if (proto_index == IPPROTO_ICMP) { // (10)
   		__u64 *counter = bpf_map_lookup_elem(&matches, &proto_index); // (11)
		if (counter) { // (11)
			(*counter)++; // (11)
		}
		return XDP_DROP; // (12)
	}
	return XDP_PASS; // (13)
}
```

**(1)** sẽ define 1 function có tên là `drop()` vầ sử dụng context `xdp_md` như 1 parameter. Struct `xdp_md` sẽ bao gồm các thông tin về network packet đi đến XDP. Struct `xdp_md` được define trong `linux/bpf.h` và có các attribute:
```
struct xdp_md {
	__u32 data; // Start of the packet data.
	__u32 data_end; // End of the packet data.
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index */
};
```

**(2)** Packet contents sẽ nằm từ `ctx->data` đến `ctx->data_end`.

**(3)** Define pointer `*eth` tương ứng với value của pointer `*data` để access vào thông tin Layer 2 của packet với ethernet header. Tham khảo tại [Ethernet header](/docs/network-headers.md#layer-2).

**(4)** Kiểm tra nếu ethernet header không đúng tiêu chuẩn sẽ thoát program với action `XDP_ABORTED`.

**(5)** Kiểm tra nếu packet đi qua có `h_proto` không phải là  IP thì sẽ bỏ qua với action `XDP_PASS`. `htons()` được define trong `arpa/inet.h` và `ETH_P_IP` được define trong `linux/if_ether.h`có giá trị là `0x0800` tương ứng với Internet Protocol packet.

**(6)** Sau khi vượt qua các kiểm tra thì sẽ pass qua buffer của ethernet header để access vào IP header.

**(7)** Define pointer `*ip` tương ứng với value của pointer `*data` để access vào thông tin Layer 3 của packet với IP header. Tham khảo tại [IP header](/docs/network-headers.md#layer-3).

**(8)** Kiểm tra nếu IP header không đúng tiêu chuẩn sẽ thoát program với action `XDP_ABORTED`.

**(9)** Lấy thông tin protocol của packet ra từ trường `ip->protocol` của IPv4 header.

**(10)** Kiểm tra protocol có phải là ICMP hay không, nếu là ICMP thì thực hiện bước **(11)**, còn không phải thì thực hiện bước **(13)**.`IPPROTO_ICMP` được define trong `linux/icmp.h`.

**(11)** Sử dụng hàm `bpf_map_lookup_elem()` để lookup ra packet tương ứng và lưu vào pointer `*counter`. Với mỗi packet tương ứng thì sẽ tăng value của `*counter` lên 1. Cú pháp của `bpf_map_lookup_elem()`:
```
void bpf_map_lookup_elem(map, void *key. ...);
```

**(12)** Drop các packet ICMP tương ứng với action `XDP_DROP`.

**(13)** Cho phép các packet không phải ICMP đi qua filter với action `XDP_PASS`.

## Demo

![0x01](/docs/gif/0x01.gif)
