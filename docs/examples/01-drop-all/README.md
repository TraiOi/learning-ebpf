# 0x01: Familar with XDP

> **Description:** Làm quen với XDP và eBPF.  
> **Author:** TraiOi  
> **Userspace:** [drop\_all.go](/src/examples/drop_all.go)  
> **Kernelspace:** [xdp\_drop\_all.c](/libc/examples/xdp_drop_all.c)  

## 1. Kernelspace

### 1.1. Create a map

```
BPF_MAP_DEF(matches) = { // (1)
	.map_type = BPF_MAP_TYPE_PERCPU_ARRAY, // (2)
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
* `.map_type` **(2)**: Một trong những **bpf_map_type**.
* `.key_size` **(3)**: Size của key (tính bằng bytes).
* `.value_size` **(4)**: Size của value (tính bằng bytes).
* `.max_entries` **(5)**: Max số lượng bản ghi trong 1 map.


