# TYPEs of eBPF MAPs

Defined by `enum bpf_map_type` in `<linux/bpf.h>`.
```
enum bpf_map_type {
       BPF_MAP_TYPE_UNSPEC,
       BPF_MAP_TYPE_HASH,
       BPF_MAP_TYPE_ARRAY,
       BPF_MAP_TYPE_PROG_ARRAY,
       BPF_MAP_TYPE_PERF_EVENT_ARRAY,
       BPF_MAP_TYPE_PERCPU_HASH,
       BPF_MAP_TYPE_PERCPU_ARRAY,
       BPF_MAP_TYPE_STACK_TRACE,
       BPF_MAP_TYPE_CGROUP_ARRAY,
       BPF_MAP_TYPE_LRU_HASH,
       BPF_MAP_TYPE_LRU_PERCPU_HASH,
};
```

## Array Maps

Array maps được định nghĩa trong `kernel/bpf/arraymap.c`. Các arrays này giới hạn key size là 4 bytes (64 bits) và không thể xóa các values.

* `BPF_MAP_TYPE_ARRAY`: Simple array, key là array index.
* `BPF_MAP_TYPE_PROG_ARRAY`: Array của BPF programs dược dùng như 1 jump table bởi `bpf_tail_call()`.
* `BPF_MAP_TYPE_PERF_EVENT_ARRAY`: Array này được sử dụng bởi kernel trong `bpf_perf_event_output()` để tracing output với những key đặc biệt. User-space có thể thông qua `poll()` để gọi các fds keys này để nhận các thông báo về data đang được theo dõi. Xem thêm ở [Perf Events](/docs/perf_events.md).
* `BPF_MAP_TYPE_PERCPU_ARRAY`: Kernel sẽ ngầm phân bổ các array này cho từng CPU. Khi `bpf_map_lookup_elem()` được gọi, nó sẽ lấy các value dựa trên giá trị của `NR_CPUS`
* `BPF_MAP_TYPE_CGROUP_ARRAY`: Array map được dùng để lưu các cgroup fds ở user-space để BPF programs sử dụng thông qua việc gọi `bpf_skb_under_cgroup()` để kiếm tra nếu skb được liên kết với cgroup trong mảng.

## Hash Maps

Hash maps được định nghĩa trong `kernel/bpf/hashmap.c`. Hash keys sẽ không bị giới hạn nhưng phải > 0. Tham khảo thêm về hash lookup ở [Hash table](https://en.wikipedia.org/wiki/Hash_table). Không giống như array, hash map có thể xóa values. Hash maps thường được dùng trong việc phân bổ hoặc thu hồi IP address.

* `BPF_MAP_TYPE_HASH`.
* `BPF_MAP_TYPE_PERCPU_HASH`.
* `BPF_MAP_TYPE_LRU_HASH`.
* `BPF_MAP_TYPE_LRU_PERCPU_HASH`.

## Other

* `BPF_MAP_TYPE_STACK_TRACE`: Được định nghĩa trong `kernel/bpf/stackmap.c`. Kernel có thể chứa các stack dựa vào `bpf_get_stackid()`.
* `BPF_MAP_TYPE_UNSPEC`.


