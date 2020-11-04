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

* `BPF_MAP_TYPE_ARRAY`: Simple array
* `BPF_MAP_TYPE_PROG_ARRAY`:
* `BPF_MAP_TYPE_PERF_EVENT_ARRAY`:
* `BPF_MAP_TYPE_PERCPU_ARRAY`:
* `BPF_MAP_TYPE_CGROUP_ARRAY`:

## Hash Maps
## BPF_MAP_TYPE_UNSPEC

## BPF_MAP_TYPE_HASH

## BPF_MAP_TYPE_PERCPU_HASH

## BPF_MAP_TYPE_STACK_TRACE

## BPF_MAP_TYPE_LRU_HASH

## BPF_MAP_TYPE_LRU_PERCPU_HASH
