# rs_tetragon_data_event_size_guard_001

Real-project seed from Tetragon's `data_event.h` user-buffer data event path.
The case preserves the map-backed event buffer, user-memory byte copy, event
size accounting, and perf-event output workflow.

The buggy program derives and stores a bounded `bounded_size`, but still passes
the masked raw syscall count to `bpf_probe_read_user` and to the emitted data
size. The intended repair is to keep the data-event workflow and pass the
bounded size through the helper/output path.
