__u8 buf[SAMPLE_BYTES];
    // ...
    bpf_probe_read_kernel(buf, sizeof(buf), data);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, buf, sizeof(buf));
