# rs_agentsight_fs_overflow_counter_merge_001

Real-project seed candidate from AgentSight `bpf/process_ext/bpf_fs.h`.
The minimized program keeps the file-path aggregation workflow: derive a
directory-prefix key, update an existing aggregate value in place, insert a new
aggregate value, and account for map-insert overflow in `agg_overflow_count`.

The injected bug checks the overflow-counter lookup only on one branch before
incrementing it after the branch merge. The verifier rejects the atomic add
because the overflow pointer can still be `map_value_or_null`. A correct repair
must make the overflow-counter proof dominate the increment while preserving
path-key aggregation, insert failure accounting, and existing-value updates.
