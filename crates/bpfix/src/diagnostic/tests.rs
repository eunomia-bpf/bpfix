use super::{
    active_object_section_is_skb_tracepoint, analyze_verifier_log, ProofEventEvidence,
    ProofEventRole, ProofSignal,
};
use crate::family::ProofObligation;
use crate::output::NextAction;
use std::collections::BTreeSet;

macro_rules! define_all_proof_signals {
        ($($variant:ident),+ $(,)?) => {
            const ALL_PROOF_SIGNALS: &[ProofSignal] = &[
                $(ProofSignal::$variant),+
            ];
        };
    }

proof_signal_variants!(define_all_proof_signals);

#[test]
fn skb_tracepoint_section_predicate_is_deliberately_narrow() {
    assert!(active_object_section_is_skb_tracepoint(&[
        "tracepoint/skb/consume_skb".to_string()
    ]));
    assert!(active_object_section_is_skb_tracepoint(&[
        "tp/skb/consume_skb".to_string()
    ]));
    assert!(!active_object_section_is_skb_tracepoint(&[
        "xdp".to_string()
    ]));
    assert!(!active_object_section_is_skb_tracepoint(
        &["tc".to_string()]
    ));
    assert!(!active_object_section_is_skb_tracepoint(&[
        "raw_tracepoint/sched_wakeup".to_string()
    ]));
    assert!(!active_object_section_is_skb_tracepoint(&[
        "kprobe/do_sys_open".to_string()
    ]));
    assert!(!active_object_section_is_skb_tracepoint(&[
        "fentry/do_sys_open".to_string()
    ]));
    assert!(!active_object_section_is_skb_tracepoint(&[
        "tracepoint/skb/consume_skb".to_string(),
        "xdp".to_string(),
    ]));
}

#[test]
fn proof_signals_have_specific_next_actions() {
    for signal in ALL_PROOF_SIGNALS {
        assert_ne!(
            signal.next_action(),
            NextAction::Other,
            "{signal:?} should expose a concrete next_action"
        );
    }
}

#[test]
fn proof_signal_metadata_is_complete_and_unique() {
    let all_signals = ALL_PROOF_SIGNALS
        .iter()
        .map(|signal| format!("{signal:?}"))
        .collect::<BTreeSet<_>>();
    let mut metadata_signals = BTreeSet::new();

    for signal in super::signal::metadata_signals_for_test() {
        assert!(
            metadata_signals.insert(format!("{signal:?}")),
            "duplicate ProofSignal metadata for {signal:?}"
        );
    }

    assert_eq!(metadata_signals, all_signals);
}

#[test]
fn unsupported_terminal_replacement_is_an_explicit_signal_whitelist() {
    let replaceable = [
        ProofSignal::BtfFuncInfoMissing,
        ProofSignal::ContextAccessSourceArgumentMismatch,
        ProofSignal::DynptrStackStorageAccess,
        ProofSignal::DynptrSliceVariableLength,
        ProofSignal::ExceptionThrowWithLiveReference,
        ProofSignal::ReferenceLiveAtExit,
        ProofSignal::IrqFlagStateMismatch,
        ProofSignal::IrqRestoreOrderMismatch,
        ProofSignal::IrqRestoreHelperClassMismatch,
        ProofSignal::IrqStateLiveAtExit,
        ProofSignal::IteratorHelperArgumentStateMismatch,
        ProofSignal::IteratorStackStorageAccess,
        ProofSignal::MapLookupKeyArgumentUnreadable,
        ProofSignal::MapPointerArgumentScalarZero,
        ProofSignal::MapValueGuardExceedsValueSize,
        ProofSignal::MapValueRelationPrecisionBoundary,
        ProofSignal::PacketGuardUndercoversAccess,
        ProofSignal::PacketMaxOffsetPrecisionBoundary,
        ProofSignal::SubprogramReferenceMetadataMissing,
        ProofSignal::TrustedNullableArgument,
    ];
    for signal in replaceable {
        assert!(
            signal.can_replace_unsupported_terminal(),
            "{signal:?} should replace unsupported terminal messages"
        );
    }

    let lowering_only = [
        ProofSignal::WideStackAlignment,
        ProofSignal::SharedInstructionPointerMerge,
        ProofSignal::SharedInstructionPathProofLoss,
        ProofSignal::Alu32PointerCopyDropsProvenance,
        ProofSignal::ConstantScalarMemoryLoad,
        ProofSignal::SharedInstructionUninitializedRegister,
        ProofSignal::PointerShiftDropsProvenance,
        ProofSignal::ModifiedContextPointer,
        ProofSignal::SubprogramContextArgumentDropped,
        ProofSignal::PacketPointerProofLostAfterBoundsCheck,
        ProofSignal::PacketRangeProofLostBeforeAccess,
        ProofSignal::MapValueWideAccess,
        ProofSignal::MapValueCheckedOffsetRelationLost,
    ];
    for signal in lowering_only {
        assert!(
            !signal.can_replace_unsupported_terminal(),
            "{signal:?} should not replace unsupported terminal messages"
        );
    }
}

#[test]
fn branch_merge_case_produces_proof_lifecycle_events() {
    let log =
        include_str!("../../../../bpfix-bench/cases/stackoverflow-53136145/replay-verifier.log");
    let analysis = analyze_verifier_log(
        log,
        Some(37),
        None,
        "R5 invalid mem access 'scalar'",
        None,
        ProofObligation::PointerProvenance,
    )
    .unwrap();

    assert_eq!(analysis.state_count, 60);
    assert_eq!(
        analysis.required_proof.obligation,
        ProofObligation::PointerProvenance
    );
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 263
    }));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished && event.source.as_ref().unwrap().line == 267
    }));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofLost
            && event.evidence == ProofEventEvidence::VerifierState
            && event.source.as_ref().unwrap().line == 267
    }));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 270
    }));
}

#[test]
fn scalar_range_case_identifies_obligation_and_rejection() {
    let log =
        include_str!("../../../../bpfix-bench/cases/stackoverflow-70750259/replay-verifier.log");
    let analysis = analyze_verifier_log(
        log,
        Some(33),
        None,
        "value -2147483648 makes pkt pointer be out of bounds",
        None,
        ProofObligation::ScalarRange,
    )
    .unwrap();

    assert_eq!(
        analysis.required_proof.obligation,
        ProofObligation::ScalarRange
    );
    assert!(analysis
        .required_proof
        .description
        .contains("cannot be negative"));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 274
    }));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 280
    }));
}

#[test]
fn map_value_access_case_describes_value_size_bounds() {
    let log =
        include_str!("../../../../bpfix-bench/cases/stackoverflow-78196801/replay-verifier.log");
    let analysis = analyze_verifier_log(
            log,
            Some(13),
            None,
            "invalid access to map value, value_size=24 off=67 size=1; R0 max value is outside of the allowed memory range",
            None,
            ProofObligation::ScalarRange,
        )
        .unwrap();

    assert_eq!(
        analysis.required_proof.obligation,
        ProofObligation::ScalarRange
    );
    assert!(analysis.required_proof.description.contains("map-value"));
    assert!(analysis
        .required_proof
        .description
        .contains("value_size=24"));
    assert!(analysis.required_proof.description.contains("off=67"));
    assert!(analysis.required_proof.description.contains("size=1"));
    assert!(analysis
        .required_proof
        .description
        .contains("map_value(value_size=24"));
    assert!(analysis
        .required_proof
        .rejection_detail
        .contains("reaches byte 68"));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofLost
            && event
                .detail
                .contains("map_value(value_size=24,range(smin=0,smax=63,umax=63)")
    }));
}

#[test]
fn packet_bounds_case_instantiates_required_range() {
    let log =
        include_str!("../../../../bpfix-bench/cases/stackoverflow-60053570/replay-verifier.log");
    let analysis = analyze_verifier_log(
        log,
        Some(26),
        None,
        "invalid access to packet, off=34 size=64, R3(id=0,off=34,r=42)",
        None,
        ProofObligation::PacketBounds,
    )
    .unwrap();

    assert_eq!(
        analysis.required_proof.obligation,
        ProofObligation::PacketBounds
    );
    assert!(analysis.required_proof.description.contains("R3"));
    assert!(analysis.required_proof.description.contains("98"));
    assert!(analysis.required_proof.description.contains("42"));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished
            && event.evidence == ProofEventEvidence::SourceComment
            && event.source.as_ref().unwrap().line == 52
    }));

    let derived_header_log =
        include_str!("../../../../bpfix-bench/cases/stackoverflow-76277872/replay-verifier.log");
    let analysis = analyze_verifier_log(
            derived_header_log,
            Some(6),
            None,
            "invalid access to packet, off=26 size=4, R1(id=0,off=26,r=14); R1 offset is outside of the packet",
            None,
            ProofObligation::PacketBounds,
        )
        .unwrap();
    assert!(
        analysis
            .signals
            .contains(&ProofSignal::PacketAccessWithoutBoundsProof),
        "signals: {:?}",
        analysis.signals
    );
}

#[test]
fn nullable_pointer_case_points_at_unchecked_helper_result() {
    let log =
        include_str!("../../../../bpfix-bench/cases/github-iovisor-bcc-10/replay-verifier.log");
    let analysis = analyze_verifier_log(
        log,
        Some(7),
        None,
        "R0 invalid mem access 'map_value_or_null'",
        None,
        ProofObligation::NullablePointer,
    )
    .unwrap();

    assert_eq!(
        analysis.required_proof.obligation,
        ProofObligation::NullablePointer
    );
    assert!(analysis.required_proof.description.contains("R0"));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 24
    }));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::Rejected && event.source.as_ref().unwrap().line == 25
    }));
}

#[test]
fn environment_case_instantiates_helper_contract() {
    let log =
        include_str!("../../../../bpfix-bench/cases/github-aya-rs-aya-1233/replay-verifier.log");
    let analysis = analyze_verifier_log(
        log,
        Some(8),
        None,
        "program of this type cannot use helper bpf_probe_read#4",
        None,
        ProofObligation::EnvironmentCapability,
    )
    .unwrap();

    assert_eq!(
        analysis.required_proof.obligation,
        ProofObligation::EnvironmentCapability
    );
    assert!(analysis
        .required_proof
        .description
        .contains("bpf_probe_read#4"));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 13
    }));
}

#[test]
fn stack_readability_case_instantiates_register_requirement() {
    let analysis = analyze_verifier_log(
        "0: (95) exit\nR0 !read_ok\n",
        Some(0),
        None,
        "R0 !read_ok",
        None,
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert_eq!(
        analysis.required_proof.obligation,
        ProofObligation::StackInitialized
    );
    assert!(analysis.required_proof.description.contains("R0"));
    assert!(analysis
        .required_proof
        .rejection_detail
        .contains("not readable"));
    assert!(analysis
        .signals
        .contains(&ProofSignal::UnreadableReturnRegister));
}

#[test]
fn unreadable_program_entry_argument_is_a_source_state_signal() {
    let log =
        include_str!("../../../../bpfix-bench/cases/stackoverflow-69506785/replay-verifier.log");
    let analysis = analyze_verifier_log(
        log,
        Some(0),
        None,
        "R2 !read_ok",
        None,
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::UnreadableProgramEntryArgument));
}

#[test]
fn unreadable_helper_argument_is_a_source_state_signal() {
    let log = include_str!(
        "../../../../bpfix-bench/cases/github-commit-cilium-6b3c9f16c99f/replay-verifier.log"
    );
    let analysis = analyze_verifier_log(
        log,
        Some(6),
        None,
        "R5 !read_ok",
        Some("bpf_skb_store_bytes"),
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::UnreadableHelperArgument));
}

#[test]
fn scalar_pointer_dereference_is_a_source_state_signal() {
    let log = include_str!(
        "../../../../bpfix-bench/cases/github-commit-bcc-02daf8d84ecd/replay-verifier.log"
    );
    let analysis = analyze_verifier_log(
        log,
        Some(1),
        None,
        "R1 invalid mem access 'scalar'",
        None,
        ProofObligation::PointerProvenance,
    )
    .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::ScalarValueUsedAsPointer));
}

#[test]
fn stale_packet_pointer_after_helper_is_a_source_state_signal() {
    let log = include_str!(
        "../../../../bpfix-bench/cases/github-commit-cilium-2ff1a462cd33/replay-verifier.log"
    );
    let analysis = analyze_verifier_log(
        log,
        Some(10),
        None,
        "R7 invalid mem access 'scalar'",
        None,
        ProofObligation::PointerProvenance,
    )
    .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::StalePointerAfterInvalidatingHelper));
    assert!(!analysis
        .signals
        .contains(&ProofSignal::DynptrDataPointerInvalidatedBeforeUse));
}

#[test]
fn stale_dynptr_data_after_reinit_helper_is_a_source_state_signal() {
    let log = include_str!(
            "../../../../bpfix-bench/cases/kernel-selftest-dynptr-fail-dynptr-invalidate-slice-reinit-raw-tp-f5b71f50/replay-verifier.log"
        );
    let analysis = analyze_verifier_log(
        log,
        Some(52),
        None,
        "R7 invalid mem access 'scalar'",
        None,
        ProofObligation::PointerProvenance,
    )
    .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::DynptrDataPointerInvalidatedBeforeUse));
    assert!(!analysis
        .signals
        .contains(&ProofSignal::StalePointerAfterInvalidatingHelper));
}

#[test]
fn prohibited_pointer_arithmetic_is_a_source_state_signal() {
    let log =
        include_str!("../../../../bpfix-bench/cases/stackoverflow-68460177/replay-verifier.log");
    let analysis = analyze_verifier_log(
        log,
        Some(37),
        None,
        "R4 bitwise operator |= on pointer prohibited",
        None,
        ProofObligation::PointerProvenance,
    )
    .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::ProhibitedPointerArithmetic));
}

#[test]
fn map_lookup_unreadable_key_stays_stack_initialization_signal() {
    let log = "\
; value = bpf_map_lookup_elem(&map, key); @ prog.c:20
4: (85) call bpf_map_lookup_elem#1
R2 !read_ok
";
    let analysis = analyze_verifier_log(
        log,
        Some(4),
        None,
        "R2 !read_ok",
        Some("bpf_map_lookup_elem"),
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::MapLookupKeyArgumentUnreadable));
    assert!(!analysis
        .signals
        .contains(&ProofSignal::UnreadableProgramEntryArgument));
    assert!(!analysis
        .signals
        .contains(&ProofSignal::UnreadableHelperArgument));
}

#[test]
fn ordinary_helper_unreadable_arg_stays_stack_initialization_without_signal() {
    let log = "\
0: R1=ctx() R10=fp0
; bpf_probe_read_kernel(dst, len, key); @ prog.c:19
2: (85) call bpf_probe_read_kernel#113
R2 !read_ok
";
    let analysis = analyze_verifier_log(
        log,
        Some(2),
        None,
        "R2 !read_ok",
        Some("bpf_probe_read_kernel"),
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(!analysis
        .signals
        .contains(&ProofSignal::UnreadableProgramEntryArgument));
    assert!(!analysis
        .signals
        .contains(&ProofSignal::UnreadableHelperArgument));
}

#[test]
fn legacy_skb_access_is_not_program_entry_abi_signal() {
    let log = "\
0: R1=ctx() R10=fp0
; asm volatile (\"r0 = *(u8 *)skb[9]\" ::: \"r0\"); @ prog.c:8
0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
";
    let analysis = analyze_verifier_log(
        log,
        Some(0),
        None,
        "R6 !read_ok",
        None,
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(!analysis
        .signals
        .contains(&ProofSignal::UnreadableProgramEntryArgument));
    assert!(!analysis
        .signals
        .contains(&ProofSignal::UnreadableHelperArgument));
    assert!(analysis
        .signals
        .contains(&ProofSignal::LegacySkbLoadUnreadableRegister));

    let readable_r6_log = "\
0: R1=ctx() R6=ctx() R10=fp0
; asm volatile (\"r0 = *(u8 *)skb[9]\" ::: \"r0\"); @ prog.c:8
0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
";
    let analysis = analyze_verifier_log(
        readable_r6_log,
        Some(0),
        None,
        "R6 !read_ok",
        None,
        ProofObligation::StackInitialized,
    )
    .unwrap();
    assert!(!analysis
        .signals
        .contains(&ProofSignal::LegacySkbLoadUnreadableRegister));

    let stale_r6_from_earlier_full_state = "\
0: R1=ctx() R6=ctx() R10=fp0
0: R1=ctx() R10=fp0
; asm volatile (\"r0 = *(u8 *)skb[9]\" ::: \"r0\"); @ prog.c:8
0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
";
    let analysis = analyze_verifier_log(
        stale_r6_from_earlier_full_state,
        Some(0),
        None,
        "R6 !read_ok",
        None,
        ProofObligation::StackInitialized,
    )
    .unwrap();
    assert!(analysis
        .signals
        .contains(&ProofSignal::LegacySkbLoadUnreadableRegister));

    let no_snapshot_log = "\
; asm volatile (\"r0 = *(u8 *)skb[9]\" ::: \"r0\"); @ prog.c:8
0: (30) r0 = *(u8 *)skb[9]
R6 !read_ok
";
    let analysis = analyze_verifier_log(
        no_snapshot_log,
        Some(0),
        None,
        "R6 !read_ok",
        None,
        ProofObligation::StackInitialized,
    )
    .unwrap();
    assert!(!analysis
        .signals
        .contains(&ProofSignal::LegacySkbLoadUnreadableRegister));
}

#[test]
fn helper_stack_read_length_exceeding_initialized_bytes_is_source_state_signal() {
    let helper_stack_read_signal = |log: &str, terminal_error: &str| {
        analyze_verifier_log(
            log,
            Some(2),
            None,
            terminal_error,
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap()
        .signals
        .contains(&ProofSignal::HelperStackReadExceedsInitializedRange)
    };
    let log = "\
0: R1=ctx() R10=fp0
1: (7b) *(u64 *)(r10 -24) = r2        ; R2_w=0 R10=fp0 fp-24_w=0
2: (bf) r3 = r10                      ; R3_w=fp0 R10=fp0
3: (07) r3 += -24                     ; R3_w=fp-24
4: (b7) r4 = 9                        ; R4_w=9
5: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    let analysis = analyze_verifier_log(
            log,
            Some(5),
            None,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

    let branch_paths_are_not_mixed = "\
0: R1=ctx() R10=fp0
1: R3=fp-32 R4=16 R10=fp0 fp-32_w=0
from 1 to 2: R3=fp-32 R4=16 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -32+8 size 16
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(helper_stack_read_signal(
            branch_paths_are_not_mixed,
            "invalid read from stack R3 off -32+8 size 16; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

    let pc_full_states_are_not_merged = "\
0: R1=ctx() R10=fp0 fp-32_w=0
1: R3=fp-32 R4=16 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -32+8 size 16
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(helper_stack_read_signal(
            pc_full_states_are_not_merged,
            "invalid read from stack R3 off -32+8 size 16; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

    let branch_delta_state_is_part_of_current_path = "\
0: R1=ctx() R10=fp0 fp-24_w=0
1: (55) if r1 != 0x0 goto pc+1      ; R3=fp-24 R4=9 R10=fp0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(helper_stack_read_signal(
            branch_delta_state_is_part_of_current_path,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

    let partial_low_half_read = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=4 R10=fp0 fp-24=0000????
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+0 size 4
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    let analysis = analyze_verifier_log(
            partial_low_half_read,
            Some(2),
            None,
            "invalid read from stack R3 off -24+0 size 4; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
    assert!(analysis
        .signals
        .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

    let partial_high_half_read = "\
0: R1=ctx() R10=fp0
1: R3=fp-20 R4=4 R10=fp0 fp-24=0000????
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -20+0 size 4
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    let analysis = analyze_verifier_log(
            partial_high_half_read,
            Some(2),
            None,
            "invalid read from stack R3 off -20+0 size 4; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
    assert!(!analysis
        .signals
        .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

    let oversized_exact_length = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=65535 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+0 size 65535
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    let analysis = analyze_verifier_log(
            oversized_exact_length,
            Some(2),
            None,
            "invalid read from stack R3 off -24+0 size 65535; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
    assert!(analysis
        .signals
        .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

    let iterator_slot_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16_w=iter_num()
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+0 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    let analysis = analyze_verifier_log(
            iterator_slot_is_not_plain_buffer,
            Some(2),
            None,
            "invalid read from stack R3 off -24+0 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
    assert!(analysis
        .signals
        .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

    let frame_pointer_spill_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16=fp-40
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(helper_stack_read_signal(
            frame_pointer_spill_is_not_plain_buffer,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

    let map_value_spill_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16=map_value(map=demo,ks=4,vs=8)
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(helper_stack_read_signal(
            map_value_spill_is_not_plain_buffer,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

    let ctx_spill_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16=ctx()
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(helper_stack_read_signal(
            ctx_spill_is_not_plain_buffer,
            "invalid read from stack R3 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

    let raw_dynptr_slot_type_is_not_plain_buffer = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0 fp-16=dddddddd
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+0 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    let analysis = analyze_verifier_log(
            raw_dynptr_slot_type_is_not_plain_buffer,
            Some(2),
            None,
            "invalid read from stack R3 off -24+0 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
    assert!(analysis
        .signals
        .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

    let adjacent_initialized_slots = "\
0: R1=ctx() R10=fp0
1: R3=fp-32 R4=16 R10=fp0 fp-32_w=0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -32+0 size 16
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    let analysis = analyze_verifier_log(
            adjacent_initialized_slots,
            Some(2),
            None,
            "invalid read from stack R3 off -32+0 size 16; arg#2 arg#3 memory, len pair leads to invalid memory access",
            Some("bpf_dynptr_slice"),
            ProofObligation::StackInitialized,
        )
        .unwrap();
    assert!(!analysis
        .signals
        .contains(&ProofSignal::HelperStackReadExceedsInitializedRange));

    let reported_register_mismatch = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R2 off -24+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(!helper_stack_read_signal(
            reported_register_mismatch,
            "invalid read from stack R2 off -24+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

    let reported_offset_mismatch = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=9 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -16+8 size 9
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(!helper_stack_read_signal(
            reported_offset_mismatch,
            "invalid read from stack R3 off -16+8 size 9; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));

    let reported_size_mismatch = "\
0: R1=ctx() R10=fp0
1: R3=fp-24 R4=70000 R10=fp0 fp-24_w=0
2: (85) call bpf_dynptr_slice#71567
invalid read from stack R3 off -24+8 size 65535
arg#2 arg#3 memory, len pair leads to invalid memory access
";
    assert!(!helper_stack_read_signal(
            reported_size_mismatch,
            "invalid read from stack R3 off -24+8 size 65535; arg#2 arg#3 memory, len pair leads to invalid memory access"
        ));
}

#[test]
fn static_helper_signature_is_not_program_entry_abi_signal() {
    let log = "\
0: R1=ctx() R10=fp0
; static int helper(void *ctx, int arg) @ prog.c:8
0: (bf) r3 = r2
R2 !read_ok
";
    let analysis = analyze_verifier_log(
        log,
        Some(0),
        None,
        "R2 !read_ok",
        None,
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(!analysis
        .signals
        .contains(&ProofSignal::UnreadableProgramEntryArgument));
    assert!(!analysis
        .signals
        .contains(&ProofSignal::UnreadableHelperArgument));
}

#[test]
fn helper_stack_write_beyond_frame_is_a_source_state_signal() {
    let log = include_str!(
        "../../../../bpfix-bench/cases/github-commit-cilium-31a01b994f8b/replay-verifier.log"
    );
    let analysis = analyze_verifier_log(
        log,
        Some(3),
        None,
        "invalid write to stack R1 off=-600 size=600",
        Some("bpf_get_current_comm"),
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(analysis
        .signals
        .contains(&ProofSignal::HelperStackWriteBeyondFrame));
}

#[test]
fn helper_stack_write_inside_frame_is_not_beyond_frame_signal() {
    let log = "\
0: R1=ctx() R10=fp0
1: R1_w=fp-16 R2_w=16 R10=fp0
1: (85) call bpf_get_current_comm#16
invalid write to stack R1 off=-16 size=16
";
    let analysis = analyze_verifier_log(
        log,
        Some(1),
        None,
        "invalid write to stack R1 off=-16 size=16",
        Some("bpf_get_current_comm"),
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(!analysis
        .signals
        .contains(&ProofSignal::HelperStackWriteBeyondFrame));
}

#[test]
fn ordinary_stack_store_is_not_helper_stack_write_signal() {
    let log = "\
0: R1=fp-600 R2=scalar(id=1) R10=fp0
0: (7b) *(u64 *)(r1 +0) = r2
invalid write to stack R1 off=-600 size=8
";
    let analysis = analyze_verifier_log(
        log,
        Some(0),
        None,
        "invalid write to stack R1 off=-600 size=8",
        None,
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(!analysis
        .signals
        .contains(&ProofSignal::HelperStackWriteBeyondFrame));
}

#[test]
fn helper_stack_write_requires_modeled_helper_signature() {
    let log = "\
0: R1=ctx() R10=fp0
1: R1_w=fp-600 R2_w=600 R10=fp0
1: (85) call bpf_probe_read_kernel#113
invalid write to stack R1 off=-600 size=600
";
    let analysis = analyze_verifier_log(
        log,
        Some(1),
        None,
        "invalid write to stack R1 off=-600 size=600",
        Some("bpf_probe_read_kernel"),
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(!analysis
        .signals
        .contains(&ProofSignal::HelperStackWriteBeyondFrame));
}

#[test]
fn helper_stack_write_requires_matching_length_state() {
    let log = "\
0: R1=ctx() R10=fp0
1: R1_w=fp-600 R2_w=16 R10=fp0
1: (85) call bpf_get_current_comm#16
invalid write to stack R1 off=-600 size=600
";
    let analysis = analyze_verifier_log(
        log,
        Some(1),
        None,
        "invalid write to stack R1 off=-600 size=600",
        Some("bpf_get_current_comm"),
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(!analysis
        .signals
        .contains(&ProofSignal::HelperStackWriteBeyondFrame));
}

#[test]
fn helper_stack_write_requires_matching_frame_pointer_offset() {
    let log = "\
0: R1=ctx() R10=fp0
1: R1_w=fp-608 R2_w=600 R10=fp0
1: (85) call bpf_get_current_comm#16
invalid write to stack R1 off=-600 size=600
";
    let analysis = analyze_verifier_log(
        log,
        Some(1),
        None,
        "invalid write to stack R1 off=-600 size=600",
        Some("bpf_get_current_comm"),
        ProofObligation::StackInitialized,
    )
    .unwrap();

    assert!(!analysis
        .signals
        .contains(&ProofSignal::HelperStackWriteBeyondFrame));
}

#[test]
fn reference_lifecycle_case_reports_acquire_and_exit() {
    let log = "\
; ref = bpf_ringbuf_reserve(&rb, 8, 0); @ prog.c:10
5: (85) call bpf_ringbuf_reserve#131 ; R0_w=ringbuf_mem_or_null(id=2,ref_obj_id=2) refs=2
; return 0; @ prog.c:11
6: (95) exit
Unreleased reference id=2 alloc_insn=5
";
    let analysis = analyze_verifier_log(
        log,
        Some(6),
        None,
        "Unreleased reference id=2 alloc_insn=5",
        None,
        ProofObligation::ReferenceLifecycle,
    )
    .unwrap();

    assert_eq!(
        analysis.required_proof.obligation,
        ProofObligation::ReferenceLifecycle
    );
    assert!(analysis
        .required_proof
        .description
        .contains("reference id 2"));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofEstablished && event.source.as_ref().unwrap().line == 10
    }));
    assert!(analysis.events.iter().any(|event| {
        event.role == ProofEventRole::ProofLost && event.source.as_ref().unwrap().line == 11
    }));
    assert!(analysis.signals.contains(&ProofSignal::ReferenceLiveAtExit));

    let released_before_exit = "\
5: (85) call bpf_ringbuf_reserve#131 ; R0_w=ringbuf_mem_or_null(id=2,ref_obj_id=2) refs=2
6: R0=scalar()
7: (95) exit
Unreleased reference id=2 alloc_insn=5
";
    let analysis = analyze_verifier_log(
        released_before_exit,
        Some(7),
        None,
        "Unreleased reference id=2 alloc_insn=5",
        None,
        ProofObligation::ReferenceLifecycle,
    )
    .unwrap();

    assert!(!analysis.signals.contains(&ProofSignal::ReferenceLiveAtExit));
}
