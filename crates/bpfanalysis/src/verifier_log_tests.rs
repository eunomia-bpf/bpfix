use super::*;

#[test]
fn parses_instruction_lines_and_call_targets() {
    assert_eq!(
        parse_instruction_line("  6: (71) r3 = *(u8 *)(r2 +0)"),
        Some((6, "(71) r3 = *(u8 *)(r2 +0)"))
    );
    assert_eq!(parse_instruction_pc("17: R1=ctx() R10=fp0"), Some(17));
    assert_eq!(parse_instruction_line("17: R1=ctx() R10=fp0"), None);
    assert_eq!(
        parse_instruction_line("21: .12....... (85) call bpf_map_lookup_elem#1"),
        Some((21, "(85) call bpf_map_lookup_elem#1"))
    );
    assert_eq!(parse_instruction_line("processed 4 insns"), None);

    assert_eq!(
        call_target_from_instruction_tail("(85) call bpf_map_lookup_elem#1"),
        Some("bpf_map_lookup_elem")
    );
    assert_eq!(
        call_target_from_instruction_tail("(85) call unknown"),
        Some("unknown")
    );
    assert_eq!(
        call_target_from_instruction_tail("(15) if r1 == 0x0 call not_a_direct_call"),
        Some("not_a_direct_call")
    );
    assert_eq!(
        direct_call_target_from_instruction_tail("(85) call bpf_dynptr_slice_rdwr#202"),
        Some("bpf_dynptr_slice_rdwr")
    );
    assert_eq!(
        direct_call_target_from_instruction_tail("(15) if r1 == 0x0 goto pc+1"),
        None
    );
}

#[test]
fn parses_instruction_register_operands() {
    assert_eq!(loose_register_operands("if r1 > r2 goto pc+1"), vec![1, 2]);
    assert_eq!(loose_register_operands("w3 = r4; r10 = fp"), vec![4, 10]);
    assert_eq!(
        loose_register_operands("r1 += 8; *(u64 *)(r10 -8) = r1"),
        vec![1, 10, 1]
    );
    assert_eq!(loose_register_operands("err12 r2foo w3"), vec![12, 2]);

    assert_eq!(register_token("r7,"), Some(7));
    assert_eq!(register_token("w7"), None);
    assert_eq!(register_token("r7+0"), None);
    assert_eq!(register_token("r"), None);
    assert_eq!(register_write_token("w7;"), Some(7));
    assert_eq!(register_write_token("r10"), Some(10));
}

#[test]
fn parses_memory_access_shape() {
    let load = "(79) r1 = *(u64 *)(r10 -8)";
    assert_eq!(memory_access_width(load), Some(8));
    assert!(memory_access_is_load(load));
    assert!(!memory_access_is_store(load));
    assert!(!memory_access_is_atomic(load));
    assert_eq!(memory_access_operand(load), Some("r10 -8"));
    assert_eq!(memory_access_base_register(load), Some(10));
    assert_eq!(memory_access_offset(load), Some(-8));

    let store = "(7b) *(u64 *)(r10 -16) = r1";
    assert_eq!(memory_access_width(store), Some(8));
    assert!(!memory_access_is_load(store));
    assert!(memory_access_is_store(store));
    assert_eq!(memory_access_base_register(store), Some(10));
    assert_eq!(memory_access_offset(store), Some(-16));

    let atomic = "(db) lock *(u64 *)(r1 +0) += r2";
    assert!(memory_access_is_atomic(atomic));
    assert_eq!(atomic_memory_access_width(atomic), Some(8));

    let slot = stack_value_range(-16, 8).unwrap();
    let access = stack_access_range("invalid read from stack R3 off -12 size 4").unwrap();
    assert!(slot.overlaps(access));
    assert!(slot.contains(-16));
    assert!(slot.contains_range(access));
    assert_eq!(slot.len(), 8);
    assert_eq!(slot.start(), -16);
    assert_eq!(slot.end(), -8);
    assert!(stack_value_range(-8, -1).is_none());
    assert!(stack_access_range("invalid read from stack R3 off -12 size -4").is_none());
}

#[test]
fn identifies_verifier_error_lines_and_fragments() {
    assert!(is_verifier_error_line(
        "invalid access to map value, value_size=2 off=1 size=2"
    ));
    assert!(is_verifier_error_line(
        "processed 1000001 insns (limit exceeded)"
    ));
    assert!(!is_verifier_error_line("12: (71) r1 = *(u8 *)(r2 +0)"));
    assert!(!is_verifier_error_line("12: R1=ctx() R10=fp0"));
    assert!(!is_verifier_error_line("processed 18 insns"));

    assert!(is_verifier_fragment_boundary("func#1 @0"));
    assert!(is_verifier_fragment_boundary(
        "invalid access to map value, value_size=2 off=1 size=2"
    ));
    assert!(!is_verifier_fragment_boundary("12: R1=ctx() R10=fp0"));

    let log = "\
0: (b7) r0 = 0
invalid access to map value, value_size=2 off=1 size=2
0: (b7) r0 = 1
1: (95) exit
";
    assert_eq!(verifier_fragment_start_line(log, 4), 3);
}

#[test]
fn locates_terminal_instruction_inside_current_fragment() {
    let log = "\
0: (b7) r1 = 0
1: (85) call bpf_map_lookup_elem#1
invalid mem access 'scalar'
0: (b7) r1 = 1
1: (79) r2 = *(u64 *)(r10 -8)
R2 invalid mem access 'scalar'
";

    let instruction = terminal_instruction_site(log, Some(1), Some(6)).unwrap();
    assert_eq!(instruction.line, 5);
    assert_eq!(instruction.tail, "(79) r2 = *(u64 *)(r10 -8)");
    assert_eq!(
        instruction_site_before_line(log, 1, 4, 6).map(|instruction| instruction.line),
        Some(5)
    );
    assert_eq!(
        instructions_in_line_range(log, 4, 6)
            .map(|instruction| instruction.line)
            .collect::<Vec<_>>(),
        vec![4, 5]
    );
    assert_eq!(
        instructions_in_line_range(log, 4, 5)
            .map(|instruction| instruction.line)
            .collect::<Vec<_>>(),
        vec![4]
    );
    assert_eq!(instructions_in_line_range(log, 6, 6).count(), 0);
    assert_eq!(instructions_in_line_range(log, 7, 6).count(), 0);
    assert_eq!(
        instruction_site_before_line(log, 0, 4, 5).map(|instruction| instruction.line),
        Some(4)
    );
    assert_eq!(instruction_site_before_line(log, 1, 4, 5), None);
    assert_eq!(
        terminal_instruction_access_width(log, Some(1), Some(6)),
        Some(8)
    );
    assert_eq!(
        terminal_instruction_memory_offset(log, Some(1), Some(6)),
        Some(-8)
    );
    assert!(terminal_instruction_contains(
        log,
        Some(1),
        Some(6),
        "*(u64 *)"
    ));
    assert_eq!(
        terminal_call_target(log, Some(1), Some(3)),
        Some("bpf_map_lookup_elem")
    );

    let direct = instruction_on_log_line(log, 5).unwrap();
    assert_eq!(direct.pc, 1);
}

#[test]
fn terminal_instruction_uses_last_matching_pc_before_terminal() {
    let log = "\
4: (bf) r2 = r1
5: (71) r3 = *(u8 *)(r2 +0)
5: (7b) *(u64 *)(r10 -8) = r3
R3 invalid mem access 'scalar'
";

    let instruction = terminal_instruction_site(log, Some(5), Some(4)).unwrap();
    assert_eq!(instruction.line, 3);
    assert_eq!(instruction.tail, "(7b) *(u64 *)(r10 -8) = r3");
    assert!(!memory_access_is_load(instruction.tail));
}

#[test]
fn queries_instruction_register_effects() {
    let copy = "(bf) r3 = r1                      ; R3_w=ctx()";
    assert_eq!(instruction_destination_register(copy), Some(3));
    assert!(instruction_assigns_register(copy, 3));
    assert!(instruction_writes_register(copy, 3));
    assert_eq!(instruction_register_copy_source(copy, 3), Some(1));
    assert_eq!(instruction_single_register_rhs_source(copy, 3), Some(1));
    assert_eq!(
        instruction_register_copy_source("(bf) r3 = r1 + 0", 3),
        None
    );
    assert_eq!(
        instruction_single_register_rhs_source("(bf) r3 = r1 + 0", 3),
        Some(1)
    );
    assert!(instruction_uses_register(
        "r1 += 8; *(u64 *)(r10 -8) = r1",
        10
    ));

    let call = "(85) call bpf_map_lookup_elem#1";
    assert!(instruction_assigns_register(call, 0));
    assert!(instruction_writes_register(call, 5));
    assert!(!instruction_writes_register(call, 6));

    let branch = "(2d) if r2 > r1 goto pc+3";
    assert_eq!(conditional_branch_registers(branch), vec![2, 1]);
    assert!(instruction_adds_register("(0f) r4 += r2", 4, 2));
    assert!(!instruction_reads_register("(bf) r4 = r2", 2));
    assert!(instruction_reads_register("(2d) if r2 > r1 goto pc+3", 2));
}

#[test]
fn queries_latest_verifier_state_before_instruction() {
    let log = "\
0: R1=ctx() R2=scalar(id=1) R10=fp0
1: (bf) r3 = r1                      ; R3_w=ctx()
2: frame1: R1=scalar(id=2) R2=fp[0]-16 R10=fp0 fp-8=00000000 refs=7
3: (b7) r0 = 0                       ; R0_w=0
";

    let states = parse_verifier_log(log);
    let instruction = VerifierLogInstruction {
        pc: 3,
        line: 4,
        tail: "(b7) r0 = 0",
    };

    assert_eq!(
        latest_reg_state_before(&states, Some(1), 1)
            .unwrap()
            .reg_type,
        "ctx"
    );
    assert_eq!(
        latest_verifier_state_before_instruction(&states, instruction, 1)
            .unwrap()
            .pc,
        2
    );
    assert_eq!(
        latest_verifier_state_at_or_before_instruction(&states, instruction, 1)
            .unwrap()
            .pc,
        3
    );
    assert_eq!(
        latest_reg_state_before_instruction(&states, instruction, 1, 1)
            .unwrap()
            .reg_type,
        "scalar"
    );
    assert_eq!(
        latest_reg_state_at_or_before_instruction(&states, instruction, 1, 0)
            .unwrap()
            .exact_u32(),
        Some(0)
    );
    assert_eq!(
        latest_reg_state_before_instruction_with_frame(&states, instruction, 1, 2)
            .unwrap()
            .1,
        0
    );
    assert_eq!(
        latest_reg_state_before_instruction_with_log_line(&states, instruction, 1, 1)
            .unwrap()
            .1,
        3
    );
    let (_, log_line, frame) =
        latest_reg_state_before_instruction_with_origin(&states, instruction, 1, 2).unwrap();
    assert_eq!((log_line, frame), (3, 1));
    assert_eq!(
        latest_reg_state_in_line_range_before(&states, 2, 4, Some(3), 2)
            .unwrap()
            .reg_type,
        "fp"
    );
    assert_eq!(
        latest_ref_state_before_instruction(&states, instruction, 1)
            .unwrap()
            .pc,
        2
    );
    assert_eq!(
        latest_verifier_state_before(&states, Some(3), Some(4))
            .unwrap()
            .pc,
        2
    );

    let snapshot = verifier_path_snapshot_before_instruction(&states, instruction, 1).unwrap();
    assert_eq!(snapshot.frame, 1);
    assert_eq!(snapshot.regs.get(&1).unwrap().reg_type, "scalar");
    assert!(!snapshot.regs.contains_key(&3));
    assert_eq!(
        initialized_stack_bytes_from_snapshot(&snapshot.stack, -8),
        8
    );
}

#[test]
fn tracks_active_validation_windows() {
    let log = "\
0: (b7) r0 = 0
Validating cb() func#1...
1: R0=scalar(smin=-1,smax=2)
Func#1 is safe for any args
Validating cb() func#2...
2: R0=scalar(smin=0,smax=1)
register R0 has value 2 should have been in [0, 1]
";

    assert!(validation_seen(log, 1, 7));
    assert_eq!(active_validation_start(log, 1, 7), Some(5));
    assert_eq!(active_validation_start(log, 1, 5), None);
}

#[test]
fn parses_real_style_branch_and_insn_states() {
    let log = r#"
from 4 to 6: R0_w=pkt(off=8,r=8) R1=ctx() R2_w=pkt(r=8) R3_w=pkt_end() R10=fp0
6: R0_w=pkt(off=8,r=8) R1=ctx() R2_w=pkt(r=8) R3_w=pkt_end() R10=fp0
6: (71) r3 = *(u8 *)(r2 +0)           ; R2_w=pkt(r=8) R3_w=scalar(umax=255,var_off=(0x0; 0xff))
7: (15) if r3 == 0x0 goto pc+1        ; R3=scalar(smin=umin=smin32=umin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff))
10: R1=map_value(map=.data.two_byte_,ks=4,vs=2,off=1) R2=1 R10=fp0 fp-8=0000???? refs=2 cb
"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 5);
    assert_eq!(verifier_states_from_log(log).unwrap().len(), 4);
    assert_eq!(
        verifier_states_with_branch_deltas_from_log(log)
            .unwrap()
            .len(),
        5
    );

    assert_eq!(insns[0].pc, 6);
    assert_eq!(insns[0].from_pc, Some(4));
    assert_eq!(insns[0].kind, VerifierInsnKind::EdgeFullState);
    assert_eq!(insns[0].frame, 0);
    assert_eq!(insns[0].regs.get(&1).unwrap().reg_type, "ctx");
    assert_eq!(insns[0].regs.get(&0).unwrap().reg_type, "pkt");
    assert_eq!(insns[0].regs.get(&0).unwrap().offset, Some(8));
    assert_eq!(insns[0].regs.get(&10).unwrap().reg_type, "fp");
    assert_eq!(insns[0].regs.get(&10).unwrap().offset, Some(0));

    assert_eq!(insns[2].pc, 6);
    let r3_after_load = insns[2].regs.get(&3).unwrap();
    assert_eq!(r3_after_load.reg_type, "scalar");
    assert_eq!(insns[2].kind, VerifierInsnKind::InsnDeltaState);
    assert_eq!(r3_after_load.value_width, VerifierValueWidth::Bits32);
    assert_eq!(r3_after_load.range.umax, Some(255));
    assert_eq!(
        r3_after_load.tnum,
        Some(Tnum {
            value: 0,
            mask: 0xff
        })
    );
    assert_eq!(r3_after_load.exact_value, None);

    assert_eq!(insns[3].pc, 7);
    assert_eq!(insns[3].kind, VerifierInsnKind::BranchDeltaState);
    let r3_before_branch = insns[3].regs.get(&3).unwrap();
    assert_eq!(r3_before_branch.range.umin, Some(0));
    assert_eq!(r3_before_branch.range.umax, Some(255));

    assert_eq!(insns[4].pc, 10);
    let r1 = insns[4].regs.get(&1).unwrap();
    assert_eq!(r1.reg_type, "map_value");
    assert_eq!(r1.offset, Some(1));
    assert_eq!(r1.map_value_size, Some(2));
    assert_eq!(r1.mem_size, None);

    let r2 = insns[4].regs.get(&2).unwrap();
    assert_eq!(r2.reg_type, "scalar");
    assert_eq!(r2.exact_u64(), Some(1));
    assert_eq!(r2.range.umin, Some(1));
    assert_eq!(r2.range.umax, Some(1));

    let fp8 = insns[4].stack.get(&-8).unwrap();
    assert_eq!(fp8.slot_types.as_deref(), Some("0000????"));
    assert!(fp8.value.is_none());
    assert_eq!(insns[4].refs, Some(2));
    assert_eq!(insns[4].callback_kind, Some(CallbackKind::Sync));
    assert!(insns[4].callback);
}

#[test]
fn parses_memory_object_size_from_register_state() {
    let log = r#"
16: (85) call bpf_dynptr_slice_rdwr#202  ; R0_w=mem(sz=14)
17: (73) *(u8 *)(r0 +14) = r6
"#;

    let insns = verifier_states_from_log(log).unwrap();
    let mem = insns[0].regs.get(&0).unwrap();
    assert_eq!(mem.reg_type, "mem");
    assert_eq!(mem.mem_size, Some(14));
}

#[test]
fn parses_constants_and_repeated_bounds_from_real_messages() {
    let log = r#"
0: R1=ctx() R10=fp0
2: (25) if r0 > 0x1 goto pc+1         ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=1,var_off=(0x0; 0x1))
4: (b7) r0 = 0                        ; R0=0
5: (b7) r0 = 1                        ; R0=1
"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 4);

    assert_eq!(insns[0].regs.get(&1).unwrap().reg_type, "ctx");
    assert_eq!(insns[0].regs.get(&10).unwrap().offset, Some(0));

    let range = insns[1].regs.get(&0).unwrap();
    assert_eq!(insns[1].kind, VerifierInsnKind::BranchDeltaState);
    assert_eq!(range.reg_type, "scalar");
    assert_eq!(range.range.smin, Some(0));
    assert_eq!(range.range.umax, Some(1));
    assert_eq!(range.exact_value, None);

    let zero = insns[2].regs.get(&0).unwrap();
    assert_eq!(zero.exact_u64(), Some(0));

    let one = insns[3].regs.get(&0).unwrap();
    assert_eq!(one.exact_u64(), Some(1));
}

#[test]
fn interprets_scalar_and_map_value_register_state() {
    let mut scalar = RegState::new("scalar", VerifierValueWidth::Bits64);
    scalar.range.smin = Some(0);
    scalar.range.smax = Some(63);
    scalar.range.umin = Some(0);
    scalar.range.umax = Some(63);
    assert_eq!(
        scalar_range_summary(&scalar),
        "scalar(smin=0,smax=63,umin=0,umax=63)"
    );
    assert_eq!(
        verifier_value_summary(&scalar),
        scalar_range_summary(&scalar)
    );
    assert_eq!(scalar_range_min_i64(&scalar), Some(0));
    assert_eq!(scalar_range_max_i64(&scalar), Some(63));
    assert!(scalar_range_has_any_bound(&scalar));
    assert!(scalar_range_may_include_zero(&scalar));
    assert!(!scalar_range_may_be_negative(&scalar));
    assert!(scalar_state_upper_bound_at_most(&scalar, 64));
    assert!(scalar_ranges_match(&scalar, &scalar));
    assert!(!scalar_range_upper_unbounded_or_too_large(&scalar));
    assert!(!scalar_range_is_unsafe(&scalar));

    let unknown = RegState::new("scalar", VerifierValueWidth::Bits64);
    assert_eq!(scalar_range_summary(&unknown), "scalar with unknown bounds");
    assert!(!scalar_ranges_match(&scalar, &unknown));
    assert!(scalar_range_may_include_zero(&unknown));
    assert!(scalar_range_may_be_negative(&unknown));
    assert!(scalar_range_upper_unbounded_or_too_large(&unknown));
    assert!(scalar_range_is_unsafe(&unknown));

    let mut map_value = RegState::new("map_value", VerifierValueWidth::Bits64);
    map_value.offset = Some(8);
    map_value.map_value_size = Some(16);
    map_value.range.umax = Some(12);
    assert_eq!(
        verifier_value_summary(&map_value),
        "map_value(off=8,value_size=16,range(umax=12))"
    );
    assert_eq!(map_value_remaining_capacity(&map_value, 16), Some(8));
    assert_eq!(map_value_variable_max_offset(&map_value), Some(12));
    assert!(map_value_access_range_may_exceed_value_size(&map_value, 1));
    assert!(map_value_range_may_exceed_value_size(&map_value));
}

#[test]
fn queries_latest_unsafe_scalar_and_nullable_state() {
    let log = r#"
0: R1=scalar(smin=-1,umax=5) R2=map_value_or_null(id=1,map=foo,ks=4,vs=8)
1: R1=1 R2=map_value(map=foo,ks=4,vs=8)
"#;

    let states = verifier_states_from_log(log).unwrap();
    let (pc, state) = latest_unsafe_scalar_state(&states, Some(1), 1).unwrap();
    assert_eq!(pc, 0);
    assert_eq!(state.range.smin, Some(-1));
    assert_eq!(
        latest_nullable_state(&states, Some(1), 2),
        Some((0, "map_value_or_null".to_string()))
    );
}

#[test]
fn parses_speculative_full_state_and_stack_spill() {
    let log = r#"
from 12 to 18 (speculative execution): frame1: R2_w=42 R10=fp0 fp-24=0000???? scalar(id=7,var_off=(0x2a; 0x0))
"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 1);

    let insn = &insns[0];
    assert_eq!(insn.kind, VerifierInsnKind::EdgeFullState);
    assert!(insn.speculative);
    assert_eq!(insn.frame, 1);

    let reg = insn.regs.get(&2).unwrap();
    assert_eq!(reg.value_width, VerifierValueWidth::Bits32);
    assert_eq!(reg.exact_u32(), Some(42));
    assert_eq!(reg.exact_u64(), None);

    let spill = insn.stack.get(&-24).unwrap();
    assert_eq!(spill.slot_types.as_deref(), Some("0000????"));
    let spilled_value = spill.value.as_ref().unwrap();
    assert_eq!(spilled_value.reg_type, "scalar");
    assert_eq!(spilled_value.id, Some(7));
    assert_eq!(
        spilled_value.tnum,
        Some(Tnum {
            value: 0x2a,
            mask: 0
        })
    );
    assert_eq!(spilled_value.exact_u64(), Some(42));
}

#[test]
fn parses_stack_access_suffixes_and_dynptr_stack_state() {
    let log = r#"
7: (85) call bpf_ringbuf_reserve_dynptr#198 ; R0_w=scalar() fp-16_w=dynptr_ringbuf(id=1,ref_id=2,dynptr_id=1) fp-8_r=0000???? fp-24_rw=0
8: (85) call bpf_local_irq_save#72094 ; fp-32_w=ffffffff refs=1
"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 2);

    let dynptr = insns[0]
        .stack
        .get(&-16)
        .and_then(|stack| stack.value.as_ref())
        .unwrap();
    assert_eq!(dynptr.reg_type, "dynptr_ringbuf");
    assert_eq!(dynptr.id, Some(1));
    assert_eq!(dynptr.ref_id, Some(2));

    assert_eq!(
        insns[0]
            .stack
            .get(&-8)
            .and_then(|stack| stack.slot_types.as_deref()),
        Some("0000????")
    );
    assert_eq!(
        insns[0]
            .stack
            .get(&-24)
            .and_then(|stack| stack.value.as_ref())
            .and_then(RegState::exact_u64),
        Some(0)
    );

    assert_eq!(
        insns[1]
            .stack
            .get(&-32)
            .and_then(|stack| stack.slot_types.as_deref()),
        Some("ffffffff")
    );
    assert!(insns[1].stack.get(&-32).unwrap().value.is_none());
    assert_eq!(insns[1].refs, Some(1));
    assert_eq!(insns[1].ref_ids, vec![1]);
}

#[test]
fn parses_frame_pointer_with_variable_offset_attributes() {
    let log = r#"
17: R4_w=fp(off=-32,smin=smin32=0,smax=umax=smax32=umax32=16,var_off=(0x0; 0x10))
"#;

    let insns = parse_verifier_log(log);
    let r4 = insns[0].regs.get(&4).unwrap();
    assert_eq!(r4.reg_type, "fp");
    assert_eq!(r4.offset, Some(-32));
    assert_eq!(r4.range.smin, Some(0));
    assert_eq!(r4.range.umax, Some(16));
    assert_eq!(r4.tnum.unwrap().mask, 0x10);
}

#[test]
fn preserves_cross_frame_pointer_source_frame() {
    let log = r#"
17: frame1: R1=fp[0]-16 R2=fp-16 R10=fp0 cb
"#;

    let insns = parse_verifier_log(log);
    let r1 = insns[0].regs.get(&1).unwrap();
    assert_eq!(r1.reg_type, "fp");
    assert_eq!(r1.offset, Some(-16));
    assert_eq!(r1.source_frame, Some(0));
    let r2 = insns[0].regs.get(&2).unwrap();
    assert_eq!(r2.reg_type, "fp");
    assert_eq!(r2.offset, Some(-16));
    assert_eq!(r2.source_frame, None);
}

#[test]
fn parses_standalone_stack_only_state_lines() {
    let log = r#"
8: fp-32_w=ffffffff refs=1
"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].pc, 8);
    assert_eq!(
        insns[0]
            .stack
            .get(&-32)
            .and_then(|stack| stack.slot_types.as_deref()),
        Some("ffffffff")
    );
    assert_eq!(insns[0].refs, Some(1));
}

#[test]
fn parses_packet_range_attribute() {
    let log = r#"
5: (2d) if r4 > r3 goto pc+14         ; R2_w=pkt(off=34,r=74) R4_w=pkt(off=74,r=74)
"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].regs.get(&2).unwrap().packet_range, Some(74));
    assert_eq!(insns[0].regs.get(&4).unwrap().packet_range, Some(74));
}

#[test]
fn parses_callback_state_tokens() {
    let log = r#"
	17: frame1: R1=scalar() R2=0 R10=fp0 refs=2 cb
	15: R1=map_ptr(map=hmap,ks=4,vs=16) R10=fp0 async_cb
	19: frame1: R1=scalar() R10=fp0 refs=bad cb
	20: (85) call bpf_local_irq_save#72094 ; frame1: refs=1,2
	21: refs=1,2,3 cb
	22: refs=0
	23: R1=ctx() refs=1,bad,2
	"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 7);
    assert_eq!(insns[0].log_line, 2);
    assert_eq!(insns[0].frame, 1);
    assert_eq!(insns[0].refs, Some(2));
    assert_eq!(insns[0].ref_ids, vec![2]);
    assert_eq!(insns[0].callback_kind, Some(CallbackKind::Sync));
    assert!(insns[0].callback);
    assert_eq!(insns[1].log_line, 3);
    assert_eq!(insns[1].refs, None);
    assert!(insns[1].ref_ids.is_empty());
    assert_eq!(insns[1].callback_kind, Some(CallbackKind::Async));
    assert!(insns[1].callback);
    assert_eq!(insns[2].log_line, 4);
    assert_eq!(insns[2].refs, None);
    assert!(insns[2].ref_ids.is_empty());
    assert_eq!(insns[2].callback_kind, Some(CallbackKind::Sync));
    assert!(insns[2].callback);
    assert_eq!(insns[3].log_line, 5);
    assert_eq!(insns[3].frame, 1);
    assert!(insns[3].regs.is_empty());
    assert!(insns[3].stack.is_empty());
    assert_eq!(insns[3].refs, Some(2));
    assert_eq!(insns[3].ref_ids, vec![1, 2]);
    assert_eq!(insns[4].log_line, 6);
    assert!(insns[4].regs.is_empty());
    assert!(insns[4].stack.is_empty());
    assert_eq!(insns[4].refs, Some(3));
    assert_eq!(insns[4].ref_ids, vec![1, 2, 3]);
    assert_eq!(insns[4].callback_kind, Some(CallbackKind::Sync));
    assert_eq!(insns[5].refs, Some(0));
    assert!(insns[5].ref_ids.is_empty());
    assert_eq!(insns[6].refs, None);
    assert!(insns[6].ref_ids.is_empty());
}

#[test]
fn distinguishes_exact_64bit_and_32bit_scalars() {
    let log = r#"
0: (b7) r3 = 42                       ; R3=42
1: (b4) w4 = 42                       ; R4_w=42
"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 2);

    let r3 = insns[0].regs.get(&3).unwrap();
    assert_eq!(r3.value_width, VerifierValueWidth::Bits64);
    assert_eq!(r3.exact_u64(), Some(42));
    assert_eq!(r3.exact_u32(), Some(42));

    let r4 = insns[1].regs.get(&4).unwrap();
    assert_eq!(r4.value_width, VerifierValueWidth::Bits32);
    assert_eq!(r4.exact_u64(), None);
    assert_eq!(r4.exact_u32(), Some(42));
}

#[test]
fn truncated_state_line_is_an_error() {
    let log = "\
0: R1=ctx() R10=fp0
1: (b7) r0 = 0                        ; R0=0
2: (07) r0 += 1                       ; R0=scalar(var_off=(0x1;
";

    let err = format!("{:#}", parse_verifier_log_result(log).unwrap_err());
    assert!(err.contains("failed to parse verifier state line 3"));
    assert!(err.contains("no register or stack state"));
}

#[test]
fn ignores_non_state_lines() {
    let log = r#"
0: (b7) r0 = 0
1: safe
from 2 to 7: safe
processed 4 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
"#;

    assert!(parse_verifier_log(log).is_empty());
}

#[test]
fn parses_frame_and_stack_tokens() {
    let log = r#"
3: frame1: R1=ctx() R2=fp-24 R10=fp0 fp-24=scalar(id=1) fp-32=0000???? fp-40=fp-56
"#;

    let insns = parse_verifier_log(log);
    assert_eq!(insns.len(), 1);
    let insn = &insns[0];
    assert_eq!(insn.pc, 3);
    assert_eq!(insn.frame, 1);
    assert_eq!(insn.regs.get(&2).unwrap().reg_type, "fp");
    assert_eq!(insn.regs.get(&2).unwrap().offset, Some(-24));

    let fp24 = insn.stack.get(&-24).unwrap();
    assert_eq!(fp24.slot_types, None);
    assert_eq!(fp24.value.as_ref().unwrap().reg_type, "scalar");

    let fp32 = insn.stack.get(&-32).unwrap();
    assert_eq!(fp32.slot_types.as_deref(), Some("0000????"));
    assert!(fp32.value.is_none());

    let fp40 = insn.stack.get(&-40).unwrap();
    assert_eq!(fp40.value.as_ref().unwrap().reg_type, "fp");
    assert_eq!(fp40.value.as_ref().unwrap().offset, Some(-56));
}
