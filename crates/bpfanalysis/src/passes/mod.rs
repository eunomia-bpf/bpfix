//! Minimal pass registry surface required by the analysis crate.
//!
//! `bpfanalysis` imports the CFG/verifier analysis code from `bpfopt` without
//! importing every optimizer pass. The analysis layer only needs pass metadata,
//! map-inline side-input types, and the kinsn descriptors used by CFG liveness.

pub mod map_inline;

use crate::pass::{kinsn_payload_reg, no_regs, regs_from_offsets, KinsnDescriptor, RegSet};

#[derive(Clone, Copy, Debug)]
pub struct PassRegistryEntry {
    pub kinsn_targets: &'static [&'static KinsnDescriptor],
}

static BPF_X86_MOVB: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_movb",
    register_uses: x86_mov_register_uses,
    register_defs: x86_mov_register_defs,
};
static BPF_X86_MOVW: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_movw",
    register_uses: x86_mov_register_uses,
    register_defs: x86_mov_register_defs,
};
static BPF_X86_MOVL: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_movl",
    register_uses: x86_mov_register_uses,
    register_defs: x86_mov_register_defs,
};
static BPF_X86_MOVQ: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_movq",
    register_uses: x86_mov_register_uses,
    register_defs: x86_mov_register_defs,
};
static BPF_X86_MOVZBL: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_movzbl",
    register_uses: x86_mov_register_uses,
    register_defs: x86_mov_register_defs,
};
static BPF_X86_MOVZWL: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_movzwl",
    register_uses: x86_mov_register_uses,
    register_defs: x86_mov_register_defs,
};
static BPF_X86_MOVSWL: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_movswl",
    register_uses: x86_mov_register_uses,
    register_defs: x86_mov_register_defs,
};
static BPF_X86_MOVSXD: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_movsxd",
    register_uses: x86_mov_register_uses,
    register_defs: x86_mov_register_defs,
};
static BPF_ARM64_MOV_X: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_arm64_mov_x",
    register_uses: arm64_mov_register_uses,
    register_defs: arm64_mov_register_defs,
};

static BPF_X86_TESTQ: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_testq",
    register_uses: x86_test_register_uses,
    register_defs: no_regs,
};
static BPF_X86_CMOVNEQ: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_cmovneq",
    register_uses: x86_cmov_register_uses,
    register_defs: cond_select_register_defs,
};
static BPF_X86_CMOVEQ: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_cmoveq",
    register_uses: x86_cmov_register_uses,
    register_defs: cond_select_register_defs,
};
static BPF_ARM64_TST: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_arm64_tst",
    register_uses: test_register_uses,
    register_defs: no_regs,
};
static BPF_ARM64_CSEL_NE: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_arm64_csel_ne",
    register_uses: cond_select_register_uses,
    register_defs: cond_select_register_defs,
};

static BPF_X86_LEAQ: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_leaq",
    register_uses: lea_register_uses,
    register_defs: lea_register_defs,
};
static BPF_X86_LEAL: KinsnDescriptor = KinsnDescriptor {
    name: "bpf_x86_leal",
    register_uses: lea_register_uses,
    register_defs: lea_register_defs,
};

pub const COMMON_KINSN_TARGETS: &[&KinsnDescriptor] = &[
    &BPF_X86_MOVB,
    &BPF_X86_MOVW,
    &BPF_X86_MOVL,
    &BPF_X86_MOVQ,
    &BPF_X86_MOVZBL,
    &BPF_X86_MOVZWL,
    &BPF_X86_MOVSWL,
    &BPF_X86_MOVSXD,
    &BPF_ARM64_MOV_X,
];

const COND_SELECT_KINSN_TARGETS: &[&KinsnDescriptor] = &[
    &BPF_X86_TESTQ,
    &BPF_X86_CMOVNEQ,
    &BPF_X86_CMOVEQ,
    &BPF_ARM64_TST,
    &BPF_ARM64_CSEL_NE,
];

const LEA_KINSN_TARGETS: &[&KinsnDescriptor] = &[&BPF_X86_LEAQ, &BPF_X86_LEAL];

pub const PASS_REGISTRY: &[PassRegistryEntry] = &[
    PassRegistryEntry {
        kinsn_targets: COND_SELECT_KINSN_TARGETS,
    },
    PassRegistryEntry {
        kinsn_targets: LEA_KINSN_TARGETS,
    },
];

fn arm64_mov_register_uses(payload: u64) -> RegSet {
    regs_from_offsets(payload, &[4])
}

fn arm64_mov_register_defs(payload: u64) -> RegSet {
    regs_from_offsets(payload, &[0])
}

fn x86_mov_register_uses(payload: u64) -> RegSet {
    match payload & 0xf {
        1 => regs_from_offsets(payload, &[8]),
        4 => regs_from_offsets(payload, &[8]),
        5 => regs_from_offsets(payload, &[8, 12]),
        6 => regs_from_offsets(payload, &[4, 8]),
        7 => regs_from_offsets(payload, &[4]),
        _ => RegSet::new(),
    }
}

fn x86_mov_register_defs(payload: u64) -> RegSet {
    match payload & 0xf {
        1 | 4 | 5 => regs_from_offsets(payload, &[4]),
        _ => RegSet::new(),
    }
}

fn test_register_uses(payload: u64) -> RegSet {
    regs_from_offsets(payload, &[0])
}

fn x86_test_register_uses(payload: u64) -> RegSet {
    regs_from_offsets(payload, &[4])
}

fn cond_select_register_uses(payload: u64) -> RegSet {
    regs_from_offsets(payload, &[4, 8, 12])
}

fn x86_cmov_register_uses(payload: u64) -> RegSet {
    regs_from_offsets(payload, &[0, 4, 8])
}

fn cond_select_register_defs(payload: u64) -> RegSet {
    regs_from_offsets(payload, &[0])
}

fn lea_register_uses(payload: u64) -> RegSet {
    let mut regs = RegSet::new();
    if ((payload >> 15) & 1) != 0 {
        regs.insert(kinsn_payload_reg(payload, 4));
    }
    if ((payload >> 14) & 1) != 0 {
        regs.insert(kinsn_payload_reg(payload, 8));
    }
    regs
}

fn lea_register_defs(payload: u64) -> RegSet {
    regs_from_offsets(payload, &[0])
}
