//! Instructions of the console's CPU that a translator does not run, done in software – what
//! `insn` (the instructions a PC CPU lacks, emulated a trap at a time) does not cover.
//!
//! Rosetta 2 raises an illegal-instruction fault for ADX (ADCX/ADOX), RDSEED, SSE4a
//! (INSERTQ/EXTRQ/MOVNTSS/MOVNTSD), CLWB, CLZERO and MONITORX/MWAITX. `insn` emulates the
//! AMD-only ones; ADX and RDSEED every PC CPU has, and MOVNTSS/MOVNTSD it does not know: those
//! are emulated here. A trap under a translator costs tens of microseconds, so the sites that
//! run in loops (ADX, INSERTQ with immediates, the CLZERO loops) are redirected to helpers.
//! This module holds the parts that do not depend on Windows, so they are tested natively
//! (`cargo test`, also as an x86-64 binary under Rosetta itself):
//!
//! * `decode` – exactly the encodings the title uses, plus the memory forms of the same
//!   opcodes: legacy prefixes, REX, ModRM/SIB/displacement, RIP-relative.
//! * `exec` – one instruction against a register file (`Cpu`): the trap-per-use path.
//! * `thunk` – a helper in host-runnable code for a faulting site of at least five bytes,
//!   which the caller redirects with `call rel32`: a trap costs tens of microseconds, so a
//!   site that runs in a loop must trap only once.
//!
//! No allocation and no panicking path: all of it runs inside an exception handler.

/// The registers an instruction reads and writes. GPR numbers are the hardware's:
/// 0 RAX, 1 RCX, 2 RDX, 3 RBX, 4 RSP, 5 RBP, 6 RSI, 7 RDI, 8–15 R8–R15.
pub trait Cpu {
    fn gpr(&self, i: u8) -> u64;
    fn set_gpr(&mut self, i: u8, v: u64);
    fn rip(&self) -> u64;
    fn set_rip(&mut self, v: u64);
    fn flags(&self) -> u32;
    fn set_flags(&mut self, v: u32);
    /// XMM register `i` as (low, high) quadword.
    fn xmm(&self, i: u8) -> (u64, u64);
    fn set_xmm(&mut self, i: u8, v: (u64, u64));
    /// 64 random bits for RDSEED; `None`: no entropy now (the instruction then clears CF).
    fn random(&mut self) -> Option<u64>;
}

pub const CF: u32 = 1 << 0;
pub const PF: u32 = 1 << 2;
pub const AF: u32 = 1 << 4;
pub const ZF: u32 = 1 << 6;
pub const SF: u32 = 1 << 7;
pub const OF: u32 = 1 << 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// 66 0F 38 F6 /r: dest = dest + src + CF, only CF changes.
    Adcx,
    /// F3 0F 38 F6 /r: dest = dest + src + OF, only OF changes.
    Adox,
    /// 0F C7 /7 (register): hardware random number, CF = 1 when one was delivered.
    Rdseed,
    /// F3 0F 2B /r (memory): store the low 4 bytes of an XMM register.
    Movntss,
    /// F2 0F 2B /r (memory): store the low 8 bytes of an XMM register.
    Movntsd,
    /// F2 0F 78 /r ib ib (registers): insert a bit field of the source's low quadword.
    InsertqImm,
    /// 0F 01 FC: zero the 64-byte line at RAX. Only `thunk` knows it (with the instruction
    /// that follows); `decode` leaves the lone instruction to the caller.
    Clzero,
}

impl Op {
    pub fn name(self) -> &'static str {
        match self {
            Op::Adcx => "ADCX",
            Op::Adox => "ADOX",
            Op::Rdseed => "RDSEED",
            Op::Movntss => "MOVNTSS",
            Op::Movntsd => "MOVNTSD",
            Op::InsertqImm => "INSERTQ",
            Op::Clzero => "CLZERO",
        }
    }
}

/// The r/m operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rm {
    Reg(u8),
    /// base + index * 2^scale + disp, or next RIP + disp (`rip`).
    Mem { base: Option<u8>, index: Option<u8>, scale: u8, disp: i32, rip: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub op: Op,
    /// Length in bytes, prefixes included.
    pub len: u8,
    /// Operand size in bytes: 8 with REX.W, else 4 (RDSEED with 66: 2).
    pub size: u8,
    /// The ModRM `reg` operand (with REX.R): destination of ADX/INSERTQ, source of MOVNTS*.
    pub reg: u8,
    pub rm: Rm,
    /// INSERTQ: field length and bit index.
    pub imm: [u8; 2],
}

fn le32(c: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes([*c.get(at)?, *c.get(at + 1)?, *c.get(at + 2)?, *c.get(at + 3)?]))
}

/// Decodes one instruction at the start of `c` (`None`: not one of ours, or cut short).
/// FS/GS overrides, 32-bit addressing (67) and LOCK are declined: no site in the title has
/// them, and a wrong effective address is worse than the unhandled fault.
pub fn decode(c: &[u8]) -> Option<Insn> {
    let (mut i, mut p66, mut pf2, mut pf3) = (0usize, false, false, false);
    loop {
        match *c.get(i)? {
            0x66 => p66 = true,
            0xF2 => pf2 = true,
            0xF3 => pf3 = true,
            0x26 | 0x2E | 0x36 | 0x3E => {} // ES/CS/SS/DS: no effect in 64-bit mode
            _ => break,
        }
        i += 1;
        if i > 4 {
            return None;
        }
    }
    let mut rex = 0u8;
    if *c.get(i)? & 0xF0 == 0x40 {
        rex = *c.get(i)?;
        i += 1;
    }
    if *c.get(i)? != 0x0F {
        return None;
    }
    let wide = rex & 8 != 0;
    let mut size = if wide { 8 } else { 4 };
    let op = match (*c.get(i + 1)?, p66, pf2, pf3) {
        (0x38, true, false, false) if *c.get(i + 2)? == 0xF6 => Op::Adcx,
        (0x38, false, false, true) if *c.get(i + 2)? == 0xF6 => Op::Adox,
        (0xC7, _, false, false) => {
            if p66 && !wide {
                size = 2;
            }
            Op::Rdseed
        }
        (0x2B, _, false, true) => Op::Movntss,
        (0x2B, _, true, false) => Op::Movntsd,
        (0x78, false, true, false) => Op::InsertqImm,
        _ => return None,
    };
    i += if matches!(op, Op::Adcx | Op::Adox) { 3 } else { 2 };
    let m = *c.get(i)?;
    i += 1;
    let (md, rm3) = (m >> 6, m & 7);
    let reg = ((m >> 3) & 7) | ((rex & 4) << 1);
    let rm = if md == 3 {
        Rm::Reg(rm3 | ((rex & 1) << 3))
    } else {
        let (mut base, mut index, mut scale, mut rip) = (None, None, 0, false);
        let mut disp_len = match md {
            1 => 1,
            2 => 4,
            _ => 0,
        };
        if rm3 == 4 {
            let sib = *c.get(i)?;
            i += 1;
            scale = sib >> 6;
            let ix = ((sib >> 3) & 7) | ((rex & 2) << 2);
            if ix != 4 {
                index = Some(ix); // index 4 without REX.X: none (R12 is a valid index)
            }
            if sib & 7 == 5 && md == 0 {
                disp_len = 4; // disp32 without a base
            } else {
                base = Some((sib & 7) | ((rex & 1) << 3));
            }
        } else if rm3 == 5 && md == 0 {
            rip = true;
            disp_len = 4;
        } else {
            base = Some(rm3 | ((rex & 1) << 3));
        }
        let disp = match disp_len {
            1 => *c.get(i)? as i8 as i32,
            4 => le32(c, i)?,
            _ => 0,
        };
        i += disp_len;
        Rm::Mem { base, index, scale, disp, rip }
    };
    let mut imm = [0u8; 2];
    let is_reg = matches!(rm, Rm::Reg(_));
    match op {
        Op::Adcx | Op::Adox => {}
        // /7 with a register; with F3 it is RDPID, with memory VMPTRST: neither is ours
        Op::Rdseed if is_reg && (m >> 3) & 7 == 7 => {}
        Op::Movntss | Op::Movntsd if !is_reg => {}
        Op::InsertqImm if is_reg => {
            imm = [*c.get(i)?, *c.get(i + 1)?];
            i += 2;
        }
        _ => return None,
    }
    if i > 15 {
        return None;
    }
    Some(Insn { op, len: i as u8, size, reg, rm, imm })
}

/// a + b + carry at 64 or 32 bits: (sum, carry out). A 32-bit sum is zero-extended, as a
/// write to a 32-bit register is.
pub fn add_carry(a: u64, b: u64, carry: bool, wide: bool) -> (u64, bool) {
    if wide {
        let (s, c1) = a.overflowing_add(b);
        let (s, c2) = s.overflowing_add(carry as u64);
        (s, c1 | c2)
    } else {
        let s = (a & 0xFFFF_FFFF) + (b & 0xFFFF_FFFF) + carry as u64;
        (s & 0xFFFF_FFFF, s >> 32 != 0)
    }
}

/// INSERTQ's field: `len` bits (0 stands for 64) from bit `idx`, cut off at bit 63.
fn insert_mask(len: u8, idx: u8) -> u64 {
    let ones = if len & 63 == 0 { u64::MAX } else { (1u64 << (len & 63)) - 1 };
    ones << (idx & 63)
}

unsafe fn address<C: Cpu>(c: &C, rm: Rm, next: u64) -> Option<u64> {
    let Rm::Mem { base, index, scale, disp, rip } = rm else { return None };
    let mut a = disp as i64 as u64;
    if rip {
        a = a.wrapping_add(next);
    }
    if let Some(b) = base {
        a = a.wrapping_add(c.gpr(b));
    }
    if let Some(x) = index {
        a = a.wrapping_add(c.gpr(x) << (scale & 3));
    }
    Some(a)
}

/// Runs `insn` on `c` and moves RIP past it. Declines memory operations when the
/// supplied check cannot establish access to the entire operand.
///
/// # Safety
/// Dereferences the instruction's memory operand after the caller's access check.
pub unsafe fn exec<C: Cpu>(
    insn: &Insn, c: &mut C, accessible: impl FnOnce(usize, usize, bool) -> bool,
) -> bool {
    let next = c.rip().wrapping_add(insn.len as u64);
    match insn.op {
        Op::Adcx | Op::Adox => {
            let wide = insn.size == 8;
            let src = match insn.rm {
                Rm::Reg(r) => c.gpr(r),
                rm => {
                    let Some(a) = address(c, rm, next) else { return false };
                    if !accessible(a as usize, if wide { 8 } else { 4 }, false) {
                        return false;
                    }
                    if wide {
                        (a as *const u64).read_unaligned()
                    } else {
                        (a as *const u32).read_unaligned() as u64
                    }
                }
            };
            let bit = if insn.op == Op::Adcx { CF } else { OF };
            let f = c.flags();
            let (sum, carry) = add_carry(c.gpr(insn.reg), src, f & bit != 0, wide);
            c.set_gpr(insn.reg, sum);
            c.set_flags(if carry { f | bit } else { f & !bit });
        }
        Op::Rdseed => {
            let Rm::Reg(r) = insn.rm else { return false };
            let v = c.random();
            let x = v.unwrap_or(0);
            c.set_gpr(
                r,
                match insn.size {
                    8 => x,
                    4 => x & 0xFFFF_FFFF,
                    _ => (c.gpr(r) & !0xFFFF) | (x & 0xFFFF), // a 16-bit write keeps the rest
                },
            );
            let f = c.flags() & !(CF | OF | SF | ZF | AF | PF);
            c.set_flags(if v.is_some() { f | CF } else { f });
        }
        Op::Movntss | Op::Movntsd => {
            let Some(a) = address(c, insn.rm, next) else { return false };
            let bytes = if insn.op == Op::Movntss { 4 } else { 8 };
            if !accessible(a as usize, bytes, true) {
                return false;
            }
            let low = c.xmm(insn.reg).0;
            if bytes == 4 {
                (a as *mut u32).write_unaligned(low as u32);
            } else {
                (a as *mut u64).write_unaligned(low);
            }
        }
        // emulated by `eh::emulate_console_only` (`insn`); here they are only redirected (`thunk`)
        Op::InsertqImm | Op::Clzero => return false,
    }
    c.set_rip(next);
    true
}

/// Largest helper `thunk` writes.
pub const THUNK_MAX: usize = 96;
/// Bytes kept for one ADX helper: they are shared by all sites with the same operands.
pub const ADX_SLOT: usize = 32;
/// Number of ADX helpers: (ADOX, REX.W, destination, source).
pub const ADX_SLOTS: usize = 1024;

/// A helper for a faulting site, to be reached by `call rel32` written over the site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thunk {
    /// Bytes of the site the helper stands for (5..=8): the call, then NOPs.
    pub site_len: u8,
    /// Bytes of helper code (and constants) in the buffer.
    pub len: u8,
    /// ADX: index of the shared helper slot.
    pub slot: Option<u16>,
    pub op: Op,
}

struct Emit<'a> {
    out: &'a mut [u8; THUNK_MAX],
    n: usize,
}

impl Emit<'_> {
    fn put(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if let Some(o) = self.out.get_mut(self.n) {
                *o = b;
            }
            self.n += 1;
        }
    }
}

/// Writes position-independent host code into `out` that does what the instruction(s) at
/// the start of `c` do, ending in RET, and says how many site bytes it replaces. The helper
/// is entered by a CALL from the site, so it sees RSP 8 lower: operands that use RSP are
/// declined, as is everything `exec` would not take over exactly. It must be placed at an
/// address that is a multiple of 16 (INSERTQ helpers carry aligned constants).
///
/// * ADCX/ADOX r, r: the flags are saved, ADC runs with CF (or OF copied into CF), and only
///   the carry out is merged into the saved flags.
/// * INSERTQ xmm, xmm, len, idx: shift/AND/OR with one spilled XMM register; no flag changes.
/// * CLZERO followed by `add rax, 0x40` or `cmp r64, r64` (the title's zeroing loops; CLZERO
///   alone is three bytes, too short for a call): eight stores, then the second instruction,
///   whose flags are the ones the loop branch reads.
pub fn thunk(c: &[u8], out: &mut [u8; THUNK_MAX]) -> Option<Thunk> {
    let mut e = Emit { out, n: 0 };
    if let [0x0F, 0x01, 0xFC, tail @ ..] = c {
        let t = match tail {
            [0x48, 0x83, 0xC0, 0x40, ..] => 4,
            // cmp r/m64, r64 or cmp r64, r/m64 between registers other than RSP
            [rex, 0x39 | 0x3B, m, ..] if rex & 0xF8 == 0x48 && m >> 6 == 3 && (m & 7 != 4 || rex & 1 != 0) && ((m >> 3) & 7 != 4 || rex & 4 != 0) => 3,
            _ => return None,
        };
        e.put(&[0x50, 0x48, 0x83, 0xE0, 0xC0]); // push rax; and rax, -64
        for d in 0..8u8 {
            e.put(&[0x48, 0xC7, 0x40, d * 8, 0, 0, 0, 0]); // mov qword [rax + d*8], 0
        }
        e.put(&[0x58]); // pop rax
        e.put(tail.get(..t)?);
        e.put(&[0xC3]);
        return Some(Thunk { site_len: 3 + t as u8, len: e.n as u8, slot: None, op: Op::Clzero });
    }
    let i = decode(c)?;
    let Rm::Reg(src) = i.rm else { return None };
    if !(5..=8).contains(&i.len) {
        return None;
    }
    match i.op {
        Op::Adcx | Op::Adox if i.reg != 4 && src != 4 => {
            let adox = i.op == Op::Adox;
            let wide = i.size == 8;
            e.put(&[0x9C]); // pushfq (changes no flag: CF is still the incoming carry)
            if adox {
                e.put(&[0x0F, 0xBA, 0x24, 0x24, 0x0B]); // bt dword [rsp], 11: CF = saved OF
            }
            let rex = 0x40 | (wide as u8) << 3 | (i.reg >> 3) << 2 | (src >> 3);
            if rex != 0x40 {
                e.put(&[rex]);
            }
            e.put(&[0x13, 0xC0 | (i.reg & 7) << 3 | (src & 7)]); // adc dest, src
            if adox {
                // jc +7; and byte [rsp+1], ~8; popfq; ret;  or byte [rsp+1], 8; popfq; ret
                e.put(&[0x72, 0x07, 0x80, 0x64, 0x24, 0x01, 0xF7, 0x9D, 0xC3, 0x80, 0x4C, 0x24, 0x01, 0x08, 0x9D, 0xC3]);
            } else {
                // jc +6; and byte [rsp], ~1; popfq; ret;  or byte [rsp], 1; popfq; ret
                e.put(&[0x72, 0x06, 0x80, 0x24, 0x24, 0xFE, 0x9D, 0xC3, 0x80, 0x0C, 0x24, 0x01, 0x9D, 0xC3]);
            }
            let slot = (adox as u16) << 9 | (wide as u16) << 8 | (i.reg as u16) << 4 | src as u16;
            Some(Thunk { site_len: i.len, len: e.n as u8, slot: Some(slot), op: i.op })
        }
        Op::InsertqImm => {
            let d = i.reg;
            // a scratch register that is neither operand
            let t = if d != 0 && src != 0 {
                0u8
            } else if d != 1 && src != 1 {
                1
            } else {
                2
            };
            const MASK_AT: usize = 64; // then the inverted mask at +16
            let field = insert_mask(i.imm[0], i.imm[1]);
            e.put(&[0x48, 0x8D, 0x64, 0x24, 0xF0]); // lea rsp, [rsp-16]
            e.put(&[0xF3, 0x0F, 0x7F, 0x04 | t << 3, 0x24]); // movdqu [rsp], xmmT
            if src >= 8 {
                e.put(&[0x41]);
            }
            e.put(&[0x0F, 0x28, 0xC0 | t << 3 | (src & 7)]); // movaps xmmT, xmmS
            e.put(&[0x66, 0x0F, 0x73, 0xF0 | t, i.imm[1] & 63]); // psllq xmmT, idx
            e.put(&[0x66, 0x0F, 0xDB, 0x05 | t << 3]); // pand xmmT, [rip + mask]
            let rel = (MASK_AT as i32) - (e.n as i32 + 4);
            e.put(&rel.to_le_bytes());
            e.put(&[0x66]);
            if d >= 8 {
                e.put(&[0x44]);
            }
            e.put(&[0x0F, 0xDB, 0x05 | (d & 7) << 3]); // pand xmmD, [rip + !mask]
            let rel = (MASK_AT as i32 + 16) - (e.n as i32 + 4);
            e.put(&rel.to_le_bytes());
            e.put(&[0x66]);
            if d >= 8 {
                e.put(&[0x44]);
            }
            e.put(&[0x0F, 0xEB, 0xC0 | (d & 7) << 3 | t]); // por xmmD, xmmT
            e.put(&[0xF3, 0x0F, 0x6F, 0x04 | t << 3, 0x24]); // movdqu xmmT, [rsp]
            e.put(&[0x48, 0x8D, 0x64, 0x24, 0x10, 0xC3]); // lea rsp, [rsp+16]; ret
            if e.n > MASK_AT {
                return None;
            }
            while e.n < MASK_AT {
                e.put(&[0xCC]);
            }
            e.put(&field.to_le_bytes());
            e.put(&[0; 8]);
            e.put(&(!field).to_le_bytes());
            e.put(&[0; 8]); // the destination's high quadword is zeroed, as `insn` has it (a Zen 5 does)
            Some(Thunk { site_len: i.len, len: e.n as u8, slot: None, op: i.op })
        }
        _ => None,
    }
}

/// The bytes that replace a site of `site_len` bytes at `site`: `call helper`, then NOPs.
/// `None`: the helper is out of the call's ±2 GiB reach or the site is too short.
pub fn call_site(site: u64, site_len: u8, helper: u64) -> Option<[u8; 8]> {
    if !(5..=8).contains(&site_len) {
        return None;
    }
    let rel = i32::try_from(helper.wrapping_sub(site.wrapping_add(5)) as i64).ok()?;
    let mut b = [0x90u8; 8];
    b[0] = 0xE8;
    b[1..5].copy_from_slice(&rel.to_le_bytes());
    Some(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encodings upstream's `insn` does not emulate are decoded here: ADCX / ADOX, RDSEED,
    /// MOVNTSS / MOVNTSD; RDPID (F3 0F C7 /7) is left to `insn`.
    #[test]
    fn decodes_what_only_a_translator_lacks() {
        // adcx rax, rcx (66 48 0F 38 F6 C1); adox r8d, r9d (F3 45 0F 38 F6 C1)
        let i = decode(&[0x66, 0x48, 0x0F, 0x38, 0xF6, 0xC1]).unwrap();
        assert_eq!((i.op, i.len, i.size, i.reg, i.rm), (Op::Adcx, 6, 8, 0, Rm::Reg(1)));
        let i = decode(&[0xF3, 0x45, 0x0F, 0x38, 0xF6, 0xC1]).unwrap();
        assert_eq!((i.op, i.len, i.size, i.reg, i.rm), (Op::Adox, 6, 4, 8, Rm::Reg(9)));
        // rdseed rax (48 0F C7 F8); movntss [rax + 8], xmm1 (F3 0F 2B 48 08)
        assert_eq!(decode(&[0x48, 0x0F, 0xC7, 0xF8]).map(|i| (i.op, i.size)), Some((Op::Rdseed, 8)));
        let i = decode(&[0xF3, 0x0F, 0x2B, 0x48, 0x08]).unwrap();
        assert_eq!((i.op, i.len, i.reg, i.rm), (Op::Movntss, 5, 1, Rm::Mem { base: Some(0), index: None, scale: 0, disp: 8, rip: false }));
        assert_eq!(decode(&[0xF3, 0x0F, 0xC7, 0xF8]), None, "RDPID is `insn`'s");
        assert_eq!(decode(&[0x0F, 0x01, 0xFC]), None, "a lone CLZERO is `insn`'s");
        assert_eq!(add_carry(u64::MAX, 0, true, true), (0, true));
        assert_eq!(add_carry(0xFFFF_FFFF, 1, false, false), (0, true));
    }

    /// INSERTQ's helper: the field mask and its complement as aligned constants, the high
    /// quadword zeroed (as `insn::insertq`'s caller does), and a call that reaches it.
    #[test]
    fn insertq_helper_zeroes_the_high_quadword() {
        // insertq xmm0, xmm1, 8, 16 (F2 0F 78 C1 08 10)
        let mut out = [0u8; THUNK_MAX];
        let t = thunk(&[0xF2, 0x0F, 0x78, 0xC1, 0x08, 0x10], &mut out).unwrap();
        assert_eq!((t.op, t.site_len, t.len as usize, t.slot), (Op::InsertqImm, 6, 96, None));
        let q = |at: usize| u64::from_le_bytes(out[at..at + 8].try_into().unwrap());
        assert_eq!([q(64), q(72), q(80), q(88)], [0xFF_0000, 0, !0xFF_0000, 0]);
        assert_eq!(*out[..64].iter().rev().find(|&&b| b != 0xCC).unwrap(), 0xC3, "the code ends in ret");
        let call = call_site(0x1000, t.site_len, 0x2000).unwrap();
        assert_eq!(call[..6], [0xE8, 0xFB, 0x0F, 0x00, 0x00, 0x90]);
        assert_eq!(call_site(0x1000, 3, 0x2000), None, "too short for a call");
        // the CLZERO loop's site: clzero; add rax, 0x40 – seven bytes, eight stores
        let t = thunk(&[0x0F, 0x01, 0xFC, 0x48, 0x83, 0xC0, 0x40], &mut out).unwrap();
        assert_eq!((t.op, t.site_len), (Op::Clzero, 7));
    }
}
