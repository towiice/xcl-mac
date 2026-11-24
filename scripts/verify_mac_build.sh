#!/usr/bin/env bash
# ==============================================================================
# XCL Mac Native Build Verification Script
# Verifies that all host-compatibility patches, hardware emulations,
# and performance subsystems are properly consolidated in the mac-native branch.
# ==============================================================================

set -euo pipefail

PASS=0
FAIL=0

check() {
    local desc="$1"
    local cmd="$2"
    printf "Checking: %-60s " "$desc"
    if eval "$cmd" > /dev/null 2>&1; then
        printf "[\033[0;32mPASS\033[0m]\n"
        PASS=$((PASS + 1))
    else
        printf "[\033[0;31mFAIL\033[0m]\n"
        FAIL=$((FAIL + 1))
    fi
}

echo "======================================================================"
echo "          XCL Mac Native Build Subsystem Verification                 "
echo "======================================================================"

# 1. Architecture & D3DMetal COM Vtable Prefix
check "D3DMetal COM vtable prefix mirroring (PREFIX = 16)" \
    "grep -q 'PREFIX: usize = 16;' crates/xcl/src/hle/d3d12x/real.rs"

check "Extended vtable test fixture (test_ext_table)" \
    "grep -q 'fn test_ext_table' crates/xcl/src/hle/d3d12x/real.rs"

# 2. Shader Recompiler & Stand-in Blending
check "Stand-in PS dual-source blending (SV_Target0 + SV_Target1)" \
    "grep -q 'SV_Target0.*SV_Target1' crates/xcl/src/hle/d3d12x/real.rs"

check "D3DMetal shader refusal host fallback (refused_on_mac_host)" \
    "grep -q 'refused_on_mac_host' crates/xcl/src/hle/d3d12x/real.rs"

check "Compute blob cache charging fix (insert_compute_blob)" \
    "grep -q 'insert_compute_blob' crates/xcl/src/hle/d3d12x/real.rs"

# 3. CPU Emulation & Rosetta 2 Support
check "Rosetta missing AMD instruction handlers (CLZERO, INSERTQ)" \
    "grep -q 'clzero' crates/xcl/src/isa.rs && grep -q 'insertq' crates/xcl/src/isa.rs"

check "Rosetta AVX masked store decoder module (crates/xcl/src/maskmov.rs)" \
    "test -f crates/xcl/src/maskmov.rs && grep -q 'pub mod maskmov' crates/xcl/src/lib.rs"

check "Rosetta masked store fault helper patching (replace_masked_stores)" \
    "grep -q 'replace_masked_stores' crates/xcl/src/loader.rs"

check "Rosetta CPU detection (util::rosetta)" \
    "grep -q 'pub fn rosetta' crates/xcl/src/util.rs"

# 4. Memory Architecture & UMA Shadow Copier
check "UMA Shadowed fallback implementation (OpenExistingHeapFromAddress)" \
    "grep -q 'pub fn shadowed' crates/xcl/src/gpu/uma.rs"

check "UMA note_copy_into for readback buffers" \
    "grep -q 'note_copy_into' crates/xcl/src/hle/d3d12x/list_x.rs"

check "GPU-visible fallback write-watch disable (XCL_WATCHED_FALLBACK)" \
    "grep -q 'watched_fallback' crates/xcl/src/hle/kernelx.rs"

check "Command queue #31 GPU view page mappings (gpu_views)" \
    "test -f crates/xcl/src/hle/d3d12x/gpu_views.rs && grep -q 'gpu_views' crates/xcl/src/hle/d3d12x/mod.rs"

check "Unwatched title textures content comparison (poll_unwatched)" \
    "grep -q 'poll_unwatched' crates/xcl/src/hle/d3d12x/title_textures.rs"

check "Unchanged title texture upload skip override (XCL_TEXTURE_SKIP_UNCHANGED)" \
    "grep -q 'XCL_TEXTURE_SKIP_UNCHANGED' crates/xcl/src/hle/d3d12x/title_textures.rs"

check "CopyMemoryToMemoryX CPU fallback for non-UMA ranges" \
    "grep -q 'CopyMemoryToMemoryX' crates/xcl/src/hle/d3d12x/cpu_writes.rs"

# 5. D3DMetal Depth & Stencil
check "D3DMetal depth-only format mapping (pc_depth_view_format)" \
    "grep -q 'depth_only_format' crates/xcl/src/hle/d3d12x/device_x.rs"

# 6. Wine & Mac Host Basics
check "Mac host utility detection (util::mac_host)" \
    "grep -q 'pub fn mac_host' crates/xcl/src/util.rs"

check "Wine isolated thread heap for DXC (own_heaps)" \
    "grep -q 'own_heaps' crates/xcl/src/gpu/recomp/dxc.rs"

check "Network isolation default off (netoff)" \
    "test -f crates/xcl/src/hle/netoff.rs && grep -q 'mod netoff' crates/xcl/src/hle/mod.rs"

check "16 MiB title stacks under Wine" \
    "grep -q '16 << 20' crates/xcl/src/hle/kernelx.rs"

# 7. Stage 6 Ingame Mechanics & Subsystems
check "Sparse buffer lock safety (try_lock in forget_buffer)" \
    "grep -q 'try_lock' crates/xcl/src/hle/d3d12x/sparse.rs && grep -q 'forget_gone' crates/xcl/src/hle/d3d12x/sparse.rs"

check "World-load watchdog & fatal crash bypass at 0x23cf683" \
    "grep -q '0x4d8bd421' crates/xcl/src/eh.rs"

check "DirectStorage BCPack acceptance (XCL_DSTORAGE_BCPACK_ACCEPT)" \
    "grep -q 'bcpack_accept' crates/xcl/src/hle/dstorage.rs"

check "Mesh root-argument layout (user_data_ms, inline_ms)" \
    "grep -q 'user_data_ms' crates/xcl/src/hle/d3d12x/console_list.rs"

check "Mesh companion DISPATCH signature creation" \
    "grep -q 'note_dispatch_mesh_signature' crates/xcl/src/hle/d3d12x/device_x.rs"

check "Real D3D12 DispatchMesh hooking (slot 127 / newer 129)" \
    "grep -q '127, b::dispatch_mesh' crates/xcl/src/hle/d3d12x/real.rs"

check "GPU-side root-changing ExecuteIndirect repack" \
    "test -f crates/xcl/src/hle/d3d12x/indirect.rs && grep -q 'pub mod indirect' crates/xcl/src/hle/d3d12x/mod.rs"

check "Two-pass DispatchMesh & ExecuteIndirect execution harness" \
    "grep -q 'dispatch_mesh' crates/xcl/src/hle/d3d12x/bind.rs && grep -q 'make_scaled_args_buffer' crates/xcl/src/hle/d3d12x/bind.rs"

# 8. CI Workflow
check "Mac cross-build CI workflow (.github/workflows/mac-cross.yml)" \
    "test -f .github/workflows/mac-cross.yml && grep -q 'x86_64-pc-windows-gnullvm' .github/workflows/mac-cross.yml"

# 9. Verification Parity & Memory Safety (R6 Hardening)
check "CreateShaderCacheSession translation layer fallback" \
    "grep -q 'CreateShaderCacheSession' crates/xcl/src/hle/d3d12_layout.rs && grep -q 'ID3D12ShaderCacheSession' crates/xcl/src/hle/d3d12_layout.rs"

check "Pointer alignment guard in is_adopted (align_of::<usize>)" \
    "grep -q 'align_of::<usize>() - 1' crates/xcl/src/hle/d3d12x/real.rs && grep -q 'misaligned_return_buffer_is_not_adopted' crates/xcl/src/hle/d3d12x/real.rs"

check "Heap mirroring and bounded root SRVs" \
    "grep -q 'mirrors::source' crates/xcl/src/hle/kernelx.rs && grep -q 'indirect::source' crates/xcl/src/hle/d3d12x/bind.rs && grep -q 'offset & !15' crates/xcl/src/hle/d3d12x/indirect.rs"

echo "======================================================================"
echo "Verification Summary: $PASS Passed, $FAIL Failed"
echo "======================================================================"

if [ "$FAIL" -gt 0 ]; then
    echo "Status: Verification FAILED"
    exit 1
else
    echo "Status: Verification SUCCESSFUL! All Mac host subsystems present."
    exit 0
fi
