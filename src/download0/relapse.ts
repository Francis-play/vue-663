// Relapse/663 (AIO Multi Cancel) KEX for 13.02/13.04 — Vue entrypoint.
// Port of polpNO jb-polpno.js (HW-proven 13.02, pass=51) to the Vue userland.
// Refs in C:\Users\Franc\AppData\Local\Temp\opencode\ref663\ (jb-polpno.js 3249 lines).
// kpatch/offsets: H32S PR #252 + adjudicated table in port-663-vue.md (F4).
// Arch B fallback ref: relapse-ntfargo.js (oid-window, minimal footprint).
//
// Flow (loader calls relapse(), waits up to 60s, then binloader_init):
//   relapse_setup  arenas + sockets + ROP workers (jb-polpno.js:600-990)
//   relapse_arm    armOnce: rthdr -> 2x AIO -> aio_multi_wait(1000us) -> spray -> cancel (:995-1050)
//   relapse_leak   leakCurthread oracle (:1052-1150)
//   relapse_pass   passA/passB decrement oracle, TD_UCRED+0x130 / CR_RUID+0x08 (:1198-1420)
//   relapse_anchor IDT anchor-sweep 0xffffff8000001a00
//   relapse_rw     kbase via kl_lock-KL_LOCK, apply_kernel_patches, jailbreak_shared
//
// F1 gate: 14MB heap in the app (script in port-663-vue.md). If it fails,
// retune N_LEAK/KA via ?n=/?ka= equivalent (TODO F3: config.json tunables).
// Fail-clean rule: any phase failure -> log + ws.broadcast + cleanup(true)
// + throw. Never KP the console from here.

import { fn, mem, BigInt, utils } from 'download0/types'
import { sysctlbyname } from 'download0/kernel'

// --- Tunables (jb-polpno.js constants; TODO F3: move to config.json) ---
const NODE_SZ = 0x38
const N_LEAK = 262144 // ?n= : lkNodes 14MB (jb-polpno.js:1048)
const KA = 32768 // ?ka=
const KB = 65537 // PAIR (jb-polpno.js:1217)
const MAXN = 131089 // arAb 7MB
const SPRAY = 512
const SPIN = 40000000 // chunked with yield_to_render (F3)
const TOWAIT_US = 1000 // was 100000us: killed armings (PR-TOWAIT)
const SWEEP = 256
const TD_UCRED_OFF = 0x130
const CR_RUID_OFF = 0x08
const IDT_ADDR = '0xffffff8000001a00'
const RELAPSE_MAX_RETRIES = 3 // jb_retries (PR #250 split)

// Syscalls 662/663/664/666/669 are registered by lapse.js (always loaded
// by loader before us). Never re-register here: use fn.* if present.
function aioAvailable () {
  const f = fn as unknown as Record<string, unknown>
  return typeof f.aio_multi_wait !== 'undefined' &&
    typeof f.aio_multi_delete !== 'undefined' &&
    typeof f.aio_multi_cancel !== 'undefined'
}

// --- Telemetry: check()/mark() gates -> log + ws.broadcast (netctrl pattern) ---
function mark (tag: string, detail?: string) {
  const msg = detail ? '[relapse:' + tag + '] ' + detail : '[relapse:' + tag + ']'
  log(msg)
  try {
    const w = (typeof ws !== 'undefined' ? ws : null) as unknown as Record<string, unknown>
    if (w && typeof w.broadcast === 'function') {
      (w.broadcast as (m: string) => void)(msg)
    }
  } catch (e) { /* ws optional */ }
}

function check (name: string, ok: boolean, detail?: string) {
  mark(ok ? 'PROOF-OK' : 'PROOF-FAIL', name + (detail ? ' ' + detail : ''))
  return ok
}

function yield_to_render (callback: () => void) {
  const id = jsmaf.setInterval(function () {
    jsmaf.clearInterval(id)
    try {
      callback()
    } catch (e) {
      log('ERROR: ' + (e as Error).message)
      cleanup(true)
    }
  }, 0)
}

let relapse_tries = 0

function cleanup (soft: boolean) {
  // TODO F3: defuseAioGroups/restoreOids/restorePipes (relapse-ntfargo.js).
  mark('CLEANUP', soft ? 'soft' : 'hard')
}

function relapse_setup () {
  mark('PR-CFG', 'nleak=' + N_LEAK + ' spray=' + SPRAY + ' spin=' + SPIN)
  if (!check('aio-syscalls-present', aioAvailable(), '662/663/664/666/669 from lapse.js')) {
    throw new Error('Relapse failed! restart and try again...')
  }
  // TODO F2: arenas A (14MB+7MB), socket pool, ROP workers (thr_new + pipe signal).
  mark('SETUP-TODO', 'arenas/workers pending F2 port')
  yield_to_render(relapse_arm)
}

function relapse_arm () {
  // TODO F2: armOnce (rthdr -> 2x AIO -> aio_multi_wait 1000us -> spray -> cancel).
  mark('ARM-TODO', 'armOnce pending F2 port')
  yield_to_render(relapse_leak)
}

function relapse_leak () {
  // TODO F2: leakCurthread oracle + re-leak.
  mark('LEAK-TODO', 'leakCurthread pending F2 port')
  yield_to_render(relapse_pass)
}

function relapse_pass () {
  // TODO F2/F3: passA/passB decrement oracle (TD_UCRED+0x130), park via
  // thr_suspend_ucontext (lapse gate W1-PARK: never crfree the wild td_ucred).
  mark('PASS-TODO', 'passA/passB pending F2 port')
  yield_to_render(relapse_anchor)
}

function relapse_anchor () {
  // TODO F2: anchor-sweep IDT 0xffffff8000001a00 (SWEEP=256).
  mark('ANCHOR-TODO', 'IDT sweep pending F2 port')
  yield_to_render(relapse_rw)
}

function relapse_rw () {
  // TODO F4: kbase via kl_lock-KL_LOCK, apply_kernel_patches (H32S diff +
  // '13.04' key fix), jailbreak_shared. Defined pending F4 offsets.
  mark('RW-TODO', 'kbase/kpatch pending F4')
  mark('RELAPSE-SCAFFOLD-OK', 'phases wired, KEX primitives pending')
}

export function relapse () {
  relapse_tries++
  mark('START', 'try ' + relapse_tries + '/' + RELAPSE_MAX_RETRIES)
  utils.notify('13.0x Detected! Relapse/663')
  if (relapse_tries > RELAPSE_MAX_RETRIES) {
    throw new Error('Relapse failed! restart and try again...')
  }
  relapse_setup()
}
