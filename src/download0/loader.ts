import { libc_addr } from 'download0/userland'
import { fn, mem, BigInt, utils } from 'download0/types'
import { sysctlbyname } from 'download0/kernel'
import { lapse } from 'download0/lapse'
import { relapse } from 'download0/relapse'
import { binloader_init } from 'download0/binloader'
import { checkJailbroken } from 'download0/check-jailbroken'

// ---------------------------------------------------------------------------
// Re-press guard (menu "Jailbreak" can be pressed again while the menu is
// already active). NEVER throw here: an uncaught top-level throw used to
// freeze the app with the key handler already disabled.
// ---------------------------------------------------------------------------
const loader_already_ran = !!jsmaf.loader_has_run
if (loader_already_ran) {
  log('[loader] Jailbreak re-press ignored: loader already ran this session')
  try { utils.notify('Vue already initialized — use Payload Menu / Config') } catch (e) { /* notify optional */ }
} else {
  jsmaf.loader_has_run = true
}

// Now load userland and lapse
// Check if libc_addr is defined
if (typeof libc_addr === 'undefined') {
  include('userland.js')
}
include('binloader.js')
include('lapse.js')
include('kernel.js')
include('check-jailbroken.js')
log('All scripts loaded')
// identify the exact build in every report (update on each release)
log('[vue-663 build] diag-build-2026-10-23 (relapse-12.5x watchdog + jb-probe + menu guard)')

export function show_success (immediate?: boolean) {
  jsmaf.vue_exploit_done = true
  if (typeof startBgmIfEnabled === 'function') {
    startBgmIfEnabled()
  }
  if (immediate) {
    jsmaf.root.children.push(bg_success)
    log('Showing Success Image...')
  } else {
    setTimeout(() => {
      jsmaf.root.children.push(bg_success)
      log('Showing Success Image...')
    }, 2000)
  }
}

const themeFolder = (typeof CONFIG !== 'undefined' && typeof CONFIG.theme === 'string') ? CONFIG.theme : 'default'

// Check if exploit has completed successfully
function is_exploit_complete () {
  // Check if we're actually jailbroken
  fn.register(24, 'getuid', [], 'bigint')
  fn.register(585, 'is_in_sandbox', [], 'bigint')
  try {
    const uid = fn.getuid()
    const sandbox = fn.is_in_sandbox()
    // Should be root (uid=0) and not sandboxed (0)
    if (!uid.eq(0) || !sandbox.eq(0)) {
      return false
    }
  } catch (e) {
    return false
  }

  return true
}

// relapse.js is not part of the boot include chain: load it on first use
// (keeps the 65KB parse out of the Lapse/Netctrl paths).
function start_relapse () {
  if (typeof relapse === 'undefined') include('relapse.js')
  relapse()
}

function write64 (addr: BigInt, val: BigInt | number) {
  mem.view(addr).setBigInt(0, new BigInt(val), true)
}

function read8 (addr: BigInt) {
  return mem.view(addr).getUint8(0)
}

function malloc (size: number) {
  return mem.malloc(size)
}

function get_fwversion () {
  const buf = malloc(0x8)
  const size = malloc(0x8)
  write64(size, 0x8)
  if (sysctlbyname('kern.sdk_version', buf, size, 0, 0)) {
    const byte1 = Number(read8(buf.add(2)))  // Minor version (first byte)
    const byte2 = Number(read8(buf.add(3)))  // Major version (second byte)

    const version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0')
    return version
  }

  return null
}

const compare_version = (a: string, b: string) => {
  const a_arr = a.split('.')
  const amaj = Number(a_arr[0])
  const amin = Number(a_arr[1])
  const b_arr = b.split('.')
  const bmaj = Number(b_arr[0])
  const bmin = Number(b_arr[1])
  return amaj === bmaj ? amin - bmin : amaj - bmaj
}

// ---------------------------------------------------------------------------
// Relapse watchdog -> Netctrl fallback (12.50/12.52 only)
//
// relapse_fail() already falls back to netctrl when it *fails* cleanly, but
// if the relapse chain stalls (setup/saturate hang with the event loop still
// alive) nothing happens. This watchdog monitors relapse's activity marks
// (relapse.ts mark() refreshes jsmaf.relapse_activity) and forces the
// netctrl include when relapse stops progressing.
// ---------------------------------------------------------------------------
function arm_relapse_watchdog (fw: string) {
  const started = Date.now()
  jsmaf.relapse_activity = started
  let done = false
  const id = jsmaf.setInterval(function () {
    if (done || jsmaf.vue_exploit_done || is_exploit_complete()) {
      done = true
      jsmaf.clearInterval(id)
      return
    }
    const act = jsmaf.relapse_activity || started
    const idle = Date.now() - act
    if (idle >= 30000) {
      done = true
      jsmaf.clearInterval(id)
      log('[watchdog] relapse stalled for ' + idle + 'ms on fw=' + fw + ' -> netctrl fallback')
      try { utils.notify('Relapse stalled — trying NetControl...') } catch (e) { /* optional */ }
      try {
        include('netctrl_c0w_twins.js')
      } catch (e2) {
        log('[watchdog] netctrl include failed: ' + (e2 as Error).message)
      }
    }
  }, 5000)
  log('[watchdog] armed (30s stall -> netctrl fallback), fw=' + fw)
}

// ---------------------------------------------------------------------------
// Main flow — wrapped so ANY failure notifies instead of freezing the app
// with a silent top-level throw.
// ---------------------------------------------------------------------------
if (!loader_already_ran) {
  try {
    const is_jailbroken = checkJailbroken()
    const FW_VERSION: string | null = get_fwversion()

    if (FW_VERSION === null) {
      log('ERROR: Failed to determine FW version')
      throw new Error('Failed to determine FW version')
    }

    if (!is_jailbroken) {
      const jb_behavior = (typeof CONFIG !== 'undefined' && typeof CONFIG.jb_behavior === 'number') ? CONFIG.jb_behavior : 0

      utils.notify(FW_VERSION + ' Detected!')

      // 13.02/13.04 testers: autoclose on with HEN-safe delay even if config.json is old
      const is663fw = FW_VERSION === '13.02' || FW_VERSION === '13.04'
      if (is663fw && typeof CONFIG !== 'undefined') {
        CONFIG.autoclose = true
        if (typeof CONFIG.autoclose_delay !== 'number' || CONFIG.autoclose_delay < 20000) {
          CONFIG.autoclose_delay = 20000
        }
      }

      // 12.50/12.52: relapse is experimental (no kernel dump) — arm the
      // stall watchdog so a hanging setup still ends in netctrl (proven).
      const is125x = compare_version(FW_VERSION, '12.50') >= 0 && compare_version(FW_VERSION, '12.52') <= 0

      let use_lapse = false

      if (jb_behavior === 1) {
        log('JB Behavior: NetControl (forced)')
        include('netctrl_c0w_twins.js')
      } else if (jb_behavior === 2) {
        log('JB Behavior: Lapse (forced)')
        use_lapse = true
        lapse()
      } else if (jb_behavior === 3) {
        log('JB Behavior: Relapse/663 (forced)')
        if (is125x) arm_relapse_watchdog(FW_VERSION)
        start_relapse()
      } else {
        log('JB Behavior: Auto Detect')
        if (compare_version(FW_VERSION, '7.00') >= 0 && compare_version(FW_VERSION, '12.02') <= 0) {
          use_lapse = true
          lapse()
        } else if (compare_version(FW_VERSION, '12.50') >= 0 && compare_version(FW_VERSION, '13.00') <= 0) {
          // Relapse first: 13.00 is proven-on-hardware, 12.50/12.52 tables are
          // experimental (first public support) and relapse falls back to netctrl
          // (poops, proven there) internally after retries are exhausted
          log('JB Behavior: Relapse/663 (auto, netctrl fallback for 12.5x)')
          if (is125x) arm_relapse_watchdog(FW_VERSION)
          start_relapse()
        } else if (is663fw) {
          log('JB Behavior: Relapse/663 (auto)')
          start_relapse()
        }
      }

      // Wait for lapse only - netctrl AND relapse self-complete (relapse calls
      // show_success + run_binloader from its own chain, netctrl-style)
      if (use_lapse) {
        const start_time = Date.now()
        const max_wait_seconds = 5
        const max_wait_ms = max_wait_seconds * 1000

        while (!is_exploit_complete()) {
          const elapsed = Date.now() - start_time

          if (elapsed > max_wait_ms) {
            log('ERROR: Timeout waiting for exploit to complete (' + max_wait_seconds + ' seconds)')
            throw new Error('Lapse failed! restart and try again...')
          }

          // Poll every 500ms
          const poll_start = Date.now()
          while (Date.now() - poll_start < 500) {
            // Busy wait
          }
        }
        const total_wait = ((Date.now() - start_time) / 1000).toFixed(1)
        log('Exploit completed successfully after ' + total_wait + ' seconds')
      }
      if (use_lapse) {
        log('Initializing binloader...')

        try {
          binloader_init()
          log('Binloader initialized and running!')
        } catch (e) {
          log('ERROR: Failed to initialize binloader')
          log('Error message: ' + (e as Error).message)
          log('Error name: ' + (e as Error).name)
          if ((e as Error).stack) {
            log('Stack trace: ' + (e as Error).stack)
          }
          throw e
        }
      }
    } else {
      utils.notify('Already Jailbroken!')
      startBgmIfEnabled()
      try { include('themes/' + themeFolder + '/main.js') } catch (e) { /* escaped sandbox */ }
    }
  } catch (e) {
    // Any failure in the flow: notify on screen instead of dying silently
    // (the menu re-press handler restores input on its own catch as well).
    log('[loader] FATAL: ' + (e as Error).message)
    if ((e as Error).stack) log('[loader] stack: ' + (e as Error).stack)
    try { utils.notify('Vue error: ' + (e as Error).message + ' — reopen Vue') } catch (e2) { /* optional */ }
  }
}

export function run_binloader () {
  log('Initializing binloader...')

  try {
    binloader_init()
    log('Binloader initialized and running!')
  } catch (e) {
    log('ERROR: Failed to initialize binloader')
    log('Error message: ' + (e as Error).message)
    log('Error name: ' + (e as Error).name)
    if ((e as Error).stack) {
      log('Stack trace: ' + (e as Error).stack)
    }
    throw e
  }
}
