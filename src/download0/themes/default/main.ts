// ---------------------------------------------------------------------------
// debug-blackboard theme (manual mode)
//
// No autorun, no menu, no images, no music. The screen is a blackboard:
//   left  -> status + buttons (run userland / prueba 1-3 / log paging)
//   right -> live log ring with synchronous paint (survives a blocked thread)
//
// The user decides every step. Logs are painted on every log() call, so if the
// exploit hangs the LAST MARK stays on screen as evidence.
// ---------------------------------------------------------------------------
import { fn, BigInt, mem, utils } from 'download0/types'
import { kernel } from 'download0/kernel'

;(function () {
  const BUILD = 'diag-build-2026-10-29'
  const RING_MAX = 3000
  const HIST_MAX = 3000
  const LOG_COLS = 100
  const LOG_ROWS = 34
  const O_WRONLY = 1
  const O_CREAT = 0x200
  const O_TRUNC = 0x400
  const USB_IDS = ['0', '1', '2', '3']
  const DUMP_CHUNK = 0x10000
  const DUMP_MIN = 0x400000
  const DUMP_MAX = 0x4800000
  const DUMP_FALLBACK = 0x2400000

  // tags that are pinned on the left panel (never scrolled away)
  const PINS = [
    'START', 'PR-CFG', 'PR-SATURATE-ENTER', 'PR-SATURATE', 'PR-POOL',
    'PR-WORKER-READY', 'ARM-FIN', 'PR-FIRE', 'PR-LEAK', 'PR-PASSA',
    'PR-PASSA-NOCROSS', 'PR-UCRED', 'ANCHOR-HANDLER', 'ANCHOR-KERNEL-BASE',
    'IDT-ALT', 'SWEEP-SUMMARY', 'FAIL-FINAL'
  ]

  const board = {
    ringT: [] as string[],
    ringS: [] as string[],
    history: [] as string[],
    paging: false,
    viewStart: 0,
    sel: 0,
    stage: 'idle',
    preflight: false,
    tried1: false,
    tried2: false,
    tried3: false,
    lastMark: '',
    pins: {} as Record<string, string>,
    counts: { rel: 0, net: 0, ldr: 0, board: 0 },
    started: Date.now(),
    dump: 'DUMP: waiting for JB + USB',
    dumping: false,
    dumpDone: false,
    usb: null as string | null,
    lastUsbTry: 0,
    size: 0,
    off: 0,
    fd: -1,
    bufAddr: null as BigInt | null,
    chunk: null as Uint8Array | null,
    uid: null as number | null,
    sand: null as number | null
  }

  // --- helpers ---------------------------------------------------------------
  function hex64 (v: BigInt) {
    const hi = (v.hi >>> 0).toString(16).padStart(8, '0')
    const lo = (v.lo >>> 0).toString(16).padStart(8, '0')
    return '0x' + hi + lo
  }
  function jsmafGet (key: string) {
    return (jsmaf as unknown as Record<string, unknown>)[key]
  }
  function jsmafSet (key: string, value: unknown) {
    try { (jsmaf as unknown as Record<string, unknown>)[key] = value } catch (e) { /* optional */ }
  }
  // cached syscall thunks (register once: the GC is disabled, avoid leaking closures)
  let getuidFn: (() => unknown) | null = null
  let sandboxFn: (() => unknown) | null = null
  function getUid (): number | null {
    try {
      if (getuidFn === null) {
        fn.register(24, 'getuid', [], 'bigint')
        getuidFn = (fn as unknown as Record<string, () => unknown>).getuid as () => unknown
      }
      const v = getuidFn() as BigInt | number
      return v instanceof BigInt ? (v.lo >>> 0) : v
    } catch (e) { return null }
  }
  function getSandbox (): number | null {
    try {
      if (sandboxFn === null) {
        fn.register(585, 'is_in_sandbox', [], 'bigint')
        sandboxFn = (fn as unknown as Record<string, () => unknown>).is_in_sandbox as () => unknown
      }
      const v = sandboxFn() as BigInt | number
      return v instanceof BigInt ? (v.lo >>> 0) : v
    } catch (e) { return null }
  }
  function kbaseHex (): string {
    try {
      const k = (typeof kernel !== 'undefined' && kernel && kernel.addr) ? (kernel.addr as unknown as Record<string, unknown>).base as BigInt : null
      if (k) return hex64(k)
    } catch (e) { /* no krw */ }
    const j = jsmafGet('kbase') as BigInt | undefined
    return j ? hex64(j) : ''
  }

  // --- styles ----------------------------------------------------------------
  jsmaf.root.children.length = 0
  new Style({ name: 'bg-title', color: '#FFFFFF', size: 30 })
  new Style({ name: 'bg-status', color: '#E9ECEF', size: 18 })
  new Style({ name: 'bg-status-on', color: '#69DB7C', size: 18 })
  new Style({ name: 'bg-btn', color: '#CED4DA', size: 22 })
  new Style({ name: 'bg-btn-sel', color: '#FFD43B', size: 22 })
  new Style({ name: 'bg-btn-off', color: '#6C757D', size: 22 })
  new Style({ name: 'bg-mark', color: '#FFD43B', size: 19 })
  new Style({ name: 'bg-hdr', color: '#ADB5BD', size: 17 })
  new Style({ name: 'bg-pin', color: '#ADB5BD', size: 15 })
  new Style({ name: 'bg-foot', color: '#868E96', size: 14 })
  new Style({ name: 'lg-sys', color: '#E9ECEF', size: 17 })
  new Style({ name: 'lg-rel', color: '#4DABF7', size: 17 })
  new Style({ name: 'lg-net', color: '#6BCF7F', size: 17 })
  new Style({ name: 'lg-err', color: '#FF6B6B', size: 17 })
  new Style({ name: 'lg-warn', color: '#FFA94D', size: 17 })

  function mkText (x: number, y: number, style: string) {
    const t = new jsmaf.Text()
    t.x = x
    t.y = y
    t.text = ''
    t.style = style
    jsmaf.root.children.push(t)
    return t
  }

  const ui = {
    title: mkText(40, 22, 'bg-title'),
    status: [] as jsmaf.Text[],
    btn: [] as jsmaf.Text[],
    counts: mkText(40, 522, 'bg-hdr'),
    markHdr: mkText(40, 552, 'bg-hdr'),
    mark: [] as jsmaf.Text[],
    pinHdr: mkText(40, 616, 'bg-hdr'),
    pin: [] as jsmaf.Text[],
    foot: [] as jsmaf.Text[],
    logHdr: mkText(680, 22, 'bg-hdr'),
    log: [] as jsmaf.Text[],
    logFoot: [] as jsmaf.Text[]
  }
  ui.title.text = 'VUE BLACKBOARD · ' + BUILD
  for (let i = 0; i < 8; i++) ui.status.push(mkText(40, 68 + i * 21, 'bg-status'))
  for (let i = 0; i < 6; i++) ui.btn.push(mkText(40, 250 + i * 44, 'bg-btn'))
  ui.mark.push(mkText(40, 572, 'bg-mark'), mkText(40, 594, 'bg-mark'))
  for (let i = 0; i < PINS.length; i++) ui.pin.push(mkText(40, 638 + i * 19, 'bg-pin'))
  for (let i = 0; i < 2; i++) ui.foot.push(mkText(40, 986 + i * 20, 'bg-foot'))
  for (let i = 0; i < LOG_ROWS; i++) ui.log.push(mkText(680, 50 + i * 26, 'lg-sys'))
  for (let i = 0; i < 3; i++) ui.logFoot.push(mkText(680, 950 + i * 20, 'bg-foot'))

  // --- log capture -----------------------------------------------------------
  const nativeLog = (typeof log === 'function') ? log : null
  const nativeDebug = (typeof debug === 'function') ? debug : null
  let logPatched = false

  function sourceStyle (msg: string) {
    if (msg.indexOf('FAIL') >= 0 || msg.indexOf('ERROR') >= 0 || msg.indexOf('NOCROSS') >= 0 ||
      msg.indexOf('NO-MATCH') >= 0 || msg.indexOf('OUT-OF-BOUNDS') >= 0) return 'lg-err'
    if (msg.indexOf('BENIGN-RETRY') >= 0 || msg.indexOf('WARN') >= 0 || msg.indexOf('stall') >= 0) return 'lg-warn'
    if (msg.indexOf('[relapse:') >= 0 || msg.indexOf('Relapse') >= 0) return 'lg-rel'
    if (msg.indexOf('[netctrl') >= 0 || msg.indexOf('kqueue') >= 0 || msg.indexOf('NetControl') >= 0) return 'lg-net'
    return 'lg-sys'
  }

  function bumpCounts (msg: string) {
    if (msg.indexOf('[relapse:') >= 0) board.counts.rel++
    else if (msg.indexOf('[netctrl') >= 0 || msg.indexOf('kqueue') >= 0) board.counts.net++
    else if (msg.indexOf('[ldr]') >= 0 || msg.indexOf('[loader') >= 0 || msg.indexOf('[watchdog') >= 0) board.counts.ldr++
    else board.counts.board++
  }

  function trackPins (msg: string) {
    const at = msg.indexOf('[relapse:')
    if (at < 0) return
    const endTag = msg.indexOf(']', at)
    if (endTag < 0) return
    const tag = msg.slice(at + 9, endTag)
    if (PINS.indexOf(tag) < 0) return
    board.pins[tag] = msg.slice(endTag + 1).trim().slice(0, 92)
    repaintPins()
  }

  function trackLastMark (msg: string) {
    if (msg.charAt(0) !== '[') return
    if (msg.indexOf('[board]') === 0) return
    board.lastMark = msg.slice(0, 120)
    paintLastMark()
  }

  function pushLine (raw: string) {
    const msg = String(raw)
    board.history.push(msg)
    if (board.history.length > HIST_MAX) board.history.shift()
    const st = sourceStyle(msg)
    let off = 0
    do {
      const chunk = msg.slice(off, off + LOG_COLS)
      board.ringT.push(chunk)
      board.ringS.push(st)
      off += LOG_COLS
    } while (off < msg.length)
    const drop = board.ringT.length - RING_MAX
    if (drop > 0) {
      board.ringT.splice(0, drop)
      board.ringS.splice(0, drop)
    }
    bumpCounts(msg)
    trackPins(msg)
    trackLastMark(msg)
    if (!board.paging) repaintLog()
  }

  try {
    if (nativeLog !== null) {
      ;(globalThis as unknown as Record<string, unknown>).log = function (msg: string) {
        pushLine(msg)
        nativeLog(msg)
      }
      logPatched = (globalThis as unknown as Record<string, unknown>).log !== nativeLog
    }
  } catch (e) { /* log stays native */ }
  try {
    if (nativeDebug !== null) {
      ;(globalThis as unknown as Record<string, unknown>).debug = function (msg: string) {
        pushLine(msg)
        nativeDebug(msg)
      }
    }
  } catch (e) { /* debug stays native */ }

  // --- painters --------------------------------------------------------------
  function repaintLog () {
    if (!board.paging) board.viewStart = Math.max(0, board.ringT.length - LOG_ROWS)
    let start = board.viewStart
    if (start > Math.max(0, board.ringT.length - LOG_ROWS)) start = Math.max(0, board.ringT.length - LOG_ROWS)
    for (let i = 0; i < LOG_ROWS; i++) {
      const idx = start + i
      const t = ui.log[i]!
      if (idx < board.ringT.length) {
        t.text = board.ringT[idx]!
        t.style = board.ringS[idx]!
      } else {
        t.text = ''
      }
    }
    const pages = Math.max(1, Math.ceil(board.ringT.length / LOG_ROWS))
    const page = Math.min(pages, Math.floor(start / LOG_ROWS) + 1)
    ui.logHdr.text = 'LOG · pág ' + page + '/' + pages + ' · ring ' + board.ringT.length + '/' + RING_MAX +
      (board.paging ? ' · SCROLL' : ' · tail')
  }

  function repaintPins () {
    for (let i = 0; i < PINS.length; i++) {
      const tag = PINS[i]!
      const val = board.pins[tag]
      ui.pin[i]!.text = val === undefined ? tag + ' ·' : tag + ' ' + val
      ui.pin[i]!.style = val === undefined ? 'bg-pin' : 'bg-status'
    }
  }

  function paintLastMark () {
    const a = board.lastMark.slice(0, 56)
    const b = board.lastMark.length > 56 ? board.lastMark.slice(56, 120) : ''
    ui.mark[0]!.text = 'LAST ' + a
    ui.mark[1]!.text = b ? '     ' + b : ''
  }

  function readCreds () {
    if (!board.preflight) return
    if (board.stage === 'preflight' || board.stage === 'prueba') return
    if (board.stage !== 'idle' && !jsmaf.vue_exploit_done) return
    const u = getUid()
    const s = getSandbox()
    if (u !== null) board.uid = u
    if (s !== null) board.sand = s
  }

  function renderStatus () {
    readCreds()
    const fw = jsmafGet('fw_version') as string | undefined
    const path = jsmafGet('exploit_path') as string | undefined
    const phase = jsmafGet('relapse_phase') as string | undefined
    const done = !!jsmaf.vue_exploit_done
    const uid = board.uid
    const sand = board.sand
    const jb = uid === 0 && sand === 0
    const kbase = kbaseHex()
    const elapsed = ((Date.now() - board.started) / 1000).toFixed(1)
    const act = jsmafGet('relapse_activity') as number | undefined
    const idle = act ? ((Date.now() - act) / 1000).toFixed(1) + 's' : '-'
    ui.status[0]!.text = 'FW ' + (fw || '?') + '    uid ' + (uid === null ? '?' : uid) +
      '    sandbox ' + (sand === null ? '?' : sand) + '    JB ' + (jb ? 'YES' : 'no')
    ui.status[0]!.style = jb ? 'bg-status-on' : 'bg-status'
    ui.status[1]!.text = 'stage ' + board.stage + (done ? ' · EXPLOIT DONE' : '') + '    t ' + elapsed + 's    idle ' + idle
    ui.status[2]!.text = 'path ' + (path || '-')
    ui.status[3]!.text = 'phase ' + (phase || '-')
    ui.status[4]!.text = 'kbase ' + (kbase || '(pendiente)')
    ui.status[5]!.text = 'preflight ' + (board.preflight ? 'done' : 'pending') +
      (logPatched ? ' · log ON' : ' · log OFF')
    ui.status[6]!.text = 'swp ' + ((jsmafGet('sweep_summary') as string | undefined) || '-')
    ui.status[7]!.text = 'tried 1:' + (board.tried1 ? 'y' : '-') + ' 2:' + (board.tried2 ? 'y' : '-') + ' 3:' + (board.tried3 ? 'y' : '-')
    ui.counts.text = 'lines rel ' + board.counts.rel + ' · net ' + board.counts.net +
      ' · ldr ' + board.counts.ldr + ' · board ' + board.counts.board
    ui.foot[0]!.text = board.dump
    ui.foot[1]!.text = 'writes ' + board.history.length + ' msgs · USB ' + (board.usb || 'none')
    ui.logFoot[0]!.text = 'teclas: 6/5 ↓ · 4/7 ↑ · X activa'
    ui.logFoot[1]!.text = 'knobs ' + knobLine()
    updateButtons()
  }

  function knobLine () {
    try {
      if (typeof CONFIG === 'undefined') return '-'
      const c = CONFIG as unknown as Record<string, unknown>
      const g = function (k: string, d: number) {
        const v = c[k]
        return typeof v === 'number' && v > 0 ? v : d
      }
      return 'rel retry=' + g('relapse_retries', 3) + ' spin=' + g('relapse_spin', 40000000) +
        ' towait=' + g('relapse_towait', 1000) + ' | nc kq=' + g('nc_kqueue_iters', 5000)
    } catch (e) { return '-' }
  }

  // --- buttons ---------------------------------------------------------------
  const BUTTONS = ['run.userland', 'prueba1', 'prueba2', 'prueba3', 'log.up', 'log.down']

  function btnEnabled (id: string) {
    if (id === 'run.userland') return !board.preflight
    if (id === 'prueba1' || id === 'prueba2') return board.preflight && board.stage !== 'prueba'
    if (id === 'prueba3') return board.preflight && sweepReady()
    if (id === 'log.up') return board.ringT.length > LOG_ROWS
    if (id === 'log.down') return board.paging
    return false
  }
  function sweepReady () {
    if (board.pins['PR-FIRE'] || board.pins['PR-LEAK'] || board.pins['PR-PASSA-NOCROSS'] || jsmafGet('sweep_ready')) return true
    // nothing to observe (e.g. the leak never completed): allow the diagnostic
    // sweep anyway once both single-shot tries have been used
    return !!(board.tried1 && board.tried2)
  }
  function btnLabel (id: string) {
    if (id === 'run.userland') return board.preflight ? 'RUN USERLAND (preflight ok)' : 'RUN USERLAND'
    if (id === 'prueba1') return 'PRUEBA 1 — relapse (IDT 1c1d00, 1 intento)'
    if (id === 'prueba2') return 'PRUEBA 2 — relapse (IDT-ALT 1c1d40)'
    if (id === 'prueba3') return sweepReady() ? 'PRUEBA 3 — SWEEP (auto)' : 'PRUEBA 3 — SWEEP (sin datos)'
    if (id === 'log.up') return 'LOG ▲ (más viejo)'
    if (id === 'log.down') return 'LOG ▼ (más nuevo)'
    return id
  }

  function updateButtons () {
    for (let i = 0; i < BUTTONS.length; i++) {
      const id = BUTTONS[i]!
      const sel = i === board.sel
      const on = btnEnabled(id)
      const t = ui.btn[i]!
      t.x = 16
      t.y = 250 + i * 44
      t.text = (sel ? '> ' : '  ') + btnLabel(id)
      t.style = sel ? (on ? 'bg-btn-sel' : 'bg-btn-off') : (on ? 'bg-btn' : 'bg-btn-off')
      t.alpha = on ? 1 : 0.45
      t.scaleX = sel ? 1.05 : 1
      t.scaleY = sel ? 1.05 : 1
      t.color = '#FFFFFF'
    }
    repaintPins()
  }

  function renderStatus () {
    readCreds()
    const fw = jsmafGet('fw_version') as string | undefined
    const path = jsmafGet('exploit_path') as string | undefined
    const phase = jsmafGet('relapse_phase') as string | undefined
    const done = !!jsmaf.vue_exploit_done
    const uid = board.uid
    const sand = board.sand
    const jb = uid === 0 && sand === 0
    const kbase = kbaseHex()
    const elapsed = ((Date.now() - board.started) / 1000).toFixed(1)
    const act = jsmafGet('relapse_activity') as number | undefined
    const idle = act ? ((Date.now() - act) / 1000).toFixed(1) + 's' : '-'
    ui.status[0]!.text = 'FW ' + (fw || '?') + '    uid ' + (uid === null ? '?' : uid) +
      '    sandbox ' + (sand === null ? '?' : sand) + '    JB ' + (jb ? 'YES' : 'no')
    ui.status[0]!.style = jb ? 'bg-status-on' : 'bg-status'
    ui.status[1]!.text = 'stage ' + board.stage + (done ? ' · EXPLOIT DONE' : '') + '    t ' + elapsed + 's    idle ' + idle
    ui.status[2]!.text = 'path ' + (path || '-')
    ui.status[3]!.text = 'phase ' + (phase || '-')
    ui.status[4]!.text = 'kbase ' + (kbase || '(pendiente)')
    ui.status[5]!.text = 'preflight ' + (board.preflight ? 'done' : 'pending') +
      (logPatched ? ' · log ON' : ' · log OFF')
    ui.status[6]!.text = 'swp ' + ((jsmafGet('sweep_summary') as string | undefined) || '-')
    ui.status[7]!.text = 'tried 1:' + (board.tried1 ? 'y' : '-') + ' 2:' + (board.tried2 ? 'y' : '-') + ' 3:' + (board.tried3 ? 'y' : '-')
    ui.counts.text = 'lines rel ' + board.counts.rel + ' · net ' + board.counts.net +
      ' · ldr ' + board.counts.ldr + ' · board ' + board.counts.board
    ui.foot[0]!.text = board.dump
    ui.foot[1]!.text = 'writes ' + board.history.length + ' msgs · USB ' + (board.usb || 'none')
    ui.logFoot[0]!.text = 'teclas: 6/5 ↓ · 4/7 ↑ · X activa'
    ui.logFoot[1]!.text = 'knobs ' + knobLine()
    updateButtons()
  }

  function pageBy (dir: number) {
    if (dir > 0) {
      if (!board.paging) {
        board.paging = true
        board.viewStart = Math.max(0, board.ringT.length - 2 * LOG_ROWS)
      } else {
        board.viewStart = Math.max(0, board.viewStart - LOG_ROWS)
      }
    } else if (board.paging) {
      board.viewStart += LOG_ROWS
      if (board.viewStart + LOG_ROWS >= board.ringT.length) board.paging = false
    }
    repaintLog()
    updateButtons()
  }

  function runUserland () {
    if (board.preflight) {
      pushLine('[board] preflight already done (loader_has_run)')
      return
    }
    jsmafSet('debug_manual', true)
    board.stage = 'preflight'
    board.started = Date.now()
    updateButtons()
    pushLine('[board] RUN USERLAND -> include(loader.js) [manual mode, no autorun]')
    try {
      include('loader.js')
    } catch (e) {
      const err = e as Error
      pushLine('[board] loader include threw: ' + (err.message || String(e)))
      if (err.stack) pushLine('[board] stack: ' + err.stack)
      board.stage = 'preflight-fail'
      updateButtons()
      return
    }
    board.preflight = true
    board.stage = 'idle'
    board.uid = getUid()
    board.sand = getSandbox()
    pushLine('[board] preflight returned: fw=' + (jsmafGet('fw_version') as string || '?') +
      ' uid=' + (board.uid === null ? '?' : board.uid) + ' sandbox=' + (board.sand === null ? '?' : board.sand))
    renderStatus()
    updateButtons()
  }

  function runPrueba (n: number) {
    if (!board.preflight) {
      pushLine('[board] PRUEBA ' + n + ' ignored: RUN USERLAND first')
      return
    }
    if (n === 3 && board.stage !== 'prueba' && !sweepReady()) {
      pushLine('[board] PRUEBA 3 ignored: no data yet (run 1 and 2)')
      return
    }
    const dsr = (globalThis as unknown as Record<string, unknown>).debug_start_relapse
    if (typeof dsr !== 'function') {
      pushLine('[board] PRUEBA ' + n + ' failed: debug_start_relapse missing (loader manual mode?)')
      return
    }
    board.stage = 'prueba'
    jsmafSet('debug_sweep', n === 3)
    jsmafSet('debug_attempt', n)
    jsmafSet('exploit_path', 'relapse(p' + n + ')')
    if (n === 1) board.tried1 = true
    if (n === 2) board.tried2 = true
    if (n === 3) board.tried3 = true
    pushLine('[board] PRUEBA ' + n + ' -> debug_start_relapse(' + n + ') sweep=' + (n === 3 ? 'on' : 'off'))
    updateButtons()
    try {
      ;(dsr as (a: number) => void)(n)
    } catch (e) {
      const err = e as Error
      pushLine('[board] PRUEBA ' + n + ' threw: ' + (err.message || String(e)))
    }
    board.stage = 'idle'
    pushLine('[board] PRUEBA ' + n + ' returned' + (jsmaf.vue_exploit_done ? ' (EXPLOIT DONE)' : ''))
    renderStatus()
    updateButtons()
  }

  function activate () {
    const id = BUTTONS[board.sel]!
    if (!btnEnabled(id)) {
      pushLine('[board] "' + id + '" disabled')
      return
    }
    if (id === 'run.userland') runUserland()
    else if (id === 'prueba1') runPrueba(1)
    else if (id === 'prueba2') runPrueba(2)
    else if (id === 'prueba3') runPrueba(3)
    else if (id === 'log.up') pageBy(1)
    else if (id === 'log.down') pageBy(-1)
  }

  const confirmKey = jsmaf.circleIsAdvanceButton ? 13 : 14
  jsmaf.onKeyDown = function (keyCode: number) {    if (keyCode === 6 || keyCode === 5) {
      board.sel = (board.sel + 1) % BUTTONS.length
      updateButtons()
    } else if (keyCode === 4 || keyCode === 7) {
      board.sel = (board.sel + BUTTONS.length - 1) % BUTTONS.length
      updateButtons()
    } else if (keyCode === confirmKey) {
      activate()
    }
  }

  // --- file helpers (open/write/close via syscalls, like binloader) ----------
  function allocString (str: string) {
    const addr = mem.malloc(str.length + 1)
    const view = mem.view(addr)
    for (let i = 0; i < str.length; i++) view.setUint8(i, str.charCodeAt(i))
    view.setUint8(str.length, 0)
    return addr
  }
  function isError (v: BigInt | number) {
    if (v instanceof BigInt) return v.hi === 0xffffffff
    return v === -1 || v === 0xffffffff
  }
  function openSys (path: string, flags: number) {
    try {
      fn.register(0x05, 'open_sys', ['bigint', 'bigint', 'bigint'], 'bigint')
      return fn.open_sys(allocString(path), new BigInt(0, flags), new BigInt(0, 0o755)) as BigInt
    } catch (e) { return new BigInt(-1) }
  }
  function writeSys (fd: number, addr: BigInt, len: number) {
    try {
      fn.register(0x04, 'write_sys', ['bigint', 'bigint', 'bigint'], 'bigint')
      return fn.write_sys(new BigInt(0, fd), addr, new BigInt(0, len)) as BigInt
    } catch (e) { return new BigInt(-1) }
  }
  function closeSys (fd: number) {
    try {
      fn.register(0x06, 'close_sys', ['number'], 'bigint')
      fn.close_sys(fd)
    } catch (e) { /* ignore */ }
  }
  function writeStr (fd: number, str: string) {
    const addr = allocString(str)
    const total = str.length
    let off = 0
    while (off < total) {
      const n = total - off > 0x1000 ? 0x1000 : total - off
      const r = writeSys(fd, addr.add(off), n)
      if (isError(r)) return false
      const wrote = r.lo
      if (!wrote) return false
      off += wrote
    }
    return true
  }

  function timestamp () {
    try {
      const d = new Date()
      const p = function (n: number) { return (n < 10 ? '0' : '') + n }
      return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
        p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds())
    } catch (e) { return '?' }
  }

  function buildHead () {
    const fw = jsmafGet('fw_version') as string | undefined
    const path = jsmafGet('exploit_path') as string | undefined
    const phase = jsmafGet('relapse_phase') as string | undefined
    let pins = ''
    for (const tag of PINS) {
      const v = board.pins[tag]
      if (v !== undefined) pins += tag + ': ' + v + '\n'
    }
    const head = 'VUE DEBUG BLACKBOARD ' + BUILD + '\n' +
      'when: ' + timestamp() + '\n' +
      'fw: ' + (fw || '?') + '\n' +
      'uid: ' + (board.uid === null ? '?' : board.uid) + ' sandbox: ' + (board.sand === null ? '?' : board.sand) + '\n' +
      'exploit: ' + (path || '-') + ' phase: ' + (phase || '-') + '\n' +
      'kbase: ' + (kbaseHex() || '-') + '\n' +
      'stage: ' + board.stage + ' tried: 1=' + (board.tried1 ? 'y' : '-') + ' 2=' + (board.tried2 ? 'y' : '-') + ' 3=' + (board.tried3 ? 'y' : '-') + '\n' +
      'sweep: ' + ((jsmafGet('sweep_summary') as string | undefined) || '-') + '\n' +
      (pins ? 'pinned:\n' + pins : '') +
      'log:\n'
    return head
  }

  // --- USB detection + log dump ----------------------------------------------
  function findUsb () {
    for (const id of USB_IDS) {
      const dir = '/mnt/usb' + id
      const fd = openSys(dir + '/vue_debug.txt', O_WRONLY | O_CREAT | O_TRUNC)
      if (!isError(fd)) {
        board.usb = dir
        board.uid = getUid()
        board.sand = getSandbox()
        writeStr(fd.lo >>> 0, buildHead() + board.history.join('\n') + '\n')
        closeSys(fd.lo >>> 0)
        board.dump = 'DUMP: log saved to ' + dir + '/vue_debug.txt'
        return dir
      }
    }
    board.usb = null
    return null
  }

  // --- kernel.elf dump --------------------------------------------------------
  function imageSize (base: BigInt) {
    const hdr = kernel.read_buffer?.(base, 0x40)
    if (!hdr || hdr.length < 0x40) return { size: DUMP_FALLBACK, elf: false }
    const magic = hdr[0] === 0x7f && hdr[1] === 0x45 && hdr[2] === 0x4c && hdr[3] === 0x46
    if (!magic) return { size: DUMP_FALLBACK, elf: false }
    let phoff = 0
    for (let i = 7; i >= 0; i--) phoff = phoff * 256 + hdr[0x20 + i]!
    const entsize = hdr[0x36]! | (hdr[0x37]! << 8)
    const phnum = hdr[0x38]! | (hdr[0x39]! << 8)
    if (!phoff || !entsize || !phnum || phnum > 32) return { size: DUMP_FALLBACK, elf: true }
    const ph = kernel.read_buffer?.(base.add(phoff), entsize * phnum)
    if (!ph) return { size: DUMP_FALLBACK, elf: true }
    let end = 0
    for (let i = 0; i < phnum; i++) {
      const o = i * entsize
      const type = ph[o]! | (ph[o + 1]! << 8) | (ph[o + 2]! << 16) | (ph[o + 3]! << 24)
      if (type !== 1) continue
      let poff = 0
      for (let b = 7; b >= 0; b--) poff = poff * 256 + ph[o + 0x08 + b]!
      let fsz = 0
      for (let b = 7; b >= 0; b--) fsz = fsz * 256 + ph[o + 0x20 + b]!
      if (poff + fsz > end) end = poff + fsz
    }
    if (end < DUMP_MIN || end > DUMP_MAX) return { size: DUMP_FALLBACK, elf: true }
    return { size: end, elf: true }
  }

  function dumpKernel (dir: string) {
    if (board.dumping || board.dumpDone) return
    let base: BigInt | null = null
    try {
      const k = (kernel.addr as unknown as Record<string, unknown>).base as BigInt | undefined
      if (k) base = k
    } catch (e) { /* ignore */ }
    if (!base && jsmafGet('kbase')) base = jsmafGet('kbase') as BigInt
    if (!base) {
      board.dump = 'DUMP: no kbase (exploit did not reach anchor)'
      board.dumpDone = true
      return
    }
    if (!kernel.read_buffer) {
      board.dump = 'DUMP: log saved, but no KRW (kernel.elf needs the relapse path)'
      board.dumpDone = true
      return
    }
    board.dumping = true
    const info = imageSize(base)
    board.size = info.size
    board.off = 0
    const fd = openSys(dir + '/kernel.elf', O_WRONLY | O_CREAT | O_TRUNC)
    if (isError(fd)) {
      board.dump = 'DUMP: cannot create kernel.elf'
      board.dumping = false
      board.dumpDone = true
      return
    }
    board.fd = fd.lo >>> 0
    board.chunk = new Uint8Array(DUMP_CHUNK)
    board.bufAddr = utils.get_backing(board.chunk)
    board.dump = 'DUMP: kernel.elf ' + (info.elf ? '(elf ' : '(raw ') + (info.size / 1048576).toFixed(1) + ' MB) starting...'
    jsmaf.setTimeout(dumpStep, 50)
  }

  function dumpStep () {
    if (board.off >= board.size || !board.chunk || !board.bufAddr) {
      closeSys(board.fd)
      board.dumping = false
      board.dumpDone = true
      board.dump = 'DUMP: OK ' + (board.off / 1048576).toFixed(1) + ' MB -> ' + board.usb + '/kernel.elf'
      return
    }
    const n = Math.min(DUMP_CHUNK, board.size - board.off)
    let ok = false
    try {
      const base = ((kernel.addr as unknown as Record<string, unknown>).base as BigInt | undefined) ||
        (jsmafGet('kbase') as BigInt)
      const data = kernel.read_buffer?.(base.add(board.off), n)
      if (data && data.length === n) {
        board.chunk.set(data)
        const r = writeSys(board.fd, board.bufAddr, n)
        ok = !isError(r) && r.lo === n
      }
    } catch (e) { ok = false }
    if (!ok) {
      closeSys(board.fd)
      board.dumping = false
      board.dumpDone = true
      board.dump = 'DUMP: FAIL at ' + (board.off / 1048576).toFixed(1) + ' MB (krw/usb error)'
      return
    }
    board.off += n
    const pct = Math.floor((board.off / board.size) * 100)
    board.dump = 'DUMP: kernel.elf ' + (board.off / 1048576).toFixed(1) + '/' + (board.size / 1048576).toFixed(1) +
      ' MB (' + pct + '%)'
    jsmaf.setTimeout(dumpStep, 1)
  }

  // --- boot: debug-friendly config, NO autorun -------------------------------
  try {
    if (typeof CONFIG !== 'undefined') {
      CONFIG.autoclose = false
      CONFIG.music = false
    }
  } catch (e) { /* ignore */ }
  jsmafSet('debug_board', true)
  jsmafSet('debug_manual', true)
  // expose state for the ws console / local harness (debug build only)
  jsmafSet('board', board)
  jsmafSet('ui', ui)
  jsmafSet('board_build', BUILD)

  repaintPins()
  paintLastMark()
  renderStatus()
  repaintLog()
  pushLine('[board] blackboard ready (build ' + BUILD + ') — no autorun, press RUN USERLAND')
  pushLine('[board] left: buttons + status + pinned marks · right: live log (LOG ▲/▼)')

  // --- watcher: status + dump once JB is confirmed ---------------------------
  jsmaf.setInterval(function () {
    renderStatus()
    if (board.dumping || board.dumpDone) return
    if (board.stage !== 'idle' || !board.preflight) return
    if (board.uid !== 0 || board.sand !== 0) return
    if (!board.usb && Date.now() - board.lastUsbTry > 10000) {
      board.lastUsbTry = Date.now()
      board.usb = findUsb()
      if (!board.usb) board.dump = 'DUMP: JB OK but no USB mounted (/mnt/usb0-3/vue_debug.txt)'
    }
    if (board.usb) dumpKernel(board.usb)
  }, 700)
})()
