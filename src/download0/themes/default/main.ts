// ---------------------------------------------------------------------------
// debug-blackboard theme (manual mode) - layout "blackboard v2"
//
//   header : brand + version/build + live chips (fw, uid, sandbox, jb, kbase, t)
//   left   : ACCIONES (buttons) - ESTADO - SALIDA (usb -> 2 elf) - ULTIMA MARCA
//   centre : run log, 26 rows, tag column + message column (aligned by x)
//   right  : MARCAS, the 17 pinned marks as a pipeline map (dim = not reached)
//
// No autorun: the user presses RUN USERLAND, then PRUEBA 1/2/3.
// Every log() call repaints synchronously, so if the exploit blocks the thread
// the LAST MARK stays on screen as evidence.
//
// Nothing here is hardcoded: fw/uid/sandbox/kbase come from syscalls, the
// version/build come from %VERSION_TAG% / %VERSION_STRING% (replaced by CI).
// ---------------------------------------------------------------------------
import { fn, BigInt, mem, utils } from 'download0/types'
import { kernel } from 'download0/kernel'

;(function () {
  const BUILD = 'diag-build-2026-10-30'
  const VERSION_RAW = '%VERSION_TAG%'
  const COMMIT_RAW = '%VERSION_STRING%'
  const VERSION = VERSION_RAW.indexOf('%') === 0 ? 'dev' : VERSION_RAW
  const COMMIT = COMMIT_RAW.indexOf('%') === 0 ? 'local' : COMMIT_RAW
  const RING_MAX = 3000
  const HIST_MAX = 3000
  const LOG_COLS = 78
  const LOG_ROWS = 26
  const O_WRONLY = 1
  const O_CREAT = 0x200
  const O_TRUNC = 0x400
  const USB_IDS = ['0', '1', '2', '3']
  const DUMP_CHUNK = 0x10000
  const DUMP_MIN = 0x400000
  const DUMP_MAX = 0x4800000
  const DUMP_FALLBACK = 0x2400000

  // step states for the SALIDA panel
  const PENDING = 0
  const RUNNING = 1
  const DONE = 2
  const FAILED = 3

  // the pipeline, in order: the rail is a map, not a growing list
  const PINS = [
    'START', 'PR-CFG', 'PR-SATURATE-ENTER', 'PR-SATURATE', 'PR-POOL',
    'PR-WORKER-READY', 'ARM-FIN', 'PR-FIRE', 'PR-LEAK', 'PR-PASSA',
    'PR-PASSA-NOCROSS', 'PR-UCRED', 'ANCHOR-HANDLER', 'ANCHOR-KERNEL-BASE',
    'IDT-ALT', 'SWEEP-SUMMARY', 'FAIL-FINAL'
  ]

  const board = {
    ringT: [] as string[],
    ringM: [] as string[],
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
    dump: 'waiting for JB + USB',
    dumping: false,
    dumpDone: false,
    usb: null as string | null,
    lastUsbTry: 0,
    autoElf: true,
    logStep: PENDING,
    elfStep: PENDING,
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

  // --- styles (one per colour+size, created once) -----------------------------
  jsmaf.root.children.length = 0
  new Style({ name: 'bb-brand', color: '#41B883', size: 34 })
  new Style({ name: 'bb-name', color: '#FFFFFF', size: 26 })
  new Style({ name: 'bb-sub', color: '#8A96A3', size: 14 })
  new Style({ name: 'bb-sec', color: '#8A96A3', size: 13 })
  new Style({ name: 'bb-rule', color: '#28313B', size: 12 })
  new Style({ name: 'bb-lbl', color: '#5C6977', size: 11 })
  new Style({ name: 'bb-val', color: '#E6EAEF', size: 18 })
  new Style({ name: 'bb-val-ok', color: '#69DB7C', size: 18 })
  new Style({ name: 'bb-val-bad', color: '#FF6B6B', size: 18 })
  new Style({ name: 'bb-val-acc', color: '#FFD43B', size: 18 })
  new Style({ name: 'bb-btn', color: '#CED4DA', size: 20 })
  new Style({ name: 'bb-btn-sel', color: '#FFD43B', size: 20 })
  new Style({ name: 'bb-btn-off', color: '#6C757D', size: 20 })
  new Style({ name: 'bb-mark', color: '#FFD43B', size: 16 })
  new Style({ name: 'bb-mark2', color: '#8A96A3', size: 16 })
  new Style({ name: 'bb-pin', color: '#5C6977', size: 12 })
  new Style({ name: 'bb-pin-val', color: '#95A2AF', size: 13 })
  new Style({ name: 'bb-pin-bad', color: '#FF9C9C', size: 13 })
  new Style({ name: 'bb-val-sm', color: '#E6EAEF', size: 14 })
  new Style({ name: 'bb-val-sm-acc', color: '#FFD43B', size: 14 })
  new Style({ name: 'bb-foot', color: '#5C6977', size: 13 })
  new Style({ name: 'lg-sys', color: '#CFD6DE', size: 17 })
  new Style({ name: 'lg-rel', color: '#A9D3F5', size: 17 })
  new Style({ name: 'lg-net', color: '#8EE6A6', size: 17 })
  new Style({ name: 'lg-err', color: '#FF9C9C', size: 17 })
  new Style({ name: 'lg-warn', color: '#FFC978', size: 17 })
  new Style({ name: 'lg-tag', color: '#4C5764', size: 17 })
  new Style({ name: 'lg-tag-rel', color: '#2E7EC4', size: 17 })
  new Style({ name: 'lg-tag-ok', color: '#3C9D5C', size: 17 })
  new Style({ name: 'lg-tag-err', color: '#B94A4A', size: 17 })
  new Style({ name: 'lg-tag-warn', color: '#B8802F', size: 17 })

  function mkText (x: number, y: number, style: string) {
    const t = new jsmaf.Text()
    t.x = x
    t.y = y
    t.text = ''
    t.style = style
    jsmaf.root.children.push(t)
    return t
  }
  function mkRule (x: number, y: number, n: number) {
    const t = mkText(x, y, 'bb-rule')
    t.text = '-'.repeat(n)
    return t
  }

  // --- layout ---------------------------------------------------------------
  // columns: left 32..556 | centre 580..1500 | right 1524..1888
  const L_X = 32
  const C_X = 580
  const M_X = 852
  const R_X = 1524
  const BTN_Y = 132
  const BTN_PITCH = 60

  const CHIPS = [
    { k: 'FW', w: 66 },
    { k: 'UID', w: 74 },
    { k: 'SBX', w: 66 },
    { k: 'JB', w: 74 },
    { k: 'KBASE', w: 196 },
    { k: 'T', w: 78 }
  ]

  const ui = {
    brand: mkText(L_X, 24, 'bb-brand'),
    name: mkText(L_X + 78, 30, 'bb-name'),
    sub: mkText(L_X, 74, 'bb-sub'),
    chipsK: [] as jsmaf.Text[],
    chipsV: [] as jsmaf.Text[],
    btn: [] as jsmaf.Text[],
    stK: [] as jsmaf.Text[],
    stV: [] as jsmaf.Text[],
    usbK: mkText(L_X, 730, 'bb-lbl'),
    usbV: mkText(L_X + 46, 724, 'bb-val'),
    elfN: [] as jsmaf.Text[],
    elfT: [] as jsmaf.Text[],
    elfS: [] as jsmaf.Text[],
    autoK: mkText(L_X, 842, 'bb-lbl'),
    autoV: mkText(L_X + 92, 836, 'bb-val'),
    markK: mkText(L_X, 866, 'bb-sec'),
    mark: [] as jsmaf.Text[],
    logHdr: mkText(C_X, 112, 'bb-sec'),
    logPage: mkText(C_X + 520, 112, 'bb-sec'),
    logTag: [] as jsmaf.Text[],
    logMsg: [] as jsmaf.Text[],
    logFoot: mkText(C_X, 944, 'bb-foot'),
    logKeys: mkText(C_X, 968, 'bb-foot'),
    pinHdr: mkText(R_X, 112, 'bb-sec'),
    pinCnt: mkText(R_X + 250, 112, 'bb-sec'),
    pinT: [] as jsmaf.Text[],
    pinV: [] as jsmaf.Text[],
    pinFoot: mkText(R_X, 896, 'bb-foot'),
    foot: mkText(L_X, 1010, 'bb-foot')
  }

  ui.brand.text = 'VUE'
  ui.name.text = 'BLACKBOARD'
  ui.sub.text = 'relapse-663 · ' + BUILD
  ui.logHdr.text = 'LOG DE CORRIDA'
  ui.pinHdr.text = 'MARCAS'
  ui.markK.text = 'ULTIMA MARCA'
  ui.usbK.text = 'USB'
  ui.autoK.text = 'AUTO ELF'
  mkRule(L_X, 100, 330)
  mkRule(C_X, 136, 172)
  mkRule(R_X, 136, 66)

  // section titles
  mkText(L_X, 108, 'bb-sec').text = 'ACCIONES'
  mkText(L_X, 544, 'bb-sec').text = 'ESTADO'
  mkText(L_X, 706, 'bb-sec').text = 'SALIDA'

  const CHIP_GAP = 16
  {
    let total = 0
    for (const c of CHIPS) total += c.w + CHIP_GAP
    let x = 1888 - total + CHIP_GAP
    for (const c of CHIPS) {
      ui.chipsK.push(mkText(x, 26, 'bb-lbl'))
      ui.chipsV.push(mkText(x, 42, 'bb-val'))
      ui.chipsK[ui.chipsK.length - 1]!.text = c.k
      x += c.w + CHIP_GAP
    }
  }

  // 7 action buttons
  for (let i = 0; i < 7; i++) ui.btn.push(mkText(L_X + 12, BTN_Y + i * BTN_PITCH, 'bb-btn'))

  // estado: 3 cells + 2 cells + 1 wide (sweep)
  const SY = 568
  const ST_POS = [
    [L_X, SY], [L_X + 172, SY], [L_X + 344, SY],
    [L_X, SY + 46], [L_X + 172, SY + 46],
    [L_X, SY + 92]
  ]
  for (let i = 0; i < 6; i++) {
    const pos = ST_POS[i]!
    ui.stK.push(mkText(pos[0]!, pos[1]!, 'bb-lbl'))
    ui.stV.push(mkText(pos[0]!, pos[1]! + 15, 'bb-val'))
  }

  // salida: 2 elf steps
  for (let i = 0; i < 2; i++) {
    ui.elfN.push(mkText(L_X, 764 + i * 36, 'bb-val'))
    ui.elfT.push(mkText(L_X + 24, 764 + i * 36, 'bb-val'))
    ui.elfS.push(mkText(L_X + 250, 764 + i * 36, 'bb-val'))
  }

  // ultima marca: 2 lines
  ui.mark.push(mkText(L_X, 892, 'bb-mark'), mkText(L_X, 916, 'bb-mark2'))

  // log rows: tag column + message column
  for (let i = 0; i < LOG_ROWS; i++) {
    ui.logTag.push(mkText(C_X, 150 + i * 30, 'lg-tag'))
    ui.logMsg.push(mkText(M_X, 150 + i * 30, 'lg-sys'))
  }

  // marks rail: 17 items, tag line + value line
  const PIN_Y = 150
  const PIN_PITCH = 44
  for (let i = 0; i < PINS.length; i++) {
    ui.pinT.push(mkText(R_X, PIN_Y + i * PIN_PITCH, 'bb-pin'))
    ui.pinV.push(mkText(R_X, PIN_Y + 16 + i * PIN_PITCH, 'bb-pin-val'))
  }

  // --- log capture -----------------------------------------------------------
  function splitTag (msg: string) {
    if (msg.charAt(0) !== '[') return { tag: '', msg }
    const end = msg.indexOf(']')
    if (end < 0 || end > 34) return { tag: '', msg }
    let tag = msg.slice(1, end)
    const colon = tag.indexOf(':')
    if (colon >= 0) tag = tag.slice(colon + 1)
    return { tag, msg: msg.slice(end + 1).trim() }
  }

  function sourceStyle (msg: string) {
    if (msg.indexOf('FAIL') >= 0 || msg.indexOf('ERROR') >= 0 || msg.indexOf('NOCROSS') >= 0 ||
      msg.indexOf('NO-MATCH') >= 0 || msg.indexOf('OUT-OF-BOUNDS') >= 0) return 'lg-err'
    if (msg.indexOf('BENIGN-RETRY') >= 0 || msg.indexOf('WARN') >= 0 || msg.indexOf('stall') >= 0) return 'lg-warn'
    if (msg.indexOf('[relapse:') >= 0 || msg.indexOf('Relapse') >= 0) return 'lg-rel'
    if (msg.indexOf('[netctrl') >= 0 || msg.indexOf('kqueue') >= 0 || msg.indexOf('NetControl') >= 0) return 'lg-net'
    return 'lg-sys'
  }

  function tagStyle (st: string) {
    if (st === 'lg-err') return 'lg-tag-err'
    if (st === 'lg-warn') return 'lg-tag-warn'
    if (st === 'lg-rel') return 'lg-tag-rel'
    if (st === 'lg-net') return 'lg-tag-ok'
    return 'lg-tag'
  }

  function bumpCounts (msg: string) {
    if (msg.indexOf('[relapse:') >= 0) board.counts.rel++
    else if (msg.indexOf('[netctrl') >= 0 || msg.indexOf('kqueue') >= 0) board.counts.net++
    else if (msg.indexOf('[ldr]') >= 0 || msg.indexOf('[loader') >= 0 || msg.indexOf('[watchdog') >= 0) board.counts.ldr++
    else board.counts.board++
  }

  function trackPins (msg: string) {
    const p = splitTag(msg)
    if (p.tag === '' || PINS.indexOf(p.tag) < 0) return
    board.pins[p.tag] = p.msg.slice(0, 92)
    repaintPins()
  }

  function trackLastMark (msg: string) {
    if (msg.charAt(0) !== '[') return
    if (msg.indexOf('[board]') === 0) return
    const p = splitTag(msg)
    board.lastMark = (p.tag ? p.tag + ' · ' : '') + p.msg
    paintLastMark()
  }

  function pushLine (raw: string) {
    const msg = String(raw)
    board.history.push(msg)
    if (board.history.length > HIST_MAX) board.history.shift()
    const st = sourceStyle(msg)
    const p = splitTag(msg)
    const body = p.msg.length > 0 ? p.msg : msg
    let off = 0
    do {
      board.ringT.push(off === 0 ? p.tag : '')
      board.ringM.push(body.slice(off, off + LOG_COLS))
      board.ringS.push(st)
      off += LOG_COLS
    } while (off < body.length)
    const drop = board.ringT.length - RING_MAX
    if (drop > 0) {
      board.ringT.splice(0, drop)
      board.ringM.splice(0, drop)
      board.ringS.splice(0, drop)
    }
    bumpCounts(msg)
    trackPins(msg)
    trackLastMark(msg)
    if (!board.paging) repaintLog()
  }

  // --- log capture -----------------------------------------------------------
  // main.js is re-included every time the user comes back from the payload menu
  // (payload_host backKey). Re-wrapping log() each time would duplicate every
  // line, so the wrapper is installed ONCE and only the sink is swapped.
  const G = globalThis as unknown as Record<string, unknown>
  G.__blackboard_sink = pushLine
  let logPatched = false
  function hookLog (name: string): boolean {
    const cur = G[name]
    if (typeof cur !== 'function') return false
    const tagged = cur as unknown as { __bbWrap?: boolean }
    if (tagged.__bbWrap === true) return true
    const orig = cur as (msg: string) => void
    const wrapped = function (msg: string) {
      const sink = G.__blackboard_sink
      if (typeof sink === 'function') (sink as (m: string) => void)(String(msg))
      orig(msg)
    }
    ;(wrapped as unknown as { __bbWrap: boolean }).__bbWrap = true
    G[name] = wrapped
    return true
  }
  try { logPatched = hookLog('log') } catch (e) { /* log stays native */ }
  try { hookLog('debug') } catch (e) { /* debug stays native */ }

  // --- painters --------------------------------------------------------------
  function setText (t: jsmaf.Text, v: string, style?: string) {
    if (t.text !== v) t.text = v
    if (style !== undefined && t.style !== style) t.style = style
  }

  function repaintLog () {
    if (!board.paging) board.viewStart = Math.max(0, board.ringT.length - LOG_ROWS)
    let start = board.viewStart
    const tail = Math.max(0, board.ringT.length - LOG_ROWS)
    if (start > tail) start = tail
    for (let i = 0; i < LOG_ROWS; i++) {
      const idx = start + i
      if (idx < board.ringT.length) {
        const st = board.ringS[idx]!
        setText(ui.logTag[i]!, board.ringT[idx]!, tagStyle(st))
        setText(ui.logMsg[i]!, board.ringM[idx]!, st)
      } else {
        setText(ui.logTag[i]!, '')
        setText(ui.logMsg[i]!, '')
      }
    }
    const pages = Math.max(1, Math.ceil(board.ringT.length / LOG_ROWS))
    const page = Math.max(1, Math.min(pages, Math.ceil((start + LOG_ROWS) / LOG_ROWS)))
    setText(ui.logPage, 'pág ' + page + '/' + pages + ' · ring ' + board.ringT.length + '/' + RING_MAX +
      (board.paging ? ' · SCROLL' : ' · tail'))
  }

  function repaintPins () {
    let reached = 0
    let lastReached = -1
    for (let i = 0; i < PINS.length; i++) {
      const tag = PINS[i]!
      const val = board.pins[tag]
      const has = val !== undefined
      if (has) { reached++; lastReached = i }
      setText(ui.pinT[i]!, (i === lastReached ? '> ' : '  ') + tag, 'bb-pin')
      setText(ui.pinV[i]!, '   ' + (has ? val.slice(0, 48) : 'no alcanzado'),
        has ? (tag === 'FAIL-FINAL' ? 'bb-pin-bad' : 'bb-pin-val') : 'bb-pin')
      ui.pinT[i]!.alpha = has ? 1 : 0.55
      ui.pinV[i]!.alpha = has ? 1 : 0.3
    }
    setText(ui.pinCnt, reached + '/' + PINS.length)
    const nextIdx = lastReached + 1
    setText(ui.pinFoot, nextIdx < PINS.length ? 'siguiente · ' + PINS[nextIdx]! : 'pipeline completo')
  }

  function paintLastMark () {
    const s = board.lastMark
    let a = s.slice(0, 56)
    let b = ''
    if (s.length > 56) {
      let cut = s.lastIndexOf(' ', 56)
      if (cut < 32) cut = 56
      a = s.slice(0, cut)
      b = s.slice(cut).trim()
    }
    setText(ui.mark[0]!, a || '-')
    setText(ui.mark[1]!, b ? '   ' + b : '')
  }

  function readCreds () {
    if (!board.preflight) return
    if (board.stage === 'preflight' || board.stage === 'prueba') return
    const u = getUid()
    const s = getSandbox()
    if (u !== null) board.uid = u
    if (s !== null) board.sand = s
  }

  function renderHeader () {
    const fw = jsmafGet('fw_version') as string | undefined
    const jb = board.uid === 0 && board.sand === 0
    const kb = kbaseHex()
    const elapsed = Math.floor((Date.now() - board.started) / 1000)
    const mm = Math.floor(elapsed / 60)
    const ss = elapsed % 60
    setText(ui.chipsV[0]!, fw || '?', 'bb-val')
    setText(ui.chipsV[1]!, board.uid === null ? '?' : String(board.uid))
    setText(ui.chipsV[2]!, board.sand === null ? '?' : String(board.sand))
    setText(ui.chipsV[3]!, jb ? 'YES' : 'no', jb ? 'bb-val-ok' : 'bb-val-bad')
    setText(ui.chipsV[4]!, kb || '(pendiente)', kb ? 'bb-val-acc' : 'bb-val')
    setText(ui.chipsV[5]!, (mm < 10 ? '0' : '') + mm + ':' + (ss < 10 ? '0' : '') + ss)
    setText(ui.sub, 'relapse-663 · ' + BUILD + ' · v' + VERSION + ' (' + COMMIT + ')')
  }

  function renderStatus () {
    const path = jsmafGet('exploit_path') as string | undefined
    const phase = jsmafGet('relapse_phase') as string | undefined
    const done = !!jsmaf.vue_exploit_done
    const act = jsmafGet('relapse_activity') as number | undefined
    const idle = act ? ((Date.now() - act) / 1000).toFixed(1) + 's' : '-'
    const swp = (jsmafGet('sweep_summary') as string | undefined) || '-'
    const keys = ['stage', 'phase', 'idle', 'path', 'preflight', 'sweep']
    const vals = [
      board.stage + (done ? ' · DONE' : ''),
      phase || '-',
      idle,
      path || '-',
      board.preflight ? 'done' : 'pending',
      swp
    ]
    const styles = [
      'bb-val',
      phase !== undefined && phase.indexOf('FAIL') >= 0 ? 'bb-val-bad' : 'bb-val',
      'bb-val', 'bb-val',
      board.preflight ? 'bb-val-ok' : 'bb-val',
      'bb-val-sm-acc'
    ]
    for (let i = 0; i < keys.length; i++) {
      setText(ui.stK[i]!, keys[i]!.toUpperCase())
      setText(ui.stV[i]!, vals[i]!, styles[i])
    }
  }

  function elfStateText (step: number) {
    if (step === DONE) return 'ok'
    if (step === FAILED) return 'fail'
    if (step === RUNNING) return 'run'
    return 'pendiente'
  }

  function renderSalida () {
    if (board.usb) {
      setText(ui.usbV, board.usb, 'bb-val-ok')
    } else if (board.uid === 0 && board.sand === 0) {
      setText(ui.usbV, 'sin USB (jb ok, buscando)', 'bb-val-sm-acc')
    } else {
      setText(ui.usbV, 'esperando JB', 'bb-val')
    }
    setText(ui.elfN[0]!, '1')
    setText(ui.elfT[0]!, 'kernel.elf')
    let elfTxt = elfStateText(board.elfStep)
    if (board.elfStep === RUNNING) {
      elfTxt = (board.off / 1048576).toFixed(1) + '/' + (board.size / 1048576).toFixed(1) + ' MB'
    } else if (board.elfStep === DONE) {
      elfTxt = 'ok ' + (board.off / 1048576).toFixed(1) + ' MB'
    }
    setText(ui.elfS[0]!, elfTxt,
      board.elfStep === DONE ? 'bb-val-ok' : (board.elfStep === FAILED ? 'bb-val-bad' : 'bb-val'))
    setText(ui.elfN[1]!, '2')
    setText(ui.elfT[1]!, 'vue_debug.txt')
    const logTxt = board.logStep === DONE
      ? 'ok ' + board.history.length + ' msgs'
      : (board.logStep === FAILED ? 'fail' : 'pendiente')
    setText(ui.elfS[1]!, logTxt,
      board.logStep === DONE ? 'bb-val-ok' : (board.logStep === FAILED ? 'bb-val-bad' : 'bb-val'))
    setText(ui.autoV, board.autoElf ? '[x] tras JB' : '[ ] manual',
      board.autoElf ? 'bb-val-ok' : 'bb-val')
  }

  function renderFoot () {
    setText(ui.logFoot, 'tried 1:' + (board.tried1 ? 'y' : '-') + ' 2:' + (board.tried2 ? 'y' : '-') +
      ' 3:' + (board.tried3 ? 'y' : '-') + ' · rel ' + board.counts.rel + ' · net ' + board.counts.net +
      ' · ldr ' + board.counts.ldr + ' · board ' + board.counts.board + ' · ' + board.history.length + ' msgs')
    setText(ui.logKeys, 'teclas 6/5 mover · X activar · 4/7 atrás' + (logPatched ? '' : ' · log OFF'))
    setText(ui.foot, board.dump + '  ·  knobs ' + knobLine())
  }

  function renderAll () {
    readCreds()
    renderHeader()
    renderStatus()
    renderSalida()
    renderFoot()
    repaintPins()
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
      return 'retry=' + g('relapse_retries', 3) + ' spin=' + g('relapse_spin', 40000000) +
        ' towait=' + g('relapse_towait', 1000)
    } catch (e) { return '-' }
  }

  // --- buttons ---------------------------------------------------------------
  const BUTTONS = ['run.userland', 'prueba1', 'prueba2', 'prueba3', 'auto.elf', 'log.up', 'log.down']

  function sweepReady () {
    if (board.pins['PR-FIRE'] || board.pins['PR-LEAK'] || board.pins['PR-PASSA-NOCROSS'] || jsmafGet('sweep_ready')) return true
    return !!(board.tried1 && board.tried2)
  }
  function btnEnabled (id: string) {
    if (id === 'run.userland') return !board.preflight
    if (id === 'prueba1' || id === 'prueba2') return board.preflight && board.stage !== 'prueba'
    if (id === 'prueba3') return board.preflight && sweepReady()
    if (id === 'auto.elf') return true
    if (id === 'log.up') return board.ringT.length > LOG_ROWS
    if (id === 'log.down') return board.paging
    return false
  }
  function btnLabel (id: string) {
    if (id === 'run.userland') return 'RUN USERLAND'
    if (id === 'prueba1') return 'PRUEBA 1'
    if (id === 'prueba2') return 'PRUEBA 2'
    if (id === 'prueba3') return 'PRUEBA 3 - SWEEP'
    if (id === 'auto.elf') return board.autoElf ? 'AUTO ELF  [x]' : 'AUTO ELF  [ ]'
    if (id === 'log.up') return 'LOG ▲'
    if (id === 'log.down') return 'LOG ▼'
    return id
  }

  function updateButtons () {
    for (let i = 0; i < BUTTONS.length; i++) {
      const id = BUTTONS[i]!
      const sel = i === board.sel
      const on = btnEnabled(id)
      const t = ui.btn[i]!
      t.x = L_X + (sel ? 16 : 12)
      t.y = BTN_Y + i * BTN_PITCH
      setText(t, (sel ? '[> ' : '[  ') + btnLabel(id) + ' ]',
        sel ? (on ? 'bb-btn-sel' : 'bb-btn-off') : (on ? 'bb-btn' : 'bb-btn-off'))
      t.alpha = on ? 1 : 0.4
      t.scaleX = sel ? 1.08 : 1
      t.scaleY = sel ? 1.08 : 1
    }
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
      if (board.viewStart + LOG_ROWS >= board.ringT.length) {
        board.viewStart = Math.max(0, board.ringT.length - LOG_ROWS)
        board.paging = false
      }
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
    renderAll()
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
    renderAll()
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
    else if (id === 'auto.elf') {
      board.autoElf = !board.autoElf
      pushLine('[board] AUTO ELF ' + (board.autoElf ? 'ON' : 'OFF') + ' (JB -> usb -> kernel.elf + vue_debug.txt)')
      renderSalida()
      updateButtons()
    } else if (id === 'log.up') pageBy(1)
    else if (id === 'log.down') pageBy(-1)
  }

  const confirmKey = jsmaf.circleIsAdvanceButton ? 13 : 14
  jsmaf.onKeyDown = function (keyCode: number) {
    if (keyCode === 6 || keyCode === 5) {
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
    return 'VUE DEBUG BLACKBOARD ' + BUILD + ' v' + VERSION + ' (' + COMMIT + ')\n' +
      'when: ' + timestamp() + '\n' +
      'fw: ' + (fw || '?') + '\n' +
      'uid: ' + (board.uid === null ? '?' : board.uid) + ' sandbox: ' + (board.sand === null ? '?' : board.sand) + '\n' +
      'exploit: ' + (path || '-') + ' phase: ' + (phase || '-') + '\n' +
      'kbase: ' + (kbaseHex() || '-') + '\n' +
      'stage: ' + board.stage + ' tried: 1=' + (board.tried1 ? 'y' : '-') + ' 2=' + (board.tried2 ? 'y' : '-') + ' 3=' + (board.tried3 ? 'y' : '-') + '\n' +
      'sweep: ' + ((jsmafGet('sweep_summary') as string | undefined) || '-') + '\n' +
      (pins ? 'pinned:\n' + pins : '') +
      'log:\n'
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
        const ok = writeStr(fd.lo >>> 0, buildHead() + board.history.join('\n') + '\n')
        closeSys(fd.lo >>> 0)
        board.logStep = ok ? DONE : FAILED
        board.dump = ok ? 'log saved to ' + dir + '/vue_debug.txt' : 'log write failed on ' + dir
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
      board.dump = 'no kbase (exploit did not reach anchor)'
      board.elfStep = FAILED
      board.dumpDone = true
      return
    }
    if (!kernel.read_buffer) {
      board.dump = 'log saved, but no KRW (kernel.elf needs the relapse path)'
      board.elfStep = FAILED
      board.dumpDone = true
      return
    }
    board.dumping = true
    const info = imageSize(base)
    board.size = info.size
    board.off = 0
    const fd = openSys(dir + '/kernel.elf', O_WRONLY | O_CREAT | O_TRUNC)
    if (isError(fd)) {
      board.dump = 'cannot create kernel.elf'
      board.dumping = false
      board.elfStep = FAILED
      board.dumpDone = true
      return
    }
    board.fd = fd.lo >>> 0
    board.chunk = new Uint8Array(DUMP_CHUNK)
    board.bufAddr = utils.get_backing(board.chunk)
    board.elfStep = RUNNING
    board.dump = 'kernel.elf ' + (info.elf ? '(elf ' : '(raw ') + (info.size / 1048576).toFixed(1) + ' MB) starting...'
    jsmaf.setTimeout(dumpStep, 50)
  }

  function dumpStep () {
    if (board.off >= board.size || !board.chunk || !board.bufAddr) {
      closeSys(board.fd)
      board.dumping = false
      board.dumpDone = true
      board.elfStep = DONE
      board.dump = 'OK ' + (board.off / 1048576).toFixed(1) + ' MB -> ' + board.usb + '/kernel.elf'
      renderSalida()
      renderFoot()
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
      board.elfStep = FAILED
      board.dump = 'FAIL at ' + (board.off / 1048576).toFixed(1) + ' MB (krw/usb error)'
      renderSalida()
      renderFoot()
      return
    }
    board.off += n
    board.dump = 'kernel.elf ' + (board.off / 1048576).toFixed(1) + '/' + (board.size / 1048576).toFixed(1) +
      ' MB (' + Math.floor((board.off / board.size) * 100) + '%)'
    renderSalida()
    renderFoot()
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
  jsmafSet('board_version', VERSION + ' ' + COMMIT)

  renderAll()
  pushLine('[board] blackboard ready (build ' + BUILD + ' v' + VERSION + ')')
  pushLine('[board] no autorun · 6/5 mover · X activar · RUN USERLAND primero')

  // --- watcher: refresh + dump once JB is confirmed -------------------------
  // a previous include (back from the payload menu) may have left a timer alive
  const prevTimer = jsmafGet('board_timer') as number | undefined
  if (typeof prevTimer === 'number') {
    try { jsmaf.clearInterval(prevTimer) } catch (e) { /* ignore */ }
  }
  const timer = jsmaf.setInterval(function () {
    renderHeader()
    renderStatus()
    renderFoot()
    if (board.dumping || board.dumpDone) return
    if (!board.autoElf) return
    if (board.stage !== 'idle' || !board.preflight) return
    if (board.uid !== 0 || board.sand !== 0) return
    if (!board.usb && Date.now() - board.lastUsbTry > 10000) {
      board.lastUsbTry = Date.now()
      board.usb = findUsb()
      if (!board.usb) board.dump = 'JB OK but no USB mounted (/mnt/usb0-3/vue_debug.txt)'
      renderSalida()
    }
    if (board.usb) dumpKernel(board.usb)
  }, 700)
  jsmafSet('board_timer', timer)
})()
