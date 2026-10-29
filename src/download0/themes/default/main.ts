// ---------------------------------------------------------------------------
// debug-blackboard theme
//
// No menu, no images, no music. On boot it auto-runs the exploit flow
// (loader.js) and turns the screen into a blackboard: live status, the last
// captured log lines, and an automatic kernel.elf dump to USB once the
// console is jailbroken.
// ---------------------------------------------------------------------------
import { fn, BigInt, mem, utils } from 'download0/types'
import { kernel } from 'download0/kernel'

;(function () {
  const MAX_LINES = 22
  const LINE_COLS = 146
  const BUILD = 'diag-build-2026-10-23'
  const O_WRONLY = 1
  const O_CREAT = 0x200
  const O_TRUNC = 0x400
  const USB_IDS = ['0', '1', '2', '3']
  const DUMP_CHUNK = 0x10000
  const DUMP_MIN = 0x400000
  const DUMP_MAX = 0x4800000
  const DUMP_FALLBACK = 0x2400000

  const board = {
    lines: [] as string[],
    started: Date.now(),
    loaderDone: false,
    loaderMs: 0,
    dump: 'DUMP: waiting for JB + USB',
    dumping: false,
    dumpDone: false,
    usb: null as string | null,
    lastUsbTry: 0,
    size: 0,
    off: 0,
    fd: -1,
    bufAddr: null as BigInt | null,
    chunk: null as Uint8Array | null
  }

  // --- log capture (best effort: patches the shell's global log) --------------
  const nativeLog = (typeof log === 'function') ? log : null
  function pushLine (raw: string) {
    const msg = String(raw)
    for (let i = 0; i < msg.length; i += LINE_COLS) {
      board.lines.push(msg.slice(i, i + LINE_COLS))
      if (board.lines.length > MAX_LINES) board.lines.shift()
    }
  }
  let logPatched = false
  if (nativeLog !== null) {
    try {
      ;(globalThis as unknown as Record<string, unknown>).log = function (msg: string) {
        pushLine(msg)
        nativeLog(msg)
      }
      logPatched = (globalThis as unknown as Record<string, unknown>).log !== nativeLog
    } catch (e) { /* log stays native */ }
  }

  // --- tiny kernel display helpers -------------------------------------------
  function hex64 (v: BigInt) {
    const hi = (v.hi >>> 0).toString(16).padStart(8, '0')
    const lo = (v.lo >>> 0).toString(16).padStart(8, '0')
    return '0x' + hi + lo
  }
  function getUid (): number | null {
    try {
      fn.register(24, 'getuid', [], 'bigint')
      const v = fn.getuid()
      return v instanceof BigInt ? (v.lo >>> 0) : v
    } catch (e) { return null }
  }
  function getSandbox (): number | null {
    try {
      fn.register(585, 'is_in_sandbox', [], 'bigint')
      const v = fn.is_in_sandbox()
      return v instanceof BigInt ? (v.lo >>> 0) : v
    } catch (e) { return null }
  }

  // --- UI: one Text per line, updated in place --------------------------------
  jsmaf.root.children.length = 0
  new Style({ name: 'dbg-title', color: 'white', size: 34 })
  new Style({ name: 'dbg-big', color: 'white', size: 26 })
  new Style({ name: 'dbg-mid', color: 'white', size: 22 })
  new Style({ name: 'dbg-body', color: 'white', size: 19 })
  new Style({ name: 'dbg-small', color: 'white', size: 16 })

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
    title: mkText(60, 34, 'dbg-title'),
    s1: mkText(60, 100, 'dbg-big'),
    s2: mkText(60, 142, 'dbg-mid'),
    s3: mkText(60, 180, 'dbg-mid'),
    sep: mkText(60, 220, 'dbg-small'),
    log: [] as jsmaf.Text[],
    dump: mkText(60, 992, 'dbg-mid'),
    foot: mkText(60, 1036, 'dbg-small')
  }
  for (let i = 0; i < MAX_LINES; i++) ui.log.push(mkText(60, 250 + i * 33, 'dbg-body'))
  ui.sep.text = '----------------------------------------------------------------------------------------------------------------------------------------------------'
  ui.title.text = 'VUE DEBUG — BLACKBOARD (' + BUILD + ')'

  function render () {
    const fw = (jsmaf as unknown as Record<string, unknown>).fw_version as string | undefined
    const path = (jsmaf as unknown as Record<string, unknown>).exploit_path as string | undefined
    const phase = (jsmaf as unknown as Record<string, unknown>).relapse_phase as string | undefined
    const done = !!jsmaf.vue_exploit_done
    const uid = getUid()
    const sand = getSandbox()
    const jb = uid === 0 && sand === 0
    let kbase: string | undefined
    try {
      const k = (typeof kernel !== 'undefined' && kernel && kernel.addr && (kernel.addr as Record<string, unknown>).base) ? (kernel.addr as Record<string, unknown>).base as BigInt : (jsmaf as unknown as Record<string, unknown>).kbase as BigInt | undefined
      if (k) kbase = hex64(k as BigInt)
    } catch (e) { /* no krw yet */ }
    const elapsed = ((Date.now() - board.started) / 1000).toFixed(1)
    const lastAct = (jsmaf as unknown as Record<string, unknown>).relapse_activity as number | undefined
    const idle = lastAct ? ((Date.now() - lastAct) / 1000).toFixed(1) : '-'

    ui.s1.text = 'FW ' + (fw || '?') + '   uid ' + (uid === null ? '?' : uid) + '   sandbox ' + (sand === null ? '?' : sand) +
      '   JB ' + (jb ? 'YES' : 'no') + (done ? '   EXPLOIT DONE' : '')
    ui.s2.text = 'path ' + (path || '-') + '   phase ' + (phase || '-') + '   idle ' + idle + 's   t ' + elapsed + 's'
    ui.s3.text = 'kbase ' + (kbase || '(pendiente)') + (logPatched ? '   log-capture ON' : '   log-capture OFF')
    ui.dump.text = board.dump
    ui.foot.text = 'loader ' + (board.loaderDone ? 'returned in ' + board.loaderMs.toFixed(1) + 's' : 'running/blocked') + '   stop with PS button'
    for (let i = 0; i < MAX_LINES; i++) {
      const n = board.lines.length
      const line = i < MAX_LINES - n ? '' : board.lines[i - (MAX_LINES - n)]
      ui.log[i]!.text = line || ''
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

  // --- USB detection + log dump ----------------------------------------------
  function findUsb () {
    for (const id of USB_IDS) {
      const dir = '/mnt/usb' + id
      const fd = openSys(dir + '/vue_debug.txt', O_WRONLY | O_CREAT | O_TRUNC)
      if (!isError(fd)) {
        board.usb = dir
        const uid = getUid()
        const sand = getSandbox()
        const fw = (jsmaf as unknown as Record<string, unknown>).fw_version as string | undefined
        const path = (jsmaf as unknown as Record<string, unknown>).exploit_path as string | undefined
        const phase = (jsmaf as unknown as Record<string, unknown>).relapse_phase as string | undefined
        let kbase = ''
        try {
          const k = (kernel.addr as Record<string, unknown>).base as BigInt | undefined
          if (k) kbase = hex64(k)
        } catch (e) { /* ignore */ }
        const head = 'VUE DEBUG BLACKBOARD ' + BUILD + '\n' +
          'when: ' + timestamp() + '\n' +
          'fw: ' + (fw || '?') + '\n' +
          'uid: ' + (uid === null ? '?' : uid) + ' sandbox: ' + (sand === null ? '?' : sand) + '\n' +
          'exploit: ' + (path || '-') + ' phase: ' + (phase || '-') + '\n' +
          'kbase: ' + (kbase || '-') + '\n' +
          'loader_ms: ' + board.loaderMs.toFixed(1) + '\n' +
          'log:\n'
        writeStr(fd.lo >>> 0, head + board.lines.join('\n') + '\n')
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
      const k = (kernel.addr as Record<string, unknown>).base as BigInt | undefined
      if (k) base = k
    } catch (e) { /* ignore */ }
    if (!base && (jsmaf as unknown as Record<string, unknown>).kbase) base = (jsmaf as unknown as Record<string, unknown>).kbase as BigInt
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
      const base = ((kernel.addr as Record<string, unknown>).base as BigInt | undefined) ||
        ((jsmaf as unknown as Record<string, unknown>).kbase as BigInt)
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

  // --- boot: force debug-friendly config, auto-run the exploit flow ---------
  try {
    if (typeof CONFIG !== 'undefined') {
      CONFIG.autoclose = false
      CONFIG.music = false
    }
  } catch (e) { /* ignore */ }
  ;(jsmaf as unknown as Record<string, unknown>).debug_board = true

  pushLine('[board] blackboard active (build ' + BUILD + ')')
  render()

  board.started = Date.now()
  try {
    include('loader.js')
  } catch (e) {
    pushLine('[board] loader include threw: ' + ((e as Error).message || String(e)))
  }
  board.loaderDone = true
  board.loaderMs = (Date.now() - board.started) / 1000
  pushLine('[board] loader returned after ' + board.loaderMs.toFixed(1) + 's')
  render()

  // --- watcher: repaint + start the dump when JB is confirmed ----------------
  jsmaf.setInterval(function () {
    render()
    if (board.dumpDone || board.dumping) return
    const uid = getUid()
    const sand = getSandbox()
    if (uid === 0 && sand === 0) {
      if (!board.usb && Date.now() - board.lastUsbTry > 10000) {
        board.lastUsbTry = Date.now()
        board.usb = findUsb()
      }
      const dir = board.usb
      if (!dir) {
        board.dump = 'DUMP: JB OK but no USB mounted (/mnt/usb0-3/vue_debug.txt)'
        return
      }
      dumpKernel(dir)
    } else if (board.loaderDone) {
      board.dump = 'DUMP: sin JB (uid/sandbox != 0) — no kernel.elf'
    }
  }, 500)
})()
