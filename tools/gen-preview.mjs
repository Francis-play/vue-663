// Generates preview1.html from the REAL built theme (dist/.../main.js).
// Every Text/Style the theme creates becomes an absolutely positioned div,
// so the screenshot is what the console will actually draw.
//
//   node tools/gen-preview.mjs            -> demo state (default)
//   node tools/gen-preview.mjs boot       -> fresh boot state
import fs from 'node:fs'
import path from 'node:path'

const root = process.cwd()
const distFile = path.join(root, 'dist/download0/themes/default/main.js')
const outFile = path.join(root, 'preview1.html')
const mode = process.argv[2]
const demo = mode !== 'boot'

const code = fs.readFileSync(distFile, 'utf8')

const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>VUE BLACKBOARD — render real (dist)</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  html,body{background:#05070A}
  #stage{display:flex;justify-content:center;padding:22px 0}
  #box{position:relative}
  #screen{position:absolute;top:0;left:0;width:1920px;height:1080px;transform-origin:0 0;overflow:hidden;
          background:#000;font-family:'Segoe UI',Inter,system-ui,sans-serif}
  .t{position:absolute;white-space:pre;transform-origin:0 0;line-height:1.15}
</style>
</head>
<body>
<div id="stage"><div id="box"><div id="screen"></div></div></div>
<script>
(function () {
  var STYLES = {}
  var screen = document.getElementById('screen')

  function Style (o) { STYLES[o.name] = { color: o.color, size: o.size } }

  function Text () {
    var self = this
    this.el = document.createElement('div')
    this.el.className = 't'
    screen.appendChild(this.el)
    this._x = 0; this._y = 0; this._text = ''; this._style = ''
    this._color = ''; this._alpha = 1; this._sx = 1; this._sy = 1
    this.apply = function () {
      var st = STYLES[self._style] || { color: '#fff', size: 16 }
      var e = self.el
      e.style.left = self._x + 'px'
      e.style.top = self._y + 'px'
      e.style.fontSize = st.size + 'px'
      e.style.color = self._color || st.color || '#fff'
      e.style.opacity = self._alpha
      e.style.transform = 'scale(' + self._sx + ',' + self._sy + ')'
      e.textContent = self._text
    }
    Object.defineProperty(this, 'x', { get: function () { return self._x }, set: function (v) { self._x = v; self.apply() } })
    Object.defineProperty(this, 'y', { get: function () { return self._y }, set: function (v) { self._y = v; self.apply() } })
    Object.defineProperty(this, 'text', { get: function () { return self._text }, set: function (v) { self._text = String(v); self.apply() } })
    Object.defineProperty(this, 'style', { get: function () { return self._style }, set: function (v) { self._style = v; self.apply() } })
    Object.defineProperty(this, 'color', { get: function () { return self._color }, set: function (v) { self._color = v; self.apply() } })
    Object.defineProperty(this, 'alpha', { get: function () { return self._alpha }, set: function (v) { self._alpha = v; self.apply() } })
    Object.defineProperty(this, 'scaleX', { get: function () { return self._sx }, set: function (v) { self._sx = v; self.apply() } })
    Object.defineProperty(this, 'scaleY', { get: function () { return self._sy }, set: function (v) { self._sy = v; self.apply() } })
    this.apply()
  }

  // --- 64-bit mock (ps4 shell maps BigInt to a 2-word object) ---
  function BigInt (hi, lo) {
    if (lo === undefined) { lo = hi; hi = 0 }
    this.hi = (hi >>> 0) >>> 0
    this.lo = (lo >>> 0) >>> 0
  }
  BigInt.prototype.add = function (n) {
    var add = (typeof n === 'object' && n !== null) ? n.lo : n
    var lo = this.lo + (add >>> 0)
    var carry = lo >= 0x100000000 ? 1 : 0
    return new BigInt(this.hi + carry, lo % 0x100000000)
  }

  var JB = ${demo ? 'true' : 'false'}

  var jsmaf = {
    root: { children: [] },
    Text: Text,
    setInterval: function (f) { return window.setInterval(f, 700) },
    setTimeout: function (f, t) { return window.setTimeout(f, t) },
    clearInterval: function (i) { window.clearInterval(i) },
    circleIsAdvanceButton: false
  }

  var include = function (name) {
    if (name === 'loader.js') { jsmaf.fw_version = '12.52'; jsmaf.loader_has_run = true }
  }
  var log = function () {}
  var debug = function () {}
  var CONFIG = { relapse_retries: 3, relapse_spin: 40000000, relapse_towait: 1000 }
  var fn = {
    register: function () {},
    getuid: function () { return new BigInt(0, JB ? 0 : 1001) },
    is_in_sandbox: function () { return new BigInt(0, JB ? 0 : 1) },
    open_sys: function () { return new BigInt(0, 4) },
    write_sys: function (fd, addr, len) { return new BigInt(0, (len && len.lo) || 0x10000) },
    close_sys: function () {}
  }
  var mem = { malloc: function () { return new BigInt(0, 0x1000) }, view: function () { return { setUint8: function () {} } } }
  var utils = { get_backing: function () { return new BigInt(0, 0x1000) } }
  var kernel = { addr: { base: null }, read_buffer: function (b, l) { return new Uint8Array(l) } }

  // expose the globals the theme patches (log/debug) and reads (CONFIG)
  window.log = log
  window.debug = debug
  window.CONFIG = CONFIG
  window.jsmaf = jsmaf

  // ---- THEME (real build from dist) ----
  function showErr (msg) {
    var d = document.createElement('div')
    d.style.cssText = 'position:absolute;left:20px;top:20px;right:20px;color:#FF6B6B;font:14px/1.4 monospace;white-space:pre-wrap;z-index:99'
    d.textContent = 'RUNTIME ERROR' + String.fromCharCode(10) + msg
    screen.appendChild(d)
  }
  window.addEventListener('error', function (ev) { showErr(ev.message + String.fromCharCode(10) + (ev.error && ev.error.stack || '')) })
  try {
${code}
  } catch (e) { showErr((e && e.stack) || String(e)) }
  // ---- end theme ----

  ${demo ? `
  // ---- demo run (only for the preview screenshot) ----
  var K = jsmaf.onKeyDown
  window.debug_start_relapse = function (n) {
    window.log('[relapse:START] try 1 maxRetries=' + (n === 3 ? 3 : 0) + ' idt=' + (n === 1 ? '0x1c1d00' : (n === 2 ? '0x1c1d40' : 'auto')))
    window.log('[relapse:DEBUG-RESET] attempt=' + n + ' retries=' + (n === 3 ? 3 : 0) + ' sweep=' + (n === 3 ? 1 : 0) + ' noFallback=1')
    if (n === 3) {
      ['PR-CFG','PR-SATURATE-ENTER','PR-SATURATE','PR-POOL','PR-WORKER-READY','ARM-FIN'].forEach(function (t, i) {
        window.log('[relapse:' + t + '] step ' + (i + 1) + ' ok')
      })
      window.log('[relapse:PR-FIRE] passA nodes=262144 sink_moved=3 node0_sink=1')
      window.log('[relapse:PR-LEAK] hits=51 walked=30211/262144 uniq=1')
      window.log('[relapse:SWEEP-OWNER] offset=0x18 hits=163 (default 0x18)')
      window.log('[relapse:SWEEP-SINK-ADOPT] sink_off -> 0x28 hits=12')
      window.log('[relapse:PR-PASSA] m=19 -> k=32750')
      window.log('[relapse:SWEEP-TDUCRED] nocross 0x130 -> try 0x128 (2/4)')
      window.log('[relapse:PR-UCRED] ucred=0xffff88800a1b2c30')
      window.log('[relapse:ANCHOR-HANDLER] handler=0xffffffff8022c140')
      window.log('[relapse:SWEEP-RVA] rva=0x1c1d40 (was 0x1c1d00) aligned 0x4000')
      window.log('[relapse:ANCHOR-KERNEL-BASE] kernel_base=0xffffffff80200000')
      jsmaf.relapse_phase = 'FAIL-FINAL'
      window.log('[relapse:FAIL-FINAL] kf: sysctl oid window did not open')
      window.log('[relapse:SWEEP-SUMMARY] owner=0x18 sink=0x28 tduc=0x128 anchor-ok')
    }
  }
  K(14)                      // RUN USERLAND
  K(6); K(14)                // PRUEBA 1
  K(6); K(14)                // PRUEBA 2
  K(6); K(14)                // PRUEBA 3 (SWEEP)
  jsmaf.sweep_summary = 'owner=0x18 sink=0x28 tduc=0x128 anchor-ok'
  jsmaf.kbase = new BigInt(0xffffffff, 0x80200000)
  ` : ''}

  // scale to the window
  var box = document.getElementById('box')
  function fit () {
    var s = Math.min(1, (window.innerWidth - 44) / 1920, (window.innerHeight - 44) / 1080)
    screen.style.transform = 'scale(' + s + ')'
    box.style.width = (1920 * s) + 'px'
    box.style.height = (1080 * s) + 'px'
  }
  window.addEventListener('resize', fit)
  fit()
})()
</script>
</body>
</html>
`

fs.writeFileSync(outFile, html)
console.log('wrote', outFile, html.length, 'bytes (demo=' + demo + ')')
