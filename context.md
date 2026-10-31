# Contexto Vue 663 (debug-blackboard)

## Proyecto activo
- Repo: `vue-663` (`github.com/Francis-play/vue-663.git`)
- Rama: `debug-blackboard` (HEAD local, ver `git log -1`)
- Build: `diag-build-2026-10-29`
- Root: `E:/laragon/tmp/vue/vue-663`

## Stack y estructura
- React Native TV (`lucide-react-native`) → `themes/default/main.ts`
- `src/download0/themes/default/` (pizarra manual, sin autorun)
- `src/download0/loader.ts` (manual mode + `debug_start_relapse`)
- `src/download0/relapse.ts` (exploit 12.50/12.52/13.00/13.02/13.04)
- `src/download0/userland.ts`, `defs.ts`, `netctrl_c0w_twins.ts`
- Build: `babel --extensions .ts src --out-dir dist` (node RAM baja → CI lo cubre)
- CI: `.github/workflows/build.yml` (`build.yml`, `pages`, `release`)

## Bug Root Cause (crash "please wait" / fondo azul)
- `payloads/explode.ts` (`:371`) hace `include('themes/.../main.js')` DENTRO del handler de cierre del vídeo (Círculo → `video_close_handler` → `main.js` arranca síncrono).
- El tema (`main.js` original) hacía `include('loader.js')` síncrono ahí → arranca sin primer frame pintado (el usuario ve "please wait").
- Además, `repaintLog()` solo ocurría en `setInterval(500)` (`main.js` original) → al colgarse el hilo nunca pinta más: los logs nunca aparecen, solo queda la notificación `12.52 Detected!` fija.
- Fix aplicado: `main.ts` reescrito sin autorun (`runUserland()` manual), con `pushLine()` que pinta síncrono (`repaintLog()` inmediato), sin timer como único mecanismo.

## Estado actual del código (2026-10-30)
- `main.ts`: pizarra manual **layout v2** (`BUILD=diag-build-2026-10-30`), sin autorun.
  - cabecera: `VUE` (verde) + `BLACKBOARD` + `relapse-663 · <BUILD> · v<VER> (<COMMIT>)`; chips a la derecha `FW / UID / SBX / JB / KBASE / T`.
  - izquierda: `ACCIONES` (7 botones tipo ficha con `[> ... ]` y `scaleX/Y`), `ESTADO` (6 celdas), `SALIDA` (USB → 2 ELF), `ULTIMA MARCA` (2 líneas, corte por palabra).
  - centro: log de 26 filas con **columna de tag fija** (x=580) y **columna de mensaje** (x=852), `LOG_COLS=78`, paginado por `LOG_ROWS`, contador `pág n/m · ring x/3000 · tail|SCROLL`.
  - derecha: `MARCAS` 17 fijas (mapa de pipeline, `alpha` 0.55/0.3 si no alcanzada), `> ` en la última alcanzada, contador `n/17` y pie `siguiente · <tag>`.
  - Los `Style` se crean una sola vez (GC desactivado); `repaintLog()` se llama síncrono desde `pushLine()`.
  - Nada hardcodeado: `fw_version`, `uid`, `sandbox`, `kbase` salen de syscalls/`kernel.addr.base`; versión/build desde `%VERSION_TAG%` / `%VERSION_STRING%` (CI los reemplaza; en local cae a `dev/local`).
- `loader.ts`: `manual` branch (`jsmaf.debug_manual` corta antes del dispatch), `debug_start_relapse(attempt)` exportado (`1=0x1c1d00`, `2=0x1c1d40`, `3=auto+rva/sink/td_ucred sweep`).
- `relapse.ts`: `MAX_RETRIES`, `OWNER_LO/HI`, `N0SINK_OFF`, `TD_UCRED_OFF` como `let`; `FORCE_IDT`; `SWEEP_MODE`; `NO_FALLBACK`; `relapse_debug_reset()`; barridos: `sweepScanOwners()` (cada 512 iteraciones, acepta 49 hits), `whoHasF()` con sink scan + adopción (`SWEEP-SINK-ADOPT`), `relapse_pass()` con `tducTry` (0x130 → 0x128 → 0x138 → 0x140), `relapse_anchor_head()` con `RVA_CANDS` auto-solve.
- `preview.html`: mock web con controles (`simPreflight`, `simFailEarly`, `simAnchorFail`, `simSweep`, etc.).
- `preview1.html`: **generado** por `node tools/gen-preview.mjs [boot]` desde `dist/.../main.js` real (cada `Text`/`Style` del tema se convierte en un div posicionado a 1920×1080 y se escala a la ventana). `boot` = estado inicial, sin argumento = corrida demo completa.

## Pendiente / Recurrente
- [x] `context.md` creado (ver este archivo).
- [x] **Lint (eslint) corrido y limpio**: `main.ts`, `loader.ts`, `relapse.ts` → 0 errores (con `NODE_OPTIONS=--max-old-space-size=768`, archivo por archivo para evitar OOM).
- [x] **Build local OK**: `babel main.ts` → `dist/download0/themes/default/main.js` sin error (con `--max-old-space-size=900`).
- [x] **Smoke test OK**: `C:\Users\Franc\AppData\Local\Temp\opencode\smoke-blackboard.mjs` → SMOKE-OK (26 filas log, 17 pins, 7 botones, 6 status, 6 chips, teclas, preflight, gates, pines, paginado).
- [x] **Layout v2 portado a `main.ts`** (acciones tipo botón + rail de marcas fijo + panel SALIDA con USB→2 ELF) y verificado con captura headless (`real6.png` demo, `boot1.png` estado inicial).
- [ ] Persistencia automática de contexto entre sesiones (definida en `tropiezos.md` #8, aún manual).
- [ ] Probar en consola real: RUN USERLAND → PRUEBA 1 → reiniciar → PRUEBA 2 → PRUEBA 3.
- [x] `tropiezos.md` con los puntos nuevos.

## Bug encontrado y corregido en esta sesión (importante)
- Una edición con `oldString` fallido dejó **dos `renderStatus()`** en `main.ts` (duplicado en la línea 380 con el cuerpo corrupto/duplicado del archivo) → `eslint: 'renderStatus' is already defined` y babel `Unexpected token (716:1)`.
- Causa raíz: al aplicar el fix se reemplazó desde `function renderStatus () {` hasta `function knobLine ()`, pero el archivo ya tenía una copia buena en 289 y la rota en 380.
- Fix: eliminar el duplicado (380-411) y reindentar `jsmaf.onKeyDown` (la fusión `{    if` rompía `brace-style`/`no-multi-spaces`).
- **Regla nueva**: antes de insertar una función en un archivo grande, `rg -n "function <nombre>"` para verificar que no exista; y tras cada edit de bloque grande, `node --check dist/...` + `eslint`. Si el `edit` falla con "could not find oldString", **no reintentar a ciegas**: leer el rango exacto primero.


## Regla de RAM (tropiezo.md #13)
- La máquina (`Win32`) tiene ~3.9GB RAM total, con frecuencia <1.5GB libres (`Get-CimInstance Win32_OperatingSystem`).
- Babel (`preset-env`) hace OOM en esta máquina. No usar `node -e` con comillas complejas (`tropiezo.md #12`).
- Propuesta: para `runPrueba` usar `node` directo con archivo `.mjs` en `C:\Users\Franc\AppData\Local\Temp\opencode\`, no inline.

## Configuración de Git / Defender
- `core.autocrlf input` aplicado (`tropiezo.md #1`, `git config`).
- `.gitignore` asegurado (`node_modules/`, `*.zip`, `build/`, `.gradle/`).
- `E:\laragon\www\v3-rn` no tiene exclusión de Defender (requiere admin, pendiente).

## Datos recientes del proyecto
- Commit: ver `git log -1` (prefijo `vue-663(debug):`)
- Rama: `debug-blackboard` (`origin` apuntando a `francis-play/vue-663`)
- Archivo: `E:\laragon\tmp\vue\vue-663\context.md` (este archivo)
- Fecha: 2026-10-30 (viernes)
- Usuario: `Franc` (`Francis-play`)

## Notas rápidas (para la próxima sesión)
- Si `babel` falla de nuevo: usar `node -e` nunca con `"` anidados; escribir `.mjs` temporal (`C:\Users\Franc\AppData\Local\Temp\opencode\*.mjs`).
- `preview.html` = simulación interactiva; `preview1.html` = render literal generado con `node tools/gen-preview.mjs` (se regenera tras cada build; no editar a mano).
- `main.ts` no usa autorun (`no autorun` en el mensaje inicial); el usuario debe presionar `RUN USERLAND` primero.
- `runPrueba(3)` ahora funciona incluso sin `PR-FIRE` en los pins si `tried1 && tried2`, como diagnóstico automático.
