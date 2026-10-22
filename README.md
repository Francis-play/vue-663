<p align="center">
    <img width="25%" height="25%" alt="logo2" src="https://github.com/user-attachments/assets/5596a357-61c3-471c-9a1e-b8c3d6de33c8" />
</p>

<h1 align="center"> Vue-After-Free — 663 (Relapse) </h1>
<p  align="center">
    PlayStation Vue userland code execution exploit for PS4, with the 663 (Relapse) entry.
</p>

> [!NOTE]
> This is a port of [Vuemony/vue-after-free](https://github.com/Vuemony/vue-after-free). It adds the **663 (Relapse)** jailbreak behaviour, its **own updater** (bootstrapped once over FTP), and **CI-built `download0.dat` images** (normal & lite) published as release assets. For the base app install see the upstream repo.

# Compatibility (choose by firmware)

| vue-after-free (Userland) | Lapse (KEX) | Netctrl (KEX) | Relapse / 663 (KEX) |
| :------------------------ | :---------- | :------------ | :------------------ |
| 5.05–13.04                | 1.01–12.02  | 1.01–13.00    | 13.02–13.04 (stable) · 12.50–13.00 (experimental) |

* 663 (Relapse) is **this repo's** entry. Relapse itself supports up to **13.52**, but this repo only ships **13.02–13.04** as tested; **12.50 / 12.52 / 13.00** are new and **experimental** (kernel table cross-validated, **not yet hardware-tested** — on failure they fall back to Netctrl automatically).
* Any other firmware keeps using Lapse / Netctrl.
* The userland exploit works 5.05–13.04 as is.

# Setup — pick your path in 10 seconds

| Your console | PS Vue installed | What to do |
| :--- | :--- | :--- |
| Jailbroken | YES | **Route A** — bootstrap the updater (1 FTP file, once) → run `updater` |
| Jailbroken | NO | **Route B** — flash `download0.dat` (full image, one FTP file) |
| NOT jailbroken | YES | **Route A** — the `ftp-server` payload is userland, works pre-JB (Case C) |
| NOT jailbroken | NO | Install the base app with an upstream no-JB method first, then Route A (Case D) |

> [!IMPORTANT]
> A network connection of any kind is always required to launch the exploit. See [Connecting to the internet](#connecting-to-the-internet).

---

## Route A — Bootstrap the updater (1 FTP file, once)

**Short version:** install the base PS Vue app if you don't have it → open Vue → run `ftp-server` → replace `payloads/updater.js` with this repo's `ftp/updater.js` → run the `updater` payload → relaunch and press **Jailbreak**.

<details>
<summary><b>Case A — Console already jailbroken + PS Vue installed</b> (most common)</summary>

1. Connect the console to a local network (see [Connecting to the internet](#connecting-to-the-internet)).
2. Open **PS Vue → Payloads → `ftp-server`**. It shows an address on screen: `ftp://<ip>:<port>` (the port is dynamic). Note it.
3. On your PC, download this repo's updater: open [`ftp/updater.js`](https://github.com/Francis-play/vue-663/blob/main/ftp/updater.js) and press **Raw**, then save it **exactly** as `updater.js` (make sure it is not `updater.js.txt`).
4. Connect with your FTP client (FileZilla, WinSCP, etc.) to that `<ip>:<port>`.
5. Navigate to the app's `payloads` folder and **replace `updater.js`** with the file from step 3. One file only.
6. In **Vue → Payloads → `updater`**. Wait until it says **Update Complete**. It only fetches what is missing (GoldHEN as `payload.bin`, plus `hen.bin`, on first run).
7. If the updater says a bin must be sent by FTP (size gate), upload it to the app's `payload.bin` (GoldHEN) or `payloads/hen.bin` once. `payload.bin` is what binloader auto-loads first.
8. Fully close Vue (PS button → **Close Application**) and open it again.
9. Press **Jailbreak** and watch the on-screen log.
   * The Jailbreak button auto-detects firmware: 13.02/13.04 → Relapse; 12.50–13.00 → Relapse (experimental, Netctrl fallback); older → Lapse. Force a specific one in **Config → JB Behavior**.
10. When the exploit finishes, Vue listens on port **9020**. If HEN did not autoload from `payloads`, send your `.bin` from the PC to `<console-ip>:9020` (netcat / payload sender).
11. From now on, updating = run the **`updater`** payload and relaunch. No FTP needed.

</details>

<details>
<summary><b>Case C — Console NOT jailbroken + PS Vue installed</b></summary>

> The `ftp-server` payload is **userland** and works **without** a jailbreak, so you can bootstrap the updater first.

1. Open Vue and do steps 1–7 of **Route A / Case A** (run `ftp-server`, replace `ftp/updater.js`, run the `updater` payload).
2. Jailbreak the console with your usual method, then reopen Vue.
3. Press **Jailbreak** and continue with steps 10–11 of **Route A / Case A**.

</details>

---

## Route B — Flash `download0.dat` (full image, one FTP file)

Instead of bootstrapping the updater file-by-file, flash this repo's prebuilt **UFS2 image** with everything inside (UI, updater, exploits, payloads, GoldHEN). Built automatically by CI on every push.

> [!WARNING]
> Route B needs **FTP access on a jailbroken console** (full-system FTP payload, e.g. Al-Azif's or GoldHEN's built-in FTP). The in-app `ftp-server` is sandboxed: it **cannot** write to `/user/download/`. Route B also **resets `config.json`** to defaults.

**How to flash:**

1. Get the image:
   * From **Releases** → download `download0_dat_uf2.zip` (or `download0_dat_lite_uf2.zip`), or
   * From **Actions** → latest build run → artifact `download0_dat_uf2.zip` (needs a GitHub login for artifact downloads).
2. Extract the zip on your PC → `download0.dat` (~256 MB).
3. On the console, run a full FTP payload with your jailbreak (Al-Azif's FTP, GoldHEN FTP, etc.).
4. Upload the file to **`/user/download/CUSA00960/download0.dat`**, overwriting the existing one (rename the old one first if you want to keep it).
5. Close and reopen **PS Vue**. Done — no bootstrap, the app already carries this repo's whole setup. Later updates go through the `updater` payload (Route A step 11), no FTP needed.

**When to choose which:**

| Situation | Route |
| :--- | :--- |
| You want the fastest full install and have JB FTP | **Route B** |
| You only want to swap files / iterate | **Route A** |
| `updater` is broken or the app is in a weird state | Re-flash via **Route B** |
| lite variant (auto-JB, closes app itself, no menu) | Route B with `download0_dat_lite_uf2.zip` |

<details>
<summary><b>Case B — Console already jailbroken + PS Vue NOT installed (upstream app install, then use this repo's image)</b></summary>

1. Install the base PS Vue app first, following the upstream **Jailbroken PS4** method (FTP `download0.dat` to `/user/download/CUSA00960/`, pkg 1.01 + 1.24 patch, save via Apollo Save Tool): [Vuemony/vue-after-free → Setup Instructions](https://github.com/Vuemony/vue-after-free#setup-instructions).
2. **Instead of the upstream's `download0.dat`**, flash this repo's image in step 4 of **Route B** — same procedure, but you get the 663/updater version directly.
3. Remember the **fake-signin save restore** (Apollo) is still required for a fresh install — the image does not carry it.

</details>

<details>
<summary><b>Case D — Console NOT jailbroken + PS Vue NOT installed</b></summary>

1. Get a jailbreak on the console first (your usual method), then install the base PS Vue app using the upstream **Jailbroken PS4** method.
   * No way to jailbreak yet? Use one of the upstream no-JB install methods (**Extended Storage** or **System Backup**) first.
2. Come back and follow **Route A** (or **Route B**, now that you have JB FTP).

</details>

---

## Requirements
* Any kind of network connection to launch the app.
* Fake or legit activated PS4 user account.
* FTP access to the console (Route A: one-time sandbox bootstrap — Route B: full FTP on a jailbroken console).
* USB flash drive (for the base install / HEN or GoldHEN).
* PlayStation Vue 1.01 base + 1.24 patch, if installing fresh. [Download](https://www.mediafire.com/file/45owcabezln2ykm/CUSA00960.zip/file)

> [!WARNING]
> Restoring a system backup (Case D, upstream method) **erases all data** on the console.

# Connecting to the internet
  1. Navigate to Settings > System > Automatic Downloads, and uncheck "Featured Content", "System Software Update Files" and "Application Update Files".
  2. Navigate to **Settings > Network > Set Up Internet Connection**.
  3. Choose your connection type:
     - **Use WiFi** > **Custom** Scroll to the bottom and select **Set Up Manually** > **Enter Manually** Enter your network name then set security to "WPA-PSK/WPA2-PSK" and put in the password. Proceed to the next step.
     - **Use a LAN Cable** > **Custom**: Proceed to the next step.
  4. **IP Address Settings**: `Automatic`.
  5. **DHCP Host Name**: `Do not Specify`.
  6. **DNS Settings**: `Manual`.
  7. Set **Primary DNS** to `127.0.0.2` or `62.210.38.117` (leave Secondary DNS blank). `127.0.0.2` limits you to local network only; the `62.210...` Nomadic DNS blocks Sony servers while allowing normal internet.
  8. **MTU Settings**: "Automatic". **Proxy Server**: "Do Not Use".
  9. Press **Test Internet Connection** and wait.
> [!NOTE]
> Getting an IP but no internet means the `62.210...` DNS is working. A successful internet connection means the DNS was not applied (local network limitation) — use `127.0.0.2`.
* The internet connection failing does not mean the console cannot connect, it means the PS4 cannot talk to Sony servers (that is the point of the DNS).

# Config
For some config changes to apply, the application must be closed and opened again.
Vue comes with a few custom options. The **Jailbreak button** auto-detects firmware and picks the matching exploit. In the config menu, under **JB Behavior**, you can choose:
  * **Auto Detect** — default. Below 12.50 → Lapse. 12.50–13.00 → Relapse (experimental, auto Netctrl fallback). 13.02/13.04 → Relapse.
  * **Lapse** — forced, 7.00–12.02.
  * **NetControl** — forced, 12.50–13.00 (runs on 9.00+).
  * **Relapse (663)** — forced. Stable on 13.02–13.04; experimental on 12.50/12.52/13.00 (fails safe back to Netctrl).

Other options: **Auto Lapse** / **Auto Relapse** (launch a kernel exploit on opening the app), **Auto Close** (close the app after a successful jailbreak), **Auto GoldHEN** (see below), **Music** (on/off — background music loads only after the jailbreak finishes, never during the exploit), **Theme**.

### Auto GoldHEN
Default **ON**. Controls which HEN-family payload is applied:
* **ON** — the auto payload is GoldHEN, shipped as `payload.bin` (app root) and loaded first by binloader.
* **OFF** — GoldHEN is not downloaded/applied; `hen.bin` (in `payloads/`) is loaded instead. The app warns "GoldHEN auto OFF".

The updater honors this: if GoldHEN is already present it is not re-downloaded; if missing and the switch is ON it is downloaded and applied; if OFF, HEN is applied instead.

# Payloads
Vue After Free comes preloaded with some payloads.

> [!IMPORTANT]
> The np-fake-signin should not be run on a real PSN account.

## FTP
The `ftp-server.ts` payload gives you sandbox FTP to quickly swap exploit or cosmetic files without running a kernel exploit.

## ELFLDR
`elfldr.elf` is used to load elf and bin payloads post-exploit when HEN or GoldHEN have not been loaded.

## WebUI
Example code for running userland code with the browser as the UI (possible alternative to jsmaf).

# Update
The **`updater`** payload grabs the latest files from this repo's GitHub Pages (`BASE_URL`) without reinstalling anything. Only works for the normal UI version, not for Lite mode.

* First time only: bootstrap it over FTP ([Route A](#route-a--bootstrap-the-updater-1-ftp-file-once)) — or skip it entirely by flashing [`download0.dat`](#route-b--flash-download0dat-full-image-one-ftp-file) ([Route B](#route-b--flash-download0dat-full-image-one-ftp-file)).
* After that: run `updater` from the Payloads menu and relaunch.
* If GoldHEN (`payload.bin`) is already present it is **not** re-downloaded. If missing: with **Auto GoldHEN ON** it is downloaded and applied; with it **OFF**, HEN is applied instead.
* Bins are downloaded on demand and size-checked: GoldHEN as `payload.bin` (app root, auto-loaded first) and `hen.bin` (in `payloads/`, manual). If a bin is flagged, send it over FTP once.
* A full re-install / recovery shortcut: re-flash the image ([Route B](#route-b--flash-download0dat-full-image-one-ftp-file)) — one FTP file, config back to defaults.

# Themes
Themes can be added by copying the folder to `/download0/themes/`. The default theme is a good example.

# FAQ & Troubleshooting

**Q: Will this work on 13.02 or above?**
Only the userland and the 663 (Relapse) entry. This repo ships **13.02–13.04** stable; **12.50/12.52/13.00** are experimental with automatic Netctrl fallback. Relapse supports up to 13.52, but files above 13.04 are not provided here yet.

**Q: Do I need an internet connection?**
You need any form of a network connection, not specifically internet. Vue will not launch the exploit without one and will show "There was a problem connecting to the internet". See [Connecting to the internet](#connecting-to-the-internet).

**Q: I am getting "There is a network communication issue".**
Either Vue updated or the save file reset. Use your own profile backup's save, or recover the save (upstream `OnlineSave` / system backup). See the upstream [Getting the jailbreak again](https://github.com/Vuemony/vue-after-free#getting-the-jailbreak-again) section.

**Q: I am getting "This service requires you to sign in to PlayStation Network" even after replacing the save file.**
Your Vue app most likely updated. Use a DNS to block Sony, then delete and reinstall the app (upstream Extended Storage method).

**Q: I ran Vue and the app crashed / the console shut down.**
The exploit failed. If it crashed, shut down and retry. On a kernel panic, press the power button twice, then retry.

**Q: How can I run a payload?**
Closing and reopening Vue is required between running JS payloads, but `.bin` / `.elf` payloads can be run one after the other from the Payload Menu.

**Q: My payload is not recognized.**
Format your USB drive as MBR partition and exFAT.

**Q: The updater says a bin is "FTP needed".**
The downloaded size did not match, so it was discarded on purpose. Send that bin to `payloads` over FTP once.

**Q: Which exploit ran on my firmware?**
The on-screen log says it: 12.02 and below → Lapse; 12.50–13.00 → Relapse (falls back to "NETCTRL-FALLBACK" in the log if the experimental tables miss); 13.02–13.04 → Relapse.

> [!IMPORTANT]
> The Vue save file may occasionally reset. Copy the encrypted save to a USB (PS4 settings menu) for easy recovery.

> [!IMPORTANT]
> DO NOT change your np environment via Debug Settings. It breaks backup save compatibility and the fake sign-in payload.

# Credits
Port / 663 (Relapse) entry: francis-play.

Based on [Vuemony/vue-after-free](https://github.com/Vuemony/vue-after-free):
- [c0w-ar](https://github.com/c0w-ar/) — Lapse and NetCtrl porting, Reverse Engineering
- [earthonion](https://github.com/earthonion) — UI, initial JS injection, Payload host, Netctrl porting, binloader, Reverse engineering and remote installer
- [ufm42](https://github.com/ufm42) — Userland Exploit and reverse engineering
- [D-Link Turtle](https://github.com/iMrDJAi) — General support for userland exploitation
- [Gezine](https://github.com/gezine) — Local JS method and PSN bypass research
- [Helloyunho](https://github.com/Helloyunho) — TypeScript port, Reverse Engineering
- [Dr.Yenyen](https://github.com/DrYenyen) — Extensive testing, quality control, end-user support/ideas, system backup and extended storage method
- [AlAzif](https://github.com/Al-Azif) — Reference for exploit table, retail application advice, Lapse AIO Fix kpatches and 12.50-13.00 kpatches
- abc — Lapse
- [TheFlow](https://github.com/TheOfficialFloW) — NetCtrl
- [Lua Loader project](https://github.com/shahrilnet/remote_lua_loader) — Remote Lua loader foundation
- [Cryptogenic](https://github.com/Cryptogenic/PS4-6.20-WebKit-Code-Execution-Exploit) — Reference for CVE-2018-4441
- [rebelle3](https://github.com/rebelle3/cve-2017-7117) — Reference for CVE-2017-7117

Relapse AIO multi-cancel KEX based on [jb-polpno](https://github.com/mansoor0x0/jb-polpno) by mansoor0x0.

## payload sources:
- [elfldr.elf](https://github.com/ps4-payload-dev/elfldr) by John Törnblom
- [AIOfix_network.elf](https://github.com/Gezine/BD-JB-1250/blob/main/payloads/lapse/src/org/bdj/external/aiofix_network.c) by Gezine
- [np-fake-signin](https://github.com/earthonion/np-fake-signin) by earthonion

---

# Guía rápida (Español)

> Resumen en 2 caminos:
> - **RUTA A**: ya tienes Vue → bootstrap del updater por FTP **una sola vez** → después se actualiza con el payload `updater`, sin FTP.
> - **RUTA B**: no tienes Vue (o quieres reinstall ful) → flasheas el `download0.dat` de este fork (FTP con jailbreak, 1 archivo) → listo, no necesita bootstrap.

### ¿Qué camino me toca?

| Tu consola | ¿Vue instalado? | Ruta |
| :--- | :--- | :--- |
| JB sí | Sí | **RUTA A** (bootstrap updater) |
| JB sí | No | **RUTA B** (flash `download0.dat`) |
| JB no | Sí | **RUTA A** (el `ftp-server` funciona sin JB) |
| JB no | No | Instala la app con método sin-JB del repo base, luego **RUTA A** o **B** |

<details>
<summary><b>RUTA A — CASO 1: Ya tienes JB y ya tienes Vue instalado (más común)</b></summary>

Necesitas: PC y consola en la misma red.

1. En la PC abre este link: https://github.com/Francis-play/vue-663/blob/main/ftp/updater.js
2. Presiona el botón **Raw** (arriba a la derecha), se abre el texto solo.
3. Guardalo:
   - En PC: **Ctrl + S**, nombre `updater.js` (ojo: que no quede como `updater.js.txt`).
   - En teléfono (Chrome): **3 puntitos** → **Descargar** (si baja con otro nombre, renombralo a `updater.js`).
4. En el PS4 abre Vue → **payloads** → corre `ftp-server`. Te muestra una dirección `ftp://<ip>:<puerto>`, anótala.
5. En la PC abre FileZilla (o el FTP que uses) y conéctate a esa dirección.
6. Busca la carpeta `payloads` y reemplaza el `updater.js` que está ahí con el que descargaste. Es **un solo archivo**.
7. En Vue → **payloads** → corre `updater`. Espera a que diga **Update Complete**. Trae solo lo que falta: GoldHEN como `payload.bin` (raíz del app, se auto-carga primero) y `hen.bin` en `payloads/`.
8. GoldHEN (`payload.bin`) lo toma el binloader solo. `hen.bin` queda en el Payload Menu para correr a mano. Si el updater dijo que alguno va por FTP, súbelo una vez.
9. Cierra Vue por completo (botón PS → cerrar aplicación) y ábrelo de nuevo.
10. Presiona **Jailbreak** y mira el log en pantalla. El botón detecta la FW solo: 13.02/13.04 → Relapse; 12.50–13.00 → Relapse (experimental, con fallback a Netctrl); más viejas → Lapse.
    - Si querés forzar algo: **Config → JB Behavior** y de nuevo **Jailbreak** en el menú principal.
11. Cuando termine, Vue queda escuchando en el puerto **9020**: si el HEN no cargó solo desde `payloads`, manda tu bin desde la PC a `<ip-consola>:9020`.
12. De ahí en más, cada actualización: corre `updater` y listo, sin FTP.

</details>

<details>
<summary><b>RUTA B — CASO: flashear download0.dat (imagen completa, 1 archivo FTP)</b></summary>

Reemplaza TODO el contenido de la app por esta imagen UFS2 que compila el CI automáticamente en cada push.

> OJO: requiere **FTP con jailbreak** (payload de FTP completo tipo Al-Azif o el FTP de GoldHEN). El `ftp-server` interno de Vue está en sandbox y **no** puede escribir en `/user/download/`. Además el flash **resetea `config.json`** a defaults.

1. Baja la imagen:
   - En **Releases** del repo: `download0_dat_uf2.zip` (o `download0_dat_lite_uf2.zip` para la variante lite).
   - O en **Actions** → el último run → artifact (necesita cuenta de GitHub para ver artifacts).
2. Descomprime el zip en la PC → queda `download0.dat` (~256 MB).
3. En la consola corre tu payload de FTP **completo** (con el JB activo).
4. Sube el archivo a **`/user/download/CUSA00960/download0.dat`**, reemplazando el que está (renombrá el viejo antes si lo querés guardar).
5. Cierra y vuelve a abrir **PS Vue**. Listo — no hace falta bootstrap. Las actualizaciones siguen después con el payload `updater`, sin FTP.

</details>

<details>
<summary><b>RUTA B — CASO 2: Ya tienes JB pero NO tienes Vue instalado</b></summary>

1. Instala la app base PS Vue siguiendo el método **Jailbroken PS4** del repo base (pkg 1.01 + parche 1.24, save con Apollo).
   Link: https://github.com/Vuemony/vue-after-free (sección **Setup Instructions → Jailbroken PS4**).
2. **En vez del `download0.dat` del repo base**, flashea el de este fork siguiendo la **RUTA B** paso 4 — mismo procedimiento, y de una llevas la versión 663 con updater.
3. Igual recuerda el **save restore de fake-signin** (Apollo): es paso aparte, la imagen no lo trae.

</details>

<details>
<summary><b>RUTA A — CASO 3: NO tienes JB pero SÍ tienes Vue instalado</b></summary>

> El payload `ftp-server` es **userland** y funciona **sin** jailbreak, así que puedes bootstrapear el updater primero.

1. Abre Vue y haz los pasos 1–7 del **CASO 1** (correr `ftp-server`, reemplazar `ftp/updater.js`, correr `updater`).
2. Haz jailbreak con tu método actual y vuelve a abrir Vue.
3. Presiona **Jailbreak** y sigue desde el paso 11 del **CASO 1**.

</details>

<details>
<summary><b>CASO 4: NO tienes JB y NO tienes Vue instalado</b></summary>

1. Primero consigue jailbreak con tu método actual y luego instala la app base (método **Jailbroken PS4** del repo base).
   - Si todavía no puedes jailbreakear, usa uno de los métodos sin-JB del repo base (**Extended Storage** o **System Backup**).
2. Con Vue abierto, vuelve al **CASO 1** (o flashea el dat ahora que tienes JB — **RUTA B**).

</details>

### Para reportar (copia y pega esto)
```
FW: 13.02 / 13.04 / 12.50 / 12.52 / 13.00 (Fat/Slim/Pro):
Version: v663betaN:
Intento #:
Resultado: [GoldHEN cargó / falló limpio + mensaje / pantallazo + apagón / app se cerró]:
Exploit usado: [Relapse / Relapse+NETCTRL-FALLBACK / Netctrl / Lapse]:
Últimas líneas del log: (pega las últimas 5-10):
Notas:
```

### Notas
- El jailbreak **no es persistente**: reboot = estado limpio, se corre de nuevo.
- **Auto GoldHEN** (Config, ON por default): ON = se aplica GoldHEN (`payload.bin`); OFF = se aplica `hen.bin` y **no** se baja GoldHEN. Si GoldHEN ya está presente, no se re-descarga.
- La música de fondo ahora carga **solo cuando el jailbreak termina** — nunca durante el exploit.
- **12.50 / 12.52 / 13.00 vía Relapse es experimental**: tablas de kernel cross-validated contra OSM/ps4hen/Al-Azif, **sin probar en hardware todavía**. Si falla, vuelve solo a Netctrl (`NETCTRL-FALLBACK` en el log).
- Cierra juegos/apps antes de probar.
- Esto es solo para las FW en la tabla de arriba. Otras FW siguen con Lapse/Netctrl y no tocan este camino.
