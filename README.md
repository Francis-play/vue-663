<p align="center">
    <img width="25%" height="25%" alt="logo2" src="https://github.com/user-attachments/assets/5596a357-61c3-471c-9a1e-b8c3d6de33c8" />
</p>

<h1 align="center"> Vue-After-Free — 663 (Relapse) </h1>
<p  align="center">
    PlayStation Vue userland code execution exploit for PS4, with the 663 (Relapse) entry.
</p>

> [!NOTE]
> This is a port of [Vuemony/vue-after-free](https://github.com/Vuemony/vue-after-free). It adds the **663 (Relapse)** jailbreak behaviour (FW **13.02 / 13.04**) and its **own updater** hosted on GitHub Pages. For the base app install and everything unrelated to 663, follow the upstream repo.

# What this repo adds
- **663 / Relapse** JB behaviour for **13.02–13.04** (see [Config](#config)).
- **Own updater**, bootstrapped **once** over FTP. It pulls from `https://francis-play.github.io/vue-663/download0/`.
- On-demand `hen.bin` / `goldhen.bin` with a **size gate**: a bad download is discarded, never written (it asks you to send that bin over FTP once).

## Vulnerability Scope
KEX = Kernel Exploit

| vue-after-free (Userland) | Lapse (KEX) | Netctrl (KEX) | Relapse / 663 (KEX) |
| :------------------------ | :---------- | :------------ | :------------------ |
| 5.05–13.04                | 1.01–12.02  | 1.01–13.00    | 13.02–13.04         |

* 663 (Relapse) is **this repo's** entry, currently shipped for **13.02–13.04**. The Relapse exploit itself supports up to **13.52**, but this repo does not provide files above 13.04 yet.
* Any other firmware keeps using Lapse / Netctrl.
* The userland exploit works 5.05–13.04 as is.

# Setup — choose your path

> [!IMPORTANT]
> You bootstrap the updater **only once** (over FTP). After that, updating is just running the **`updater`** payload — no FTP again.
>
> A network connection of any kind is always required to launch the exploit. See [Connecting to the internet](#connecting-to-the-internet).

**Short version:** install the base PS Vue app if you don't have it → open Vue → run `ftp-server` → replace `payloads/updater.js` with this repo's `ftp/updater.js` → run the `updater` payload → relaunch and press **Jailbreak**.

<details>
<summary><b>Case A — Console already jailbroken + PS Vue installed</b> (most common)</summary>

1. Connect the console to a local network (see [Connecting to the internet](#connecting-to-the-internet)).
2. Open **PS Vue → Payloads → `ftp-server`**. It shows an address on screen: `ftp://<ip>:<port>` (the port is dynamic). Note it.
3. On your PC, download this repo's updater: open [`ftp/updater.js`](https://github.com/Francis-play/vue-663/blob/main/ftp/updater.js) and press **Raw**, then save it **exactly** as `updater.js` (make sure it is not `updater.js.txt`).
4. Connect with your FTP client (FileZilla, WinSCP, etc.) to that `<ip>:<port>`.
5. Navigate to the app's `payloads` folder and **replace `updater.js`** with the file from step 3. One file only.
6. In **Vue → Payloads → `updater`**. Wait until it says **Update Complete**. It only fetches what is missing (including `hen.bin` / `goldhen.bin` on first run).
7. If the updater says a bin must be sent by FTP (size gate), upload it to `payloads` once. The Payload Menu should now list `hen.bin` and `goldhen.bin`.
8. Fully close Vue (PS button → **Close Application**) and open it again.
9. Press **Jailbreak** and watch the on-screen log.
   * If it does not run: **Config → JB Behavior → `Relapse (663)`**, go back and press **Jailbreak** from the main menu.
10. When the exploit finishes, Vue listens on port **9020**. If HEN did not autoload from `payloads`, send your `.bin` from the PC to `<console-ip>:9020` (netcat / payload sender).
11. From now on, updating = run the **`updater`** payload and relaunch. No FTP needed.

</details>

<details>
<summary><b>Case B — Console already jailbroken + PS Vue NOT installed</b></summary>

1. Install the base PS Vue app first, following the upstream **Jailbroken PS4** method (FTP `download0.dat` to `/user/download/CUSA00960/`, pkg 1.01 + 1.24 patch, save via Apollo Save Tool): [Vuemony/vue-after-free → Setup Instructions](https://github.com/Vuemony/vue-after-free#setup-instructions).
2. Come back and follow **Case A**.

</details>

<details>
<summary><b>Case C — Console NOT jailbroken + PS Vue installed</b></summary>

> The `ftp-server` payload is **userland** and works **without** a jailbreak, so you can bootstrap the updater first.

1. Open Vue and do steps 1–7 of **Case A** (run `ftp-server`, replace `ftp/updater.js`, run the `updater` payload).
2. Jailbreak the console with your usual method, then reopen Vue.
3. Press **Jailbreak** (Config → JB Behavior → `Relapse (663)` if needed). Continue with steps 10–11 of **Case A**.

</details>

<details>
<summary><b>Case D — Console NOT jailbroken + PS Vue NOT installed</b></summary>

1. Get a jailbreak on the console first (your usual method), then install the base PS Vue app using the upstream **Jailbroken PS4** method.
   * No way to jailbreak yet? Use one of the upstream no-JB install methods (**Extended Storage** or **System Backup**) first.
2. Come back and follow **Case A**.

</details>

## Requirements
* Any kind of network connection to launch the app.
* Fake or legit activated PS4 user account.
* FTP access to the console (for the one-time bootstrap).
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
  * **Auto Detect** — default, picks by firmware.
  * **Lapse** — 7.00–12.02.
  * **NetControl** — 12.50–13.00 (runs on 9.00+).
  * **Relapse (663)** — **13.02–13.04** (this repo's entry).

Other options: **Auto Lapse** / **Auto Relapse** (launch a kernel exploit on opening the app), **Auto Close** (close the app after a successful jailbreak), **Music** (on/off), **Theme**.

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

* First time only: bootstrap it over FTP (see [Setup](#setup--choose-your-path)).
* After that: run `updater` from the Payloads menu and relaunch.
* Bins (`hen.bin`, `goldhen.bin`) are downloaded on demand and size-checked. If a bin is flagged, send it over FTP once.

# Themes
Themes can be added by copying the folder to `/download0/themes/`. The default theme is a good example.

# FAQ & Troubleshooting

**Q: Will this work on 13.02 or above?**
Only the userland and the 663 (Relapse) entry. This repo ships **13.02–13.04** (Relapse supports up to 13.52, but files above 13.04 are not provided here yet).

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

## payload sources:
- [elfldr.elf](https://github.com/ps4-payload-dev/elfldr) by John Törnblom
- [AIOfix_network.elf](https://github.com/Gezine/BD-JB-1250/blob/main/payloads/lapse/src/org/bdj/external/aiofix_network.c) by Gezine
- [np-fake-signin](https://github.com/earthonion/np-fake-signin) by earthonion

---

# Guía rápida (Español)

> Resumen: si ya tienes la app PS Vue, el bootstrap del updater se hace **una sola vez** por FTP y después actualizas con el payload `updater`. Si no tienes la app, primero la instalas (método del repo base) y luego sigues el CASO 1.

<details>
<summary><b>CASO 1 — Ya tienes JB y ya tienes Vue instalado</b></summary>

Necesitas: PC y consola en la misma red.

1. En la PC abre este link: https://github.com/Francis-play/vue-663/blob/main/ftp/updater.js
2. Presiona el botón **Raw** (arriba a la derecha), se abre el texto solo.
3. Guardalo:
   - En PC: **Ctrl + S**, nombre `updater.js` (ojo: que no quede como `updater.js.txt`).
   - En teléfono (Chrome): **3 puntitos** → **Descargar** (si baja con otro nombre, renombralo a `updater.js`).
4. En el PS4 abre Vue → **payloads** → corre `ftp-server`. Te muestra una dirección `ftp://<ip>:<puerto>`, anótala.
5. En la PC abre FileZilla (o el FTP que uses) y conéctate a esa dirección.
6. Busca la carpeta `payloads` y reemplaza el `updater.js` que está ahí con el que descargaste. Es **un solo archivo**.
7. En Vue → **payloads** → corre `updater`. Espera a que diga **Update Complete**. Trae solo lo que falta: si no tienes `hen.bin` o `goldhen.bin`, los baja solos; si ya los tienes, los omite.
8. Abre el **Payload Menu**: si ves `hen.bin` y `goldhen.bin`, ya estás. Si el updater dijo que alguno va por FTP, súbelo a `payloads` (una sola vez).
9. Cierra Vue por completo (botón PS → cerrar aplicación) y ábrelo de nuevo.
10. Presiona **Jailbreak** y mira el log en pantalla.
    - Si no arranca: **Config → JB Behavior → `Relapse (663)`** y de nuevo **Jailbreak** en el menú principal.
11. Cuando termine, Vue queda escuchando en el puerto **9020**: si el HEN no cargó solo desde `payloads`, manda tu bin desde la PC a `<ip-consola>:9020`.
12. De ahí en más, cada prueba nueva: corre `updater` y listo, sin FTP.

</details>

<details>
<summary><b>CASO 2 — Ya tienes JB pero NO tienes Vue instalado</b></summary>

1. Instala la app base PS Vue siguiendo el método **Jailbroken PS4** del repo base (FTP de `download0.dat` a `/user/download/CUSA00960/`, pkg 1.01 + parche 1.24, save con Apollo).
   Link: https://github.com/Vuemony/vue-after-free (sección **Setup Instructions → Jailbroken PS4**).
2. Con Vue abierto, vuelve al **CASO 1**.

</details>

<details>
<summary><b>CASO 3 — NO tienes JB pero SÍ tienes Vue instalado</b></summary>

> El payload `ftp-server` es **userland** y funciona **sin** jailbreak, así que puedes bootstrapear el updater primero.

1. Abre Vue y haz los pasos 1–7 del **CASO 1** (correr `ftp-server`, reemplazar `ftp/updater.js`, correr `updater`).
2. Haz jailbreak con tu método actual y vuelve a abrir Vue.
3. Presiona **Jailbreak** (**Config → JB Behavior → `Relapse (663)`** si hace falta) y sigue desde el paso 11 del **CASO 1**.

</details>

<details>
<summary><b>CASO 4 — NO tienes JB y NO tienes Vue instalado</b></summary>

1. Primero consigue jailbreak con tu método actual y luego instala la app base (método **Jailbroken PS4** del repo base).
   - Si todavía no puedes jailbreakear, usa uno de los métodos sin-JB del repo base (**Extended Storage** o **System Backup**).
2. Con Vue abierto, vuelve al **CASO 1**.

</details>

### Para reportar (copia y pega esto)
```
FW: 13.02 / 13.04 (Fat/Slim/Pro):
Version: v663betaN:
Intento #:
Resultado: [GoldHEN cargó / falló limpio + mensaje / pantallazo + apagón / app se cerró]:
Últimas líneas del log: (pega las últimas 5-10):
Notas:
```

### Notas
- El jailbreak **no es persistente**: reboot = estado limpio, se corre de nuevo.
- Cierra juegos/apps antes de probar.
- Esto es solo para **13.02/13.04**. Relapse llega hasta 13.52, pero este repo todavía no trae archivos arriba de 13.04. Otras FW siguen con Lapse/Netctrl y no tocan este camino.
