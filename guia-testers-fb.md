# Guia testers 663 (pegar en FB)

Probamos el jailbreak 663 (Relapse) para PS4 **13.02 y 13.04** dentro de la app PS Vue.
La parte de kernel esta probada; lo nuevo es la entrada por Vue: si algo falla, el log en pantalla nos dice donde, y seguimos iterando sin reinstalar nada.

Nuestro repo (todo se descarga de aqui): https://github.com/Francis-play/vue-663

---

## CASO 1: ya tienes Vue instalado y te abre

Necesitas: PC y consola en la misma red (wifi de la casa sirve).

1. En la PC abre este link: https://github.com/Francis-play/vue-663/blob/main/ftp/updater.js
2. Ahi presiona el boton **Raw** (arriba a la derecha del archivo), se abre el texto solo.
3. Guardalo:
   - En PC: presiona **Ctrl + S**, nombre `updater.js` (fijate que no quede como `updater.js.txt`).
   - En telefono (Chrome): presiona los **3 puntitos** arriba a la derecha -> **Descargar** (baja como `updater.js`; si baja con otro nombre, renombralo a `updater.js` con tu administrador de archivos).
4. En el PS4 abre Vue -> payloads -> corre `ftp-server`. Te muestra una direccion IP, anotala.
5. En la PC abre FileZilla (o el FTP que uses), conectate a esa IP.
6. Busca la carpeta `payloads` y reemplaza el archivo `updater.js` que esta ahi con el que descargaste en el paso 3. Es UN solo archivo, nada mas.
7. En Vue -> payloads -> corre `updater`. Espera a que diga Update Complete. El updater trae solo lo que falta: si no tienes `hen.bin` o `goldhen.bin` en `payloads`, los descarga solos; si ya los tienes, los omite.
8. Abre en Vue el Payload Menu: si ves `hen.bin` y `goldhen.bin` en la lista, ya estas. Si el updater te dijo que alguno va por FTP, subelo a `payloads` (una sola vez, queda guardado).
10. Cierra Vue del todo (boton PS -> cerrar aplicacion) y abrelo de nuevo.
11. Presiona Jailbreak y mira el log en pantalla.
12. Cuando el exploit termine, Vue queda escuchando en el puerto 9020: si el HEN no cargo solo desde `payloads`, envia tu bin desde la PC (netcat o payload sender a la IP de la consola, puerto 9020).
13. De ahi en mas, cada prueba nueva: corre `updater` y listo, sin FTP.

Si tu config es vieja no toques nada: en 13.02/13.04 todo se ajusta solo.

## CASO 2: no tienes Vue instalado

Sin jailbreak no se puede instalar el pkg de Vue, asi que el orden es:

1. Haz jailbreak con tu metodo actual (webkit/exploit host desde PC) y carga HEN. Ojo: en 13.02/13.04 usa HEN, no GoldHEN (GoldHEN oficial aun no llega a esas FW).
2. Ya con jailbreak, instala Vue siguiendo la guia del repo base (metodo PS4 con jailbreak: FTP del `download0.dat` a `/user/download/CUSA00960/`, pkg 1.01 + parche 1.24, save CUSA00960 con Apollo).
   Link: https://github.com/Vuemony/vue-after-free (seccion Jailbroken PS4).
3. Con Vue abierto, vuelve al CASO 1 desde el paso 1.

---

## Diagnóstico 12.52 (reporte de fallo con relapse)

Si Vue se congela o falla en 12.52, esta guia nos da la historia completa en **una sola pasada**. Necesitas: USB (MBR + exFAT) y los dos payloads `vue_applog.elf` y `vue_kdump.elf` (estan en `src/download0/payloads/` del repo).

**Orden importante: NO hagas jailbreak con BD-J ni reinicies antes de los pasos 3-4** — si la consola ya esta "already jailbroken", Vue no corre el exploit y no hay nada que diagnosticar.

1. Arranca la consola, abre Vue (sin jailbreak previo) y presiona **Jailbreak**. En 12.52 veras: primero `[relapse:...]`; o bien se queda sin avanzar y a los ~30s aparece **"Relapse stalled — trying NetControl..."** (el watchdog lo manda a NetControl solo); o falla limpio con "Relapse failed".
2. Deja el resultado como este (aunque este "congelada" la app) **sin apagar ni reiniciar**.
3. Carga `vue_applog.elf` (payload loader de GoldHEN o netcat a puerto 9020). Espera ~10 s.
4. Carga `vue_kdump.elf`. Espera ~30 s.
5. Apaga la consola del todo, saca el USB.

Quedan en la raiz del USB: **`vue_diag.tar`** (config real de Vue + logs/sandbox de la sesión) y **`kernel.elf`** (dump del kernel de 12.52). Mandanos esos dos archivos.

- `vue_diag.tar` se abre con cualquier 7-zip/WinRAR (es un .tar).
- `kernel.elf` es para validar los offsets de 12.52 (IDT/sysctl/AIO) — nos lo puede mandar quien lo obtenga primero.

Si no podes cargar los payloads tras el fallo: cerra Vue (boton PS -> cerrar), cargalos igual y mandalos — perdemos los logs en vivo pero la config y el kernel dump salen completos.

---

## Para reportar (copia y pega esto)

FW: 13.02 / 13.04 (Fat/Slim/Pro):
Version: v663betaN:
Intento #:
Resultado: [GoldHEN cargo / fallo limpio + mensaje / pantallazo + apagon / app se cerro]:
Ultimas lineas del log: (pega las ultimas 5-10):
Notas:

## Notas

- El jailbreak NO es persistente: reboot = estado limpio, se corre de nuevo.
- Cierra juegos/apps antes de probar.
- Esto es solo para 13.02/13.04. Otras FW siguen con Lapse/Netctrl, no tocan este camino.
