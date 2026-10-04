// F1 smoke test — corre en la app Vue (13.02/13.04), pega los numeros.
// Metodo: FTP a /user/download/CUSA00960/payloads/f1-smoke.js (userland, sin jailbreak),
// payloads -> correr f1-smoke, o via updater cuando este publicado.
// Pasa (arquitectura A, port fiel polpNO) si imprime ok + avail apenas baja.
// Falla -> avisar con los dos numeros y bajar a n=65536/ka=16384 (plan B).
(function () {
  var before = (typeof debugging !== 'undefined' && debugging.info && debugging.info.memory)
    ? debugging.info.memory.available
    : -1;
  log('F1 before avail=' + before);
  var t = new Uint8Array(14 << 20);
  t[0] = 1;
  t[t.length - 1] = 1;
  var after = (typeof debugging !== 'undefined' && debugging.info && debugging.info.memory)
    ? debugging.info.memory.available
    : -1;
  log('F1 ok after avail=' + after + ' delta=' + (before - after));
})();
