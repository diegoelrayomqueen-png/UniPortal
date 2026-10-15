/* Seguridad de la cuenta: estado de la sesión, renovación manual y cierre. */
(function () {
  "use strict";
  const { API, Store, Nav, ui, Layout } = window.UniPortal;

  function paint() {
    const s = Store.get(); if (!s) return;
    ui.$("#access-exp").textContent = ui.time(s.access_expires_at);
    ui.$("#refresh-exp").textContent = ui.date(s.refresh_expires_at) + ", " + ui.time(s.refresh_expires_at);
  }

  (async function () {
    const user = await Layout.init();
    if (!user) return;
    ui.$("#s-email").textContent = user.email;
    paint();
    const btn = ui.$("#renew"), box = ui.$("#alert");
    btn.addEventListener("click", async () => {
      ui.hideAlert(box); ui.setBusy(btn, true, "Renovando…");
      try {
        await API.refresh(); paint();
        ui.setBusy(btn, false); ui.flash(btn, "success");
        ui.alert(box, "success", "Sesión renovada: el servidor emitió tokens nuevos y el refresh token anterior quedó inválido.");
      } catch (err) {
        ui.setBusy(btn, false); ui.flash(btn, "error");
        if (err.status === 401 || err.status === 403) { Store.clear(); return Nav.toError("expired"); }
        ui.alert(box, "error", err.message);
      }
    });
  })();
})();
