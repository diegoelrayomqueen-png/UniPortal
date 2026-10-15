/* Panel principal: datos de la cuenta e indicadores de seguridad. */
(function () {
  "use strict";
  const { Store, ui, Layout } = window.UniPortal;

  (async function () {
    const user = await Layout.init();
    if (!user) return;
    ui.$("#welcome").textContent = "Hola, " + user.full_name.split(" ")[0];
    ui.$("#d-name").textContent = user.full_name;
    ui.$("#d-email").textContent = user.email;
    ui.$("#d-since").textContent = ui.date(user.created_at);
    ui.$("#d-updated").textContent = ui.date(user.updated_at);
    const s = Store.get();
    if (s) ui.$("#d-session").textContent = "Hasta las " + ui.time(s.refresh_expires_at) + " (" + ui.date(s.refresh_expires_at) + ")";
  })();
})();
