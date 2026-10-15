/* Estructura común de las pantallas protegidas: menú móvil, cierre de sesión y datos del usuario. */
(function (global) {
  "use strict";
  const { API, Store, Nav, ui } = global.UniPortal;

  function wire() {
    const sidebar = ui.$(".sidebar"), scrim = ui.$(".scrim"), btn = ui.$(".menu-btn");
    const toggle = (open) => { sidebar.classList.toggle("open", open); scrim.classList.toggle("show", open); btn.setAttribute("aria-expanded", String(open)); };
    btn.addEventListener("click", () => toggle(!sidebar.classList.contains("open")));
    scrim.addEventListener("click", () => toggle(false));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") toggle(false); });
    document.querySelectorAll("[data-logout]").forEach((b) => b.addEventListener("click", async () => {
      ui.setBusy(b, true, "Cerrando…");
      const revoked = await API.logout();
      Nav.toLogin(revoked ? "loggedout=1" : "loggedout=partial");
    }));
  }

  /* Valida que haya sesión, rellena el encabezado y devuelve el perfil (o null si redirigió). */
  async function init() {
    if (!Nav.requireAuth()) return null;
    wire();
    try {
      const user = await API.profile();
      ui.$("#user-name").textContent = user.full_name;
      ui.$("#user-avatar").textContent = ui.initials(user.full_name);
      return user;
    } catch (err) {
      if (!Nav.fatal(err)) Nav.toError("network");
      return null;
    }
  }

  global.UniPortal.Layout = { init };
})(window);
