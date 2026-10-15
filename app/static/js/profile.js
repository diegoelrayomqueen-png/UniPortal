/* Perfil: consulta y edición del nombre completo. */
(function () {
  "use strict";
  const { API, Nav, ui, Layout } = window.UniPortal;

  (async function () {
    const user = await Layout.init();
    if (!user) return;
    const form = ui.$("#profile-form"), box = ui.$("#alert"), btn = ui.$("#submit");
    const name = ui.$("#name"), field = ui.$("#f-name");
    const fill = (u) => { name.value = u.full_name; ui.$("#email").value = u.email; ui.$("#since").textContent = ui.date(u.created_at); ui.$("#updated").textContent = ui.date(u.updated_at); };
    fill(user);
    ui.$("#loading").classList.add("hidden"); form.classList.remove("hidden");

    form.addEventListener("submit", async (e) => {
      e.preventDefault(); ui.hideAlert(box);
      const value = name.value.trim().replace(/\s+/g, " ");
      if (value.length < 2) { ui.fieldState(field, "invalid", "Escribe tu nombre completo."); return; }
      ui.fieldState(field, null);
      ui.setBusy(btn, true, "Guardando…");
      try {
        const updated = await API.updateProfile({ full_name: value });
        fill(updated);
        ui.$("#user-name").textContent = updated.full_name; ui.$("#user-avatar").textContent = ui.initials(updated.full_name);
        ui.setBusy(btn, false); ui.flash(btn, "success");
        ui.alert(box, "success", "Perfil actualizado correctamente.");
      } catch (err) {
        ui.setBusy(btn, false); ui.flash(btn, "error");
        if (err.status === 401 || err.status === 403 || err.status === 0) return Nav.fatal(err);
        ui.alert(box, "error", err.message);
      }
    });
  })();
})();
