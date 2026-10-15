/* Lógica de inicio, registro, login y verificación OTP (según data-page del <body>). */
(function () {
  "use strict";
  const { API, Store, ui } = window.UniPortal;
  const page = document.body.dataset.page;

  function networkOr(box, err) { ui.alert(box, "error", err.message); }

  function initHome() {
    const logged = !!Store.get();
    document.querySelectorAll("[data-guest]").forEach((el) => el.classList.toggle("hidden", logged));
    document.querySelectorAll("[data-user]").forEach((el) => el.classList.toggle("hidden", !logged));
  }

  function initRegister() {
    const form = ui.$("#register-form"), box = ui.$("#alert"), btn = ui.$("#submit");
    const f = { name: ui.$("#f-name"), email: ui.$("#f-email"), pass: ui.$("#f-pass"), conf: ui.$("#f-conf") };
    const input = (field) => field.querySelector("input");
    const rulesList = ui.$("#rules");
    ui.passwordRules.forEach(([id, label]) => { const li = document.createElement("li"); li.dataset.rule = id; li.textContent = label; rulesList.appendChild(li); });

    const checkName = () => { const ok = input(f.name).value.trim().length >= 2; ui.fieldState(f.name, ok ? "valid" : "invalid", ok ? "" : "Escribe tu nombre completo."); return ok; };
    const checkEmail = () => { const ok = ui.isEmail(input(f.email).value.trim()); ui.fieldState(f.email, ok ? "valid" : "invalid", ok ? "" : "Ingresa un correo válido."); return ok; };
    const checkPass = () => {
      const v = input(f.pass).value; let all = true;
      ui.passwordRules.forEach(([id, , test]) => { const met = test(v); all = all && met; rulesList.querySelector('[data-rule="' + id + '"]').classList.toggle("met", met); });
      ui.fieldState(f.pass, v ? (all ? "valid" : "invalid") : null, "");
      return all;
    };
    const checkConf = () => { const ok = input(f.conf).value !== "" && input(f.conf).value === input(f.pass).value; ui.fieldState(f.conf, ok ? "valid" : "invalid", ok ? "" : "Las contraseñas no coinciden."); return ok; };
    input(f.name).addEventListener("blur", checkName);
    input(f.email).addEventListener("blur", checkEmail);
    input(f.pass).addEventListener("input", () => { checkPass(); if (input(f.conf).value) checkConf(); });
    input(f.conf).addEventListener("input", checkConf);

    form.addEventListener("submit", async (e) => {
      e.preventDefault(); ui.hideAlert(box);
      const results = [checkName(), checkEmail(), checkPass(), checkConf()];
      if (!results.every(Boolean)) { ui.alert(box, "error", "Revisa los campos marcados antes de continuar."); return; }
      ui.setBusy(btn, true, "Creando cuenta…");
      try {
        await API.register({ full_name: input(f.name).value.trim(), email: input(f.email).value.trim(), password: input(f.pass).value });
        ui.setBusy(btn, false); ui.flash(btn, "success");
        ui.alert(box, "success", "¡Cuenta creada! Te llevamos al inicio de sesión…");
        setTimeout(() => location.assign("/login.html?registered=1"), 1200);
      } catch (err) {
        ui.setBusy(btn, false); ui.flash(btn, "error");
        if (err.status === 409) ui.fieldState(f.email, "invalid", err.message);
        networkOr(box, err);
      }
    });
  }

  function initLogin() {
    const form = ui.$("#login-form"), box = ui.$("#alert"), btn = ui.$("#submit"), q = ui.params();
    if (q.get("registered")) ui.alert(box, "success", "Cuenta creada. Inicia sesión para continuar.");
    else if (q.get("loggedout") === "1") ui.alert(box, "info", "Cerraste sesión correctamente.");
    else if (q.get("loggedout") === "partial") ui.alert(box, "info", "Cerraste sesión en este navegador, pero no pudimos contactar al servidor: la sesión podría seguir activa allí hasta que venza.");
    else if (q.get("expired")) ui.alert(box, "info", "Inicia sesión para acceder al portal.");
    if (Store.get() && !q.get("loggedout")) { location.replace("/dashboard.html"); return; }

    form.addEventListener("submit", async (e) => {
      e.preventDefault(); ui.hideAlert(box);
      const email = ui.$("#email").value.trim(), password = ui.$("#password").value;
      if (!ui.isEmail(email) || !password) { ui.alert(box, "error", "Ingresa tu correo y tu contraseña."); return; }
      ui.setBusy(btn, true, "Verificando…");
      try {
        const data = await API.login({ email, password });
        Store.setChallenge(data);
        ui.setBusy(btn, false); ui.flash(btn, "success");
        location.assign("/verify-otp.html");
      } catch (err) {
        ui.setBusy(btn, false); ui.flash(btn, "error"); networkOr(box, err);
      }
    });
  }

  function initVerify() {
    const challenge = Store.getChallenge();
    if (!challenge || challenge.expires_at < Date.now()) { Store.clearChallenge(); location.replace("/login.html?expired=1"); return; }
    const form = ui.$("#otp-form"), box = ui.$("#alert"), btn = ui.$("#submit"), code = ui.$("#code"), resend = ui.$("#resend");
    ui.$("#email-hint").textContent = challenge.email_hint;
    code.focus();
    code.addEventListener("input", () => { code.value = code.value.replace(/\D/g, "").slice(0, 6); btn.disabled = code.value.length !== 6; });
    btn.disabled = true;

    let timer = null;
    function tick() {
      const left = Math.ceil(((Store.getChallenge() || {}).resend_at - Date.now()) / 1000);
      if (left > 0) { resend.disabled = true; resend.textContent = "Reenviar código (" + left + " s)"; }
      else { resend.disabled = false; resend.textContent = "Reenviar código"; clearInterval(timer); }
    }
    timer = setInterval(tick, 1000); tick();

    const restart = (msg) => { Store.clearChallenge(); ui.alert(box, "error", msg + " Redirigiendo al inicio de sesión…"); setTimeout(() => location.replace("/login.html"), 2500); };

    form.addEventListener("submit", async (e) => {
      e.preventDefault(); ui.hideAlert(box);
      ui.setBusy(btn, true, "Verificando…");
      try {
        const tokens = await API.verifyOtp({ challenge_token: challenge.token, code: code.value });
        Store.clearChallenge(); Store.set(tokens);
        ui.flash(btn, "success"); location.replace("/dashboard.html");
      } catch (err) {
        ui.setBusy(btn, false); btn.disabled = code.value.length !== 6; ui.flash(btn, "error");
        if (err.status === 401) return restart(err.message);
        if (err.code === "otp_locked" || err.code === "otp_expired" || err.code === "otp_used") { code.value = ""; btn.disabled = true; }
        networkOr(box, err);
      }
    });

    resend.addEventListener("click", async () => {
      ui.hideAlert(box); resend.disabled = true;
      try {
        const data = await API.resendOtp({ challenge_token: challenge.token });
        Store.patchChallenge({ resend_at: Date.now() + data.resend_available_in * 1000 });
        ui.alert(box, "success", data.message); code.value = ""; btn.disabled = true; code.focus();
      } catch (err) {
        if (err.status === 401) return restart(err.message);
        if (err.retryAfter) Store.patchChallenge({ resend_at: Date.now() + err.retryAfter * 1000 });
        networkOr(box, err);
      }
      clearInterval(timer); timer = setInterval(tick, 1000); tick();
    });
  }

  ({ home: initHome, register: initRegister, login: initLogin, verify: initVerify })[page]();
})();
