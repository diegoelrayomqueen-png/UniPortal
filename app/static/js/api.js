/* Cliente de la API + sesión + utilidades de interfaz. Namespace global: window.UniPortal */
(function (global) {
  "use strict";
  const SESSION_KEY = "uniportal.session";
  const CHALLENGE_KEY = "uniportal.challenge";

  class ApiError extends Error {
    constructor(status, code, message, data) {
      super(message);
      this.status = status; this.code = code; this.data = data || null;
    }
  }

  /* Los tokens viven en sessionStorage (se borran al cerrar la pestaña). Ver README: limitaciones. */
  const Store = {
    get() { try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch (e) { return null; } },
    set(t) {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify({
        access_token: t.access_token, refresh_token: t.refresh_token,
        access_expires_at: Date.now() + t.expires_in * 1000,
        refresh_expires_at: Date.now() + t.refresh_expires_in * 1000,
      }));
    },
    clear() { sessionStorage.removeItem(SESSION_KEY); sessionStorage.removeItem(CHALLENGE_KEY); },
    getChallenge() { try { return JSON.parse(sessionStorage.getItem(CHALLENGE_KEY)); } catch (e) { return null; } },
    setChallenge(c) {
      sessionStorage.setItem(CHALLENGE_KEY, JSON.stringify({
        token: c.challenge_token, email_hint: c.email_hint,
        resend_at: Date.now() + c.resend_available_in * 1000,
        expires_at: Date.now() + c.challenge_expires_in * 1000,
      }));
    },
    patchChallenge(patch) { const c = this.getChallenge(); if (c) sessionStorage.setItem(CHALLENGE_KEY, JSON.stringify({ ...c, ...patch })); },
    clearChallenge() { sessionStorage.removeItem(CHALLENGE_KEY); },
  };

  function messageFrom(data, status) {
    if (data && Array.isArray(data.errors) && data.errors.length) return data.errors.map((e) => e.message).join(" ");
    if (data && typeof data.detail === "string") return data.detail;
    return "Ocurrió un error inesperado (" + status + ").";
  }

  async function request(path, { method = "GET", body, token } = {}) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (token) headers.Authorization = "Bearer " + token;
    let res;
    try {
      res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    } catch (e) {
      throw new ApiError(0, "network", "No pudimos conectar con el servidor. Revisa tu conexión e inténtalo de nuevo.");
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* respuesta sin JSON */ }
    if (!res.ok) {
      const err = new ApiError(res.status, (data && data.code) || "error", messageFrom(data, res.status), data);
      err.retryAfter = Number(res.headers.get("Retry-After")) || null;
      throw err;
    }
    return data;
  }

  let refreshing = null; // evita varias renovaciones simultáneas
  function refreshTokens() {
    if (!refreshing) {
      refreshing = (async () => {
        const s = Store.get();
        if (!s) throw new ApiError(401, "missing_token", "Sin sesión.");
        const data = await request("/auth/refresh", { method: "POST", token: s.refresh_token });
        Store.set(data);
        return data;
      })().finally(() => { refreshing = null; });
    }
    return refreshing;
  }

  /* Petición autenticada: si el access token venció, renueva una vez y reintenta. */
  async function authed(path, opts = {}) {
    let s = Store.get();
    if (!s) throw new ApiError(401, "missing_token", "Inicia sesión para continuar.");
    try {
      return await request(path, { ...opts, token: s.access_token });
    } catch (e) {
      if (!(e.status === 401 && e.code === "token_expired")) throw e;
      try { await refreshTokens(); } catch (r) {
        Store.clear();
        throw new ApiError(401, "session_expired", "Tu sesión venció. Inicia sesión de nuevo.");
      }
      s = Store.get();
      return request(path, { ...opts, token: s.access_token });
    }
  }

  const API = {
    register: (d) => request("/auth/register", { method: "POST", body: d }),
    login: (d) => request("/auth/login", { method: "POST", body: d }),
    verifyOtp: (d) => request("/auth/verify-otp", { method: "POST", body: d }),
    resendOtp: (d) => request("/auth/resend-otp", { method: "POST", body: d }),
    refresh: refreshTokens,
    profile: () => authed("/users/profile"),
    updateProfile: (d) => authed("/users/profile", { method: "PUT", body: d }),
    /* El logout SIEMPRE limpia el navegador, pero primero pide al servidor revocar la sesión. */
    async logout() {
      let revoked = true;
      try { await authed("/auth/logout", { method: "POST" }); } catch (e) {
        revoked = e.status === 401; // 401 = la sesión ya estaba revocada/vencida en el servidor
      }
      Store.clear();
      return revoked;
    },
  };

  const Nav = {
    toLogin(flag) { location.replace("/login.html" + (flag ? "?" + flag : "")); },
    toError(type) { location.replace("/error.html?type=" + type + "&from=" + encodeURIComponent(location.pathname)); },
    /* Decide a qué pantalla enviar según el error de una página protegida. */
    fatal(err) {
      if (err.status === 0) return Nav.toError("network");
      if (err.status === 403) return Nav.toError("denied");
      if (err.status === 401) { Store.clear(); return Nav.toError("expired"); }
      return false;
    },
    requireAuth() { if (!Store.get()) { Nav.toLogin("expired=1"); return false; } return true; },
  };

  const ui = {
    $: (sel, root) => (root || document).querySelector(sel),
    params: () => new URLSearchParams(location.search),
    setBusy(btn, busy, label) {
      if (busy) { btn.dataset.label = btn.textContent; btn.textContent = label || "Procesando…"; }
      else if (btn.dataset.label) { btn.textContent = btn.dataset.label; }
      btn.disabled = busy; btn.classList.toggle("loading", busy); btn.setAttribute("aria-busy", String(busy));
    },
    flash(btn, kind) { btn.classList.add(kind); setTimeout(() => btn.classList.remove(kind), 1600); },
    alert(box, kind, text) {
      box.className = "alert " + kind; box.textContent = text; box.classList.remove("hidden"); box.setAttribute("role", kind === "error" ? "alert" : "status");
    },
    hideAlert(box) { box.classList.add("hidden"); },
    fieldState(field, state, msg) {
      field.classList.remove("invalid", "valid");
      if (state) field.classList.add(state);
      const slot = field.querySelector(".field-error"); if (slot) slot.textContent = msg || "";
    },
    date(iso) { return new Date(iso).toLocaleDateString("es-CO", { year: "numeric", month: "long", day: "numeric" }); },
    time(ms) { return new Date(ms).toLocaleTimeString("es-CO", { hour: "2-digit", minute: "2-digit" }); },
    initials(name) { return name.trim().split(/\s+/).slice(0, 2).map((p) => p[0].toUpperCase()).join(""); },
    isEmail: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v),
    passwordRules: [
      ["len", "8 a 72 caracteres", (p) => p.length >= 8 && new TextEncoder().encode(p).length <= 72],
      ["low", "Una minúscula", (p) => /[a-z]/.test(p)],
      ["up", "Una mayúscula", (p) => /[A-Z]/.test(p)],
      ["num", "Un número", (p) => /\d/.test(p)],
      ["sym", "Un símbolo", (p) => /[^A-Za-z0-9]/.test(p)],
    ],
  };

  global.UniPortal = { API, Store, Nav, ui, ApiError };
})(window);
