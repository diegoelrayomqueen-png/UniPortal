/* Pantalla de error genérica según ?type=denied|expired|network|notfound. */
(function () {
  "use strict";
  const { ui, Store } = window.UniPortal;
  const types = {
    denied: ["⛔", "Acceso denegado", "No tienes permiso para realizar esta acción con la sesión actual.", "Ir al panel", "/dashboard.html"],
    expired: ["⌛", "Sesión vencida", "Tu sesión terminó o fue cerrada. Inicia sesión de nuevo para continuar.", "Iniciar sesión", "/login.html"],
    network: ["📡", "Error de conexión", "No pudimos comunicarnos con el servidor. Revisa tu conexión e inténtalo otra vez.", "Reintentar", null],
    notfound: ["🧭", "Página no encontrada", "La página que buscas no existe.", "Ir al inicio", "/"],
  };
  const type = types[ui.params().get("type")] ? ui.params().get("type") : "notfound";
  const [icon, title, text, label, href] = types[type];
  if (type === "expired") Store.clear();
  ui.$("#icon").textContent = icon; ui.$("#title").textContent = title; ui.$("#text").textContent = text;
  const action = ui.$("#action"); action.textContent = label;
  const from = ui.params().get("from");
  action.href = href || (from && from.startsWith("/") && !from.startsWith("//") ? from : "/");
})();
