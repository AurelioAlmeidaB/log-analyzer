// Comportamentos pequenos de usabilidade. Tudo funciona sem JS; isto só deixa mais rápido.

// Botões "Copiar" ao lado de blocos de código, chaves e links de convite.
document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const target = document.getElementById(button.dataset.copy);
  if (!target) return;
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(target.textContent.trim());
    button.textContent = "Copiado";
  } catch (_) {
    button.textContent = "Selecione e copie";
  }
  setTimeout(() => { button.textContent = original; }, 1600);
});

// Mostrar/ocultar senha.
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-toggle-password]");
  if (!button) return;
  const input = document.getElementById(button.dataset.togglePassword);
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  button.textContent = show ? "Ocultar" : "Mostrar";
  button.setAttribute("aria-pressed", String(show));
  input.focus();
});

// Confirmação antes de ações que não dá para desfazer.
document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});

// Trocar de organização ao escolher na lista.
document.addEventListener("change", (event) => {
  if (event.target.matches("select[data-autosubmit]")) event.target.form.requestSubmit();
});

// Código de 6 dígitos: envia sozinho ao completar (uma vez só).
document.addEventListener("input", (event) => {
  const input = event.target;
  if (!input.matches("input[data-autosubmit-code]") || input.dataset.sent) return;
  if (/^\d{6}$/.test(input.value.replace(/\s/g, ""))) {
    input.dataset.sent = "1";
    input.form.requestSubmit();
  }
});
