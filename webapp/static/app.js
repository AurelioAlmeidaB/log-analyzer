// Botões "Copiar" ao lado de blocos de código e da chave de API.
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
