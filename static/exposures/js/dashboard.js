document.querySelectorAll("[data-bar-value]").forEach((node) => {
  const value = Number(node.dataset.barValue || 0);
  node.style.setProperty("--bar-value", `${Math.max(0, Math.min(100, value))}%`);
});
