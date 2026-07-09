const bars = Array.from(document.querySelectorAll("[data-bar-value]"));
const maxValue = Math.max(1, ...bars.map((node) => Number(node.dataset.barValue || 0)));

bars.forEach((node) => {
  const value = Number(node.dataset.barValue || 0);
  const width = Math.max(6, Math.min(100, (value / maxValue) * 100));
  node.style.setProperty("--bar-value", `${width}%`);
});
