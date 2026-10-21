// Small progressive enhancements. Everything works without this file.
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-copy]");
  if (!btn || !navigator.clipboard) return;
  navigator.clipboard.writeText(btn.dataset.copy).then(() => {
    const label = btn.textContent;
    btn.textContent = "Copied";
    setTimeout(() => { btn.textContent = label; }, 1400);
  });
});

// Stop double submits on slow actions (verification waits on DNS).
document.addEventListener("submit", (e) => {
  const btn = e.submitter;
  if (btn && !btn.disabled) {
    setTimeout(() => { btn.disabled = true; btn.textContent = "Working…"; }, 0);
  }
});

// While an asset is being checked, reload once the checks are likely done.
if (document.querySelector(".dot.busy")) {
  setTimeout(() => location.reload(), 15000);
}
