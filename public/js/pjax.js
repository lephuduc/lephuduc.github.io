(() => {
  // <stdin>
  window.addEventListener("pjax:success", () => {
    _$$("script[data-pjax]").forEach((element) => {
      const { textContent, parentNode, id, className, type, src, dataset } = element;
      const code = textContent || "";
      const script = document.createElement("script");
      id && (script.id = id);
      className && (script.className = className);
      type && (script.type = type);
      dataset.pjax !== void 0 && (script.dataset.pjax = "");
      if (src) {
        script.src = src;
        script.async = false;
      } else if (code) {
        script.textContent = code;
      }
      parentNode?.replaceChild(script, element);
    });
  });
  window.addEventListener("pjax:complete", () => {
    _$("#header-nav")?.classList.remove("header-nav-hidden");
    const mode = window.localStorage.getItem("dark_mode");
    if (mode == "true") {
      document.body.dispatchEvent(new CustomEvent("dark-theme-set"));
    } else if (mode == "false") {
      document.body.dispatchEvent(new CustomEvent("light-theme-set"));
    }
    if (window.walineInstance) {
      window.walineInstance.destroy();
      window.walineInstance = null;
    }
  });
  window.addEventListener("pjax:send", () => {
    window.lightboxStatus = "loading";
  });
  if (window.startLoading) window.addEventListener("pjax:send", startLoading);
  if (window.endLoading) window.addEventListener("pjax:complete", endLoading);
  if (window.aosInit) window.addEventListener("pjax:success", aosInit);
})();
