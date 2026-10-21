"use strict";

(() => {
  const root = document.documentElement;

  // ---- Theme: follows the system until the visitor picks one ----
  const toggle = document.getElementById("theme-toggle");
  const systemDark = matchMedia("(prefers-color-scheme: dark)");
  const effective = () => root.dataset.theme || (systemDark.matches ? "dark" : "light");
  const label = () => {
    toggle.setAttribute("aria-label", effective() === "dark" ? "Switch to light mode" : "Switch to dark mode");
  };
  if (toggle) {
    toggle.hidden = false;
    label();
    toggle.addEventListener("click", () => {
      const next = effective() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        localStorage.setItem("secblitz-theme", next);
      } catch {
        // Not saved; the choice still applies to this visit.
      }
      label();
    });
    systemDark.addEventListener("change", label);
  }

  // ---- Copy an installer checksum ----
  for (const copy of document.querySelectorAll("button[data-copy]")) {
    copy.addEventListener("click", async () => {
      const target = document.getElementById(copy.dataset.copy);
      try {
        await navigator.clipboard.writeText(target.textContent.trim());
        copy.textContent = "Copied";
      } catch {
        getSelection().selectAllChildren(target);
        copy.textContent = "Selected";
      }
      setTimeout(() => { copy.textContent = "Copy"; }, 2000);
    });
  }

  // ---- Offer the ARM installer to PCs with an ARM processor ----
  const arm = document.querySelector('a[data-arch="arm64"]');
  const high = navigator.userAgentData && navigator.userAgentData.getHighEntropyValues;
  if (arm && high) {
    navigator.userAgentData.getHighEntropyValues(["architecture"])
      .then(({ architecture }) => {
        if (architecture !== "arm") return;
        for (const button of document.querySelectorAll("a[data-auto-download]")) {
          button.href = arm.href;
        }
      })
      .catch(() => {
        // The button keeps the installer for most PCs; both links stay visible.
      });
  }

  // ---- Tour video: plays only while visible. Reduced motion and data saver
  // start on the still; the button lets anyone play or pause it. ----
  const video = document.getElementById("tour-video");
  const button = document.getElementById("tour-toggle");
  if (!video) return;
  const motion = matchMedia("(prefers-reduced-motion: reduce)");
  const connection = navigator.connection;
  const state = { ready: false, visible: false, failed: false, choice: null };
  video.muted = true;
  // The visitor's own choice wins; until they make one, follow their settings.
  const wanted = () => state.choice ? state.choice === "play" : !motion.matches && !connection?.saveData;
  const allowed = () => state.ready && state.visible && !document.hidden && wanted();
  const render = () => {
    if (!button) return;
    const playing = wanted();
    button.hidden = !state.ready || state.failed;
    button.classList.toggle("is-playing", playing);
    button.querySelector("use").setAttribute("href", playing ? "#i-pause" : "#i-play");
    button.querySelector("span").textContent = playing ? "Pause the tour" : "Play the tour";
  };
  const sync = () => {
    if (allowed()) video.play().catch(() => {});
    else video.pause();
    // The themed still underneath shows until the recording really plays, and
    // again if the visitor never chose to play it. A paused tour stays on its frame.
    if (!wanted() && state.choice === null) video.hidden = true;
    render();
  };
  video.addEventListener("playing", () => {
    state.failed = false;
    if (wanted()) video.hidden = false;
    render();
  });
  video.addEventListener("error", () => {
    if (video.error || video.networkState === HTMLMediaElement.NETWORK_NO_SOURCE) {
      state.failed = true;
      video.hidden = true;
      render();
    }
  }, true);
  video.addEventListener("loadedmetadata", () => { state.ready = true; sync(); });
  button?.addEventListener("click", () => {
    state.choice = wanted() ? "pause" : "play";
    sync();
  });
  document.addEventListener("visibilitychange", sync);
  motion.addEventListener("change", sync);
  new IntersectionObserver(entries => {
    state.visible = entries[0].isIntersecting;
    sync();
  // Watch the frame, not the video: the video stays hidden until it plays.
  }, { threshold: 0.25 }).observe(video.parentElement);
  if (video.readyState >= 1) video.dispatchEvent(new Event("loadedmetadata"));
})();
