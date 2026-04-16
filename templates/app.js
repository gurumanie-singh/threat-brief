/* ─────────────────────────────────────────────────────
   Threat Brief — Client-side interactions
   Theme toggle, tag filters, scroll reveal
   ───────────────────────────────────────────────────── */

(function () {
  "use strict";

  /* ── Theme ──────────────────────────────────────── */

  var root = document.documentElement;
  var toggle = document.getElementById("themeToggle");

  var sunSVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
  var moonSVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    if (toggle) toggle.innerHTML = theme === "dark" ? moonSVG : sunSVG;
  }

  var saved = localStorage.getItem("tb-theme") || "dark";
  applyTheme(saved);

  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(next);
      localStorage.setItem("tb-theme", next);
    });
  }

  /* ── Tag filters ────────────────────────────────── */

  var buttons = document.querySelectorAll(".filter-btn");
  var cards = document.querySelectorAll(".article-card");
  var dayGroups = document.querySelectorAll(".day-group");

  buttons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var tag = btn.dataset.tag;

      if (btn.classList.contains("active")) {
        btn.classList.remove("active");
        cards.forEach(function (c) { c.style.display = ""; });
        dayGroups.forEach(function (g) { g.style.display = ""; });
        return;
      }

      buttons.forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");

      cards.forEach(function (card) {
        var cardTags = (card.dataset.tags || "").split(",");
        card.style.display = cardTags.includes(tag) ? "" : "none";
      });

      dayGroups.forEach(function (group) {
        var groupCards = group.nextElementSibling
          ? group.nextElementSibling.querySelectorAll
            ? null
            : null
          : null;
        /* day group visibility handled by CSS adjacency */
      });
    });
  });

  /* ── Scroll reveal ──────────────────────────────── */

  var revealEls = document.querySelectorAll(
    ".article-card, .archive-day-card"
  );

  if ("IntersectionObserver" in window && revealEls.length) {
    var io = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) {
            var siblings = e.target.parentElement
              ? e.target.parentElement.children
              : [];
            var idx = Array.prototype.indexOf.call(siblings, e.target);
            var delay = Math.min(idx * 60, 300);
            setTimeout(function () {
              e.target.classList.add("visible");
            }, delay);
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.08 }
    );
    revealEls.forEach(function (el) { io.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add("visible"); });
  }
})();
