/* ─────────────────────────────────────────────────────
   Threat Brief — Client-side interactions
   Theme · Search · Combined filters · Scroll reveal
   ───────────────────────────────────────────────────── */

(function () {
  "use strict";

  /* ── Theme ──────────────────────────────────────── */

  var root = document.documentElement;
  var toggle = document.getElementById("themeToggle");

  var sunSVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
  var moonSVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    if (toggle) toggle.innerHTML = theme === "dark" ? moonSVG : sunSVG;
  }

  applyTheme(localStorage.getItem("tb-theme") || "dark");

  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      applyTheme(next);
      localStorage.setItem("tb-theme", next);
    });
  }

  /* ── Search ─────────────────────────────────────── */

  var searchInput = document.getElementById("searchInput");
  var searchClear = document.getElementById("searchClear");
  var searchQuery = "";

  if (searchInput) {
    searchInput.addEventListener("input", function () {
      searchQuery = searchInput.value.trim().toLowerCase();
      if (searchClear) {
        searchClear.classList.toggle("visible", searchQuery.length > 0);
      }
      applyFilters();
    });
  }

  if (searchClear) {
    searchClear.addEventListener("click", function () {
      searchInput.value = "";
      searchQuery = "";
      searchClear.classList.remove("visible");
      applyFilters();
      searchInput.focus();
    });
  }

  /* ── Combined filters ───────────────────────────── */

  var allFilterBtns = document.querySelectorAll(".filter-btn");
  var activeSeverity = "";
  var activeVendor = "";
  var activeTag = "";

  allFilterBtns.forEach(function (btn) {
    btn.addEventListener("click", function () {
      var group = btn.dataset.filterGroup;
      var value = btn.dataset.filterValue || btn.dataset.tag;

      if (group === "severity") {
        if (activeSeverity === value) {
          activeSeverity = "";
          btn.classList.remove("active");
        } else {
          document.querySelectorAll('[data-filter-group="severity"]').forEach(function (b) { b.classList.remove("active"); });
          activeSeverity = value;
          btn.classList.add("active");
        }
      } else if (group === "vendor") {
        if (activeVendor === value) {
          activeVendor = "";
          btn.classList.remove("active");
        } else {
          document.querySelectorAll('[data-filter-group="vendor"]').forEach(function (b) { b.classList.remove("active"); });
          activeVendor = value;
          btn.classList.add("active");
        }
      } else {
        if (activeTag === value) {
          activeTag = "";
          btn.classList.remove("active");
        } else {
          document.querySelectorAll('.filter-btn:not([data-filter-group])').forEach(function (b) { b.classList.remove("active"); });
          document.querySelectorAll('[data-filter-group="tag"]').forEach(function (b) { b.classList.remove("active"); });
          activeTag = value;
          btn.classList.add("active");
        }
      }

      applyFilters();
    });
  });

  /* ── Apply all filters ──────────────────────────── */

  function applyFilters() {
    var cards = document.querySelectorAll(".article-card");
    var dayGroups = document.querySelectorAll(".day-group");
    var visibleCount = 0;

    cards.forEach(function (card) {
      var show = true;

      if (searchQuery) {
        var searchable = (card.dataset.title || "") + " " +
          (card.dataset.tags || "") + " " +
          (card.dataset.vendors || "") + " " +
          (card.textContent || "").toLowerCase();
        if (searchable.indexOf(searchQuery) === -1) show = false;
      }

      if (show && activeSeverity) {
        if (card.dataset.severity !== activeSeverity) show = false;
      }

      if (show && activeVendor) {
        var cardVendors = (card.dataset.vendors || "").split(",");
        if (cardVendors.indexOf(activeVendor) === -1) show = false;
      }

      if (show && activeTag) {
        var cardTags = (card.dataset.tags || "").split(",");
        if (cardTags.indexOf(activeTag) === -1) show = false;
      }

      card.style.display = show ? "" : "none";
      if (show) visibleCount++;
    });

    dayGroups.forEach(function (group) {
      var next = group.nextElementSibling;
      var hasVisible = false;
      while (next && !next.classList.contains("day-group")) {
        if (next.classList.contains("article-card") && next.style.display !== "none") {
          hasVisible = true;
        }
        next = next.nextElementSibling;
      }
      group.style.display = hasVisible ? "" : "none";
    });

    var counter = document.getElementById("filterCount");
    var anyFilter = searchQuery || activeSeverity || activeVendor || activeTag;
    if (counter) {
      if (anyFilter) {
        counter.textContent = visibleCount + " result" + (visibleCount !== 1 ? "s" : "");
        counter.style.display = "";
      } else {
        counter.style.display = "none";
      }
    }
  }

  /* ── Archive search ───────────────────────────────── */

  var archiveInput = document.getElementById("archiveSearch");
  if (archiveInput) {
    var archiveCards = document.querySelectorAll(".archive-day-card");
    archiveInput.addEventListener("input", function () {
      var q = archiveInput.value.trim().toLowerCase();
      archiveCards.forEach(function (card) {
        var data = card.dataset.search || "";
        card.style.display = !q || data.indexOf(q) !== -1 ? "" : "none";
      });
    });
  }

  /* ── Hourly auto-refresh ──────────────────────────── */

  setTimeout(function () { location.reload(); }, 60 * 60 * 1000);

  /* ── Scroll reveal (minimal, disabled on mobile) ── */

  if (window.innerWidth >= 640) {
    var revealEls = document.querySelectorAll(".article-card, .archive-day-card");
    if ("IntersectionObserver" in window && revealEls.length) {
      revealEls.forEach(function (el) {
        el.style.opacity = "0";
        el.style.transform = "translateY(12px)";
        el.style.transition = "opacity 0.4s ease, transform 0.4s ease";
      });
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) {
            e.target.style.opacity = "1";
            e.target.style.transform = "translateY(0)";
            io.unobserve(e.target);
          }
        });
      }, { threshold: 0.05 });
      revealEls.forEach(function (el) { io.observe(el); });
    }
  }
})();
