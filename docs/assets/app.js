/* ─────────────────────────────────────────────────────
   Threat Brief — Client-side interactions
   Theme · Relative time · Search · Filters · Expand ·
   Mark-as-read · Auto-refresh
   ───────────────────────────────────────────────────── */

(function () {
  "use strict";

  /* ── Theme ──────────────────────────────────────── */

  var root = document.documentElement;
  var toggle = document.getElementById("themeToggle");

  var sunSVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
  var moonSVG =
    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

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

  /* ── Relative time ─────────────────────────────── */

  function relativeTime(isoStr) {
    try {
      var diff = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000);
      if (diff < 0) return null;
      if (diff < 60) return "just now";
      if (diff < 3600) return Math.floor(diff / 60) + "m ago";
      if (diff < 86400) return Math.floor(diff / 3600) + "h ago";
      if (diff < 172800) return "Yesterday";
      if (diff < 604800) return Math.floor(diff / 86400) + "d ago";
    } catch (e) { /* fall through */ }
    return null;
  }

  function updateRelativeTimes() {
    document.querySelectorAll("time[data-iso]").forEach(function (el) {
      var rel = relativeTime(el.dataset.iso);
      if (rel) el.textContent = rel;
    });
  }

  updateRelativeTimes();
  setInterval(updateRelativeTimes, 60000);

  /* ── Mark as read ──────────────────────────────── */

  var READ_KEY = "tb-read";

  function getReadIds() {
    try { return JSON.parse(localStorage.getItem(READ_KEY) || "[]"); }
    catch (e) { return []; }
  }

  function markAsRead(id) {
    if (!id) return;
    var ids = getReadIds();
    if (ids.indexOf(id) === -1) {
      ids.push(id);
      if (ids.length > 300) ids = ids.slice(-300);
      localStorage.setItem(READ_KEY, JSON.stringify(ids));
    }
    var card = document.querySelector('[data-id="' + id + '"]');
    if (card) card.classList.add("is-read");
  }

  getReadIds().forEach(function (id) {
    var card = document.querySelector('[data-id="' + id + '"]');
    if (card) card.classList.add("is-read");
  });

  /* ── Card expand / collapse ────────────────────── */

  document.querySelectorAll(".card-body").forEach(function (body) {
    body.addEventListener("click", function (e) {
      if (e.target.closest("a")) return;

      var card = body.closest(".article-card");
      if (!card) return;
      var detail = card.querySelector(".card-detail");
      if (!detail) return;

      var wasOpen = detail.getAttribute("aria-hidden") === "false";

      document.querySelectorAll('.card-detail[aria-hidden="false"]').forEach(function (d) {
        d.setAttribute("aria-hidden", "true");
        d.closest(".article-card").classList.remove("is-expanded");
      });

      if (!wasOpen) {
        detail.setAttribute("aria-hidden", "false");
        card.classList.add("is-expanded");
        markAsRead(card.dataset.id);
      }
    });
  });

  document.querySelectorAll(".detail-read").forEach(function (link) {
    link.addEventListener("click", function () {
      var card = link.closest(".article-card");
      if (card) markAsRead(card.dataset.id);
    });
  });

  /* ── CVE copy buttons ──────────────────────────── */

  document.querySelectorAll(".cve-copy").forEach(function (btn) {
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      var cve = btn.closest("[data-cve]");
      if (cve && navigator.clipboard) {
        navigator.clipboard.writeText(cve.dataset.cve).then(function () {
          btn.style.opacity = "1";
          setTimeout(function () { btn.style.opacity = ""; }, 1200);
        });
      }
    });
  });

  /* ── Search ────────────────────────────────────── */

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

  /* ── Unified filters ───────────────────────────── */

  var activeSeverity = "";
  var activeVendor = "";
  var activeTag = "";
  var activeSpecial = "";

  function clearGroupActive(group) {
    document.querySelectorAll('[data-filter-group="' + group + '"]').forEach(function (b) {
      b.classList.remove("active");
    });
  }

  function handleFilterClick(btn) {
    var group = btn.dataset.filterGroup;
    var value = btn.dataset.filterValue;

    if (group === "severity") {
      if (activeSeverity === value) { activeSeverity = ""; btn.classList.remove("active"); }
      else { clearGroupActive("severity"); activeSeverity = value; btn.classList.add("active"); }
      activeSpecial = "";
      clearGroupActive("special");
    } else if (group === "vendor") {
      if (activeVendor === value) { activeVendor = ""; btn.classList.remove("active"); }
      else { clearGroupActive("vendor"); activeVendor = value; btn.classList.add("active"); }
    } else if (group === "tag") {
      if (activeTag === value) { activeTag = ""; btn.classList.remove("active"); }
      else { clearGroupActive("tag"); activeTag = value; btn.classList.add("active"); }
    } else if (group === "special") {
      if (activeSpecial === value) { activeSpecial = ""; btn.classList.remove("active"); }
      else {
        clearGroupActive("special");
        clearGroupActive("severity");
        activeSeverity = "";
        activeSpecial = value;
        btn.classList.add("active");
      }
    }

    applyFilters();
  }

  document.querySelectorAll(".qf-btn:not(#moreFiltersBtn), .filter-btn").forEach(function (btn) {
    btn.addEventListener("click", function () { handleFilterClick(btn); });
  });

  /* ── More filters toggle ───────────────────────── */

  var moreBtn = document.getElementById("moreFiltersBtn");
  var advPanel = document.getElementById("advFilters");

  if (moreBtn && advPanel) {
    moreBtn.addEventListener("click", function () {
      var isOpen = !advPanel.hidden;
      advPanel.hidden = isOpen;
      moreBtn.setAttribute("aria-expanded", String(!isOpen));
      moreBtn.classList.toggle("active", !isOpen);
    });
  }

  /* ── Apply all filters ─────────────────────────── */

  function isWithin6h(isoStr) {
    try { return (Date.now() - new Date(isoStr).getTime()) < 6 * 3600 * 1000; }
    catch (e) { return false; }
  }

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
        var cv = (card.dataset.vendors || "").split(",");
        if (cv.indexOf(activeVendor) === -1) show = false;
      }

      if (show && activeTag) {
        var ct = (card.dataset.tags || "").split(",");
        if (ct.indexOf(activeTag) === -1) show = false;
      }

      if (show && activeSpecial === "action") {
        if (card.dataset.action !== "true") show = false;
      }

      if (show && activeSpecial === "6h") {
        if (!isWithin6h(card.dataset.published)) show = false;
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
    var anyFilter = searchQuery || activeSeverity || activeVendor || activeTag || activeSpecial;
    if (counter) {
      if (anyFilter) {
        counter.textContent = visibleCount + " result" + (visibleCount !== 1 ? "s" : "");
        counter.style.display = "";
      } else {
        counter.style.display = "none";
      }
    }
  }

  /* ── Archive search ────────────────────────────── */

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

  /* ── Hourly auto-refresh ───────────────────────── */

  setTimeout(function () { location.reload(); }, 60 * 60 * 1000);

})();
