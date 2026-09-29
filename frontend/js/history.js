/* ============================================================
   PhishGuard - history.js
   Scan history table with pagination and filters
   ============================================================ */
(function () {
  "use strict";

  var currentPage = 1;
  var pageSize = 20;
  var currentQuery = "";
  var currentClassification = "";

  function initHistoryPage() {
    var searchInput = document.getElementById("history-search");
    var classFilter = document.getElementById("history-classification");

    if (searchInput) {
      var debounceTimer;
      searchInput.addEventListener("input", function () {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(function () {
          currentQuery = searchInput.value.trim();
          currentPage = 1;
          loadHistory();
        }, 400);
      });
    }

    if (classFilter) {
      classFilter.addEventListener("change", function () {
        currentClassification = classFilter.value;
        currentPage = 1;
        loadHistory();
      });
    }

    loadHistory();
  }

  function loadHistory() {
    var tbody = document.getElementById("history-tbody");
    var loader = document.getElementById("history-loader");
    var emptyState = document.getElementById("history-empty");
    var paginationEl = document.getElementById("history-pagination");

    if (loader) loader.classList.remove("hidden");
    if (emptyState) emptyState.classList.add("hidden");
    if (tbody) tbody.innerHTML = "";

    var params = new URLSearchParams();
    params.set("page", currentPage);
    params.set("page_size", pageSize);
    if (currentQuery) params.set("q", currentQuery);
    if (currentClassification) params.set("classification", currentClassification);

    PG.api("/api/history?" + params.toString()).then(function (data) {
      if (loader) loader.classList.add("hidden");

      if (!data.items || data.items.length === 0) {
        if (emptyState) emptyState.classList.remove("hidden");
        if (paginationEl) paginationEl.innerHTML = "";
        return;
      }

      data.items.forEach(function (item) {
        var tr = PG.el("tr");

        // URL cell
        var urlCell = PG.el("td");
        var urlLink = PG.el("a", {
          href: "/result.html?id=" + encodeURIComponent(item.scan_id),
          className: "scan-link table-url"
        }, item.url || item.hostname || "N/A");
        urlCell.appendChild(urlLink);
        tr.appendChild(urlCell);

        // Classification
        var classCell = PG.el("td");
        var badge = PG.el("span", { className: PG.classBadge(item.classification) }, item.classification || "N/A");
        classCell.appendChild(badge);
        tr.appendChild(classCell);

        // Risk Score
        var scoreCell = PG.el("td", { className: "risk-score-cell" });
        if (item.risk_score !== null && item.risk_score !== undefined) {
          scoreCell.textContent = item.risk_score;
          scoreCell.style.color = PG.riskColor(item.risk_score);
        } else {
          scoreCell.textContent = "N/A";
        }
        tr.appendChild(scoreCell);

        // Date
        var dateCell = PG.el("td", { className: "text-sm text-secondary" }, PG.fmt.date(item.created_at));
        tr.appendChild(dateCell);

        // Actions
        var actionCell = PG.el("td");
        var viewLink = PG.el("a", {
          href: "/result.html?id=" + encodeURIComponent(item.scan_id),
          className: "btn btn-sm btn-ghost"
        }, "View");
        actionCell.appendChild(viewLink);
        tr.appendChild(actionCell);

        tbody.appendChild(tr);
      });

      renderPagination(paginationEl, data.total, data.page, data.page_size);
    }).catch(function (err) {
      if (loader) loader.classList.add("hidden");
      PG.toast(err.message || "Failed to load history", "error");
    });
  }

  function renderPagination(container, total, page, size) {
    if (!container) return;
    container.innerHTML = "";

    var totalPages = Math.ceil(total / size);
    if (totalPages <= 1) return;

    var info = PG.el("span", { className: "pagination-info" },
      "Showing " + ((page - 1) * size + 1) + "-" + Math.min(page * size, total) + " of " + total);
    container.appendChild(info);

    // Previous
    var prevBtn = PG.el("button", { className: "btn btn-sm btn-secondary" }, "Prev");
    if (page <= 1) prevBtn.disabled = true;
    prevBtn.addEventListener("click", function () {
      if (currentPage > 1) {
        currentPage--;
        loadHistory();
      }
    });
    container.appendChild(prevBtn);

    // Page numbers
    var startPage = Math.max(1, page - 2);
    var endPage = Math.min(totalPages, page + 2);

    for (var i = startPage; i <= endPage; i++) {
      var pageBtn = PG.el("button", {
        className: "btn btn-sm " + (i === page ? "active" : "btn-secondary")
      }, String(i));
      pageBtn.dataset.page = i;
      pageBtn.addEventListener("click", function () {
        currentPage = parseInt(this.dataset.page, 10);
        loadHistory();
      });
      container.appendChild(pageBtn);
    }

    // Next
    var nextBtn = PG.el("button", { className: "btn btn-sm btn-secondary" }, "Next");
    if (page >= totalPages) nextBtn.disabled = true;
    nextBtn.addEventListener("click", function () {
      if (currentPage < totalPages) {
        currentPage++;
        loadHistory();
      }
    });
    container.appendChild(nextBtn);
  }

  document.addEventListener("DOMContentLoaded", function () {
    PG.init().then(initHistoryPage);
  });
})();
