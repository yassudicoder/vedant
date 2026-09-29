/* ============================================================
   PhishGuard - dashboard.js
   Admin dashboard: stats, charts, tables
   ============================================================ */
(function () {
  "use strict";

  function initDashboard() {
    // Check admin role
    if (!PG.auth.user || PG.auth.user.role !== "admin") {
      PG.toast("Admin access required", "error");
      PG.navigate("/login.html?redirect=/dashboard.html");
      return;
    }

    loadStats();
    loadUsers();
  }

  function loadStats() {
    PG.api("/api/admin/stats").then(function (data) {
      renderStats(data);
      renderDailyChart(data.daily);
      renderDistributionChart(data.risk_distribution);
      renderRecentScans(data.recent);
    }).catch(function (err) {
      PG.toast(err.message || "Failed to load dashboard data", "error");
    });
  }

  function renderStats(data) {
    var totals = data.totals || {};

    var items = [
      { id: "stat-total", value: totals.total || 0 },
      { id: "stat-phishing", value: totals.phishing || 0 },
      { id: "stat-suspicious", value: totals.suspicious || 0 },
      { id: "stat-legitimate", value: totals.legitimate || 0 }
    ];

    items.forEach(function (item) {
      var el = document.getElementById(item.id);
      if (el) el.textContent = String(item.value);
    });
  }

  function renderDailyChart(dailyData) {
    var canvas = document.getElementById("chart-daily");
    if (!canvas || !dailyData || typeof Chart === "undefined") return;

    var labels = dailyData.map(function (d) {
      return d.date;
    });
    var counts = dailyData.map(function (d) {
      return d.count;
    });

    new Chart(canvas, {
      type: "line",
      data: {
        labels: labels,
        datasets: [{
          label: "Daily Scans",
          data: counts,
          borderColor: "#16A34A",
          backgroundColor: "rgba(22, 163, 74, 0.1)",
          fill: true,
          tension: 0.3,
          pointRadius: 2,
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 } },
          x: {
            grid: { display: false },
            ticks: {
              maxTicksLimit: 10,
              maxRotation: 0
            }
          }
        }
      }
    });
  }

  function renderDistributionChart(distribution) {
    var canvas = document.getElementById("chart-distribution");
    if (!canvas || !distribution || typeof Chart === "undefined") return;

    var labels = distribution.map(function (d) { return d.range; });
    var counts = distribution.map(function (d) { return d.count; });
    var colors = distribution.map(function (d) {
      var mid = parseInt(d.range.split("-")[0], 10);
      return PG.riskColor(mid + 5);
    });

    new Chart(canvas, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Scans",
          data: counts,
          backgroundColor: colors,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 } },
          x: { grid: { display: false } }
        }
      }
    });
  }

  function renderRecentScans(scans) {
    var tbody = document.getElementById("recent-scans-tbody");
    if (!tbody || !scans) return;
    tbody.innerHTML = "";

    scans.forEach(function (scan) {
      var tr = PG.el("tr");

      var idCell = PG.el("td");
      var link = PG.el("a", {
        href: "/result.html?id=" + encodeURIComponent(scan.scan_id),
        className: "scan-link mono text-xs"
      }, scan.scan_id);
      idCell.appendChild(link);
      tr.appendChild(idCell);

      var urlCell = PG.el("td", { className: "table-url" }, scan.url || "");
      tr.appendChild(urlCell);

      var classCell = PG.el("td");
      classCell.appendChild(PG.el("span", { className: PG.classBadge(scan.classification) }, scan.classification || "N/A"));
      tr.appendChild(classCell);

      var scoreCell = PG.el("td", { className: "risk-score-cell" });
      if (scan.risk_score != null) {
        scoreCell.textContent = String(scan.risk_score);
        scoreCell.style.color = PG.riskColor(scan.risk_score);
      } else {
        scoreCell.textContent = "N/A";
      }
      tr.appendChild(scoreCell);

      tr.appendChild(PG.el("td", { className: "text-sm text-secondary" }, PG.fmt.date(scan.created_at)));

      tbody.appendChild(tr);
    });
  }

  function loadUsers() {
    PG.api("/api/admin/users").then(function (data) {
      var tbody = document.getElementById("users-tbody");
      if (!tbody) return;
      tbody.innerHTML = "";

      var users = Array.isArray(data) ? data : (data.users || []);

      users.forEach(function (user) {
        var tr = PG.el("tr");
        tr.appendChild(PG.el("td", { className: "text-sm" }, user.email));

        var roleCell = PG.el("td");
        roleCell.appendChild(PG.el("span", { className: "badge " + (user.role === "admin" ? "badge-info" : "badge-legitimate") }, user.role));
        tr.appendChild(roleCell);

        tr.appendChild(PG.el("td", { className: "text-sm text-secondary" }, PG.fmt.date(user.created_at)));
        tr.appendChild(PG.el("td", { className: "text-sm" }, user.scan_count != null ? String(user.scan_count) : "0"));
        tr.appendChild(PG.el("td", { className: "text-sm text-secondary" }, PG.fmt.date(user.last_login_at)));
        tbody.appendChild(tr);
      });
    }).catch(function (err) {
      PG.toast("Failed to load users", "error");
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    PG.init().then(initDashboard);
  });
})();
