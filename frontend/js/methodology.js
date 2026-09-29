/* ============================================================
   PhishGuard - methodology.js
   Methodology page: detection info, ML model, rules
   ============================================================ */
(function () {
  "use strict";

  function initMethodologyPage() {
    loadModelInfo();
  }

  function loadModelInfo() {
    PG.api("/api/model/info").then(function (data) {
      renderModelMetrics(data);
      renderRulesList(data.rules);
    }).catch(function (err) {
      var metricsEl = document.getElementById("ml-metrics");
      if (metricsEl) {
        metricsEl.appendChild(PG.el("p", { className: "text-secondary" },
          "ML model information is currently unavailable."));
      }
    });
  }

  function renderModelMetrics(data) {
    var container = document.getElementById("ml-metrics");
    if (!container) return;
    container.innerHTML = "";

    var grid = PG.el("div", { className: "ml-metrics-grid" });

    var metrics = [];

    if (data.model_name) {
      metrics.push({ label: "Model", value: data.model_name });
    }
    if (data.accuracy != null) {
      metrics.push({ label: "Accuracy", value: PG.fmt.pct(data.accuracy * 100) });
    }
    if (data.precision != null) {
      metrics.push({ label: "Precision", value: PG.fmt.pct(data.precision * 100) });
    }
    if (data.recall != null) {
      metrics.push({ label: "Recall", value: PG.fmt.pct(data.recall * 100) });
    }
    if (data.f1_score != null) {
      metrics.push({ label: "F1 Score", value: PG.fmt.pct(data.f1_score * 100) });
    }
    if (data.dataset) {
      metrics.push({ label: "Dataset", value: data.dataset });
    }
    if (data.total_samples != null) {
      metrics.push({ label: "Training Samples", value: String(data.total_samples) });
    }
    if (data.features_count != null) {
      metrics.push({ label: "Features", value: String(data.features_count) });
    }
    if (data.trained_at) {
      metrics.push({ label: "Trained", value: PG.fmt.date(data.trained_at) });
    }

    metrics.forEach(function (m) {
      var card = PG.el("div", { className: "ml-metric-card" });
      card.appendChild(PG.el("div", { className: "ml-metric-value" }, m.value));
      card.appendChild(PG.el("div", { className: "ml-metric-label" }, m.label));
      grid.appendChild(card);
    });

    container.appendChild(grid);

    // Feature set info
    if (data.feature_set) {
      container.appendChild(PG.el("p", { className: "text-sm text-secondary mt-4" },
        "Feature set: " + data.feature_set));
    }

    // Bias / limitations note
    if (data.bias_note) {
      container.appendChild(PG.el("div", { className: "alert alert-info mt-4" },
        PG.icon("info"),
        PG.el("span", null, data.bias_note)
      ));
    }
  }

  function renderRulesList(rules) {
    var container = document.getElementById("rules-list");
    if (!container) return;
    container.innerHTML = "";

    if (!rules || rules.length === 0) {
      container.appendChild(PG.el("p", { className: "text-secondary" }, "Rule information not available."));
      return;
    }

    rules.forEach(function (rule) {
      var item = PG.el("div", { className: "rule-item" });
      item.appendChild(PG.el("h5", null, rule.name || rule.id));
      if (rule.description) {
        item.appendChild(PG.el("p", null, rule.description));
      }
      var meta = PG.el("div", { className: "flex items-center gap-2 mt-2" });
      if (rule.severity) {
        var severityClass = rule.severity === "strong" ? "badge-phishing" :
          rule.severity === "medium" ? "badge-suspicious" :
            rule.severity === "positive" ? "badge-legitimate" : "badge-info";
        meta.appendChild(PG.el("span", { className: "badge " + severityClass }, rule.severity));
      }
      if (rule.points != null) {
        meta.appendChild(PG.el("span", { className: "text-xs mono" },
          (rule.points > 0 ? "+" : "") + rule.points + " pts"));
      }
      item.appendChild(meta);
      container.appendChild(item);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    PG.init().then(initMethodologyPage);
  });
})();
