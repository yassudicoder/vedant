/* ============================================================
   PhishGuard - result.js
   Full report display with tabs, gauge, charts, findings
   ============================================================ */
(function () {
  "use strict";

  var report = null;

  function initResultPage() {
    var scanId = PG.param("id");
    if (!scanId) {
      PG.navigate("/");
      return;
    }

    var loader = document.getElementById("result-loader");
    var content = document.getElementById("result-content");
    var errorEl = document.getElementById("result-error");

    PG.api("/api/report/" + encodeURIComponent(scanId)).then(function (data) {
      report = data;
      if (loader) loader.classList.add("hidden");
      if (content) content.classList.remove("hidden");
      renderReport(data);
    }).catch(function (err) {
      if (loader) loader.classList.add("hidden");
      if (errorEl) {
        errorEl.classList.remove("hidden");
        var msg = errorEl.querySelector("span");
        if (msg) msg.textContent = err.message || "Report not found.";
      }
    });
  }

  function renderReport(r) {
    // Scan ID and timestamp
    var idEl = document.getElementById("report-id");
    if (idEl) idEl.textContent = r.scan_id || "";

    var timeEl = document.getElementById("report-time");
    if (timeEl) timeEl.textContent = PG.fmt.date(r.created_at);

    // URL display
    var urlEl = document.getElementById("report-url");
    if (urlEl) urlEl.textContent = r.url || r.normalized_url || "";

    // Risk gauge
    renderGauge(r.risk_score);

    // Classification badge
    var classEl = document.getElementById("report-classification");
    if (classEl) {
      classEl.className = PG.classBadge(r.classification) + " badge-lg";
      classEl.textContent = r.classification || "N/A";
    }

    // Risk band
    var bandEl = document.getElementById("report-band");
    if (bandEl) bandEl.textContent = r.risk_band ? r.risk_band + " Risk" : "";

    // Confidence
    var confEl = document.getElementById("report-confidence");
    if (confEl) confEl.textContent = PG.fmt.pct(r.confidence);

    // Summary
    var summaryEl = document.getElementById("report-summary");
    if (summaryEl) summaryEl.textContent = r.summary || "";

    // Recommendation
    var recEl = document.getElementById("report-recommendation");
    if (recEl) recEl.textContent = r.recommendation || "";

    // Category scores
    renderCategoryScores(r.category_scores);

    // Tabs
    setupTabs();

    // Tab content
    renderOverviewTab(r);
    renderURLTab(r.url_analysis);
    renderDomainTab(r.domain_analysis);
    renderTLSTab(r.tls_analysis);
    renderPageTab(r.webpage_analysis);
    renderRedirectsTab(r.redirect_analysis);
    renderMLTab(r.ml_analysis);
    renderRulesTab(r.rule_analysis);

    // Findings
    renderFindings(r.indicator_groups);

    // Actions
    setupActions(r.scan_id);

    // Charts
    renderCharts(r);
  }

  /* --- Risk Gauge (semicircular) --- */
  function renderGauge(score) {
    var gaugeEl = document.getElementById("risk-gauge");
    if (!gaugeEl) return;

    var safeScore = (score !== null && score !== undefined) ? score : 0;
    var color = PG.riskColor(score);

    var svgNS = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("viewBox", "0 0 200 120");
    svg.setAttribute("aria-label", "Risk score: " + (score !== null ? score : "N/A"));

    // Background arc
    var bgArc = document.createElementNS(svgNS, "path");
    bgArc.setAttribute("d", describeArc(100, 100, 80, 180, 360));
    bgArc.setAttribute("fill", "none");
    bgArc.setAttribute("stroke", "#E5E7EB");
    bgArc.setAttribute("stroke-width", "12");
    bgArc.setAttribute("stroke-linecap", "round");
    svg.appendChild(bgArc);

    // Score arc
    if (score !== null && score !== undefined) {
      var angle = 180 + (safeScore / 100) * 180;
      var scoreArc = document.createElementNS(svgNS, "path");
      scoreArc.setAttribute("d", describeArc(100, 100, 80, 180, angle));
      scoreArc.setAttribute("fill", "none");
      scoreArc.setAttribute("stroke", color);
      scoreArc.setAttribute("stroke-width", "12");
      scoreArc.setAttribute("stroke-linecap", "round");
      svg.appendChild(scoreArc);
    }

    // Score text
    var text = document.createElementNS(svgNS, "text");
    text.setAttribute("x", "100");
    text.setAttribute("y", "95");
    text.setAttribute("text-anchor", "middle");
    text.setAttribute("font-size", "36");
    text.setAttribute("font-weight", "700");
    text.setAttribute("fill", color);
    text.textContent = score !== null && score !== undefined ? String(score) : "N/A";
    svg.appendChild(text);

    var label = document.createElementNS(svgNS, "text");
    label.setAttribute("x", "100");
    label.setAttribute("y", "115");
    label.setAttribute("text-anchor", "middle");
    label.setAttribute("font-size", "12");
    label.setAttribute("fill", "#6B7280");
    label.textContent = "Risk Score";
    svg.appendChild(label);

    gaugeEl.innerHTML = "";
    gaugeEl.appendChild(svg);
  }

  function describeArc(x, y, radius, startAngle, endAngle) {
    var start = polarToCartesian(x, y, radius, endAngle);
    var end = polarToCartesian(x, y, radius, startAngle);
    var largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
    return "M " + start.x + " " + start.y +
      " A " + radius + " " + radius + " 0 " + largeArcFlag + " 0 " + end.x + " " + end.y;
  }

  function polarToCartesian(cx, cy, radius, angleDeg) {
    var angleRad = (angleDeg - 90) * Math.PI / 180;
    return {
      x: cx + radius * Math.cos(angleRad),
      y: cy + radius * Math.sin(angleRad)
    };
  }

  /* --- Category Scores --- */
  function renderCategoryScores(scores) {
    var container = document.getElementById("category-scores");
    if (!container || !scores) return;
    container.innerHTML = "";

    scores.forEach(function (cat) {
      var risk = cat.risk;
      if (risk === null || risk === undefined) risk = 0;

      var bar = PG.el("div", { className: "score-bar" });
      bar.appendChild(PG.el("span", { className: "score-bar-label" }, cat.label || cat.key));

      var track = PG.el("div", { className: "score-bar-track" });
      var fill = PG.el("div", { className: "score-bar-fill" });
      fill.style.width = risk + "%";
      fill.style.backgroundColor = PG.riskColor(risk);
      track.appendChild(fill);
      bar.appendChild(track);

      var statusText = cat.status === "unavailable" ? "N/A" : PG.fmt.pct(risk);
      bar.appendChild(PG.el("span", { className: "score-bar-value" }, statusText));

      container.appendChild(bar);
    });
  }

  /* --- Tabs --- */
  function setupTabs() {
    var tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var target = btn.dataset.tab;
        tabBtns.forEach(function (b) { b.classList.remove("active"); });
        btn.classList.add("active");

        document.querySelectorAll(".tab-panel").forEach(function (p) {
          p.classList.remove("active");
        });
        var panel = document.getElementById("tab-" + target);
        if (panel) panel.classList.add("active");
      });
    });
  }

  /* --- Tab Renderers --- */
  function renderOverviewTab(r) {
    var panel = document.getElementById("tab-overview");
    if (!panel) return;

    var container = panel.querySelector(".tab-content");
    if (!container) return;
    container.innerHTML = "";

    // Explanation
    if (r.explanation) {
      container.appendChild(PG.el("p", { className: "mb-4" }, r.explanation));
    }

    // Disclaimer
    if (r.disclaimer) {
      var disc = PG.el("div", { className: "disclaimer" });
      disc.appendChild(PG.icon("info", "icon-sm"));
      disc.appendChild(PG.el("span", null, " " + r.disclaimer));
      container.appendChild(disc);
    }

    // Duration
    if (r.duration_ms) {
      container.appendChild(PG.el("p", { className: "text-sm text-secondary mt-4" },
        "Analysis completed in " + (r.duration_ms / 1000).toFixed(1) + "s"));
    }
  }

  function renderURLTab(ua) {
    var panel = document.getElementById("tab-url");
    if (!panel || !ua) return;
    var container = panel.querySelector(".tab-content");
    if (!container) return;
    container.innerHTML = "";

    if (ua.status === "unavailable") {
      container.appendChild(PG.el("p", { className: "text-secondary" }, ua.message || "URL analysis unavailable."));
      return;
    }

    var grid = PG.el("div", { className: "report-data-grid" });

    var fields = [
      { label: "Hostname", value: ua.hostname },
      { label: "Registered Domain", value: ua.registered_domain },
      { label: "Scheme", value: ua.scheme },
      { label: "HTTPS", value: ua.https ? "Yes" : "No" },
      { label: "URL Length", value: ua.url_length },
      { label: "Hostname Length", value: ua.hostname_length },
      { label: "Path Depth", value: ua.path_depth },
      { label: "Subdomains", value: ua.num_subdomains },
      { label: "IP Address Host", value: ua.has_ip ? "Yes" : "No" },
      { label: "Punycode", value: ua.has_punycode ? "Detected" : "No" },
      { label: "Suspicious TLD", value: ua.suspicious_tld ? "Yes" : "No" },
      { label: "URL Shortener", value: ua.is_shortener ? (ua.shortener_service || "Yes") : "No" },
      { label: "Domain Entropy", value: ua.domain_entropy != null ? ua.domain_entropy.toFixed(2) : "N/A" },
      { label: "Random Domain Score", value: ua.random_domain_score != null ? (ua.random_domain_score * 100).toFixed(0) + "%" : "N/A" }
    ];

    fields.forEach(function (f) {
      var item = PG.el("div", { className: "report-data-item" });
      item.appendChild(PG.el("dt", null, f.label));
      item.appendChild(PG.el("dd", null, String(f.value !== null && f.value !== undefined ? f.value : "N/A")));
      grid.appendChild(item);
    });

    container.appendChild(grid);

    if (ua.suspicious_keywords && ua.suspicious_keywords.length > 0) {
      container.appendChild(PG.el("h5", { className: "mt-4 mb-2" }, "Suspicious Keywords"));
      var kwList = PG.el("div", { className: "flex flex-wrap gap-2" });
      ua.suspicious_keywords.forEach(function (kw) {
        kwList.appendChild(PG.el("span", { className: "badge badge-suspicious" }, kw));
      });
      container.appendChild(kwList);
    }
  }

  function renderDomainTab(da) {
    var panel = document.getElementById("tab-domain");
    if (!panel || !da) return;
    var container = panel.querySelector(".tab-content");
    if (!container) return;
    container.innerHTML = "";

    if (da.status === "unavailable") {
      container.appendChild(PG.el("p", { className: "text-secondary" }, da.message || "Domain analysis unavailable."));
      return;
    }

    var grid = PG.el("div", { className: "report-data-grid" });

    var regInfo = da.registration || {};
    var dnsInfo = da.dns || {};
    var asnInfo = da.asn || {};

    var fields = [
      { label: "Domain", value: da.domain },
      { label: "Registrar", value: regInfo.registrar },
      { label: "Created", value: PG.fmt.date(regInfo.created) },
      { label: "Domain Age", value: regInfo.domain_age_days != null ? regInfo.domain_age_days + " days" : "Unknown" },
      { label: "Expires", value: PG.fmt.date(regInfo.expires) },
      { label: "DNS Resolves", value: dnsInfo.resolves ? "Yes" : "No" },
      { label: "A Records", value: dnsInfo.a ? dnsInfo.a.join(", ") : "None" },
      { label: "NS Records", value: dnsInfo.ns ? dnsInfo.ns.join(", ") : "None" },
      { label: "Has SPF", value: dnsInfo.has_spf != null ? (dnsInfo.has_spf ? "Yes" : "No") : "Unknown" },
      { label: "Has DMARC", value: dnsInfo.has_dmarc != null ? (dnsInfo.has_dmarc ? "Yes" : "No") : "Unknown" },
      { label: "ASN", value: asnInfo.asn || "N/A" },
      { label: "AS Name", value: asnInfo.as_name || "N/A" }
    ];

    fields.forEach(function (f) {
      var item = PG.el("div", { className: "report-data-item" });
      item.appendChild(PG.el("dt", null, f.label));
      item.appendChild(PG.el("dd", null, String(f.value !== null && f.value !== undefined ? f.value : "N/A")));
      grid.appendChild(item);
    });

    container.appendChild(grid);

    // Popularity
    if (da.popularity) {
      container.appendChild(PG.el("h5", { className: "mt-4 mb-2" }, "Popularity"));
      container.appendChild(PG.el("p", { className: "text-sm" },
        da.popularity.available ? "Rank: " + da.popularity.rank + " (" + da.popularity.source + ")" : da.popularity.message || "Not available"));
    }

    // Reputation
    if (da.reputation) {
      container.appendChild(PG.el("h5", { className: "mt-4 mb-2" }, "Reputation"));
      if (da.reputation.configured && da.reputation.listed != null) {
        var repBadge = PG.el("span", {
          className: da.reputation.listed ? "badge badge-phishing" : "badge badge-legitimate"
        }, da.reputation.listed ? "Flagged" : "Clean");
        container.appendChild(repBadge);
        if (da.reputation.threats && da.reputation.threats.length > 0) {
          container.appendChild(PG.el("p", { className: "text-sm mt-2" }, "Threats: " + da.reputation.threats.join(", ")));
        }
      } else {
        container.appendChild(PG.el("p", { className: "text-sm text-secondary" }, da.reputation.message || "Not configured"));
      }
    }
  }

  function renderTLSTab(ta) {
    var panel = document.getElementById("tab-tls");
    if (!panel || !ta) return;
    var container = panel.querySelector(".tab-content");
    if (!container) return;
    container.innerHTML = "";

    if (ta.status === "unavailable" || ta.status === "error") {
      container.appendChild(PG.el("p", { className: "text-secondary" }, ta.message || "TLS information unavailable."));
      return;
    }

    var grid = PG.el("div", { className: "tls-grid" });

    var items = [
      { label: "HTTPS Available", value: ta.https_available ? "Yes" : "No", ok: ta.https_available },
      { label: "Certificate Valid", value: ta.certificate_valid ? "Yes" : "No", ok: ta.certificate_valid },
      { label: "Hostname Match", value: ta.hostname_match ? "Yes" : "No", ok: ta.hostname_match },
      { label: "TLS Version", value: ta.tls_version || "N/A" },
      { label: "Issuer", value: (ta.issuer && ta.issuer.organization) || (ta.issuer && ta.issuer.common_name) || "N/A" },
      { label: "Subject CN", value: (ta.subject && ta.subject.common_name) || "N/A" },
      { label: "Valid From", value: PG.fmt.date(ta.not_before) },
      { label: "Valid Until", value: PG.fmt.date(ta.not_after) },
      { label: "Days Until Expiry", value: ta.days_until_expiry != null ? String(ta.days_until_expiry) : "N/A" },
      { label: "Self-Signed", value: ta.self_signed ? "Yes" : "No", ok: !ta.self_signed },
      { label: "Issuer Category", value: ta.issuer_category || "N/A" },
      { label: "Cipher", value: ta.cipher || "N/A" }
    ];

    items.forEach(function (item) {
      var el = PG.el("div", { className: "tls-item" });
      if (item.ok !== undefined) {
        el.appendChild(PG.icon(item.ok ? "check-circle" : "x-circle", "icon-sm"));
      }
      var content = PG.el("div");
      content.appendChild(PG.el("div", { className: "tls-item-label" }, item.label));
      content.appendChild(PG.el("div", { className: "tls-item-value" }, item.value));
      el.appendChild(content);
      grid.appendChild(el);
    });

    container.appendChild(grid);

    if (ta.note) {
      container.appendChild(PG.el("p", { className: "disclaimer mt-4" }, ta.note));
    }
  }

  function renderPageTab(wa) {
    var panel = document.getElementById("tab-page");
    if (!panel || !wa) return;
    var container = panel.querySelector(".tab-content");
    if (!container) return;
    container.innerHTML = "";

    if (wa.status === "unavailable" || wa.status === "error") {
      container.appendChild(PG.el("p", { className: "text-secondary" }, wa.message || "Page analysis unavailable."));
      return;
    }

    if (wa.status === "restricted") {
      container.appendChild(PG.el("div", { className: "alert alert-warning" },
        PG.icon("alert-triangle"),
        PG.el("span", null, wa.message || "Access restricted.")
      ));
    }

    var grid = PG.el("div", { className: "report-data-grid" });

    var fields = [
      { label: "Title", value: wa.title },
      { label: "HTTP Status", value: wa.http_status },
      { label: "Content Type", value: wa.content_type },
      { label: "Language", value: wa.language },
      { label: "Forms", value: wa.forms ? wa.forms.count : "N/A" },
      { label: "Password Fields", value: wa.has_password_field ? "Yes" : "No" },
      { label: "Login Wording", value: wa.has_login_wording ? "Detected" : "No" },
      { label: "External Links", value: wa.links ? wa.links.external : "N/A" },
      { label: "Iframes", value: wa.iframes ? wa.iframes.count : "N/A" },
      { label: "Hidden Elements", value: wa.hidden_elements != null ? wa.hidden_elements : "N/A" },
      { label: "Inline Scripts", value: wa.scripts ? wa.scripts.inline_count : "N/A" },
      { label: "Element Count", value: wa.structure ? wa.structure.element_count : "N/A" }
    ];

    fields.forEach(function (f) {
      var item = PG.el("div", { className: "report-data-item" });
      item.appendChild(PG.el("dt", null, f.label));
      item.appendChild(PG.el("dd", null, String(f.value !== null && f.value !== undefined ? f.value : "N/A")));
      grid.appendChild(item);
    });

    container.appendChild(grid);

    // Suspicious patterns
    if (wa.scripts && wa.scripts.suspicious_patterns && wa.scripts.suspicious_patterns.length > 0) {
      container.appendChild(PG.el("h5", { className: "mt-4 mb-2" }, "Suspicious Script Patterns"));
      wa.scripts.suspicious_patterns.forEach(function (p) {
        var item = PG.el("div", { className: "finding finding-medium" });
        item.appendChild(PG.el("span", { className: "finding-message" }, p.description || p.pattern));
        if (p.count) item.appendChild(PG.el("span", { className: "finding-points" }, "x" + p.count));
        container.appendChild(item);
      });
    }
  }

  function renderRedirectsTab(ra) {
    var panel = document.getElementById("tab-redirects");
    if (!panel || !ra) return;
    var container = panel.querySelector(".tab-content");
    if (!container) return;
    container.innerHTML = "";

    if (ra.status === "unavailable") {
      container.appendChild(PG.el("p", { className: "text-secondary" }, "Redirect analysis unavailable."));
      return;
    }

    container.appendChild(PG.el("p", { className: "mb-4" },
      ra.num_redirects + " redirect(s) detected" +
      (ra.crossed_domains ? " across " + ra.distinct_domains + " domains" : "") + "."));

    if (ra.chain && ra.chain.length > 0) {
      var chain = PG.el("div", { className: "redirect-chain" });
      ra.chain.forEach(function (hop, idx) {
        var hopEl = PG.el("div", { className: "redirect-hop" });
        hopEl.appendChild(PG.el("span", { className: "redirect-hop-status" }, String(hop.status_code)));
        hopEl.appendChild(PG.el("span", { className: "redirect-hop-url" }, hop.url || ""));
        if (idx < ra.chain.length - 1) {
          hopEl.appendChild(PG.icon("arrow-right", "icon-sm redirect-hop-arrow"));
        }
        chain.appendChild(hopEl);
      });

      // Final URL
      if (ra.final_url) {
        var finalHop = PG.el("div", { className: "redirect-hop" });
        finalHop.appendChild(PG.el("span", { className: "redirect-hop-status" }, "Final"));
        finalHop.appendChild(PG.el("span", { className: "redirect-hop-url" }, ra.final_url));
        chain.appendChild(finalHop);
      }

      container.appendChild(chain);
    }

    var flags = [];
    if (ra.https_downgrade) flags.push("HTTPS Downgrade detected");
    if (ra.meta_refresh) flags.push("Meta Refresh redirect detected");
    if (ra.js_redirect_detected) flags.push("JavaScript redirect detected");

    if (flags.length > 0) {
      container.appendChild(PG.el("h5", { className: "mt-4 mb-2" }, "Redirect Flags"));
      flags.forEach(function (f) {
        container.appendChild(PG.el("div", { className: "alert alert-warning mb-2" },
          PG.icon("alert-triangle"),
          PG.el("span", null, f)
        ));
      });
    }
  }

  function renderMLTab(ml) {
    var panel = document.getElementById("tab-ml");
    if (!panel || !ml) return;
    var container = panel.querySelector(".tab-content");
    if (!container) return;
    container.innerHTML = "";

    if (ml.status === "unavailable") {
      container.appendChild(PG.el("p", { className: "text-secondary" }, ml.message || "ML model unavailable."));
      return;
    }

    // Verdict
    var verdictRow = PG.el("div", { className: "flex items-center gap-4 mb-6" });
    if (ml.ml_verdict) {
      verdictRow.appendChild(PG.el("span", { className: PG.classBadge(ml.ml_verdict) + " badge-lg" }, ml.ml_verdict));
    }
    if (ml.probability_phishing != null) {
      verdictRow.appendChild(PG.el("span", { className: "text-sm text-secondary" },
        "Phishing probability: " + PG.fmt.pct(ml.probability_phishing * 100)));
    }
    container.appendChild(verdictRow);

    // Model info
    var grid = PG.el("div", { className: "report-data-grid mb-6" });
    [
      { label: "Model", value: ml.model_name },
      { label: "Version", value: ml.model_version },
      { label: "Dataset", value: ml.dataset },
      { label: "Feature Set", value: ml.feature_set }
    ].forEach(function (f) {
      var item = PG.el("div", { className: "report-data-item" });
      item.appendChild(PG.el("dt", null, f.label));
      item.appendChild(PG.el("dd", null, String(f.value || "N/A")));
      grid.appendChild(item);
    });
    container.appendChild(grid);

    // Top features
    if (ml.top_features && ml.top_features.length > 0) {
      container.appendChild(PG.el("h5", { className: "mb-3" }, "Top Contributing Features"));
      var features = PG.el("div", { className: "top-features" });

      ml.top_features.forEach(function (f) {
        var row = PG.el("div", { className: "top-feature" });
        row.appendChild(PG.el("span", { className: "top-feature-name" }, f.feature));
        var bar = PG.el("div", { className: "top-feature-bar" });
        var fill = PG.el("div", { className: "top-feature-fill" });
        var imp = Math.min(f.importance * 100, 100);
        fill.style.width = imp + "%";
        bar.appendChild(fill);
        row.appendChild(bar);
        row.appendChild(PG.el("span", { className: "top-feature-value" }, f.value != null ? String(f.value) : ""));
        features.appendChild(row);
      });

      container.appendChild(features);
    }

    if (ml.note) {
      container.appendChild(PG.el("p", { className: "disclaimer mt-4" }, ml.note));
    }
  }

  function renderRulesTab(ra) {
    var panel = document.getElementById("tab-rules");
    if (!panel || !ra) return;
    var container = panel.querySelector(".tab-content");
    if (!container) return;
    container.innerHTML = "";

    if (!ra.fired_rules || ra.fired_rules.length === 0) {
      container.appendChild(PG.el("p", { className: "text-secondary" }, "No rules were triggered for this scan."));
      return;
    }

    var list = PG.el("div", { className: "rule-list" });
    ra.fired_rules.forEach(function (rule) {
      var item = PG.el("div", { className: "rule-item rule-item-fired" });
      item.appendChild(PG.el("h5", null, rule.name || rule.id));
      item.appendChild(PG.el("p", null, rule.description || ""));
      var meta = PG.el("div", { className: "flex items-center gap-2 mt-2" });
      meta.appendChild(PG.el("span", { className: "badge badge-" + (rule.severity === "strong" ? "phishing" : rule.severity === "medium" ? "suspicious" : "info") },
        rule.severity || ""));
      if (rule.points != null) {
        meta.appendChild(PG.el("span", { className: "text-xs mono" }, (rule.points > 0 ? "+" : "") + rule.points + " pts"));
      }
      item.appendChild(meta);
      list.appendChild(item);
    });

    container.appendChild(list);
  }

  /* --- Findings --- */
  function renderFindings(groups) {
    var container = document.getElementById("findings-list");
    if (!container || !groups) return;
    container.innerHTML = "";

    var order = ["strong", "medium", "low", "positive", "info"];
    var iconMap = {
      strong: "x-circle",
      medium: "alert-triangle",
      low: "alert-triangle",
      positive: "check-circle",
      info: "info"
    };

    order.forEach(function (severity) {
      var findings = groups[severity];
      if (!findings || findings.length === 0) return;

      findings.forEach(function (f) {
        var el = PG.el("div", { className: "finding finding-" + severity });
        el.appendChild(PG.el("span", { className: "finding-icon severity-" + severity },
          PG.icon(iconMap[severity] || "info", "icon-sm")));
        var content = PG.el("div", { className: "finding-content" });
        content.appendChild(PG.el("div", { className: "finding-message" }, f.message || ""));
        if (f.detail) {
          content.appendChild(PG.el("div", { className: "finding-detail" }, f.detail));
        }
        el.appendChild(content);
        if (f.points != null && f.points !== 0) {
          el.appendChild(PG.el("span", { className: "finding-points" }, (f.points > 0 ? "+" : "") + f.points));
        }
        container.appendChild(el);
      });
    });

    if (container.children.length === 0) {
      container.appendChild(PG.el("p", { className: "text-secondary" }, "No findings to display."));
    }
  }

  /* --- Actions --- */
  function setupActions(scanId) {
    var pdfBtn = document.getElementById("download-pdf-btn");
    if (pdfBtn) {
      pdfBtn.addEventListener("click", function () {
        window.open("/api/report/" + encodeURIComponent(scanId) + "/pdf", "_blank");
      });
    }

    var shareBtn = document.getElementById("share-btn");
    if (shareBtn) {
      shareBtn.addEventListener("click", function () {
        var url = window.location.href;
        if (navigator.clipboard) {
          navigator.clipboard.writeText(url).then(function () {
            PG.toast("Link copied to clipboard", "success");
          });
        }
      });
    }
  }

  /* --- Charts --- */
  function renderCharts(r) {
    // Category scores radar chart
    var radarCanvas = document.getElementById("chart-categories");
    if (radarCanvas && r.category_scores && typeof Chart !== "undefined") {
      var labels = [];
      var values = [];
      r.category_scores.forEach(function (c) {
        labels.push(c.label || c.key);
        values.push(c.risk != null ? c.risk : 0);
      });

      new Chart(radarCanvas, {
        type: "radar",
        data: {
          labels: labels,
          datasets: [{
            label: "Risk by Category",
            data: values,
            backgroundColor: "rgba(11, 18, 32, 0.15)",
            borderColor: "#0B1220",
            borderWidth: 2,
            pointBackgroundColor: values.map(function (v) { return PG.riskColor(v); })
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            r: {
              beginAtZero: true,
              max: 100,
              ticks: { stepSize: 25 }
            }
          }
        }
      });
    }

    // Scoring components bar chart
    var compCanvas = document.getElementById("chart-components");
    if (compCanvas && r.scoring && r.scoring.components && typeof Chart !== "undefined") {
      var compLabels = [];
      var compValues = [];
      var compColors = [];

      Object.keys(r.scoring.components).forEach(function (key) {
        var comp = r.scoring.components[key];
        if (comp.available === false) return;
        compLabels.push(key.charAt(0).toUpperCase() + key.slice(1));
        compValues.push(comp.score != null ? comp.score : 0);
        compColors.push(PG.riskColor(comp.score));
      });

      new Chart(compCanvas, {
        type: "bar",
        data: {
          labels: compLabels,
          datasets: [{
            label: "Component Score",
            data: compValues,
            backgroundColor: compColors,
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            y: { beginAtZero: true, max: 100 },
            x: { grid: { display: false } }
          }
        }
      });
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    PG.init().then(initResultPage);
  });
})();
