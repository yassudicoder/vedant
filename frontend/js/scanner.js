/* ============================================================
   PhishGuard - scanner.js
   Scan page: safety confirmation + NDJSON streaming progress
   ============================================================ */
(function () {
  "use strict";

  var STAGES = [
    { key: "validate", label: "Analyzing URL..." },
    { key: "dns", label: "Checking domain..." },
    { key: "https", label: "Checking HTTPS..." },
    { key: "redirects", label: "Following safe redirects..." },
    { key: "webpage", label: "Analyzing webpage structure..." },
    { key: "features", label: "Extracting security features..." },
    { key: "model", label: "Running detection model..." },
    { key: "report", label: "Generating report..." }
  ];

  function initScanPage() {
    var url = PG.param("url");
    var confirmSection = document.getElementById("scan-confirm");
    var progressSection = document.getElementById("scan-progress");

    if (!url) {
      PG.navigate("/");
      return;
    }

    // Show URL in confirm section
    var urlDisplay = document.getElementById("scan-url-display");
    if (urlDisplay) urlDisplay.textContent = url;

    var proceedBtn = document.getElementById("scan-proceed-btn");
    if (proceedBtn) {
      proceedBtn.addEventListener("click", function () {
        startScan(url, confirmSection, progressSection);
      });
    }

    // If auto-scan param is set, skip confirmation
    if (PG.param("auto") === "1") {
      startScan(url, confirmSection, progressSection);
    }
  }

  function startScan(url, confirmSection, progressSection) {
    if (confirmSection) confirmSection.classList.add("hidden");
    if (progressSection) progressSection.classList.remove("hidden");

    var progressUrl = document.getElementById("scan-progress-url");
    if (progressUrl) progressUrl.textContent = url;

    // Build stage list
    var stageList = document.getElementById("stage-list");
    if (stageList) {
      stageList.innerHTML = "";
      STAGES.forEach(function (stage) {
        var item = PG.el("li", { className: "stage-item", id: "stage-" + stage.key });
        var iconWrap = PG.el("span", { className: "stage-icon" });
        iconWrap.appendChild(document.createTextNode("•"));
        item.appendChild(iconWrap);
        item.appendChild(PG.el("span", null, stage.label));
        stageList.appendChild(item);
      });
    }

    // Update overall progress bar
    var progressBar = document.getElementById("scan-progress-bar");
    var completedCount = 0;

    streamAnalysis(url, function onStage(data) {
      if (data.type === "stage") {
        var stageEl = document.getElementById("stage-" + data.stage);
        if (!stageEl) return;

        if (data.state === "started") {
          stageEl.classList.add("active");
          stageEl.classList.remove("done");
          var iconWrap = stageEl.querySelector(".stage-icon");
          if (iconWrap) {
            iconWrap.innerHTML = "";
            var spinner = PG.el("span", { className: "stage-spinner" });
            iconWrap.appendChild(spinner);
          }
        } else if (data.state === "done") {
          stageEl.classList.remove("active");
          stageEl.classList.add("done");
          var iconWrap2 = stageEl.querySelector(".stage-icon");
          if (iconWrap2) {
            iconWrap2.innerHTML = "";
            iconWrap2.appendChild(PG.icon("check-circle", "icon-sm"));
          }
          completedCount++;
          if (progressBar) {
            var pct = Math.round((completedCount / STAGES.length) * 100);
            progressBar.style.width = pct + "%";
          }
        }
      }
    }, function onResult(report) {
      if (progressBar) progressBar.style.width = "100%";
      if (report && report.scan_id) {
        setTimeout(function () {
          PG.navigate("/result.html?id=" + encodeURIComponent(report.scan_id));
        }, 500);
      }
    }, function onError(err) {
      PG.toast(err.message || "Analysis failed", "error");
      var errorDisplay = document.getElementById("scan-error");
      if (errorDisplay) {
        errorDisplay.classList.remove("hidden");
        var errorMsg = errorDisplay.querySelector(".alert");
        if (!errorMsg) {
          errorMsg = PG.el("div", { className: "alert alert-danger" });
          errorMsg.appendChild(PG.icon("x-circle"));
          var msgSpan = PG.el("span");
          errorDisplay.appendChild(errorMsg);
          errorMsg.appendChild(msgSpan);
        }
        var span = errorMsg.querySelector("span");
        if (span) span.textContent = err.message || "An error occurred during analysis.";
      }
    });
  }

  function streamAnalysis(url, onStage, onResult, onError) {
    fetch("/api/analyze/stream", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "PhishGuard"
      },
      credentials: "same-origin",
      body: JSON.stringify({ url: url })
    }).then(function (res) {
      if (!res.ok) {
        return res.json().then(function (data) {
          var err = data && data.error ? data.error : {};
          onError({ code: err.code || "UNKNOWN", message: err.message || "Request failed" });
        });
      }

      var reader = res.body.getReader();
      var decoder = new TextDecoder();
      var buffer = "";

      function read() {
        reader.read().then(function (result) {
          if (result.done) return;

          buffer += decoder.decode(result.value, { stream: true });
          var lines = buffer.split("\n");
          buffer = lines.pop() || "";

          lines.forEach(function (line) {
            line = line.trim();
            if (!line) return;
            try {
              var data = JSON.parse(line);
              if (data.type === "stage") {
                onStage(data);
              } else if (data.type === "result") {
                onResult(data.report);
              } else if (data.type === "error") {
                onError(data.error);
              }
            } catch (e) {
              // skip malformed lines
            }
          });

          read();
        }).catch(function (err) {
          onError({ code: "STREAM_ERROR", message: "Connection lost" });
        });
      }

      read();
    }).catch(function (err) {
      onError({ code: "NETWORK_ERROR", message: "Could not connect to server" });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    PG.init().then(initScanPage);
  });
})();
