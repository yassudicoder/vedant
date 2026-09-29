/* ============================================================
   PhishGuard - index.js
   Landing page: URL form submission
   ============================================================ */
(function () {
  "use strict";

  function initIndexPage() {
    var form = document.getElementById("url-form");
    if (!form) return;

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var input = form.querySelector("input[name=\"url\"]");
      var url = input ? input.value.trim() : "";
      if (!url) return;

      PG.navigate("/scan.html?url=" + encodeURIComponent(url));
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    PG.init().then(initIndexPage);
  });
})();
