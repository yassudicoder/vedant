/* ============================================================
   PhishGuard - app.js
   Core namespace, API helper, DOM builder, auth, header/footer
   ============================================================ */
(function () {
  "use strict";

  /* --- ApiError class --- */
  function ApiError(status, code, message) {
    this.status = status;
    this.code = code;
    this.message = message;
  }
  ApiError.prototype = Object.create(Error.prototype);
  ApiError.prototype.constructor = ApiError;
  ApiError.prototype.name = "PG.ApiError";

  /* --- Core namespace --- */
  var PG = {
    ApiError: ApiError,

    /**
     * API helper - auto-adds X-Requested-With, JSON, credentials
     * @param {string} path - API path e.g. "/api/health"
     * @param {object} opts - {method, body, headers, raw}
     * @returns {Promise<any>}
     */
    api: function (path, opts) {
      opts = opts || {};
      var method = (opts.method || "GET").toUpperCase();
      var headers = Object.assign({
        "X-Requested-With": "PhishGuard"
      }, opts.headers || {});

      var fetchOpts = {
        method: method,
        headers: headers,
        credentials: "same-origin"
      };

      if (opts.body !== undefined && method !== "GET") {
        headers["Content-Type"] = "application/json";
        fetchOpts.body = JSON.stringify(opts.body);
      }

      fetchOpts.headers = headers;

      return fetch(path, fetchOpts).then(function (res) {
        if (opts.raw) return res;
        if (res.status === 204) return null;
        return res.json().then(function (data) {
          if (!res.ok) {
            var err = data && data.error ? data.error : {};
            throw new ApiError(res.status, err.code || "UNKNOWN", err.message || res.statusText);
          }
          return data;
        });
      });
    },

    /**
     * Safe DOM builder - never uses innerHTML with data
     * @param {string} tag - element tag
     * @param {object|null} attrs - attributes
     * @param {...(string|Node)} children
     * @returns {HTMLElement}
     */
    el: function (tag, attrs) {
      var elem = document.createElement(tag);
      if (attrs) {
        Object.keys(attrs).forEach(function (key) {
          if (key === "className") {
            elem.className = attrs[key];
          } else if (key === "dataset") {
            Object.keys(attrs[key]).forEach(function (dk) {
              elem.dataset[dk] = attrs[key][dk];
            });
          } else if (key.indexOf("on") === 0) {
            // skip inline handlers - use addEventListener
          } else {
            elem.setAttribute(key, attrs[key]);
          }
        });
      }
      for (var i = 2; i < arguments.length; i++) {
        var child = arguments[i];
        if (child === null || child === undefined) continue;
        if (typeof child === "string" || typeof child === "number") {
          elem.appendChild(document.createTextNode(String(child)));
        } else if (child instanceof Node) {
          elem.appendChild(child);
        }
      }
      return elem;
    },

    /**
     * Create an SVG <use> icon element
     * @param {string} name - icon id without "icon-" prefix
     * @param {string} [cls] - additional CSS class
     * @returns {SVGElement}
     */
    icon: function (name, cls) {
      var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("class", "icon" + (cls ? " " + cls : ""));
      svg.setAttribute("aria-hidden", "true");
      var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
      use.setAttribute("href", "/img/icons.svg#icon-" + name);
      svg.appendChild(use);
      return svg;
    },

    /* --- Auth state --- */
    auth: {
      user: null,
      _promise: null,

      /**
       * Get current user, cached
       * @returns {Promise<object|null>}
       */
      me: function () {
        if (PG.auth._promise) return PG.auth._promise;
        PG.auth._promise = PG.api("/api/auth/me").then(function (data) {
          PG.auth.user = data && data.user ? data.user : data;
          return PG.auth.user;
        }).catch(function () {
          PG.auth.user = null;
          return null;
        });
        return PG.auth._promise;
      },

      /**
       * Logout current user
       * @returns {Promise}
       */
      logout: function () {
        return PG.api("/api/auth/logout", { method: "POST" }).then(function () {
          PG.auth.user = null;
          PG.auth._promise = null;
          window.location.href = "/";
        }).catch(function () {
          PG.auth.user = null;
          PG.auth._promise = null;
          window.location.href = "/";
        });
      }
    },

    /* --- Formatters --- */
    fmt: {
      /**
       * Format ISO date string
       * @param {string} iso
       * @returns {string}
       */
      date: function (iso) {
        if (!iso) return "N/A";
        try {
          var d = new Date(iso);
          return d.toLocaleDateString(undefined, {
            year: "numeric", month: "short", day: "numeric",
            hour: "2-digit", minute: "2-digit"
          });
        } catch (e) {
          return iso;
        }
      },

      /**
       * Format percentage
       * @param {number} n - 0..100
       * @returns {string}
       */
      pct: function (n) {
        if (n === null || n === undefined) return "N/A";
        return Math.round(n) + "%";
      }
    },

    /**
     * Return badge CSS class for classification
     * @param {string} classification
     * @returns {string}
     */
    classBadge: function (classification) {
      if (!classification) return "badge";
      var c = classification.toUpperCase();
      if (c === "LEGITIMATE") return "badge badge-legitimate";
      if (c === "SUSPICIOUS") return "badge badge-suspicious";
      if (c === "PHISHING") return "badge badge-phishing";
      if (c === "ANALYSIS_FAILED") return "badge badge-failed";
      return "badge badge-info";
    },

    /**
     * Return color hex for risk score
     * @param {number} score 0-100
     * @returns {string}
     */
    riskColor: function (score) {
      if (score === null || score === undefined) return "#9CA3AF";
      if (score < 30) return "#16A34A";
      if (score < 60) return "#F59E0B";
      if (score < 80) return "#F97316";
      return "#DC2626";
    },

    /**
     * Show toast notification
     * @param {string} message
     * @param {string} type - "success"|"error"|"warning"|"info"
     */
    toast: function (message, type) {
      type = type || "info";
      var container = document.getElementById("pg-toast-container");
      if (!container) {
        container = PG.el("div", { id: "pg-toast-container", className: "toast-container" });
        container.setAttribute("aria-live", "polite");
        document.body.appendChild(container);
      }

      var iconName = type === "success" ? "check-circle" :
        type === "error" ? "x-circle" :
          type === "warning" ? "alert-triangle" : "info";

      var toast = PG.el("div", { className: "toast toast-" + type },
        PG.icon(iconName),
        PG.el("span", null, message)
      );

      var closeBtn = PG.el("button", { className: "toast-close", "aria-label": "Close" });
      closeBtn.appendChild(PG.icon("x-circle", "icon-sm"));
      closeBtn.addEventListener("click", function () {
        removeToast(toast);
      });
      toast.appendChild(closeBtn);

      container.appendChild(toast);

      var timer = setTimeout(function () {
        removeToast(toast);
      }, 5000);

      function removeToast(t) {
        clearTimeout(timer);
        t.classList.add("toast-out");
        setTimeout(function () {
          if (t.parentNode) t.parentNode.removeChild(t);
        }, 200);
      }
    },

    /**
     * Initialize - inject header/footer, check auth
     */
    _initialized: false,
    init: function () {
      if (PG._initialized) return PG._initPromise;
      PG._initialized = true;
      PG._initPromise = PG.auth.me().then(function () {
        PG._injectHeader();
        PG._injectFooter();
      });
      return PG._initPromise;
    },

    /**
     * Inject header into #pg-header
     */
    _injectHeader: function () {
      var headerEl = document.getElementById("pg-header");
      if (!headerEl) return;

      var currentPath = window.location.pathname;

      var header = PG.el("header", { className: "pg-header" });
      var container = PG.el("div", { className: "container" });

      // Logo
      var logo = PG.el("a", { href: "/", className: "pg-logo" });
      logo.appendChild(PG.icon("shield"));
      logo.appendChild(document.createTextNode("PhishGuard"));

      // Nav
      var nav = PG.el("nav", { className: "pg-nav", id: "pg-nav", "aria-label": "Main navigation" });

      var navLinks = [
        { href: "/", label: "Home", icon: "home" },
        { href: "/scan.html", label: "Scan", icon: "search" },
        { href: "/history.html", label: "History", icon: "clock" },
        { href: "/methodology.html", label: "Methodology", icon: "info" }
      ];

      navLinks.forEach(function (link) {
        var a = PG.el("a", { href: link.href }, link.label);
        if (currentPath === link.href || (link.href === "/" && currentPath === "/index.html")) {
          a.className = "active";
        }
        nav.appendChild(a);
      });

      // Admin link
      if (PG.auth.user && PG.auth.user.role === "admin") {
        var adminLink = PG.el("a", { href: "/dashboard.html" }, "Dashboard");
        if (currentPath === "/dashboard.html") adminLink.className = "active";
        nav.appendChild(adminLink);
      }

      // Divider
      nav.appendChild(PG.el("span", { className: "pg-nav-divider" }));

      // Auth section
      if (PG.auth.user) {
        var userMenu = PG.el("span", { className: "pg-user-menu" });
        userMenu.appendChild(PG.el("span", { className: "pg-user-email" }, PG.auth.user.email));
        var logoutBtn = PG.el("button", { className: "btn btn-sm btn-ghost" });
        logoutBtn.className = "btn btn-sm btn-ghost";
        logoutBtn.appendChild(PG.icon("log-out", "icon-sm"));
        logoutBtn.appendChild(document.createTextNode(" Logout"));
        logoutBtn.addEventListener("click", function () {
          PG.auth.logout();
        });
        userMenu.appendChild(logoutBtn);
        nav.appendChild(userMenu);
      } else {
        var loginLink = PG.el("a", { href: "/login.html", className: "btn btn-sm btn-ghost" }, "Login");
        var registerLink = PG.el("a", { href: "/register.html", className: "btn btn-sm btn-primary" }, "Register");
        if (currentPath === "/login.html") loginLink.classList.add("active");
        if (currentPath === "/register.html") registerLink.classList.add("active");
        nav.appendChild(loginLink);
        nav.appendChild(registerLink);
      }

      // Mobile toggle
      var mobileToggle = PG.el("button", {
        className: "pg-mobile-toggle",
        "aria-label": "Toggle navigation",
        "aria-expanded": "false"
      });
      mobileToggle.appendChild(PG.icon("menu"));
      mobileToggle.addEventListener("click", function () {
        var isOpen = nav.classList.toggle("open");
        mobileToggle.setAttribute("aria-expanded", isOpen ? "true" : "false");
      });

      container.appendChild(logo);
      container.appendChild(nav);
      container.appendChild(mobileToggle);
      header.appendChild(container);
      headerEl.appendChild(header);
    },

    /**
     * Inject footer into #pg-footer
     */
    _injectFooter: function () {
      var footerEl = document.getElementById("pg-footer");
      if (!footerEl) return;

      var footer = PG.el("footer", { className: "pg-footer" });
      var container = PG.el("div", { className: "container" });

      var copy = PG.el("div", { className: "pg-footer-copy" },
        "PhishGuard - URL Safety Analysis Tool. For educational and research purposes."
      );

      var links = PG.el("div", { className: "pg-footer-links" });
      links.appendChild(PG.el("a", { href: "/methodology.html" }, "Methodology"));
      links.appendChild(PG.el("a", { href: "/history.html" }, "Scan History"));

      container.appendChild(copy);
      container.appendChild(links);
      footer.appendChild(container);
      footerEl.appendChild(footer);
    },

    /**
     * Get URL search parameter
     * @param {string} key
     * @returns {string|null}
     */
    param: function (key) {
      return new URLSearchParams(window.location.search).get(key);
    },

    /**
     * Navigate to a URL
     * @param {string} url
     */
    navigate: function (url) {
      window.location.href = url;
    }
  };

  window.PG = PG;

  /* --- Auto-init on DOMContentLoaded --- */
  document.addEventListener("DOMContentLoaded", function () {
    PG.init();
  });
})();
