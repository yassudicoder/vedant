/* ============================================================
   PhishGuard - auth.js
   Login, register, forgot password, reset password
   ============================================================ */
(function () {
  "use strict";

  function initAuthPage() {
    var loginForm = document.getElementById("login-form");
    var registerForm = document.getElementById("register-form");
    var forgotForm = document.getElementById("forgot-form");
    var resetForm = document.getElementById("reset-form");

    if (loginForm) setupLogin(loginForm);
    if (registerForm) setupRegister(registerForm);
    if (forgotForm) setupForgot(forgotForm);
    if (resetForm) setupReset(resetForm);
  }

  function clearErrors(form) {
    var errors = form.querySelectorAll(".form-error");
    errors.forEach(function (el) {
      el.textContent = "";
    });
    var inputs = form.querySelectorAll(".form-input.error");
    inputs.forEach(function (el) {
      el.classList.remove("error");
    });
  }

  function showFieldError(form, fieldName, message) {
    var input = form.querySelector("[name=\"" + fieldName + "\"]");
    if (input) input.classList.add("error");
    var errorEl = form.querySelector("[data-error=\"" + fieldName + "\"]");
    if (errorEl) errorEl.textContent = message;
  }

  function setSubmitting(btn, loading) {
    if (loading) {
      btn.disabled = true;
      btn.dataset.originalText = btn.textContent;
      btn.textContent = "Please wait...";
    } else {
      btn.disabled = false;
      if (btn.dataset.originalText) {
        btn.textContent = btn.dataset.originalText;
      }
    }
  }

  function validateEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function validatePassword(password) {
    return password.length >= 8;
  }

  /* --- Login --- */
  function setupLogin(form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      clearErrors(form);

      var email = form.querySelector("[name=\"email\"]").value.trim();
      var password = form.querySelector("[name=\"password\"]").value;
      var submitBtn = form.querySelector("button[type=\"submit\"]");
      var valid = true;

      if (!email || !validateEmail(email)) {
        showFieldError(form, "email", "Please enter a valid email address.");
        valid = false;
      }
      if (!password) {
        showFieldError(form, "password", "Please enter your password.");
        valid = false;
      }
      if (!valid) return;

      setSubmitting(submitBtn, true);
      PG.api("/api/auth/login", {
        method: "POST",
        body: { email: email, password: password }
      }).then(function (data) {
        PG.auth.user = data.user || data;
        PG.auth._promise = null;
        PG.toast("Login successful", "success");
        var redirect = PG.param("redirect") || "/";
        setTimeout(function () { PG.navigate(redirect); }, 500);
      }).catch(function (err) {
        setSubmitting(submitBtn, false);
        var generalError = form.querySelector("[data-error=\"general\"]");
        if (generalError) {
          generalError.textContent = err.message || "Invalid email or password.";
        }
      });
    });
  }

  /* --- Register --- */
  function setupRegister(form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      clearErrors(form);

      var email = form.querySelector("[name=\"email\"]").value.trim();
      var password = form.querySelector("[name=\"password\"]").value;
      var confirmPassword = form.querySelector("[name=\"confirm_password\"]").value;
      var submitBtn = form.querySelector("button[type=\"submit\"]");
      var valid = true;

      if (!email || !validateEmail(email)) {
        showFieldError(form, "email", "Please enter a valid email address.");
        valid = false;
      }
      if (!validatePassword(password)) {
        showFieldError(form, "password", "Password must be at least 8 characters.");
        valid = false;
      }
      if (password !== confirmPassword) {
        showFieldError(form, "confirm_password", "Passwords do not match.");
        valid = false;
      }
      if (!valid) return;

      setSubmitting(submitBtn, true);
      PG.api("/api/auth/register", {
        method: "POST",
        body: { email: email, password: password }
      }).then(function (data) {
        PG.auth.user = data.user || data;
        PG.auth._promise = null;
        PG.toast("Account created successfully", "success");
        setTimeout(function () { PG.navigate("/"); }, 500);
      }).catch(function (err) {
        setSubmitting(submitBtn, false);
        var generalError = form.querySelector("[data-error=\"general\"]");
        if (generalError) {
          generalError.textContent = err.message || "Registration failed. Please try again.";
        }
      });
    });
  }

  /* --- Forgot Password --- */
  function setupForgot(form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      clearErrors(form);

      var email = form.querySelector("[name=\"email\"]").value.trim();
      var submitBtn = form.querySelector("button[type=\"submit\"]");

      if (!email || !validateEmail(email)) {
        showFieldError(form, "email", "Please enter a valid email address.");
        return;
      }

      setSubmitting(submitBtn, true);
      PG.api("/api/auth/forgot-password", {
        method: "POST",
        body: { email: email }
      }).then(function () {
        var successMsg = document.getElementById("forgot-success");
        if (successMsg) successMsg.classList.remove("hidden");
        form.classList.add("hidden");
      }).catch(function () {
        // Always show success (don't leak whether email exists)
        var successMsg = document.getElementById("forgot-success");
        if (successMsg) successMsg.classList.remove("hidden");
        form.classList.add("hidden");
      });
    });
  }

  /* --- Reset Password --- */
  function setupReset(form) {
    var token = PG.param("token");
    if (!token) {
      var errorEl = document.getElementById("reset-error");
      if (errorEl) {
        errorEl.classList.remove("hidden");
        errorEl.textContent = "Invalid or missing reset token.";
      }
      form.classList.add("hidden");
      return;
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      clearErrors(form);

      var password = form.querySelector("[name=\"password\"]").value;
      var confirmPassword = form.querySelector("[name=\"confirm_password\"]").value;
      var submitBtn = form.querySelector("button[type=\"submit\"]");
      var valid = true;

      if (!validatePassword(password)) {
        showFieldError(form, "password", "Password must be at least 8 characters.");
        valid = false;
      }
      if (password !== confirmPassword) {
        showFieldError(form, "confirm_password", "Passwords do not match.");
        valid = false;
      }
      if (!valid) return;

      setSubmitting(submitBtn, true);
      PG.api("/api/auth/reset-password", {
        method: "POST",
        body: { token: token, new_password: password }
      }).then(function () {
        PG.toast("Password reset successfully. Please log in.", "success");
        setTimeout(function () { PG.navigate("/login.html"); }, 1500);
      }).catch(function (err) {
        setSubmitting(submitBtn, false);
        var generalError = form.querySelector("[data-error=\"general\"]");
        if (generalError) {
          generalError.textContent = err.message || "Failed to reset password. Token may be expired.";
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    PG.init().then(initAuthPage);
  });
})();
