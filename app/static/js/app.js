/* ==========================================================================
   Multi-Factor Authentication System - client-side helpers.

   IMPORTANT (and stated in the project report): nothing here is a security
   control. No secret, key or authentication decision lives in this file.
   Every rule mirrored below is also enforced on the server, in
   app/security/passwords.py and the route handlers. This script only makes
   the forms pleasanter to use.
   ========================================================================== */

(function () {
  "use strict";

  /* ------------------------------------------------- OTP input behaviour -- */

  function initOtpInputs() {
    document.querySelectorAll("[data-otp-input]").forEach(function (input) {
      input.setAttribute("autocomplete", "one-time-code");
      input.setAttribute("inputmode", "numeric");

      // Strip anything that is not a digit, so a pasted "123 456" still works.
      input.addEventListener("input", function () {
        var digits = input.value.replace(/\D/g, "").slice(0, 6);
        if (input.value !== digits) {
          input.value = digits;
        }
        var form = input.form;
        if (digits.length === 6 && form && input.dataset.otpAutosubmit === "true") {
          // Submit once the code is complete. The server still validates.
          form.requestSubmit ? form.requestSubmit() : form.submit();
        }
      });

      if (!input.value) {
        input.focus();
      }
    });
  }

  /* ---------------------------------------------- password strength hints -- */

  function scorePassword(value, minLength) {
    var rules = {
      length: value.length >= minLength,
      upper: /[A-Z]/.test(value),
      lower: /[a-z]/.test(value),
      digit: /\d/.test(value),
      symbol: /[^A-Za-z0-9]/.test(value)
    };
    var met = Object.keys(rules).filter(function (key) {
      return rules[key];
    }).length;
    return { rules: rules, met: met, total: 5 };
  }

  function initPasswordMeter() {
    var field = document.querySelector("[data-password-field]");
    if (!field) {
      return;
    }
    var meter = document.querySelector("[data-password-meter]");
    var list = document.querySelector("[data-password-rules]");
    var minLength = parseInt(field.dataset.minLength || "12", 10);

    function render() {
      var result = scorePassword(field.value, minLength);

      if (meter) {
        var pct = (result.met / result.total) * 100;
        meter.style.width = pct + "%";
        meter.style.backgroundColor =
          result.met >= 5 ? "#17795e" : result.met >= 3 ? "#9a6b05" : "#b3261e";
        meter.parentElement.setAttribute("aria-valuenow", String(result.met));
      }

      if (list) {
        list.querySelectorAll("[data-rule]").forEach(function (item) {
          var name = item.dataset.rule;
          item.classList.toggle("met", Boolean(result.rules[name]));
        });
      }
    }

    field.addEventListener("input", render);
    render();
  }

  /* ------------------------------------------------------ reveal password -- */

  function initPasswordToggles() {
    document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
      button.addEventListener("click", function () {
        var target = document.querySelector(button.dataset.togglePassword);
        if (!target) {
          return;
        }
        var showing = target.getAttribute("type") === "text";
        target.setAttribute("type", showing ? "password" : "text");
        button.textContent = showing ? "Show" : "Hide";
        button.setAttribute("aria-pressed", showing ? "false" : "true");
      });
    });
  }

  /* ------------------------------------------------------- copy to clipboard */

  function initCopyButtons() {
    document.querySelectorAll("[data-copy-target]").forEach(function (button) {
      button.addEventListener("click", function () {
        var target = document.querySelector(button.dataset.copyTarget);
        if (!target) {
          return;
        }
        var text = (target.textContent || target.value || "").trim();
        var done = function () {
          var original = button.textContent;
          button.textContent = "Copied";
          window.setTimeout(function () {
            button.textContent = original;
          }, 1500);
        };

        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard.writeText(text).then(done, function () {
            /* ignore: the user can still select the text manually */
          });
        } else if (target.select) {
          target.select();
          done();
        }
      });
    });
  }

  /* --------------------------------------- confirm destructive actions ----- */

  function initConfirmations() {
    document.querySelectorAll("[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (event) {
        if (!window.confirm(form.dataset.confirm)) {
          event.preventDefault();
        }
      });
    });
  }

  /* ------------------------------------------------------------- printing -- */

  /* Handled here rather than with an inline onclick attribute, because the
     Content-Security-Policy sets script-src 'self' with no 'unsafe-inline',
     so an inline handler would be blocked by the browser. */
  function initPrintButtons() {
    document.querySelectorAll("[data-print-page]").forEach(function (button) {
      button.addEventListener("click", function () {
        window.print();
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initPrintButtons();
    initOtpInputs();
    initPasswordMeter();
    initPasswordToggles();
    initCopyButtons();
    initConfirmations();
  });
})();
