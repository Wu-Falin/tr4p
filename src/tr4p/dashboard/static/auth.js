"use strict";

// Shared by the sign-in and first-time setup pages.
(function () {
  const mode = document.body.dataset.mode;
  const form = document.getElementById("form");
  const error = document.getElementById("error");
  const button = form.querySelector("button");

  function fail(message) {
    error.textContent = message;
    error.hidden = false;
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    error.hidden = true;
    const password = document.getElementById("password").value;
    const payload = { password: password };

    if (mode === "setup") {
      payload.code = document.getElementById("code").value;
      if (password !== document.getElementById("confirm").value) {
        fail("The two passwords do not match.");
        return;
      }
    }

    button.disabled = true;
    try {
      const response = await fetch("/api/v1/" + mode, {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-Requested-With": "dashboard" },
        body: JSON.stringify(payload),
      });
      if (response.ok) {
        window.location.replace("/");
        return;
      }
      let message = "Request failed (" + response.status + ").";
      try {
        const data = await response.json();
        if (data && typeof data.error === "string") { message = data.error; }
      } catch (ignored) { /* keep the generic message */ }
      fail(message);
    } catch (networkError) {
      fail("Could not reach the service.");
    } finally {
      button.disabled = false;
    }
  });
})();
