"use strict";

const form = document.getElementById("login-form");
const errorBox = document.getElementById("login-error");
const submit = document.getElementById("login-submit");
const submitLabel = document.getElementById("login-submit-label");
const spinner = document.getElementById("login-spinner");
const username = document.getElementById("login-username");
const password = document.getElementById("login-password");
const toggle = document.getElementById("password-toggle");

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function clearError() {
  errorBox.hidden = true;
  errorBox.textContent = "";
}

function setBusy(busy) {
  submit.disabled = busy;
  username.disabled = busy;
  password.disabled = busy;
  submitLabel.textContent = busy ? "Signing in…" : "Enter dashboard";
  spinner.hidden = !busy;
}

toggle.addEventListener("click", () => {
  const showing = password.type === "text";
  password.type = showing ? "password" : "text";
  toggle.setAttribute("aria-pressed", showing ? "false" : "true");
  toggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  document.querySelector(".eye-open").hidden = !showing;
  document.querySelector(".eye-closed").hidden = showing;
  password.focus();
});

[username, password].forEach((input) => {
  input.addEventListener("input", clearError);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (submit.disabled) return;
  clearError();

  const user = username.value.trim();
  const pass = password.value;
  if (!user || !pass) {
    showError("Enter both your username and password.");
    (user ? password : username).focus();
    return;
  }

  setBusy(true);
  try {
    const response = await fetch("/api/login", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ username: user, password: pass }),
    });
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }
    if (!response.ok) {
      showError((data && data.error) || `Sign-in failed (${response.status}).`);
      setBusy(false);
      password.select();
      return;
    }
    window.location.assign("/");
  } catch {
    showError("Could not reach the control plane. Check the server and try again.");
    setBusy(false);
  }
});
