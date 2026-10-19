// AFTERHOURS — inscription et connexion via l'API.
document.documentElement.classList.add("js-ready");

const API_URL = "https://afterhouse-api.onrender.com";
const $ = (selector) => document.querySelector(selector);
const signupForm = $("#signup-form");
const loginForm = $("#login-form");
const message = $("#account-message");
const profile = $("#account-profile");
const signupTab = $("#show-signup");
const loginTab = $("#show-login");

document.querySelectorAll('a[href^="#"]').forEach((link) => {
  link.addEventListener("click", () => {
    const target = document.querySelector(link.getAttribute("href"));
    if (target) target.setAttribute("tabindex", "-1");
  });
});

function showMessage(text, isError = false) {
  message.textContent = text;
  message.classList.toggle("error", isError);
}
function setMode(mode) {
  const signup = mode === "signup";
  signupForm.hidden = !signup;
  loginForm.hidden = signup;
  signupTab.classList.toggle("active", signup);
  loginTab.classList.toggle("active", !signup);
  signupTab.setAttribute("aria-selected", String(signup));
  loginTab.setAttribute("aria-selected", String(!signup));
  profile.hidden = true;
  message.textContent = "";
}
signupTab.addEventListener("click", () => setMode("signup"));
loginTab.addEventListener("click", () => setMode("login"));

async function api(path, options = {}) {
  const response = await fetch(API_URL + path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data.detail;
    throw new Error(Array.isArray(detail) ? detail.map((x) => x.msg).join(", ") : (detail || "Une erreur est survenue."));
  }
  return data;
}
function displayUser(user) {
  signupForm.hidden = true;
  loginForm.hidden = true;
  signupTab.hidden = true;
  loginTab.hidden = true;
  profile.hidden = false;
  $("#profile-name").textContent = user.display_name;
  $("#profile-email").textContent = user.email;
  showMessage("Connexion réussie.");
}
function clearSession() {
  localStorage.removeItem("afterhours_token");
  signupTab.hidden = false;
  loginTab.hidden = false;
  setMode("signup");
}
signupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(signupForm);
  const birthDate = form.get("birth_date");
  const ageDate = new Date(birthDate + "T00:00:00");
  const cutoff = new Date();
  cutoff.setFullYear(cutoff.getFullYear() - 18);
  if (!birthDate || ageDate > cutoff) {
    showMessage("L'inscription est réservée aux personnes âgées d'au moins 18 ans.", true);
    return;
  }
  const button = signupForm.querySelector('button[type="submit"]');
  button.disabled = true;
  showMessage("Création du compte en cours…");
  try {
    const result = await api("/auth/signup", { method: "POST", body: JSON.stringify({
      display_name: form.get("display_name").trim(),
      email: form.get("email").trim(),
      birth_date: birthDate,
      password: form.get("password")
    }) });
    localStorage.setItem("afterhours_token", result.token);
    displayUser(result.user);
  } catch (error) {
    showMessage(error.message || "Impossible de créer le compte. Réessaie.", true);
  } finally {
    button.disabled = false;
  }
});
loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(loginForm);
  const button = loginForm.querySelector('button[type="submit"]');
  button.disabled = true;
  showMessage("Connexion en cours…");
  try {
    const result = await api("/auth/login", { method: "POST", body: JSON.stringify({
      email: form.get("email").trim(),
      password: form.get("password")
    }) });
    localStorage.setItem("afterhours_token", result.token);
    displayUser(result.user);
  } catch (error) {
    showMessage(error.message || "Connexion impossible. Vérifie tes identifiants.", true);
  } finally {
    button.disabled = false;
  }
});
$("#logout-button").addEventListener("click", clearSession);

async function restoreSession() {
  const token = localStorage.getItem("afterhours_token");
  if (!token) return;
  try {
    const result = await api("/me", { headers: { Authorization: "Bearer " + token } });
    displayUser(result.user);
  } catch {
    localStorage.removeItem("afterhours_token");
  }
}
restoreSession();


// Open account access only in a modal popup.
const accountDialog = $("#account-dialog");
const closeAccountDialog = $("#close-account-dialog");
document.querySelectorAll("[data-account-open]").forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    if (!accountDialog.open) accountDialog.showModal();
  });
});
closeAccountDialog.addEventListener("click", () => accountDialog.close());
accountDialog.addEventListener("click", (event) => {
  if (event.target === accountDialog) accountDialog.close();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && accountDialog.open) accountDialog.close();
});
