// AFTERHOURS starter: intentionally no tracking, accounts, or network requests.
document.documentElement.classList.add("js-ready");
document.querySelectorAll('a[href^="#"]').forEach((link) => {
  link.addEventListener("click", () => {
    const target = document.querySelector(link.getAttribute("href"));
    if (target) target.setAttribute("tabindex", "-1");
  });
});