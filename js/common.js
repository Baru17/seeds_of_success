/* ===================================================
   Seeds of Success - Common JavaScript
=================================================== */

// ==========================
// Mobile Navigation
// ==========================

const hamburger = document.getElementById("hamburger");
const navLinks = document.getElementById("navLinks");

if (hamburger && navLinks) {
    hamburger.addEventListener("click", () => {
        hamburger.classList.toggle("open");
        navLinks.classList.toggle("show");
    });
}

// ==========================
// Close menu after clicking
// ==========================

document.querySelectorAll(".nav-links a").forEach(link => {
    link.addEventListener("click", () => {
        if (hamburger && navLinks) {
            hamburger.classList.remove("open");
            navLinks.classList.remove("show");
        }
    });
});

// ==========================
// Smooth Page Transition
// ==========================

document.querySelectorAll("a[href]").forEach(link => {
    const href = link.getAttribute("href");

    if (
        !href ||
        href.startsWith("#") ||
        href.startsWith("http") ||
        href.startsWith("mailto:") ||
        href.startsWith("tel:") ||
        link.target === "_blank"
    ) return;

    link.addEventListener("click", function(e) {
        e.preventDefault();

        const loader = document.getElementById("pageLoader");
        document.body.classList.add("is-leaving");
        if (loader) loader.classList.add("show");

        setTimeout(() => {
            window.location.href = href;
        }, 250);
    });
});

// ==========================
// Restore page
// ==========================

window.addEventListener("pageshow", function () {
    const loader = document.getElementById("pageLoader");
    document.body.classList.remove("is-leaving");
    if (loader) loader.classList.remove("show");
});

// ==========================
// Dynamic Footer Year
// ==========================

document.querySelectorAll(".footer-bottom").forEach(el => {
    el.textContent = el.textContent.replace(/\b\d{4}\b/, new Date().getFullYear());
});

// ==========================
// Password visibility toggle
// ==========================

document.querySelectorAll(".password-toggle").forEach(toggle => {
    toggle.addEventListener("click", () => {
        const field = toggle.closest(".password-field");
        if (!field) return;
        const input = field.querySelector("input");
        const isHidden = input.type === "password";
        input.type = isHidden ? "text" : "password";
        toggle.classList.toggle("show", !isHidden);
        toggle.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
        input.focus();
    });
});
