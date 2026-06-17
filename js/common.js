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

        document.body.classList.add("is-leaving");

        // Match the CSS fade duration for a smoother feel
        setTimeout(() => {

            window.location.href = href;

        }, 320);

    });

});

// ==========================
// Restore page
// ==========================

window.addEventListener("pageshow", function () {

    document.body.classList.remove("is-leaving");

});


const loader = document.getElementById("pageLoader");

document.querySelectorAll("a").forEach(link => {

    const href = link.getAttribute("href");

    if (
        href &&
        !href.startsWith("#") &&
        !href.startsWith("mailto") &&
        !href.startsWith("tel") &&
        !link.target
    ) {

        link.addEventListener("click", function(e) {

            e.preventDefault();

            loader.classList.add("show");

            setTimeout(() => {
                window.location.href = href;
            }, 250);

        });

    }

});