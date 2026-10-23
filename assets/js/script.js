"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const menuButton = document.querySelector(".menu-toggle");
    const navigation = document.querySelector("#primary-nav");

    if (menuButton && navigation) {
        menuButton.addEventListener("click", () => {
            const isExpanded =
                menuButton.getAttribute("aria-expanded") === "true";

            menuButton.setAttribute("aria-expanded", String(!isExpanded));
            navigation.classList.toggle("is-open", !isExpanded);
        });

        navigation.querySelectorAll("a").forEach((link) => {
            link.addEventListener("click", () => {
                menuButton.setAttribute("aria-expanded", "false");
                navigation.classList.remove("is-open");
            });
        });
    }

    document.querySelectorAll("[data-password-toggle]").forEach((toggle) => {
        toggle.addEventListener("click", () => {
            const input = document.getElementById(
                toggle.dataset.passwordToggle
            );

            if (!input) {
                return;
            }

            const shouldShow = input.type === "password";
            input.type = shouldShow ? "text" : "password";
            toggle.textContent = shouldShow ? "Hide" : "Show";
            toggle.setAttribute("aria-pressed", String(shouldShow));
        });
    });

    const projectCards = document.querySelectorAll(".project-card");

    if ("IntersectionObserver" in window) {
        const observer = new IntersectionObserver(
            (entries) => {
                entries.forEach((entry) => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add("is-visible");
                        observer.unobserve(entry.target);
                    }
                });
            },
            { threshold: 0.12 }
        );

        projectCards.forEach((card) => observer.observe(card));
    } else {
        projectCards.forEach((card) => {
            card.classList.add("is-visible");
        });
    }
});