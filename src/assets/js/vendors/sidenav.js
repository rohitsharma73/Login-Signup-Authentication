// Sidebar nav

document.addEventListener("DOMContentLoaded", function (event) {
    // Get the current page URL
    var url = window.location.href;

    // Select all navigation links
    var navLinks = document.querySelectorAll(".nav-account .nav-link");

    // Loop through the links
    for (var i = 0; i < navLinks.length; i++) {
        // Check if the link's URL matches the current page URL
        if (navLinks[i].href === url) {
            // Add the "active" class to the parent <li> element
            navLinks[i].classList.add("active");

            // Store the active link in local storage
            localStorage.setItem("activeLink", navLinks[i].href);
        }
    }

    // Retrieve the active link from local storage
    var activeLink = localStorage.getItem("activeLink");

    // If an active link is found, reapply the "active" class
    if (activeLink) {
        for (var i = 0; i < navLinks.length; i++) {
            if (navLinks[i].href === activeLink) {
                navLinks[i].classList.add("active");
            }
        }
    }
});
