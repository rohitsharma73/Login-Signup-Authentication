// intl.js

const input = document.querySelector("#phone");
window.intlTelInput(input, {
   initialCountry: "in",
   strictMode: true,
   utilsScript: "https://cdn.jsdelivr.net/npm/intl-tel-input@23.0.11/build/js/utils.js", // just for formatting/placeholders etc
});
