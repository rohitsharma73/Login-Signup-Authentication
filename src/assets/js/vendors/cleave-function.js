// Cleave js

// Phone
if (document.querySelector(".input-phone")) {
    var cleavePhone = new Cleave(".input-phone", {
        phone: true,
        phoneRegionCode: "IN",
    });
}

// Date
if (document.querySelector(".input-date")) {
    var cleaveDate = new Cleave(".input-date", {
        date: true,
    });
}

// Credit card
if (document.querySelector(".input-credit-card")) {
    var cleaveCreditCard = new Cleave(".input-credit-card", {
        visaCard: true,
        blocks: [4, 4, 4, 4],
        delimiter: "-",
    });
}
