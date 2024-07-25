// Pricing js

if (document.querySelector(".price-switchers") !== null) {
    var wrappers = document.querySelectorAll(".price-wrapper");
    for (var i = 0; i < wrappers.length; i++) {
        var wrap = wrappers[i];
        var switchers = wrap.querySelector(".price-switchers");
        var switcher = wrap.querySelectorAll(".price-switcher");
        var price = wrap.querySelectorAll(".price");
        switchers.addEventListener("click", function (e) {
            for (var j = 0; j < switcher.length; j++) {
                switcher[j].classList.toggle("price-switcher-active");
            }
            for (var k = 0; k < price.length; k++) {
                price[k].classList.remove("price-hidden");
                price[k].classList.toggle("price-show");
                price[k].classList.toggle("price-hide");
            }
        });
    }
}
