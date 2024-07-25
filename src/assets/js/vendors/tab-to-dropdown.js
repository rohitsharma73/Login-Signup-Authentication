// Tab Dropdown

document.addEventListener("DOMContentLoaded", function () {
   const tabsToDropdown = document.querySelector(".tabs-to-dropdown");

   function generateDropdownMarkup(container) {
      const navPills = container.querySelector(".nav-line-bottom");
      const firstTextLink = navPills.querySelector("li:first-child a").textContent.trim();
      const items = navPills.querySelectorAll("li");
      let markup = `
        <div class="dropdown d-lg-none mb-4 ">
          <button class="btn btn-light w-100 d-flex justify-content-between dropdown-toggle" type="button" id="dropdownMenuButton" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
            ${firstTextLink}
          </button>
          <div class="dropdown-menu w-100" aria-labelledby="dropdownMenuButton">
            ${generateDropdownLinksMarkup(items)}
          </div>
        </div>
      `;
      container.insertAdjacentHTML("afterbegin", markup);
   }

   function generateDropdownLinksMarkup(items) {
      let markup = "";
      items.forEach(function (item, index) {
         const textLink = item.querySelector("a").textContent.trim();
         markup += `<a class="dropdown-item d-inline-block " href="#!" data-index="${index}">${textLink}</a>`;
      });

      return markup;
   }

   function showDropdownHandler(e) {
      const dropdown = e.target.closest(".dropdown");
      const dropdownToggle = dropdown.querySelector(".dropdown-toggle");
      const dropdownToggleText = dropdownToggle.textContent.trim();
      const dropdownMenuLinks = dropdown.querySelectorAll(".dropdown-menu a");
      dropdownMenuLinks.forEach(function (link) {
         if (link.textContent.trim() === dropdownToggleText) {
            link.classList.add("d-none");
         } else {
            link.classList.remove("d-none");
         }
      });
   }

   function clickHandler(e) {
      e.preventDefault();
      const link = e.target;
      const index = link.getAttribute("data-index");
      const text = link.textContent.trim();
      const dropdown = link.closest(".dropdown");
      const dropdownToggle = dropdown.querySelector(".dropdown-toggle");
      dropdownToggle.textContent = text;
      const parentTabs = dropdown.closest(".tabs-to-dropdown");
      const targetTabLink = parentTabs.querySelector(`.nav-pills li:nth-child(${parseInt(index) + 1}) a`);
      targetTabLink.click();
   }

   function shownTabsHandler(e) {
      const tabLink = e.target;
      const index = [...tabLink.parentNode.children].indexOf(tabLink);
      const parentTabs = tabLink.closest(".tabs-to-dropdown");
      const dropdownMenuLinks = parentTabs.querySelectorAll(".dropdown-menu a");
      const dropdownToggle = parentTabs.querySelector(".dropdown-toggle");
      dropdownToggle.textContent = dropdownMenuLinks[index].textContent;
   }

   generateDropdownMarkup(tabsToDropdown);

   tabsToDropdown.querySelectorAll(".dropdown").forEach(function (dropdown) {
      dropdown.addEventListener("show.bs.dropdown", showDropdownHandler);
      dropdown.querySelectorAll(".dropdown-menu a").forEach(function (link) {
         link.addEventListener("click", clickHandler);
      });
   });

   tabsToDropdown.querySelectorAll('a[data-bs-toggle="pill"]').forEach(function (tabLink) {
      tabLink.addEventListener("shown.bs.tab", shownTabsHandler);
   });
});
