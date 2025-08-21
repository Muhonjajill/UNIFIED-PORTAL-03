function toggleSidebar() {
  const sidebar = document.getElementById("sidebar");
  const overlay = document.querySelector(".sidebar-overlay");
  sidebar.classList.toggle("active");
  overlay.classList.toggle("active");
}

// Attach toggle to hamburger click
const hamburger = document.getElementById("hamburger");
if (hamburger) {
  hamburger.addEventListener("click", toggleSidebar);
}

// Submenu toggle
document.querySelectorAll(".has-submenu > a").forEach(link => {
  link.addEventListener("click", function (e) {
    e.preventDefault();
    this.parentElement.classList.toggle("expanded");
  });
});
