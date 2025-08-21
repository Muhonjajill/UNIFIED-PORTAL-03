document.addEventListener("DOMContentLoaded", function () {
  // Profile dropdown toggle
  const userProfile = document.getElementById('userProfile');
  if (userProfile) {
    userProfile.addEventListener('click', function (e) {
      this.classList.toggle('active');
      e.stopPropagation();
    });

    window.addEventListener('click', function (e) {
      if (!userProfile.contains(e.target)) {
        userProfile.classList.remove('active');
      }
    });
  }

  // Sidebar toggle (hamburger)
  const hamburger = document.getElementById('hamburger');
  const sidebarToggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');

  const toggleSidebar = () => {
    if (sidebar) sidebar.classList.toggle('active');
  };

  if (hamburger) {
    hamburger.addEventListener('click', toggleSidebar);
  }

  if (sidebarToggle) {
    sidebarToggle.addEventListener('click', toggleSidebar);
  }

  // Sidebar close when clicking outside
  document.addEventListener('click', function (e) {
    if (sidebar && !sidebar.contains(e.target) && !hamburger.contains(e.target)) {
      sidebar.classList.remove('active');
    }
  });

  // Navbar search input (Enter key redirect)
  const searchInput = document.getElementById('navbarSearchInput');
  if (searchInput) {
    searchInput.addEventListener('keypress', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        const query = searchInput.value.trim();
        if (query !== '') {
          window.location.href = `/search/?q=${encodeURIComponent(query)}`;
          searchInput.value = ''; // Clear input after search
        }
      }
    });
  }
});

// Table filter function (remains outside since it's called on input events)
function filterTable() {
  const input = document.getElementById("searchInput");
  const filter = input.value.toLowerCase();
  const rows = document.querySelectorAll(".version-table tbody tr");

  rows.forEach(row => {
    const rowText = row.textContent.toLowerCase();
    row.style.display = rowText.includes(filter) ? "" : "none";
  });
}
