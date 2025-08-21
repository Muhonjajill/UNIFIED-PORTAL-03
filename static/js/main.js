document.addEventListener('DOMContentLoaded', () => {
  const hamburger = document.getElementById('hamburger');
  const sidebar = document.querySelector('.sidebar');
  const userProfile = document.getElementById('userProfile');

  // Toggle sidebar for mobile
  if (hamburger && sidebar) {
    hamburger.addEventListener('click', () => {
      sidebar.classList.toggle('active');
    });
  }

  // Toggle user dropdown
  if (userProfile) {
    userProfile.addEventListener('click', () => {
      userProfile.classList.toggle('active');
    });

    document.addEventListener('click', (e) => {
      if (!userProfile.contains(e.target)) {
        userProfile.classList.remove('active');
      }
    });
  }
});

