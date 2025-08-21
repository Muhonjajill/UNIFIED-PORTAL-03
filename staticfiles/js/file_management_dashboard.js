// Toggle profile dropdown
const userProfile = document.getElementById('userProfile');
const dropdown = document.querySelector('.dropdown-content');
const modal = document.getElementById('profileModal');

// Toggle dropdown on profile click
if (userProfile) {
  userProfile.addEventListener('click', function (event) {
    event.stopPropagation();
    this.classList.toggle('active');
    dropdown?.classList.toggle('show');
  });
}

// Close dropdown and modal on window click
window.addEventListener('click', function (event) {
  // Close dropdown if clicked outside
  if (!event.target.closest('#userProfile')) {
    userProfile?.classList.remove('active');
    dropdown?.classList.remove('show');
  }

  // Close modal if clicked outside modal content
  if (modal && event.target === modal) {
    modal.style.display = "none";
  }
});

// Open profile modal with AJAX
function openProfileModal(event) {
  event.preventDefault();
  fetch("{% url 'profile_view' %}", {
    headers: {
      'X-Requested-With': 'XMLHttpRequest'
    }
  })
  .then(response => response.text())
  .then(data => {
    if (modal) {
      modal.classList.add("show");
      document.getElementById("profileContent").innerHTML = data;
      modal.style.display = "block";
    }
  });
}

// Close profile modal
function closeModal() {
  if (modal) {
    modal.style.display = "none";
  }
}
