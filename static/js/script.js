document.addEventListener("DOMContentLoaded", function() {
  const form = document.querySelector('form');
  
  form.addEventListener('submit', function(e) {
    // Client-side password validation for registration
    const password = document.querySelector('#password');
    const confirmPassword = document.querySelector('#confirm-password');
    const errorMessage = document.querySelector('#error-message'); // Assuming you will add a div for error message
    
    if (password && confirmPassword && password.value !== confirmPassword.value) {
      e.preventDefault();  // Prevent form submission
      if (errorMessage) {
        errorMessage.textContent = "Passwords do not match!"; // Display custom error message
        errorMessage.style.color = 'red';
      }
    } else if (errorMessage) {
      errorMessage.textContent = ''; // Clear error message when passwords match
    }
  });
});
