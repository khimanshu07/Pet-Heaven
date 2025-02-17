document.addEventListener("DOMContentLoaded", function () {
    // **Password Match Validation**
    const form = document.querySelector("form");
    if (form) {
      form.addEventListener("submit", function (e) {
        const password = document.querySelector("#password");
        const confirmPassword = document.querySelector("#confirm_password");
        const errorMessage = document.querySelector("#error-message"); // Optional error message container
  
        if (password && confirmPassword && password.value !== confirmPassword.value) {
          e.preventDefault(); // Prevent form submission
          if (errorMessage) {
            errorMessage.textContent = "Passwords do not match!";
            errorMessage.style.color = "red";
          } else {
            alert("Passwords do not match!"); // Fallback alert
          }
        } else if (errorMessage) {
          errorMessage.textContent = ""; // Clear error message when passwords match
        }
      });
    }
  
    // **Flash Message Auto-hide**
    const flashMessages = document.querySelectorAll(".flash-message");
    if (flashMessages) {
      flashMessages.forEach((message) => {
        setTimeout(() => {
          message.style.opacity = "0";
          setTimeout(() => message.remove(), 500); // Remove message after fade-out
        }, 3000); // Visible for 3 seconds
      });
    }
  
    // **Toggle Password Visibility**
    const togglePasswordIcons = document.querySelectorAll(".password-toggle");
    togglePasswordIcons.forEach((icon) => {
      icon.addEventListener("click", function () {
        const input = document.querySelector(`#${this.dataset.target}`);
        if (input.type === "password") {
          input.type = "text";
          this.textContent = "Hide"; // Update icon or text
        } else {
          input.type = "password";
          this.textContent = "Show"; // Update icon or text
        }
      });
    });
  });
  