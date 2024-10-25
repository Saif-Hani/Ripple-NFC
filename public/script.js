// Populate the username dynamically
document.addEventListener('DOMContentLoaded', () => {
  // Replace this with the actual username from the session if needed
  const username = '<%= username %>'; 
  document.getElementById('username').textContent = username;
});
