// dummy data for initial display
let passwords = [
  { id: 1, website: 'example.com', username: 'user1', password: 'password1' },
  { id: 2, website: 'example.net', username: 'user2', password: 'password2' },
];
//get elements
const loginForm = document.getElementById('login-form');
const masterPasswordInput = document.getElementById('master-password');
const passwordsContainer = document.querySelector('.passwords-container');
const passwordList = document.getElementById('password-list');
const addPasswordForm = document.getElementById('add-password-form');
const websiteNameInput = document.getElementById('website-name');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
// Login form submit event
loginForm.addEventListener('submit', (e) => {
  e.preventDefault();

  const masterPassword = masterPasswordInput.value;

  // Perform authentication logic here
  if ('/* authenticate master password */') {
    showPasswordsContainer();
  } else {
    // Show error message or redirect to login page
  }
});
// Add password form submit event
addPasswordForm.addEventListener('submit', (e) => {
  e.preventDefault();

  const websiteName = websiteNameInput.value;
  const username = usernameInput.value;
  const password = passwordInput.value;

  // Perform CRUD operations on password vault here
  const id = passwords.length + 1;
  passwords.push({ id, website: websiteName, username, password });
  displayPasswords();

  // Clear input fields
  websiteNameInput.value = '';
  usernameInput.value = '';
  passwordInput.value = '';
});
// Show passwords container
function showPasswordsContainer() {
  loginForm.style.display = 'none';
  passwordsContainer.style.display = 'block';
  displayPasswords();
}
// Display passwords in password list
function displayPasswords() {
  passwordList.innerHTML = '';

  passwords.forEach((password) => {
    const passwordElement = document.createElement('div');
    passwordElement.classList.add('password');

    passwordElement.innerHTML = `
        <div class="password-details">
          <span class="website">${password.website}</span>
          <span class="username">${password.username}</span>
          <span class="password">${password.password}</span>
        </div>
        <div class="password-actions">
          <button class="edit-button">Edit</button>
          <button class="delete-button">Delete</button>
        </div>
      `;

    passwordList.appendChild(passwordElement);
  });
}
