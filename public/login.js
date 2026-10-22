const form = document.getElementById('login-form');
const button = document.getElementById('login-button');
const errorText = document.getElementById('login-error');
const passwordInput = document.getElementById('access-password');

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  button.disabled = true;
  errorText.classList.add('hidden');
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {'content-type':'application/json'},
      credentials: 'same-origin',
      cache: 'no-store',
      body: JSON.stringify({password: passwordInput.value}),
    });
    passwordInput.value = '';
    const outcome = await response.json().catch(() => ({}));
    if (!response.ok || !outcome.ok) {
      errorText.textContent = outcome.error || 'Access denied. Please try again.';
      errorText.classList.remove('hidden');
      return;
    }
    window.location.replace('/');
  } catch {
    passwordInput.value = '';
    errorText.textContent = 'Unable to contact SMTP Probe. Check the connection.';
    errorText.classList.remove('hidden');
  } finally {
    button.disabled = false;
  }
});
