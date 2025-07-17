document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const loginBtn = document.getElementById('login-btn');
    const errorDiv = document.getElementById('login-error');

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        errorDiv.textContent = '';
        loginBtn.disabled = true;
        loginBtn.textContent = 'Logging in...';

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (!response.ok) {
                const data = await response.json();
                errorDiv.textContent = data.message || 'Login failed. Please try again.';
                loginBtn.disabled = false;
                loginBtn.textContent = 'Login';
                return;
            }

            const data = await response.json();
            // Save token and username to localStorage
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('username', username);

            // Redirect to notes page
            window.location.href = '/notes';
        } catch (err) {
            errorDiv.textContent = 'Network error. Please try again.';
        } finally {
            loginBtn.disabled = false;
            loginBtn.textContent = 'Login';
        }
    });
});
