document.addEventListener('DOMContentLoaded', async () => {
    const sessionStatus = document.getElementById('session-status');
    const loginPanel = document.getElementById('login-panel');
    const dashboardPanel = document.getElementById('dashboard-panel');
    const btnLogin = document.getElementById('btn-login');
    const btnLogout = document.getElementById('btn-logout');
    
    const profileSub = document.getElementById('profile-sub');
    const profileUsername = document.getElementById('profile-username');
    const profileEmail = document.getElementById('profile-email');
    const profileRoles = document.getElementById('profile-roles');
    
    const btnFetchUser = document.getElementById('btn-fetch-user');
    const btnFetchAdmin = document.getElementById('btn-fetch-admin');
    const apiOutputBox = document.getElementById('api-output-box');

    // Obsluga akcji klikniecia przycisku logowania
    btnLogin.addEventListener('click', () => {
        window.location.href = generateLoginUrl();
    });

    // Czyszczenie sesji i lokalnych tokenów podczas wylogowywania
    btnLogout.addEventListener('click', () => {
        localStorage.removeItem('access_token');
        localStorage.removeItem('id_token');
        localStorage.removeItem('oauth_state');
        window.location.href = '/';
    });

    btnFetchUser.addEventListener('click', () => querySecureApi('/api/user-data'));
    btnFetchAdmin.addEventListener('click', () => querySecureApi('/api/admin-data'));

    const currentPath = window.location.pathname;

    // Obsluga powrotu z serwera autoryzacji (Callback URL)
    if (currentPath === '/callback') {
        sessionStatus.textContent = 'Trwa autoryzacja... Weryfikacja kodu jednorazowego.';
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        const state = urlParams.get('state');
        const savedState = localStorage.getItem('oauth_state');

        // Walidacja parametru state przeciwdzialajaca atakom Session Fixation
        if (state!== savedState) {
            showUiError('Blad walidacji stanu (State mismatch). Potencjalna próba ataku CSRF!');
            return;
        }

        if (code) {
            try {
                // Przekazanie kodu do backendu w celu wykonania bezpiecznej wymiany
                const response = await fetch('/auth/callback', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        code: code,
                        redirectUri: OIDC_CONFIG.redirectUri
                    })
                });

                const data = await response.json();

                if (response.ok && data.access_token) {
                    localStorage.setItem('access_token', data.access_token);
                    if (data.id_token) {
                        localStorage.setItem('id_token', data.id_token);
                    }
                    sessionStatus.textContent = 'Autoryzacja pomyślna! Przekierowanie...';
                    setTimeout(() => { window.location.href = '/'; }, 1000);
                } else {
                    showUiError('Blad podczas wymiany kodu na token: ' + (data.error_description || 'Nieznany blad'));
                }
            } catch (err) {
                console.error(err);
                showUiError('Blad komunikacji sieciowej z serwerem API.');
            }
        } else {
            showUiError('Brak kodu autoryzacyjnego w parametrach zwrotnych.');
        }
    } else {
        // Logika glówna SPA - badanie obecności oraz waznosci zapisanego tokenu
        const token = localStorage.getItem('access_token');
        if (token) {
            const payload = parseJwtPayload(token);
            const isTokenExpired = payload && (payload.exp * 1000 < Date.now());

            if (isTokenExpired) {
                localStorage.removeItem('access_token');
                sessionStatus.textContent = 'Sesja wygasla. Wymagane ponowne uwierzytelnienie.';
                renderLoggedOutState();
            } else {
                sessionStatus.textContent = `Zalogowany: ${payload.preferred_username}`;
                renderLoggedInState(payload);
            }
        } else {
            sessionStatus.textContent = 'Nieuwierzytelniony';
            renderLoggedOutState();
        }
    }

    function renderLoggedInState(payload) {
        loginPanel.classList.add('hidden');
        dashboardPanel.classList.remove('hidden');

        profileSub.textContent = payload.sub || 'brak';
        profileUsername.textContent = payload.preferred_username || 'brak';
        profileEmail.textContent = payload.email || 'brak';
        
        const roles = payload.realm_access && payload.realm_access.roles;
        profileRoles.textContent = roles? roles.join(', ') : 'brak przypisanych rol';
    }

    function renderLoggedOutState() {
        loginPanel.classList.remove('hidden');
        dashboardPanel.classList.add('hidden');
    }

    function showUiError(message) {
        sessionStatus.textContent = message;
        sessionStatus.style.borderColor = 'var(--color-danger)';
        sessionStatus.style.color = 'var(--color-danger)';
        renderLoggedOutState();
    }

    // Wykonanie zapytania asynchronicznego z dolaczeniem tokenu w naglówku Bearer
    async function querySecureApi(endpoint) {
        const token = localStorage.getItem('access_token');
        if (!token) {
            apiOutputBox.textContent = 'Blad lokalny: Brak tokenu uwierzytelniajacego w lokalnej pamięci przegladarki!';
            return;
        }

        try {
            apiOutputBox.textContent = 'Wysylanie autoryzowanego zadania HTTP...';
            const response = await fetch(endpoint, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            const responseData = await response.json();
            apiOutputBox.textContent = `Status odpowiedzi: ${response.status} ${response.statusText}\n\n` + JSON.stringify(responseData, null, 2);
        } catch (err) {
            apiOutputBox.textContent = 'Blad polaczenia sieciowego z API: ' + err.message;
        }
    }
});