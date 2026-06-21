const OIDC_CONFIG = {
    clientId: 'moj-frontend-client',
    issuerUrl: 'http://localhost:8080/realms/moj-realm',
    redirectUri: 'http://localhost/callback',
    scope: 'openid profile email'
};

// Generowanie adresu żądania logowania zgodnie ze specyfikacja standardu OIDC
function generateLoginUrl() {
    const state = crypto.randomUUID();
    localStorage.setItem('oauth_state', state); // Zapis stanu do ochrony przed atakami typu CSRF
    
    const params = new URLSearchParams({
        client_id: OIDC_CONFIG.clientId,
        redirect_uri: OIDC_CONFIG.redirectUri,
        response_type: 'code',
        scope: OIDC_CONFIG.scope,
        state: state
    });
    
    return `${OIDC_CONFIG.issuerUrl}/protocol/openid-connect/auth?${params.toString()}`;
}

// Lokalna analiza zawartości tokena w celu dynamicznego dostosowania interfejsu SPA
function parseJwtPayload(token) {
    try {
        const base64Url = token.split('.');
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        
        return JSON.parse(jsonPayload);
    } catch (e) {
        console.error('Blad podczas parsowania struktury tokenu:', e);
        return null;
    }
}