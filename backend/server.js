const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const jwksRsa = require('jwks-rsa');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

app.use(cors({ origin: 'http://localhost' }));
app.use(express.json());

// Inicjalizacja klienta JWKS do pobierania kluczy publicznych z kontenera Keycloak
const jwksClientInstance = jwksRsa({
  jwksUri: process.env.KEYCLOAK_JWKS_URI,
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10
});

// Funkcja pobierajaca klucz publiczny odpowiadajacy identyfikatorowi 'kid' z naglowka JWT
function getSigningKey(header, callback) {
  jwksClientInstance.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// Oprogramowanie pośredniczące (middleware) do weryfikacji tokenu JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader ||!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Brak tokenu lub nieprawidlowy format naglowka Authorization' });
  }

  const token = authHeader.split(' ')[1];

  // Walidacja podpisu kryptograficznego, zgodności wystawcy oraz okresu ważności
  jwt.verify(token, getSigningKey, {
    algorithms: ['RS256'],
    issuer: process.env.KEYCLOAK_ISSUER
  }, (err, decoded) => {
    if (err) {
      console.error('Blad walidacji tokenu JWT:', err.message);
      return res.status(401).json({ error: 'Niewazny lub uszkodzony token autoryzacyjny' });
    }
    req.user = decoded;
    next();
  });
}

// Oprogramowanie pośredniczące do kontroli dostępu opartej na rolach (RBAC)
function requireRole(requiredRole) {
  return (req, res, next) => {
    const roles = req.user && req.user.realm_access && req.user.realm_access.roles;
    if (roles && roles.includes(requiredRole)) {
      next();
    } else {
      res.status(403).json({ error: `Odmowa dostepu. Wymagana rola: ${requiredRole}` });
    }
  };
}

// Punkt końcowy pośredniczący w bezpiecznej wymianie kodu autoryzacyjnego na tokeny (Confidential Client Flow)
app.post('/auth/callback', async (req, res) => {
  const { code, redirectUri } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Brak kodu autoryzacji' });
  }

  try {
    const tokenRequestParams = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
      client_id: 'moj-frontend-client',
      client_secret: CLIENT_SECRET
    });

    const response = await fetch(process.env.KEYCLOAK_TOKEN_URI, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenRequestParams
    });

    const tokenData = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({ error: tokenData });
    }

    res.json(tokenData);
  } catch (error) {
    console.error('Blad podczas komunikacji sieciowej z Keycloak:', error);
    res.status(500).json({ error: 'Wewnetrzny blad serwera API' });
  }
});

// Endpointy biznesowe z róznymi poziomami dostępu (RBAC)
app.get('/api/public', (req, res) => {
  res.json({ message: 'Zasoby publiczne: Dostep otwarty dla kazdego' });
});

app.get('/api/user-data', verifyToken, requireRole('user'), (req, res) => {
  res.json({
    message: 'Dane standardowe uzytkownika zaimportowane pomyslnie!',
    content: {
      owner: req.user.preferred_username,
      email: req.user.email,
      assignedRoles: req.user.realm_access.roles,
      action: 'Podglad przypisanych zadan w systemie (Rola: Uzytkownik)' 
    }
  });
});

app.get('/api/admin-data', verifyToken, requireRole('admin'), (req, res) => {
  res.json({
    message: 'Strefa administracyjna: Dostep autoryzowany rola Manager!',
    content: {
      owner: req.user.preferred_username,
      subjectId: req.user.sub,
      action: 'Pelne uprawnienia: Wglad, edycja i usuwanie zadan (Rola: Admin/Manager)' 
    }
  });
});

app.listen(PORT, () => {
  console.log(`Serwer backendowy bezpiecznie uruchomiony na porcie ${PORT}`);
});