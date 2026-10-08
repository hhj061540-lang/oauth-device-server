const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5900;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --------------------------------------------------
// Files
// --------------------------------------------------

const DATA_DIR = path.join(__dirname, "data");

const USERS_FILE = path.join(DATA_DIR, "users.json");
const APPS_FILE = path.join(DATA_DIR, "oauth-apps.json");
const SECRET_FILE = path.join(DATA_DIR, "oauth-secret.key");
const REVOKED_TOKENS_FILE = path.join(
  DATA_DIR,
  "revoked-tokens.json"
);

fs.mkdirSync(DATA_DIR, { recursive: true });

function ensureFile(file, value = []) {
  if (!fs.existsSync(file)) {
    fs.writeFileSync(file, JSON.stringify(value, null, 2));
  }
}

ensureFile(USERS_FILE);
ensureFile(APPS_FILE);
ensureFile(REVOKED_TOKENS_FILE);

// --------------------------------------------------
// OAuth secret
// --------------------------------------------------

let OAUTH_SECRET;

if (fs.existsSync(SECRET_FILE)) {
  OAUTH_SECRET = fs.readFileSync(SECRET_FILE, "utf8").trim();
}

if (!OAUTH_SECRET) {
  OAUTH_SECRET = crypto.randomBytes(64).toString("hex");

  fs.writeFileSync(
    SECRET_FILE,
    OAUTH_SECRET,
    {
      mode: 0o600
    }
  );
}

console.log("OAuth secret key loaded/generated.");

// --------------------------------------------------
// Temporary storage
// --------------------------------------------------

const deviceCodes = new Map();
const authorizationCodes = new Map();

// --------------------------------------------------
// Helpers
// --------------------------------------------------

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function writeJson(file, value) {
  fs.writeFileSync(
    file,
    JSON.stringify(value, null, 2)
  );
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

function randomBase64Url(bytes = 32) {
  return crypto
    .randomBytes(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function generateClientId() {
  return "client_" + randomHex(16);
}

function generateClientSecret() {
  return "secret_" + randomHex(32);
}

function generateDeviceCode() {
  return crypto
    .randomBytes(4)
    .toString("hex")
    .toUpperCase();
}

function generateAuthorizationCode() {
  return randomBase64Url(32);
}

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function baseUrl(req) {
  const protocol =
    req.headers["x-forwarded-proto"] ||
    req.protocol;

  return `${protocol}://${req.get("host")}`;
}

// --------------------------------------------------
// PKCE
// --------------------------------------------------

function base64UrlSha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function verifyPKCE(
  codeVerifier,
  codeChallenge,
  method
) {
  if (!codeVerifier || !codeChallenge) {
    return false;
  }

  if (method !== "S256") {
    return false;
  }

  return (
    base64UrlSha256(codeVerifier) ===
    codeChallenge
  );
}

// --------------------------------------------------
// Token revocation
// --------------------------------------------------

function isTokenRevoked(jti) {
  if (!jti) {
    return false;
  }

  const revoked = readJson(
    REVOKED_TOKENS_FILE
  );

  return revoked.some(
    item => item.jti === jti
  );
}

function revokeToken(jti, exp) {
  const revoked = readJson(
    REVOKED_TOKENS_FILE
  );

  if (
    revoked.some(
      item => item.jti === jti
    )
  ) {
    return;
  }

  revoked.push({
    jti,
    exp: exp || null,
    revokedAt: new Date().toISOString()
  });

  writeJson(
    REVOKED_TOKENS_FILE,
    revoked
  );
}

// --------------------------------------------------
// HTML
// --------------------------------------------------

const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>Connect Account</title>

<style>
body {
  background:#111;
  color:#00ff66;
  font-family:monospace;
  padding:25px;
}

.container {
  max-width:520px;
  margin:auto;
  background:#1b1b1b;
  padding:25px;
  border-radius:8px;
}

h1,h2 {
  border-bottom:1px solid #333;
  padding-bottom:8px;
}

input,
button {
  width:100%;
  box-sizing:border-box;
  padding:12px;
  margin:6px 0;
  background:#222;
  color:white;
  border:1px solid #444;
  font-family:monospace;
}

button {
  background:#0088cc;
  cursor:pointer;
  font-weight:bold;
}

button:hover {
  background:#00aaff;
}

hr {
  border:0;
  border-top:1px solid #333;
  margin:25px 0;
}
</style>
</head>

<body>

<div class="container">

<h1>Connect Account</h1>

<p>
Enter your device code to connect your account.
</p>

<form method="POST"
      action="/login/device">

<input
 name="device_code"
 placeholder="Enter your device code"
 required>

<h2>Login</h2>

<input
 name="username"
 placeholder="Enter username"
 required>

<input
 type="password"
 name="password"
 placeholder="Enter password"
 required>

<button type="submit">
Connect Account
</button>

</form>

<hr>

<h2>Register Account</h2>

<form method="POST"
      action="/api/auth/register">

<input
 name="username"
 placeholder="Enter username"
 required>

<input
 type="password"
 name="password"
 placeholder="Enter password"
 required>

<button type="submit">
Create Account
</button>

</form>

</div>

</body>
</html>
`;

// --------------------------------------------------
// Device pages
// --------------------------------------------------

app.get("/oauth/device", (req, res) => {
  res.send(htmlContent);
});

app.get("/login/device", (req, res) => {
  res.send(htmlContent);
});

// --------------------------------------------------
// Device code
// --------------------------------------------------

app.post("/oauth/device/code", (req, res) => {
  const deviceCode = randomHex(32);
  const userCode = generateDeviceCode();

  const expiresIn = 600;

  const entry = {
    deviceCode,
    userCode,

    clientId:
      req.body.client_id || null,

    username: null,

    status: "pending",

    createdAt: Date.now(),

    expiresAt:
      Date.now() +
      expiresIn * 1000
  };

  deviceCodes.set(
    deviceCode,
    entry
  );

  res.json({
    device_code: deviceCode,
    user_code: userCode,

    verification_uri:
      `${baseUrl(req)}/oauth/device`,

    verification_uri_complete:
      `${baseUrl(req)}/oauth/device?code=${encodeURIComponent(userCode)}`,

    expires_in: expiresIn,

    interval: 5
  });
});

// --------------------------------------------------
// Register
// --------------------------------------------------

app.post("/api/auth/register", (req, res) => {
  const {
    username,
    password
  } = req.body;

  if (
    typeof username !== "string" ||
    typeof password !== "string"
  ) {
    return res.status(400).json({
      error:
        "username_and_password_required"
    });
  }

  if (
    username.length < 3 ||
    password.length < 8
  ) {
    return res.status(400).json({
      error:
        "invalid_registration",

      message:
        "Username must contain at least 3 characters and password at least 8 characters."
    });
  }

  const users = readJson(
    USERS_FILE
  );

  if (
    users.some(
      user =>
        user.username === username
    )
  ) {
    return res.status(409).json({
      error:
        "username_already_exists"
    });
  }

  const user = {
    id: randomHex(16),

    username,

    passwordHash:
      hashPassword(password),

    createdAt:
      new Date().toISOString()
  };

  users.push(user);

  writeJson(
    USERS_FILE,
    users
  );

  res.status(201).json({
    status: "success",
    message: "Account created",
    username
  });
});

// --------------------------------------------------
// Login
// --------------------------------------------------

app.post("/api/auth/login", (req, res) => {
  const {
    username,
    password
  } = req.body;

  const users = readJson(
    USERS_FILE
  );

  const user = users.find(
    u =>
      u.username === username
  );

  if (
    !user ||
    user.passwordHash !==
      hashPassword(password || "")
  ) {
    return res.status(401).json({
      error:
        "invalid_credentials"
    });
  }

  const accessToken = jwt.sign(
    {
      sub: user.id,

      username:
        user.username,

      jti:
        randomHex(32)
    },

    OAUTH_SECRET,

    {
      expiresIn: "1h"
    }
  );

  res.json({
    access_token: accessToken,

    token_type: "Bearer",

    expires_in: 3600
  });
});

// --------------------------------------------------
// Device login
// --------------------------------------------------

app.post("/login/device", (req, res) => {
  const {
    device_code,
    username,
    password
  } = req.body;

  if (
    !device_code ||
    !username ||
    !password
  ) {
    return res.status(400).send(
      "Device code, username and password are required."
    );
  }

  let device = null;

  for (
    const item
    of deviceCodes.values()
  ) {
    if (
      item.deviceCode === device_code ||
      item.userCode ===
        device_code.toUpperCase()
    ) {
      device = item;
      break;
    }
  }

  if (!device) {
    return res.status(400).send(
      "Invalid device code."
    );
  }

  if (
    Date.now() >
    device.expiresAt
  ) {
    return res.status(400).send(
      "Device code expired."
    );
  }

  const users = readJson(
    USERS_FILE
  );

  const user = users.find(
    u =>
      u.username === username
  );

  if (
    !user ||
    user.passwordHash !==
      hashPassword(password)
  ) {
    return res.status(401).send(
      "Invalid username or password."
    );
  }

  device.status = "approved";
  device.username = username;

  res.redirect(
    `/login/device/success?device_code=${encodeURIComponent(
      device.deviceCode
    )}`
  );
});

// --------------------------------------------------
// Device success
// --------------------------------------------------

app.get(
  "/login/device/success",
  (req, res) => {
    const {
      device_code
    } = req.query;

    const device =
      deviceCodes.get(
        device_code
      );

    if (!device) {
      return res.status(404).send(
        "Device code not found."
      );
    }

    res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Device Connected</title>
<style>
body {
  background:#111;
  color:#00ff66;
  font-family:monospace;
  padding:30px;
}

.box {
  max-width:600px;
  margin:auto;
  background:#1b1b1b;
  padding:25px;
}
</style>
</head>

<body>

<div class="box">

<h1>Device Connected</h1>

<p>
Account successfully connected.
</p>

<p>
Username:
<strong>${escapeHtml(device.username)}</strong>
</p>

<p>
You can return to your application.
</p>

</div>

</body>
</html>
`);
  }
);

// --------------------------------------------------
// OAuth application creation
// --------------------------------------------------

app.post(
  ["/oauth/apps", "/create"],
  (req, res) => {
    const {
      name,
      redirect_uri
    } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim()
    ) {
      return res.status(400).json({
        error:
          "application_name_required"
      });
    }

    const clientId =
      generateClientId();

    const clientSecret =
      generateClientSecret();

    const apps =
      readJson(APPS_FILE);

    const oauthApp = {
      id: randomHex(16),

      name: name.trim(),

      client_id: clientId,

      client_secret:
        clientSecret,

      redirect_uri:
        redirect_uri ||
        null,

      createdAt:
        new Date().toISOString()
    };

    apps.push(oauthApp);

    writeJson(
      APPS_FILE,
      apps
    );

    res.status(201).json({
      status: "success",

      name:
        oauthApp.name,

      client_id:
        clientId,

      client_secret:
        clientSecret,

      redirect_uri:
        oauthApp.redirect_uri
    });
  }
);

// --------------------------------------------------
// Create app HTML
// --------------------------------------------------

app.get("/create", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>

<head>
<title>Create OAuth App</title>
</head>

<body style="
background:#111;
color:#00ff66;
font-family:monospace;
padding:30px;
">

<h2>Register OAuth App</h2>

<form
 method="POST"
 action="/create"
>

<input
 name="name"
 placeholder="App Name"
 required
 style="
 padding:10px;
 background:#222;
 color:#fff;
 border:1px solid #444;
 margin-bottom:10px;
 display:block;
">

<input
 name="redirect_uri"
 placeholder="Redirect URI"
 style="
 padding:10px;
 background:#222;
 color:#fff;
 border:1px solid #444;
 margin-bottom:10px;
 display:block;
">

<button
 type="submit"
 style="
 padding:10px 20px;
 background:#0088cc;
 color:#fff;
 border:none;
 cursor:pointer;
 "
>
Create App
</button>

</form>

</body>
</html>
`);
});

// --------------------------------------------------
// JWT authentication
// --------------------------------------------------

function authenticateJWT(
  req,
  res,
  next
) {
  const authorization =
    req.headers.authorization || "";

  if (
    !authorization.startsWith(
      "Bearer "
    )
  ) {
    return res.status(401).json({
      error: "unauthorized",

      message:
        "Bearer access token required"
    });
  }

  const token =
    authorization.substring(7);

  try {
    const decoded =
      jwt.verify(
        token,
        OAUTH_SECRET
      );

    if (
      decoded.jti &&
      isTokenRevoked(
        decoded.jti
      )
    ) {
      return res.status(401).json({
        error:
          "invalid_token",

        message:
          "Token has been logged out"
      });
    }

    req.user = decoded;
    req.accessToken = token;

    next();
  } catch {
    return res.status(401).json({
      error:
        "invalid_token",

      message:
        "Invalid or expired access token"
    });
  }
}

// --------------------------------------------------
// GET /oauth/apps
// List applications
// --------------------------------------------------

app.get(
  "/oauth/apps",
  authenticateJWT,
  (req, res) => {
    const apps =
      readJson(APPS_FILE);

    const safeApps =
      apps.map(item => ({
        id: item.id,

        name: item.name,

        client_id:
          item.client_id,

        redirect_uri:
          item.redirect_uri,

        createdAt:
          item.createdAt
      }));

    res.json({
      count: safeApps.length,

      apps: safeApps
    });
  }
);

// --------------------------------------------------
// GET /oauth/apps/:client_id
// View application
// --------------------------------------------------

app.get(
  "/oauth/apps/:client_id",
  authenticateJWT,
  (req, res) => {
    const apps =
      readJson(APPS_FILE);

    const oauthApp =
      apps.find(
        item =>
          item.client_id ===
          req.params.client_id
      );

    if (!oauthApp) {
      return res.status(404).json({
        error:
          "oauth_app_not_found"
      });
    }

    res.json({
      id: oauthApp.id,

      name: oauthApp.name,

      client_id:
        oauthApp.client_id,

      redirect_uri:
        oauthApp.redirect_uri,

      createdAt:
        oauthApp.createdAt
    });
  }
);

// --------------------------------------------------
// DELETE /oauth/apps/:client_id
// Delete application
// --------------------------------------------------

app.delete(
  "/oauth/apps/:client_id",
  authenticateJWT,
  (req, res) => {
    const apps =
      readJson(APPS_FILE);

    const index =
      apps.findIndex(
        item =>
          item.client_id ===
          req.params.client_id
      );

    if (index === -1) {
      return res.status(404).json({
        error:
          "oauth_app_not_found"
      });
    }

    const deleted =
      apps[index];

    apps.splice(index, 1);

    writeJson(
      APPS_FILE,
      apps
    );

    res.json({
      status: "success",

      message:
        "OAuth application deleted",

      client_id:
        deleted.client_id
    });
  }
);

// --------------------------------------------------
// OAuth authorization endpoint
//
// Supports:
//
// response_type=code
// client_id=...
// redirect_uri=...
// scope=openid profile email offline_access
// code_challenge=...
// code_challenge_method=S256
// state=...
// --------------------------------------------------

app.get(
  "/oauth/authorize",
  (req, res) => {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      code_challenge,
      code_challenge_method,
      state
    } = req.query;

    if (
      response_type !== "code"
    ) {
      return res.status(400).json({
        error:
          "unsupported_response_type"
      });
    }

    if (!client_id) {
      return res.status(400).json({
        error:
          "client_id_required"
      });
    }

    const apps =
      readJson(APPS_FILE);

    const oauthApp =
      apps.find(
        item =>
          item.client_id ===
          client_id
      );

    if (!oauthApp) {
      return res.status(400).json({
        error:
          "invalid_client"
      });
    }

    if (
      !redirect_uri
    ) {
      return res.status(400).json({
        error:
          "redirect_uri_required"
      });
    }

    if (
      oauthApp.redirect_uri &&
      oauthApp.redirect_uri !==
        redirect_uri
    ) {
      return res.status(400).json({
        error:
          "redirect_uri_mismatch"
      });
    }

    // Require PKCE S256.
    if (
      !code_challenge ||
      code_challenge_method !==
        "S256"
    ) {
      return res.status(400).json({
        error:
          "invalid_request",

        message:
          "PKCE S256 code_challenge is required"
      });
    }

    const requestedScopes =
      typeof scope === "string"
        ? scope
            .split(/\s+/)
            .filter(Boolean)
        : [];

    // Show login/approval page.
    res.send(`
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
 name="viewport"
 content="width=device-width,initial-scale=1"
>

<title>Authorize Application</title>

<style>

body {
  background:#111;
  color:#00ff66;
  font-family:monospace;
  padding:30px;
}

.box {
  max-width:650px;
  margin:auto;
  background:#1b1b1b;
  padding:25px;
  border-radius:8px;
}

input,
button {
  width:100%;
  box-sizing:border-box;
  padding:12px;
  margin:7px 0;
  background:#222;
  color:white;
  border:1px solid #444;
  font-family:monospace;
}

button {
  background:#0088cc;
  cursor:pointer;
}

.scope {
  background:#222;
  padding:8px;
  margin:5px 0;
}

</style>

</head>

<body>

<div class="box">

<h1>Authorize Application</h1>

<p>
Application:
<strong>${escapeHtml(oauthApp.name)}</strong>
</p>

<p>
Client ID:
${escapeHtml(client_id)}
</p>

<h3>Requested permissions</h3>

${
  requestedScopes.length
    ? requestedScopes
        .map(
          s =>
            `<div class="scope">${escapeHtml(s)}</div>`
        )
        .join("")
    : "<div class=\"scope\">No scopes requested</div>"
}

<form
 method="POST"
 action="/oauth/authorize"
>

<input
 type="hidden"
 name="response_type"
 value="code"
>

<input
 type="hidden"
 name="client_id"
 value="${escapeHtml(client_id)}"
>

<input
 type="hidden"
 name="redirect_uri"
 value="${escapeHtml(redirect_uri)}"
>

<input
 type="hidden"
 name="scope"
 value="${escapeHtml(scope || "")}"
>

<input
 type="hidden"
 name="code_challenge"
 value="${escapeHtml(code_challenge)}"
>

<input
 type="hidden"
 name="code_challenge_method"
 value="S256"
>

<input
 type="hidden"
 name="state"
 value="${escapeHtml(state || "")}"
>

<h3>Login</h3>

<input
 name="username"
 placeholder="Username"
 required
>

<input
 type="password"
 name="password"
 placeholder="Password"
 required
>

<button type="submit">
Authorize
</button>

</form>

</div>

</body>

</html>
`);
  }
);

// --------------------------------------------------
// OAuth authorization approval
// --------------------------------------------------

app.post(
  "/oauth/authorize",
  (req, res) => {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      code_challenge,
      code_challenge_method,
      state,
      username,
      password
    } = req.body;

    if (
      response_type !== "code"
    ) {
      return res.status(400).json({
        error:
          "unsupported_response_type"
      });
    }

    if (
      !client_id ||
      !redirect_uri
    ) {
      return res.status(400).json({
        error:
          "invalid_request"
      });
    }

    const apps =
      readJson(APPS_FILE);

    const oauthApp =
      apps.find(
        item =>
          item.client_id ===
          client_id
      );

    if (!oauthApp) {
      return res.status(400).json({
        error:
          "invalid_client"
      });
    }

    if (
      oauthApp.redirect_uri &&
      oauthApp.redirect_uri !==
        redirect_uri
    ) {
      return res.status(400).json({
        error:
          "redirect_uri_mismatch"
      });
    }

    if (
      !code_challenge ||
      code_challenge_method !==
        "S256"
    ) {
      return res.status(400).json({
        error:
          "invalid_request",

        message:
          "PKCE S256 is required"
      });
    }

    const users =
      readJson(USERS_FILE);

    const user =
      users.find(
        item =>
          item.username ===
          username
      );

    if (
      !user ||
      user.passwordHash !==
        hashPassword(
          password || ""
        )
    ) {
      return res.status(401).send(`
<!DOCTYPE html>
<html>
<body style="
background:#111;
color:#ff4444;
font-family:monospace;
padding:30px;
">

<h1>Login Failed</h1>

<p>Invalid username or password.</p>

<a
 href="javascript:history.back()"
 style="color:#00ff66"
>
Go Back
</a>

</body>
</html>
`);
    }

    const authorizationCode =
      generateAuthorizationCode();

    authorizationCodes.set(
      authorizationCode,
      {
        code:
          authorizationCode,

        clientId:
          client_id,

        userId:
          user.id,

        username:
          user.username,

        redirectUri:
          redirect_uri,

        scope:
          scope || "",

        codeChallenge:
          code_challenge,

        codeChallengeMethod:
          code_challenge_method,

        createdAt:
          Date.now(),

        expiresAt:
          Date.now() +
          5 * 60 * 1000
      }
    );

    const callback =
      new URL(
        redirect_uri,
        baseUrl(req)
      );

    callback.searchParams.set(
      "code",
      authorizationCode
    );

    if (state) {
      callback.searchParams.set(
        "state",
        state
      );
    }

    res.redirect(
      callback.toString()
    );
  }
);

// --------------------------------------------------
// OAuth token endpoint
//
// Supports authorization_code + PKCE
// and device_code.
// --------------------------------------------------

app.post(
  "/oauth2/token",
  (req, res) => {
    const {
      grant_type,
      code,
      redirect_uri,
      client_id,
      client_secret,
      code_verifier,
      device_code
    } = req.body;

    // ----------------------------------------------
    // Authorization code
    // ----------------------------------------------

    if (
      grant_type ===
        "authorization_code" ||
      code
    ) {
      if (!code) {
        return res.status(400).json({
          error:
            "code_required"
        });
      }

      const authorization =
        authorizationCodes.get(
          code
        );

      if (!authorization) {
        return res.status(400).json({
          error:
            "invalid_grant"
        });
      }

      if (
        Date.now() >
        authorization.expiresAt
      ) {
        authorizationCodes.delete(
          code
        );

        return res.status(400).json({
          error:
            "expired_authorization_code"
        });
      }

      if (
        client_id &&
        client_id !==
          authorization.clientId
      ) {
        return res.status(400).json({
          error:
            "invalid_client"
        });
      }

      if (
        redirect_uri &&
        redirect_uri !==
          authorization.redirectUri
      ) {
        return res.status(400).json({
          error:
            "redirect_uri_mismatch"
        });
      }

      if (
        !verifyPKCE(
          code_verifier,
          authorization.codeChallenge,
          authorization.codeChallengeMethod
        )
      ) {
        return res.status(400).json({
          error:
            "invalid_grant",

          message:
            "PKCE verification failed"
        });
      }

      // Authorization codes are one-time use.
      authorizationCodes.delete(
        code
      );

      const accessToken =
        jwt.sign(
          {
            sub:
              authorization.userId,

            username:
              authorization.username,

            client_id:
              authorization.clientId,

            scope:
              authorization.scope,

            jti:
              randomHex(32)
          },

          OAUTH_SECRET,

          {
            expiresIn:
              "1h"
          }
        );

      res.json({
        access_token:
          accessToken,

        token_type:
          "Bearer",

        expires_in:
          3600,

        scope:
          authorization.scope
      });

      return;
    }

    // ----------------------------------------------
    // Device code
    // ----------------------------------------------

    if (
      grant_type ===
        "urn:ietf:params:oauth:grant-type:device_code" ||
      device_code
    ) {
      if (!device_code) {
        return res.status(400).json({
          error:
            "device_code_required"
        });
      }

      if (client_id) {
        const apps =
          readJson(APPS_FILE);

        const oauthApp =
          apps.find(
            item =>
              item.client_id ===
                client_id &&
              (
                !client_secret ||
                item.client_secret ===
                  client_secret
              )
          );

        if (!oauthApp) {
          return res.status(401).json({
            error:
              "invalid_client"
          });
        }
      }

      const device =
        deviceCodes.get(
          device_code
        );

      if (!device) {
        return res.status(400).json({
          error:
            "invalid_device_code"
        });
      }

      if (
        Date.now() >
        device.expiresAt
      ) {
        deviceCodes.delete(
          device_code
        );

        return res.status(400).json({
          error:
            "expired_device_code"
        });
      }

      if (
        device.status ===
        "pending"
      ) {
        return res.status(428).json({
          error:
            "authorization_pending"
        });
      }

      if (
        device.status !==
        "approved"
      ) {
        return res.status(400).json({
          error:
            "invalid_device_state"
        });
      }

      const accessToken =
        jwt.sign(
          {
            sub:
              device.username,

            username:
              device.username,

            device_code:
              device.deviceCode,

            jti:
              randomHex(32)
          },

          OAUTH_SECRET,

          {
            expiresIn:
              "1h"
          }
        );

      deviceCodes.delete(
        device_code
      );

      res.json({
        access_token:
          accessToken,

        token_type:
          "Bearer",

        expires_in:
          3600
      });

      return;
    }

    return res.status(400).json({
      error:
        "unsupported_grant_type"
    });
  }
);

// --------------------------------------------------
// Logout
// --------------------------------------------------

app.post(
  "/api/auth/logout",
  authenticateJWT,
  (req, res) => {
    if (!req.user.jti) {
      return res.status(400).json({
        error:
          "token_missing_jti"
      });
    }

    revokeToken(
      req.user.jti,
      req.user.exp
    );

    res.json({
      status: "success",

      message:
        "Logged out successfully"
    });
  }
);

// --------------------------------------------------
// Userinfo
// --------------------------------------------------

app.get(
  [
    "/api/auth/me",
    "/api/whoami",
    "/oauth/userinfo"
  ],

  authenticateJWT,

  (req, res) => {
    res.json({
      authenticated: true,

      sub:
        req.user.sub,

      username:
        req.user.username,

      token_type:
        "Bearer",

      scope:
        req.user.scope || undefined
    });
  }
);

// --------------------------------------------------
// RAM
// --------------------------------------------------

app.get(
  "/api/get-ram",
  authenticateJWT,
  (req, res) => {
    res.json({
      ram_mb: 1024,

      username:
        req.user.username
    });
  }
);

// --------------------------------------------------
// OAuth status
// --------------------------------------------------

app.get(
  "/api/oauth/status",
  authenticateJWT,
  (req, res) => {
    res.json({
      authenticated: true,

      username:
        req.user.username,

      token_type:
        "Bearer",

      ram_mb: 1024
    });
  }
);

// --------------------------------------------------
// OAuth discovery
// --------------------------------------------------

function oauthMetadata(req) {
  const issuer =
    baseUrl(req);

  return {
    issuer,

    authorization_endpoint:
      `${issuer}/oauth/authorize`,

    token_endpoint:
      `${issuer}/oauth2/token`,

    userinfo_endpoint:
      `${issuer}/oauth/userinfo`,

    device_authorization_endpoint:
      `${issuer}/oauth/device/code`,

    registration_endpoint:
      `${issuer}/oauth/apps`,

    scopes_supported: [
      "openid",
      "profile",
      "email",
      "offline_access"
    ],

    response_types_supported: [
      "code"
    ],

    grant_types_supported: [
      "authorization_code",
      "urn:ietf:params:oauth:grant-type:device_code"
    ],

    token_endpoint_auth_methods_supported: [
      "none",
      "client_secret_post"
    ],

    code_challenge_methods_supported: [
      "S256"
    ],

    subject_types_supported: [
      "public"
    ],

    id_token_signing_alg_values_supported: [
      "HS256"
    ],

    claims_supported: [
      "sub",
      "username",
      "email"
    ]
  };
}

// --------------------------------------------------
// OAuth Authorization Server Metadata
// --------------------------------------------------

app.get(
  "/.well-known/oauth-authorization-server",
  (req, res) => {
    res.json(
      oauthMetadata(req)
    );
  }
);

// --------------------------------------------------
// OpenID Configuration
// --------------------------------------------------

app.get(
  "/.well-known/openid-configuration",
  (req, res) => {
    const metadata =
      oauthMetadata(req);

    res.json({
      ...metadata,

      jwks_uri:
        `${baseUrl(req)}/oauth/jwks`
    });
  }
);

// --------------------------------------------------
// OAuth metadata alias
// --------------------------------------------------

app.get(
  "/oauth/metadata",
  (req, res) => {
    res.json(
      oauthMetadata(req)
    );
  }
);

// --------------------------------------------------
// JWKS placeholder
// --------------------------------------------------

app.get(
  "/oauth/jwks",
  (req, res) => {
    res.json({
      keys: []
    });
  }
);

// --------------------------------------------------
// Health
// --------------------------------------------------

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      status: "ok",

      service:
        "oauth-device-server",

      version:
        "1.0.0",

      pkce:
        "S256"
    });
  }
);

// --------------------------------------------------
// HTML escaping
// --------------------------------------------------

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// --------------------------------------------------
// 404
// --------------------------------------------------

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "not_found"
    });
  }
);

// --------------------------------------------------
// Start
// --------------------------------------------------

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `OAuth server running on port ${PORT}`
    );

    console.log(
      `Device login: http://localhost:${PORT}/oauth/device`
    );

    console.log(
      `Create App: http://localhost:${PORT}/create`
    );

    console.log(
      `OAuth authorize: http://localhost:${PORT}/oauth/authorize`
    );

    console.log(
      `OAuth token: http://localhost:${PORT}/oauth2/token`
    );

    console.log(
      `OAuth discovery: http://localhost:${PORT}/.well-known/oauth-authorization-server`
    );

    console.log(
      `OpenID discovery: http://localhost:${PORT}/.well-known/openid-configuration`
    );
  }
);
