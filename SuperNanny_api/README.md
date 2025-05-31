# SuperNanny API

The **SuperNanny API** serves as a secure interface for managing users, roles, default policies, permission sets, and sandbox logs in a Linux environment. It is designed to enforce a permission-based model, backed by cookie-secured authentication and CSRF protection. **SuperNanny API** is intended to be used in coordination with a Yew-based frontend and a TLS-enabled reverse proxy (NGINX) for secure communication. It uses Rust (Actix-Web, PostgreSQL, JWT) and ensures secure, isolated control over system-level permissions. All communication is encrypted over HTTPS.

---

## Overview

* **Language & Framework**: Rust (Actix-Web)
* **Authentication**: Cookie-based with CSRF protection
* **Authorization**: JWT + Role/Permission system
* **Endpoints**: RESTful
* **Security**: HTTPS via self-signed TLS (TLS 1.3)

---

## Core Features

### Authentication

* `POST /admin/login`:

  * Receives `username` and `password`.
  * If valid, sets two cookies:

    * `admin_token`: Secure, HttpOnly JWT.
    * `csrf_token`: Readable by the frontend, used for CSRF protection.
* `POST /admin/logout`: Clears both cookies.

### Admin Access Control (JWT Permissions)

Upon successful login, a signed JWT is issued and stored in an `HttpOnly` cookie. It contains a list of 4 permission strings defining allowed sections of the admin interface:

* `view_users`
* `view_roles`
* `view_policies`
* `view_dashboard`

These permissions are checked on every protected route via backend middleware. If the required permission is not in the decoded JWT, the request is rejected with `403 Forbidden`. On the frontend, these same permissions are used to filter UI access.

JWTs are:

* **Signed** using HS256 (secret key from `.env`)
* **Time-limited** (60-minute expiration, configurable)
* **Blacklisted** in memory on logout or revocation (to prevent reuse)

### Session Management

* `GET /admin/me`: Returns current session info (username + permissions).
* Used by the frontend SessionProvider to initialize context at startup.

### Users

* `GET /users` – List all users.
* `POST /users/create_with_role` – Create a user and assign role.
* `DELETE /users/:id` – Delete a user.

### Rules

These endpoints manage **runtime enforcement rules** used by the sandbox to restrict system-level operations (like file access, networking, etc.).

* `GET /rules` – List all active rules enforced on the system.
* `GET /rules/:id` – Inspect a specific rule.
* `POST /rules` – Create a new rule for a target application or context.
* `PUT /rules/:id` – Modify an existing rule.
* `DELETE /rules/:id` – Remove a rule from the system.

Each rule is bound to a subject (app or binary), and defines what actions are allowed or denied at runtime. These rules are automatically updated in the backend and may be reflected in the live monitoring dashboards.

> Note: These are **system-level policies** enforced through the sandboxing layer and are independent from admin authentication or interface permissions.

### Roles & Permissions

* `GET /roles` – List all roles.
* `POST /roles/create_with_default` – Create a role with default policies.
* `DELETE /roles/{role_id}` – Delete a role.
* `GET /roles/{role_id}/permissions` – List permissions associated to a role.
* `POST /roles/{role_id}/permissions` – Assign a permission to a role.
* `DELETE /roles/{role_id}/permissions/{perm_id}` – Remove a permission.
* `GET /roles/default_policies/{role_id}` – Get default policies.
* `PUT /roles/default_policies/{role_id}` – Update default policies.

> Note: These permissions are specific to the app sandbox and do not affect API access.

### Dashboard / Logs

This part is managed by the nginx reverse proxy.

---

## Security Guards

SuperNanny API includes several runtime protections to mitigate abuse and unauthorized access:

* **Rate Limiting**: Max 100 requests per minute per IP. Exceeding results in `HTTP 429 Too Many Requests`.
* **Brute-Force Protection**: Login attempts are tracked per IP. If more than 5 failures occur within 10 minutes, the IP is temporarily blocked.
* **JWT Expiration**: Tokens expire after 60 minutes. Users must reauthenticate to regain access.
* **Wrapper Guards**: Middleware components (like `Needs(permission)`) wrap sensitive endpoints to enforce consistent checks.

### Security & CSRF Flow

1. **Login Phase**: Cookies `admin_token` (JWT) and `csrf_token` are set.
2. **Session Initialization**: Frontend fetches `/admin/me`.
3. **State-Changing Requests**:

   * Must include `X-CSRF-Token` header (value from cookie).
   * Backend validates token against the `csrf_token` cookie.
4. **All API calls require HTTPS**.

---

## API Folder Structure

```
api/
├── main.rs                 # Actix-Web entrypoint
├── auth.rs                 # Login, session, logout
├── users.rs                # Users endpoints
├── roles.rs                # Role & permission logic
├── models.rs               # Shared structs (users, roles, policies)
├── policies.rs             # Default policy & app policy routes
├── logs.rs                 # Sandbox event logs
├── middleware.rs           # JWT guard middleware
├── csrf.rs                 # CSRF token generation & validation
├── utils.rs                # General helpers
└── config.rs               # TLS setup & app config
```

---

## Tech Stack

* **Rust**: Memory-safe backend with strong type guarantees
* **Actix-Web**: Fast and modular web server
* **serde / serde\_json**: Serialization and deserialization of request/response payloads
* **jsonwebtoken**: Secure JWT-based session tokens
* **rustls**: TLS 1.3 implementation for self-signed HTTPS

---

## Deployment

* Build in release mode:

  ```bash
  cargo build --release
  ```
* Serve on HTTPS port (default `9443`)
* TLS certs must be present in `certs/` folder (`dev-cert.pem`, `dev-key.pem`)

---

## External Access

* This API is not public.
* Only accessible from the Yew frontend or local admin tools.

---

## Contact

For internal questions or security audits, contact the SuperNanny team.

---

**Note**: This API is part of a broader secure system for managing Linux app permissions and monitoring sandbox activity in real-time.
