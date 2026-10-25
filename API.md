# TrustVault API and Permissions

TrustVault currently exposes server-rendered HTML routes with JSON error responses for many protected failures. All state-changing requests require a valid CSRF token unless the route is rejected earlier by authentication middleware.

## Authentication and sessions

| Method | Path | Access | Behavior |
|---|---|---|---|
| GET | `/auth/register` | Public | Registration form with CSRF token |
| POST | `/auth/register` | Public + CSRF | Creates a bcrypt-hashed account with role `viewer` |
| GET | `/auth/login` | Public | Login form with CSRF token |
| POST | `/auth/login` | Public + CSRF + rate limit | Authenticates an active account and regenerates the session |
| POST | `/auth/logout` | Authenticated + CSRF | Destroys the session and redirects to login |

Registration does not accept a client-selected role. There is no public admin-registration or role-change endpoint.

## Documents

| Method | Path | Access | Behavior |
|---|---|---|---|
| GET | `/documents` | Authenticated active account | Lists the caller's owned/shared documents and applies search/filter parameters |
| GET | `/documents/upload` | Authenticated active account | Upload form |
| POST | `/documents/upload` | Authenticated active account + CSRF + rate limit | Private upload, or atomic upload-and-share to an existing active user |
| GET | `/documents/shared` | Authenticated active account | Lists active documents shared with the caller |
| GET | `/documents/:id/download` | Owner or active grantee | Streams the file as an attachment |
| GET | `/documents/:id/preview` | Owner or active grantee | Inline preview for PDF, PNG, and JPEG only |
| GET | `/documents/:id/edit` | Owner or active `edit` grantee | Metadata edit form |
| POST | `/documents/:id/edit` | Owner or active `edit` grantee + CSRF | Updates title, description, and category |
| POST | `/documents/:id/delete` | Owner + CSRF | Persists pending deletion, revokes grants, removes the file, and records the outcome |

Upload form fields include `title`, `description`, `category`, `share_email`, `share_permission`, `_csrf`, and the multipart `file` field. The optional recipient must already be an active registered user. Valid share permissions are `read` and `edit`.

Document listing supports the query parameters `q`, `mime`, `category`, `from`, `to`, `minSize`, `maxSize`, and `page`. Values are validated and bound as SQL parameters.

## Permissions

| Method | Path | Access | Behavior |
|---|---|---|---|
| GET | `/documents/:id/permissions` | Document owner | Displays active and revoked grants |
| POST | `/documents/:id/permissions/grant` | Document owner + CSRF | Grants or replaces a recipient's active `read` or `edit` level |
| POST | `/documents/:id/permissions/:permId/revoke` | Document owner + CSRF | Revokes the selected active grant immediately |

The server resolves recipients by normalized email and never trusts a client-supplied user ID for a grantee. Every download, preview, list, and shared-document query requires `revoked_at IS NULL` for a grant. Revocation therefore applies to the next request; it cannot erase copies already downloaded.

## Administration

All `/admin/*` routes are mounted behind `requireAuth`, `requireActiveAccount(db)`, and `requireRole('admin', db)`. The role is re-read from the database for the current session user.

| Method | Path | Access | Behavior |
|---|---|---|---|
| GET | `/admin/audit` | Active database-backed admin | Paginated and filtered audit dashboard |
| GET | `/admin/users` | Active database-backed admin | Lists user roles and account status |
| POST | `/admin/users/:id/deactivate` | Admin + CSRF | Deactivates another account; an admin cannot deactivate themselves |
| POST | `/admin/users/:id/activate` | Admin + CSRF | Re-activates an account |
| GET | `/admin/categories` | Active database-backed admin | Lists categories and active document counts |
| POST | `/admin/categories/:id/delete` | Admin + CSRF | Deletes a category and clears document category assignments through the foreign key |

There is no role-promotion route. Administrator bootstrap is an operator-run local database procedure documented in `README.md`; it must not be exposed as a public request.

## Audit behavior

Successful and relevant denied/error outcomes are recorded in `audit_events`. The audit dashboard displays actor, action, resource, outcome, detail, and timestamp. The application does not expose audit-row update/delete routes or document download links from the audit page.

Unauthenticated requests rejected by `requireAuth` are handled before protected route handlers and are not currently recorded as route-level audit events. Page views such as `GET /admin/audit` are also not treated as audit events.

## Security response expectations

- Unauthenticated browser requests to protected routes generally redirect to `/auth/login`.
- Authenticated non-admin requests to `/admin/*` return HTTP 403 JSON.
- Invalid or missing CSRF tokens return HTTP 403.
- Unknown or unauthorized document access returns HTTP 403.
- Unsupported upload types return HTTP 400; oversized uploads return HTTP 413.
- Successful admin audit access returns HTTP 200 HTML containing the `Audit Log` page.
