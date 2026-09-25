# signaldesk-web

**Not for production use.**

Flask browser front end for SignalDesk. It holds no data of its own: every login,
diagnostic, and export request is forwarded to the SignalDesk control API with the
web BFF service credential, and responses are validated against strict field sets
and size limits before rendering.

- `/login` and `/logout` authenticate against the control API and keep only
  `user_id`, `organization_id`, `role`, and a CSRF token in a signed, HTTP-only
  `signaldesk_session` cookie. Sessions are signed with the current key; configured
  fallback keys are accepted for verification only.
- `/diagnostics` and `/exports` create tenant-scoped jobs, `/diagnostics/<id>` and
  `/exports/<id>` show one, and `/exports/<id>/download` shows the download
  details for a completed export.
- Every state-changing form requires a CSRF token, and authenticated pages are
  served with `Cache-Control: no-store`.
- `/healthz` returns `{"status": "ok"}`.

Configuration is read only from `SIGNALDESK_WEB_*` environment variables
(`ENVIRONMENT`, `CONTROL_API_BASE_URL`, `BFF_SERVICE_CREDENTIAL`,
`FLASK_SECRET_KEY`, `FLASK_SECRET_KEY_FALLBACKS`, plus optional session and
timeout limits). Invalid configuration fails closed without echoing secrets. Run
it through `signaldesk-deploy` for the full local stack.

## License

MIT. See [LICENSE](LICENSE).
