# PDNS Manager

A web-based manager for the [PowerDNS Authoritative Server](https://doc.powerdns.com/authoritative/http-api/) HTTP API.

> **Status: Work in progress.** This project is under active development and not
> ready for production use. Expect breaking changes, missing features, and bugs.

## Development

The only prerequisites are `go`, `make`, and `docker` (with the Compose plugin).

The dev environment is provided by a dedicated compose file
(`docker-compose.dev.yml`) that is **not** the default compose file — it is only
used through the `make dev-*` targets. It brings up:

- **PostgreSQL** — the application database (host port `5432`), with credentials
  that match the app's default DSN so the app connects with no configuration.
- **PowerDNS Authoritative Server** — its HTTP API on host port `8081` (using a
  PostgreSQL backend), which the app manages.
- **Mailpit** — a local mail catcher. Emails the app sends (verification, password
  reset) are captured and viewable in a web UI at `http://localhost:8025` instead
  of only being printed to the app log.

```bash
make dev-up      # start PostgreSQL + PowerDNS (waits for them to be healthy)
make dev-run     # run the app on the host against the dev infrastructure
make dev-logs    # tail infra logs
make dev-psql    # open a psql shell in the dev PostgreSQL (app database)
make dev-down    # stop the dev containers (keeps data)
make dev-clean   # stop the dev containers AND delete their data volumes
make help        # list all targets
```

Typical workflow:

```bash
make dev-up      # once: bring up PostgreSQL + PowerDNS
make dev-run     # run pdns-manager; web UI at http://localhost:8080
```

`make dev-run` points the app at the PowerDNS API
(`PDNS_API_URL=http://localhost:8081/api/v1`, `PDNS_API_KEY=dev-secret-key`,
matching `docker/dev/pdns.conf`) and at Mailpit (via the `--smtp-addr`,
`--smtp-user`, `--smtp-pass` and `--mail-from` flags, whose defaults match the
Mailpit service). On first run the app stores the PowerDNS settings in its
database, so later `go run . start` invocations reuse them automatically.
Verification/reset emails land in Mailpit's web UI at `http://localhost:8025`;
copy the verification token from the captured email and open
`http://localhost:8080/auth/confirm_mail?token=<token>` to confirm the account.

Run `make help` for the full list of targets, including `build`, `test`, `fmt`,
and CSS helpers.
