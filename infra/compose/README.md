# Local development stack

This folder holds the Docker Compose files for running the factory's dependencies on your own machine. Today that is PostgreSQL and nothing else. Later work packages add services here when they need them.

It is a development setup. It is not the production deployment.

## Start and stop

From the repository root:

```bash
scripts/dev-up.sh                  # first run: creates .env with a random password, starts PostgreSQL, waits until healthy
scripts/dev-up.sh --status         # what is running
scripts/dev-up.sh --down           # stop and remove the containers, keep the data
scripts/dev-up.sh --destroy --yes  # also delete the data volume
```

The script needs Docker with Compose 2.24 or newer. If Docker is missing or not running, it exits with code 3 and says why. It does not pretend to have started anything.

You can also run Compose yourself once `.env` exists:

```bash
docker compose -f infra/compose/docker-compose.yml up -d --wait
```

## Files

| File | What it does |
|---|---|
| `docker-compose.yml` | Names the project (`factory-dev`) and includes each service file. |
| `postgres.yml` | The PostgreSQL service: pinned image, health check, named volume, hardening. |
| `../../.env.example` | The settings Compose reads, with no secret in it. Copy to `.env`, or let `scripts/dev-up.sh` do it. |

## Security choices

- **Loopback only.** The database port is published as `127.0.0.1:PORT`. Other computers on your network cannot connect. Checked by connecting to this machine's network address, which was refused.
- **No credential in a Compose file.** The password comes from `.env`, which Git ignores. `.env.example` leaves it empty on purpose, so a copied file fails to start instead of starting with a known password.
- **Pinned image.** The image is referenced by digest, so a rebuilt tag cannot change what runs.
- **Hardened container.** Read-only root file system, all capabilities dropped except the four the image needs to start, `no-new-privileges`, and limits on memory and processes.
- **Named volume.** The data outlives `docker compose down`. Only `--destroy` or `docker compose down --volumes` deletes it.

## Troubleshooting

| What you see | Why | What to do |
|---|---|---|
| `no such file or directory ... .env` | Compose needs the root `.env`. | Run `scripts/dev-up.sh`, or `cp .env.example .env` and set `POSTGRES_PASSWORD`. |
| `required variable POSTGRES_PASSWORD is missing a value` | `.env` exists but the password is empty. | Run `scripts/dev-up.sh`. It fills an empty password. |
| `port is already allocated` or `address already in use` | Another program uses the port. | Set `POSTGRES_HOST_PORT` in `.env` to a free port, then run `scripts/dev-up.sh` again. |
| The script exits with code 3 and says `BLOCKED` | Docker is missing, too old, or not running. | Start Docker Desktop, or install Docker Compose 2.24 or newer. |
| The container is `unhealthy` | PostgreSQL did not finish starting. | `docker compose -f infra/compose/docker-compose.yml logs postgres`. |
| You changed the password in `.env` and login still uses the old one | PostgreSQL stores the password inside the data volume when it first creates the database. | Either change the password with `ALTER USER`, or run `scripts/dev-up.sh --destroy --yes` to start from an empty database. |

## Changing the PostgreSQL version

ADR 0007 leaves the major version (17 or 18) to the DBA. To change it, edit the `image:` line in `postgres.yml` and the volume path (PostgreSQL 18 images keep data under `/var/lib/postgresql`). Review the change like any other dependency update, because `infra/**` is a sensitive path in `policies/security.yaml`.
