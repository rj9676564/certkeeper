# certkeeper

Self-hosted ACME certificate manager for Alibaba Cloud DNS. It reads domains
from a single `config.yaml`, obtains and renews certificates over DNS-01 using
per-domain AccessKeys, writes certificate files atomically, runs optional
reload commands, and calls webhooks on renewal or failure.

- Go binary, no runtime dependencies
- Let's Encrypt (including staging)
- Wildcard certificates
- Different Alibaba Cloud AccessKeys per domain
- Automatic renewal with a built-in daemon
- Webhook notifications and optional `curl` failure hook
- Multi-arch Docker image built by GitHub Actions

## Security

`config.yaml` contains AccessKeys. Keep it out of git, use mode `0600`, and
never bake it into an image.

```bash
chmod 600 config.yaml
```

Use a dedicated RAM user with DNS permissions only. The minimum recommended
policy is `AliyunDNSFullAccess`.

The container can execute `reload` commands. Mounting
`/var/run/docker.sock` gives it root-equivalent access to the host. Only enable
it when you need commands such as `docker restart <name>`.

## Quick start

Deployment uses exactly two files: `compose.yaml` and `config.yaml`.

```bash
mkdir -p certkeeper && cd certkeeper
chmod 600 config.yaml
docker compose up -d
docker compose logs -f
```

`compose.yaml`:

```yaml
services:
  certkeeper:
    image: ghcr.io/rj9676564/certkeeper:latest
    container_name: certkeeper
    restart: unless-stopped
    command: ["daemon", "--config", "/config/config.yaml"]
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      - ./data:/data
      - ./certs:/certs
      - /var/run/docker.sock:/var/run/docker.sock
```

Remove the `docker.sock` mount if you do not use `docker restart` reload hooks.

## Configuration

```yaml
version: 1
email: admin@example.com
renew_before_days: 30

storage:
  dir: /certs
  state_dir: /data
  cert_mode: "0644"
  key_mode: "0600"
  backup: true

acme:
  directory: https://acme-v02.api.letsencrypt.org/directory
  staging_directory: https://acme-staging-v02.api.letsencrypt.org/directory

dns_providers:
  ali_main:
    type: alidns
    access_key: "LTAI..."
    secret_key: "..."
  ali_secondary:
    type: alidns
    access_key: "LTAI..."
    secret_key: "..."

domains:
  - name: fenfa.mrlb.top
    dns: ali_main
    key_type: ec256
    reload:
      - docker restart fenfa

  - name: "*.hait.wang"
    alt_names:
      - hait.wang
    dns: ali_secondary
    reload:
      - nginx -s reload

notify:
  timeout: 10s
  retries: 3
  webhooks:
    - name: feishu
      url: https://open.feishu.cn/open-apis/bot/v2/hook/xxxx
      method: POST
      headers:
        Content-Type: application/json
      events: [failure, renewed]
      body: |
        {"msg_type":"text","content":{"text":"certkeeper {{.Status}} {{.Domain}} {{.Error}}"}}

  failure_command: |
    curl -s -X POST "https://example.com/hook" \
      -H "Content-Type: application/json" \
      -d "{\"text\":\"certkeeper failed: $CERTKEEPER_DOMAIN $CERTKEEPER_ERROR\"}"
```

### Fields

| Field | Description |
|---|---|
| `email` | ACME account email |
| `renew_before_days` | Renew when the certificate has this many days left (default `30`) |
| `storage.dir` | Certificate output directory |
| `storage.state_dir` | ACME account and lock files |
| `domains[].dns` | Name of a `dns_providers` entry |
| `domains[].alt_names` | Additional SANs |
| `domains[].cert_file` / `key_file` | Optional output filenames, relative to `storage.dir` |
| `domains[].reload` | Commands to run after a successful write |
| `notify.webhooks[].events` | `failure`, `renewed`, or `skipped` |
| `notify.failure_command` | Shell command run on failure |

### Per-domain AccessKeys

Each domain references a credential set:

```yaml
dns_providers:
  ali_main:
    type: alidns
    access_key: "..."
    secret_key: "..."
  ali_secondary:
    type: alidns
    access_key_env: ALIYUN_SECONDARY_AK
    secret_key_file: /run/secrets/aliyun_secondary_sk

domains:
  - name: a.example.com
    dns: ali_main
  - name: b.example.com
    dns: ali_secondary
```

Credentials can come from `access_key` / `secret_key`, from
`access_key_env` / `secret_key_env`, or from `access_key_file` /
`secret_key_file`. Direct values take precedence. `security_token` variants are
supported for STS.

### Notifications

Webhooks receive a JSON body by default. Custom bodies use Go templates with
these fields: `.Status`, `.Domain`, `.Error`, `.ExpiresAt`, `.DaysLeft`,
`.DNSProvider`, `.Hostname`, `.Time`, `.RunID`.

`failure_command` receives:

- `CERTKEEPER_STATUS`
- `CERTKEEPER_DOMAIN`
- `CERTKEEPER_ERROR`
- `CERTKEEPER_EXPIRES_AT`
- `CERTKEEPER_DAYS_LEFT`
- `CERTKEEPER_DNS_PROVIDER`
- `CERTKEEPER_RUN_ID`
- `CERTKEEPER_TIME`

## CLI

```bash
certkeeper run --config /config/config.yaml
certkeeper run --staging              # Let's Encrypt staging
certkeeper run --dry-run              # no issuance, no writes
certkeeper run --force                # renew even when still valid
certkeeper run --domain example.com
certkeeper check --config /config/config.yaml --json
certkeeper daemon --config /config/config.yaml --interval 12h --jitter 0.1
certkeeper version
```

Exit codes: `0` success, `1` one or more domains failed or need attention, `2`
configuration or usage error.

## Development

```bash
go test ./...
go vet ./...
go build -o certkeeper ./cmd/certkeeper
```

Build the Docker image:

```bash
docker build -t certkeeper .
```

## Releases

Push a tag such as `v0.1.0`. GitHub Actions runs tests, creates cross-platform
binaries and checksums with GoReleaser, and publishes
`ghcr.io/rj9676564/certkeeper:latest` plus the version tag for
`linux/amd64` and `linux/arm64`.

## License

MIT
