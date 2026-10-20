# Security

`config.yaml` contains Alibaba Cloud AccessKeys and must never be committed.
Keep it at mode `0600` and add it to `.gitignore`.

Use a dedicated RAM user with DNS permissions only. The minimum recommended
policy is `AliyunDNSFullAccess`; restrict it further to the zones you manage
if your account supports fine-grained policies.

The Docker image can run `reload` commands. Mounting
`/var/run/docker.sock` gives the container root-equivalent access to the host.
Only enable it when you need commands such as `docker restart <name>`.

Report security issues privately to the repository owner instead of opening a
public issue.
