---
description: "Ansible roles, playbooks, and infrastructure conventions for Dyatel"
applyTo: "ansible/**"
---

# Ansible Instructions (`ansible/`)

- `ansible/roles/dyatel_gateway` is frozen at v1.0.1 semantics — do not modify
  it unless explicitly requested.
- Ansible manages host skeleton only (packages, systemd units, drop-ins, env
  files); runtime peers, UFW rules, NAT chains, and transports belong in Go
  `internal/reconcile`, never in Jinja templates.
- Symmetric lifecycle: every `install` task/playbook must preserve its paired
  `uninstall` / `state=absent` teardown path.
- Use drop-in files (`.d/`) instead of editing monolithic OS configs directly,
  `community.general.ufw` instead of raw iptables scripts, and `systemd` units
  instead of `cron`.
- Never commit real server IPs, domains, or secrets: use `CHANGE_ME_*`
  placeholders in defaults and `ansible/inventory.example.*`.
- Validate with `ansible-lint` under the `production` profile (`.ansible-lint`).
