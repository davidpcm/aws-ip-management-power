# AWS IP Management — Kiro Power

Multi-account AWS IP address management MCP server for Kiro. Scan VPCs, subnets, EIPs, and ENIs across your AWS accounts, look up any IP to find its resource, and identify cost waste.

**No hardcoded profiles** — auto-discovers from `~/.aws/config` and lets you register accounts dynamically.

## Tools

| Tool | Description |
|------|-------------|
| `list_accounts` | List all registered and auto-discovered AWS profiles |
| `add_account` | Register an AWS profile with friendly name and env tag |
| `remove_account` | Remove a profile from the registry |
| `scan_accounts` | Scan VPCs/subnets/EIPs/ENIs across accounts |
| `lookup_ip` | Find which resource owns a specific IP |
| `get_unused_eips` | Find unused EIPs (cost waste ~$3.60/mo each) |
| `get_account_ip_map` | Detailed IP-to-resource map for one account |
| `get_cidr_plan` | Show the CIDR allocation plan |

## Install in Kiro

1. Open Kiro → Powers panel → **Add Custom Power**
2. Select **Git Repository**
3. Paste: `https://github.com/davidpcm/certis-ip-management-power`
4. Edit `mcp.json` — replace `PLACEHOLDER_SERVER_PATH` with the local path to this repo
5. Update `AWS_PROFILE` and `AWS_REGION` to match your environment

## Prerequisites

- `uv` installed (Python package runner)
- AWS CLI with SSO profiles configured in `~/.aws/config`
- Active SSO session for your target profiles

## Quick Start

After installing, ask Kiro:
1. "List all my AWS accounts" — see what profiles are available
2. "Add account my-prod with name Production and env PROD" — register accounts to scan
3. "Scan my accounts for IP resources" — run the scan
4. "What resource is using IP 10.0.1.5?" — look up any IP
5. "Show me unused Elastic IPs" — find cost waste
