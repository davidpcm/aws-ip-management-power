# AWS IP Management — Kiro Power Setup Guide

A step-by-step guide for installing and using the AWS IP Management power in Kiro.

---

## Prerequisites

| Requirement | How to check | Install |
|-------------|-------------|---------|
| **Kiro IDE** | Open Kiro | [kiro.dev](https://kiro.dev) |
| **uv** (Python package runner) | `uv --version` | [Install guide](https://docs.astral.sh/uv/getting-started/installation/) |
| **AWS CLI** with SSO profiles | `aws --version` | [Install guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |

Your AWS profiles must be configured in `~/.aws/config` with SSO. Example:

```ini
[sso-session my-org]
sso_start_url = https://my-org.awsapps.com/start
sso_region = ap-southeast-1
sso_registration_scopes = sso:account:access

[profile my-prod]
sso_session = my-org
sso_account_id = 123456789012
sso_role_name = my-admin-role

[profile my-nonprod]
sso_session = my-org
sso_account_id = 987654321098
sso_role_name = my-admin-role
```

---

## Step 1: Install the Power

1. Open **Kiro**
2. Click the **Powers** icon in the sidebar (or search `Powers` in the command palette)
3. Click **Add Custom Power** at the top
4. Select **Git Repository**
5. Paste this URL:

```
https://github.com/davidpcm/aws-ip-management-power
```

6. Click **Add** — Kiro will download and install the power

---

## Step 2: Configure the Server Path

The power needs to know where `server.py` lives on your machine.

1. Find where Kiro installed the power:

| OS | Typical path |
|----|-------------|
| Windows | `C:\Users\<YourName>\.kiro\powers\aws-ip-management-power\` |
| macOS | `~/.kiro/powers/aws-ip-management-power/` |
| Linux | `~/.kiro/powers/aws-ip-management-power/` |

2. Open `mcp.json` inside that directory

3. Replace `PLACEHOLDER_SERVER_PATH` with the **full path** to the power directory:

**Before:**
```json
{
  "mcpServers": {
    "aws-ip-management": {
      "command": "uv",
      "args": ["run", "--with", "mcp[cli]", "--with", "boto3", "python", "PLACEHOLDER_SERVER_PATH/server.py"],
      "env": {
        "AWS_PROFILE": "sandbox4",
        "AWS_REGION": "ap-southeast-1"
      }
    }
  }
}
```

**After (Windows example):**
```json
{
  "mcpServers": {
    "aws-ip-management": {
      "command": "uv",
      "args": ["run", "--with", "mcp[cli]", "--with", "boto3", "python", "C:/Users/JohnDoe/.kiro/powers/aws-ip-management-power/server.py"],
      "env": {
        "AWS_PROFILE": "my-prod",
        "AWS_REGION": "ap-southeast-1"
      }
    }
  }
}
```

4. Update `AWS_PROFILE` to your default profile name
5. Update `AWS_REGION` if your region differs from `ap-southeast-1`
6. Save the file — Kiro will auto-reconnect the MCP server

---

## Step 3: Login to AWS SSO

Before scanning, ensure your SSO session is active:

```bash
aws sso login --profile my-prod
```

> **Tip:** All profiles under the same `sso_session` share one login. You only need to login once.

---

## Step 4: Register Your Accounts

The power auto-discovers all profiles from `~/.aws/config`, but you should register the specific accounts you want to scan regularly.

In Kiro chat, first check what's available:

```
List all my AWS accounts
```

Then register the ones you want:

```
Add account my-prod with name Production-SG and env PROD
```

```
Add account my-nonprod with name NonProd-SG and env NONPROD
```

```
Add account my-sandbox with name Sandbox and env SANDBOX
```

Registered accounts are saved locally in `accounts-registry.json` — they persist across restarts.

To remove an account:

```
Remove account my-old-profile
```

---

## Step 5: Start Using

### Available Tools

| Tool | Description |
|------|-------------|
| `list_accounts` | List all registered and auto-discovered profiles |
| `add_account` | Register a profile with friendly name and env tag |
| `remove_account` | Remove a profile from the registry |
| `scan_accounts` | Scan VPCs, subnets, EIPs, ENIs across accounts |
| `lookup_ip` | Find which resource owns a specific IP |
| `get_unused_eips` | Find unused EIPs (cost waste) |
| `get_account_ip_map` | Detailed IP-to-resource map for one account |
| `get_cidr_plan` | Show the CIDR allocation plan |

### Example Prompts

| What you want | What to ask Kiro |
|---------------|-----------------|
| Scan all registered accounts | "Scan my AWS accounts for IP resources" |
| Scan specific accounts | "Scan accounts my-prod and my-nonprod" |
| Look up a private IP | "What resource is using IP 10.69.4.10?" |
| Look up a public IP | "Who owns public IP 52.221.160.22?" |
| Find cost waste | "Show me unused Elastic IPs across all accounts" |
| Map one account's IPs | "Show me the IP map for my-prod" |
| View CIDR plan | "What's the CIDR allocation plan?" |
| Check account list | "List all my AWS accounts" |

---

## Customizing the CIDR Plan

The CIDR plan is defined in `server.py` at the bottom. Edit the `CIDR_PLAN` dictionary to match your organization's IP allocation:

```python
CIDR_PLAN = {
    "supernets": {
        "10.69.0.0/16": "PROD-SG",
        "10.99.0.0/16": "NONPROD-SG",
    },
    "central_vpcs": {
        "Inspection VPC": "10.69.2.0/24",
        "Central Egress VPC": "10.69.3.0/24",
    },
    "account_allocations": [
        {"account": "My-Prod", "env": "PROD", "cidrs": ["10.69.12.0/22"]},
        {"account": "My-NonProd", "env": "NONPROD", "cidrs": ["10.99.12.0/22"]},
    ],
}
```

---

## Troubleshooting

### "Token has expired and refresh failed"

Your AWS SSO session expired. Run:

```bash
aws sso login --profile my-prod
```

### "Profile 'xyz' not found in ~/.aws/config"

The profile name doesn't exist in your AWS CLI config. Add it to `~/.aws/config` first, then register it with `add_account`.

### "AccessDeniedException"

Your IAM role lacks the required permissions. The role needs:

- `ec2:DescribeVpcs`
- `ec2:DescribeSubnets`
- `ec2:DescribeAddresses`
- `ec2:DescribeNetworkInterfaces`
- `sts:GetCallerIdentity`

### MCP server not starting

1. Check `uv` is installed: `uv --version`
2. Verify `PLACEHOLDER_SERVER_PATH` was replaced in `mcp.json`
3. Check the path uses forward slashes (`/`) even on Windows
4. Try running manually to see errors:
   ```bash
   uv run --with "mcp[cli]" --with boto3 python /path/to/server.py
   ```

### No tools showing in Kiro

1. Open the MCP Servers view in Kiro's sidebar
2. Check if `aws-ip-management` shows as connected
3. If disconnected, click reconnect
4. If still failing, check `mcp.json` syntax (valid JSON?)

### Scan returns errors for some accounts

This is normal — accounts you don't have SSO access to will show errors. Only accounts where your SSO session is active and your role has EC2 describe permissions will scan successfully.

---

## IAM Permissions (Minimum Required)

If your team needs a custom IAM policy for scanning, here's the minimum:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeAddresses",
                "ec2:DescribeNetworkInterfaces",
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## Repository

**GitHub:** https://github.com/davidpcm/aws-ip-management-power

For issues or feature requests, open a GitHub issue.
