---
name: "aws-ip-management"
displayName: "AWS IP Management"
description: "Multi-account AWS IP address management. Scan VPCs, subnets, EIPs, and ENIs across accounts, track IP lifecycle, and generate interactive dashboards."
keywords: ["ip", "vpc", "subnet", "cidr", "network", "aws", "eip", "eni", "ipam"]
author: "davidpcm"
---

# AWS IP Management

## Overview

AWS IP Management provides multi-account IP address scanning, tracking, and visualization. It scans VPCs, subnets, Elastic IPs, and Elastic Network Interfaces across your AWS accounts, maps every IP to its owning resource (EC2, ELB, RDS, Lambda, ECS, NAT Gateway, etc.), and supports persistent IP lifecycle tracking.

Profiles are **auto-discovered** from `~/.aws/config` — no hardcoding needed. You can also register specific accounts with friendly names and environment tags using the `add_account` tool.

Key capabilities:
- Auto-discover AWS profiles from `~/.aws/config`
- Scan IP resources across multiple AWS accounts in parallel
- Map every private and public IP to its AWS resource
- Track IP first seen, last seen, status changes, and resource reassignments
- Identify unused Elastic IPs (cost waste)
- Manage account registry dynamically (add/remove accounts)

## Onboarding

### Prerequisites
- Python 3.10+ (via `uv`)
- AWS CLI configured with SSO profiles in `~/.aws/config`
- Active SSO session for target profiles

### Quick Start

1. Install the power in Kiro
2. Replace `PLACEHOLDER_SERVER_PATH` in `mcp.json` with the path to this directory
3. Register your accounts: ask Kiro "Add account sandbox4 with name Sandbox and env SANDBOX"
4. Start scanning: ask Kiro "Scan my AWS accounts for IP resources"

### Configuration

The MCP server auto-discovers all profiles from `~/.aws/config`. By default, scanning uses only **registered** accounts (added via `add_account`). If no accounts are registered, it falls back to all discovered profiles.

## Available Tools

### Account Management

#### list_accounts
List all registered and auto-discovered AWS profiles.

#### add_account
Register an AWS profile for scanning with a friendly name and environment tag.
- `profile` (required): AWS CLI profile name from `~/.aws/config`
- `name` (optional): Friendly display name
- `env` (optional): Environment tag (PROD, NONPROD, SANDBOX, CORE)
- `account_id` (optional): AWS account ID (auto-detected on first scan)

#### remove_account
Remove a profile from the scanning registry.
- `profile` (required): Profile name to remove

### IP Scanning

#### scan_accounts
Scan VPCs, subnets, EIPs, and ENIs across accounts.
- `profiles` (optional): Comma-separated profile names. Empty = all registered.
- `region` (optional): AWS region. Default: ap-southeast-1.

#### lookup_ip
Find which resource owns a specific IP address.
- `ip` (required): IP address to look up.
- `profiles` (optional): Profiles to search.

#### get_unused_eips
Find unused Elastic IPs (cost waste ~$3.60/month each).
- `profiles` (optional): Profiles to search.

#### get_account_ip_map
Detailed IP-to-resource map for a single account.
- `profile` (required): Profile name.

#### get_cidr_plan
Show the CIDR allocation plan (customizable in server.py).

## Common Workflows

### First Time Setup
1. "List all my AWS accounts" → `list_accounts`
2. "Add account my-prod with name Production and env PROD" → `add_account`
3. "Scan my accounts" → `scan_accounts`

### Quick IP Lookup
"What resource is using IP 10.69.4.10?" → `lookup_ip`

### Find Cost Waste
"Show me unused Elastic IPs" → `get_unused_eips`

## Troubleshooting

### SSO Token Expired
**Error:** "Token has expired and refresh failed"
**Solution:** Run `aws sso login --profile <your-profile>` in your terminal.

### Profile Not Found
**Error:** "Profile 'xyz' not found in ~/.aws/config"
**Solution:** Add the profile to your AWS CLI config first, then register it with `add_account`.

### Access Denied
**Error:** "AccessDeniedException"
**Solution:** Ensure the IAM role has `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeAddresses`, `ec2:DescribeNetworkInterfaces`.

## MCP Config Placeholders

- **`PLACEHOLDER_SERVER_PATH`**: Absolute path to the directory containing `server.py`.
  - Example: `C:/Users/YourName/aws-ip-management-power`

- **`AWS_PROFILE`**: Default AWS profile. Change to your preferred profile.
- **`AWS_REGION`**: Default region. Change if needed.

---

**MCP Server:** aws-ip-management
**Runtime:** Python (via uv + fastmcp)
