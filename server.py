"""
AWS IP Management MCP Server
=============================
FastMCP server that exposes IP management tools for multi-account AWS scanning,
IP lookup, tracking, and dashboard generation.

Profiles are auto-discovered from ~/.aws/config or managed via a local registry file.
"""

import json
import os
import sys
import re
import ipaddress
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from fastmcp import FastMCP

mcp = FastMCP("aws-ip-management")

# ─── Profile Registry ─────────────────────────────────────────────────────────
# Profiles can come from:
# 1. A local registry file (accounts-registry.json) — managed via add_account/remove_account tools
# 2. Auto-discovered from ~/.aws/config
# The registry file takes precedence for metadata (friendly name, env tag).

REGISTRY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts-registry.json")


def _load_registry():
    """Load the accounts registry from disk."""
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_registry(registry):
    """Save the accounts registry to disk."""
    with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)


def _discover_aws_profiles():
    """Auto-discover AWS profiles from ~/.aws/config."""
    config_path = Path.home() / ".aws" / "config"
    profiles = {}
    if not config_path.exists():
        return profiles
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()
    for match in re.finditer(r'\[profile\s+(.+?)\]', content):
        profile_name = match.group(1).strip()
        profiles[profile_name] = {
            "name": profile_name,
            "account_id": "",
            "env": "",
            "source": "aws-config",
        }
    return profiles


def _get_all_profiles():
    """Get merged profile list: registry overrides auto-discovered."""
    discovered = _discover_aws_profiles()
    registry = _load_registry()
    # Registry entries override discovered ones
    merged = {}
    for k, v in discovered.items():
        merged[k] = v
    for k, v in registry.items():
        merged[k] = v
        merged[k]["source"] = "registry"
    return merged


def _parse_profiles(profiles_str):
    """Parse a comma-separated profile string, or return all registered profiles."""
    if not profiles_str:
        all_profiles = _get_all_profiles()
        # If registry has entries, use only those (user curated list)
        registry = _load_registry()
        if registry:
            return list(registry.keys())
        # Otherwise fall back to all discovered profiles
        return list(all_profiles.keys())
    return [p.strip() for p in profiles_str.split(",")]


# ─── Helper Functions ─────────────────────────────────────────────────────────

def _get_tag(tags, key):
    for tag in tags or []:
        if tag["Key"] == key:
            return tag["Value"]
    return None


def _identify_resource(eni_type, description, instance_id, requester, tags):
    desc_lower = (description or "").lower()
    tag_name = _get_tag(tags, "Name") or ""
    if instance_id:
        return "EC2", instance_id, tag_name or instance_id
    if "elb" in desc_lower or eni_type == "network_load_balancer":
        parts = description.split("/")
        return "ELB", parts[1] if len(parts) >= 2 else description, parts[1] if len(parts) >= 2 else description
    if "lambda" in desc_lower:
        return "Lambda", description, tag_name or description
    if "rds" in desc_lower:
        return "RDS", description, tag_name or description
    if "ecs" in desc_lower:
        return "ECS", description, tag_name or description
    if "nat gateway" in desc_lower or eni_type == "nat_gateway":
        return "NAT-GW", description, tag_name or "NAT Gateway"
    if "vpce" in desc_lower or eni_type == "vpc_endpoint":
        return "VPC-Endpoint", description, tag_name or description
    if "firewall" in desc_lower or eni_type == "network_firewall":
        return "NW-Firewall", description, tag_name or description
    if "transit gateway" in desc_lower or eni_type == "transit_gateway":
        return "TGW", description, tag_name or "Transit Gateway"
    if eni_type == "interface" and requester:
        return "AWS-Managed", description or requester, tag_name or description
    return eni_type or "Unknown", description or "—", tag_name or description


def _scan_account(profile, region):
    """Scan a single account for VPCs, subnets, EIPs, ENIs."""
    all_profiles = _get_all_profiles()
    info = all_profiles.get(profile, {})
    account_name = info.get("name", profile)
    result = {"profile": profile, "account_name": account_name, "account_id": "", "region": region,
              "vpcs": [], "eips": [], "enis": [], "errors": []}
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        result["account_id"] = session.client("sts").get_caller_identity()["Account"]
        ec2 = session.client("ec2", region_name=region)
    except Exception as e:
        result["errors"].append(str(e))
        result["account_id"] = info.get("account_id", "unknown")
        return result

    # VPCs & Subnets
    try:
        for vpc in ec2.describe_vpcs()["Vpcs"]:
            vpc_id, vpc_cidr = vpc["VpcId"], vpc["CidrBlock"]
            subnets = []
            for sn in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]:
                net = ipaddress.IPv4Network(sn["CidrBlock"])
                total = net.num_addresses - 5
                avail = sn["AvailableIpAddressCount"]
                subnets.append({"subnet_id": sn["SubnetId"], "name": _get_tag(sn.get("Tags", []), "Name") or sn["SubnetId"],
                    "cidr": sn["CidrBlock"], "az": sn["AvailabilityZone"], "total_ips": total,
                    "available_ips": avail, "used_ips": total - avail,
                    "utilization_pct": round((total - avail) / total * 100, 1) if total > 0 else 0})
            net = ipaddress.IPv4Network(vpc_cidr)
            allocated = sum(ipaddress.IPv4Network(s["cidr"]).num_addresses for s in subnets)
            result["vpcs"].append({"vpc_id": vpc_id, "vpc_name": _get_tag(vpc.get("Tags", []), "Name") or vpc_id,
                "cidr": vpc_cidr, "is_default": vpc.get("IsDefault", False), "total_ips": net.num_addresses,
                "subnet_allocated_ips": allocated, "unallocated_ips": net.num_addresses - allocated,
                "subnets": sorted(subnets, key=lambda s: s["cidr"])})
    except Exception as e:
        result["errors"].append(f"VPC: {e}")

    # EIPs
    try:
        for eip in ec2.describe_addresses()["Addresses"]:
            result["eips"].append({"public_ip": eip.get("PublicIp", "N/A"), "allocation_id": eip.get("AllocationId", ""),
                "private_ip": eip.get("PrivateIpAddress"), "name": _get_tag(eip.get("Tags", []), "Name") or "Untagged",
                "in_use": eip.get("AssociationId") is not None, "instance_id": eip.get("InstanceId"),
                "eni_id": eip.get("NetworkInterfaceId")})
    except Exception as e:
        result["errors"].append(f"EIP: {e}")

    # ENIs
    try:
        for page in ec2.get_paginator("describe_network_interfaces").paginate():
            for eni in page["NetworkInterfaces"]:
                rt, rid, rname = _identify_resource(eni.get("InterfaceType", ""), eni.get("Description", ""),
                    eni.get("Attachment", {}).get("InstanceId"), eni.get("RequesterId", ""), eni.get("Tags", []))
                pips = [{"ip": p.get("PrivateIpAddress", ""), "primary": p.get("Primary", False),
                    "public_ip": p.get("Association", {}).get("PublicIp")} for p in eni.get("PrivateIpAddresses", [])]
                result["enis"].append({"eni_id": eni["NetworkInterfaceId"], "vpc_id": eni.get("VpcId", ""),
                    "subnet_id": eni.get("SubnetId", ""), "az": eni.get("AvailabilityZone", ""),
                    "resource_type": rt, "resource_id": rid, "resource_name": rname, "private_ips": pips})
    except Exception as e:
        result["errors"].append(f"ENI: {e}")

    return result


def _scan_all(profiles_str, region):
    profiles = _parse_profiles(profiles_str)
    region = region or os.environ.get("AWS_REGION", "ap-southeast-1")
    results = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        futs = {ex.submit(_scan_account, p, region): p for p in profiles}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception as e:
                p = futs[f]
                results.append({"profile": p, "account_name": p,
                    "account_id": "error", "region": region, "vpcs": [], "eips": [], "enis": [], "errors": [str(e)]})
    return sorted(results, key=lambda r: r["account_name"])


# ─── MCP Tools: Account Management ───────────────────────────────────────────

@mcp.tool()
def list_accounts() -> str:
    """List all registered AWS accounts and auto-discovered profiles.
    Shows profile name, friendly name, account ID, environment tag, and source."""
    all_profiles = _get_all_profiles()
    registry = _load_registry()
    accounts = []
    for profile, info in sorted(all_profiles.items(), key=lambda x: x[1].get("name", x[0])):
        accounts.append({
            "profile": profile,
            "name": info.get("name", profile),
            "account_id": info.get("account_id", ""),
            "env": info.get("env", ""),
            "source": "registry" if profile in registry else "aws-config (auto-discovered)",
        })
    return json.dumps({"total": len(accounts), "registered": len(registry),
                        "auto_discovered": len(accounts) - len(registry), "accounts": accounts}, indent=2)


@mcp.tool()
def add_account(profile: str, name: str = "", env: str = "", account_id: str = "") -> str:
    """Register an AWS profile for IP scanning. The profile must exist in ~/.aws/config.

    Args:
        profile: AWS CLI profile name (must exist in ~/.aws/config).
        name: Friendly display name for this account (e.g. "Production-SG"). Defaults to profile name.
        env: Environment tag (e.g. PROD, NONPROD, SANDBOX, CORE). Optional.
        account_id: AWS account ID. Optional — will be auto-detected on first scan if omitted.
    """
    # Verify profile exists in AWS config
    discovered = _discover_aws_profiles()
    if profile not in discovered:
        return json.dumps({"success": False, "error": f"Profile '{profile}' not found in ~/.aws/config. "
                           "Add it to your AWS config first, then register it here."})

    registry = _load_registry()
    registry[profile] = {
        "name": name or profile,
        "account_id": account_id,
        "env": env.upper() if env else "",
        "source": "registry",
    }
    _save_registry(registry)
    return json.dumps({"success": True, "message": f"Account '{name or profile}' registered with profile '{profile}'.",
                        "total_registered": len(registry)})


@mcp.tool()
def remove_account(profile: str) -> str:
    """Remove an AWS profile from the scanning registry.

    Args:
        profile: AWS CLI profile name to remove.
    """
    registry = _load_registry()
    if profile not in registry:
        return json.dumps({"success": False, "error": f"Profile '{profile}' is not in the registry. "
                           "It may be auto-discovered from ~/.aws/config — those can't be removed, only registry entries."})
    removed = registry.pop(profile)
    _save_registry(registry)
    return json.dumps({"success": True, "message": f"Removed '{removed.get('name', profile)}' ({profile}) from registry.",
                        "total_registered": len(registry)})


# ─── MCP Tools: IP Scanning ──────────────────────────────────────────────────

@mcp.tool()
def scan_accounts(profiles: str = "", region: str = "") -> str:
    """Scan VPCs, subnets, EIPs, and ENIs across one or more AWS accounts.

    Args:
        profiles: Comma-separated AWS profile names. Empty = all registered accounts.
        region: AWS region. Default: ap-southeast-1.
    """
    results = _scan_all(profiles or None, region or None)
    summary = {
        "accounts_scanned": len(results),
        "accounts_ok": sum(1 for r in results if not r["errors"]),
        "accounts_with_errors": sum(1 for r in results if r["errors"]),
        "total_vpcs": sum(len(r["vpcs"]) for r in results),
        "total_subnets": sum(len(v["subnets"]) for r in results for v in r["vpcs"]),
        "total_eips": sum(len(r["eips"]) for r in results),
        "unused_eips": sum(1 for r in results for e in r["eips"] if not e["in_use"]),
        "total_enis": sum(len(r["enis"]) for r in results),
    }
    return json.dumps({"summary": summary, "accounts": results}, default=str)


@mcp.tool()
def lookup_ip(ip: str, profiles: str = "", region: str = "") -> str:
    """Look up a specific IP address across all scanned accounts.
    Searches both private and public IPs, returns the resource that owns it.

    Args:
        ip: IP address to look up (e.g. 10.69.4.10 or 52.221.160.22).
        profiles: Comma-separated AWS profile names. Empty = all registered accounts.
        region: AWS region. Default: ap-southeast-1.
    """
    results = _scan_all(profiles or None, region or None)
    matches = []
    for r in results:
        for eni in r.get("enis", []):
            for pip in eni.get("private_ips", []):
                if pip.get("ip") == ip or pip.get("public_ip") == ip:
                    matches.append({
                        "account": r["account_name"], "account_id": r["account_id"],
                        "ip": pip["ip"], "public_ip": pip.get("public_ip"),
                        "resource_type": eni["resource_type"], "resource_id": eni["resource_id"],
                        "resource_name": eni["resource_name"], "eni_id": eni["eni_id"],
                        "vpc_id": eni["vpc_id"], "subnet_id": eni["subnet_id"], "az": eni.get("az", ""),
                    })
        for eip in r.get("eips", []):
            if eip.get("public_ip") == ip or eip.get("private_ip") == ip:
                matches.append({
                    "account": r["account_name"], "account_id": r["account_id"],
                    "ip": ip, "type": "EIP", "public_ip": eip["public_ip"],
                    "private_ip": eip.get("private_ip"), "in_use": eip["in_use"],
                    "allocation_id": eip["allocation_id"], "name": eip["name"],
                })
    if not matches:
        return json.dumps({"found": False, "ip": ip, "message": f"IP {ip} not found in any scanned account"})
    return json.dumps({"found": True, "ip": ip, "match_count": len(matches), "matches": matches})


@mcp.tool()
def get_unused_eips(profiles: str = "", region: str = "") -> str:
    """Find all unused Elastic IPs across accounts. Unused EIPs cost ~$3.60/month each.

    Args:
        profiles: Comma-separated AWS profile names. Empty = all registered accounts.
        region: AWS region. Default: ap-southeast-1.
    """
    results = _scan_all(profiles or None, region or None)
    unused = []
    for r in results:
        for eip in r.get("eips", []):
            if not eip["in_use"]:
                unused.append({
                    "account": r["account_name"], "account_id": r["account_id"],
                    "public_ip": eip["public_ip"], "allocation_id": eip["allocation_id"],
                    "name": eip["name"], "estimated_monthly_cost_usd": 3.60,
                })
    return json.dumps({"unused_count": len(unused),
        "total_monthly_waste_usd": round(len(unused) * 3.60, 2), "unused_eips": unused})


@mcp.tool()
def get_account_ip_map(profile: str, region: str = "") -> str:
    """Get a detailed IP-to-resource map for a specific account.

    Args:
        profile: AWS profile name for the account to map.
        region: AWS region. Default: ap-southeast-1.
    """
    results = _scan_all(profile, region or None)
    if not results:
        return json.dumps({"error": "No results for profile: " + profile})
    r = results[0]
    if r["errors"]:
        return json.dumps({"error": r["errors"][0], "account": r["account_name"]})
    ip_map = []
    for eni in r.get("enis", []):
        for pip in eni.get("private_ips", []):
            ip_map.append({
                "private_ip": pip["ip"], "public_ip": pip.get("public_ip"),
                "resource_type": eni["resource_type"], "resource_id": eni["resource_id"],
                "resource_name": eni["resource_name"], "vpc_id": eni["vpc_id"],
                "subnet_id": eni["subnet_id"], "az": eni.get("az", ""), "eni_id": eni["eni_id"],
            })
    counts = {}
    for item in ip_map:
        v = item.get("resource_type", "Unknown")
        counts[v] = counts.get(v, 0) + 1
    return json.dumps({"account": r["account_name"], "account_id": r["account_id"],
        "total_ips": len(ip_map), "by_resource_type": dict(sorted(counts.items(), key=lambda x: -x[1])),
        "ip_map": sorted(ip_map, key=lambda x: x["private_ip"])})


@mcp.tool()
def get_cidr_plan() -> str:
    """Get the CIDR allocation plan showing account CIDR assignments,
    supernets, and central VPC ranges. Edit this data in server.py to match your organization."""
    return json.dumps(CIDR_PLAN, indent=2)


# ─── Default CIDR Plan (customize for your organization) ─────────────────────
CIDR_PLAN = {
    "note": "Edit this section in server.py to match your organization's CIDR plan.",
    "supernets": {
        "10.69.0.0/16": "PROD-SG",
        "10.99.0.0/16": "NONPROD-SG",
        "10.127.0.0/16": "SANDBOX",
    },
    "central_vpcs": {
        "Inspection VPC": "10.69.2.0/24",
        "Central Egress VPC": "10.69.3.0/24",
        "Network Services VPC": "10.69.4.0/24",
        "Central Ingress VPC": "10.69.5.0/24",
    },
    "account_allocations": [
        {"account": "Example-Prod", "env": "PROD", "cidrs": ["10.69.12.0/22"]},
        {"account": "Example-NonProd", "env": "NONPROD", "cidrs": ["10.99.12.0/22"]},
    ],
}
