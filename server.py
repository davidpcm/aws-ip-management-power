"""
AWS IP Management MCP Server
=============================
MCP server for multi-account AWS IP scanning, lookup, and tracking.
Profiles are auto-discovered from ~/.aws/config or managed via a local registry.
"""

import json
import os
import re
import ipaddress
import asyncio
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("aws-ip-management")

# ─── Profile Registry ─────────────────────────────────────────────────────────

REGISTRY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts-registry.json")


def _load_registry():
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_registry(registry):
    with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)


def _discover_aws_profiles():
    config_path = Path.home() / ".aws" / "config"
    profiles = {}
    if not config_path.exists():
        return profiles
    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()
    for match in re.finditer(r'\[profile\s+(.+?)\]', content):
        name = match.group(1).strip()
        profiles[name] = {"name": name, "account_id": "", "env": "", "source": "aws-config"}
    return profiles


def _get_all_profiles():
    discovered = _discover_aws_profiles()
    registry = _load_registry()
    merged = dict(discovered)
    for k, v in registry.items():
        merged[k] = v
        merged[k]["source"] = "registry"
    return merged


def _parse_profiles(profiles_str):
    if not profiles_str:
        registry = _load_registry()
        return list(registry.keys()) if registry else list(_get_all_profiles().keys())
    return [p.strip() for p in profiles_str.split(",")]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_tag(tags, key):
    for tag in tags or []:
        if tag["Key"] == key:
            return tag["Value"]
    return None


def _identify_resource(eni_type, description, instance_id, requester, tags):
    desc = (description or "").lower()
    tag_name = _get_tag(tags, "Name") or ""
    if instance_id:
        return "EC2", instance_id, tag_name or instance_id
    if "elb" in desc or eni_type == "network_load_balancer":
        parts = description.split("/")
        lb = parts[1] if len(parts) >= 2 else description
        return "ELB", lb, lb
    if "lambda" in desc:
        return "Lambda", description, tag_name or description
    if "rds" in desc:
        return "RDS", description, tag_name or description
    if "ecs" in desc:
        return "ECS", description, tag_name or description
    if "nat gateway" in desc or eni_type == "nat_gateway":
        return "NAT-GW", description, tag_name or "NAT Gateway"
    if "vpce" in desc or eni_type == "vpc_endpoint":
        return "VPC-Endpoint", description, tag_name or description
    if "firewall" in desc or eni_type == "network_firewall":
        return "NW-Firewall", description, tag_name or description
    if "transit gateway" in desc or eni_type == "transit_gateway":
        return "TGW", description, tag_name or "Transit Gateway"
    if eni_type == "interface" and requester:
        return "AWS-Managed", description or requester, tag_name or description
    return eni_type or "Unknown", description or "-", tag_name or description


def _scan_account(profile, region):
    info = _get_all_profiles().get(profile, {})
    result = {"profile": profile, "account_name": info.get("name", profile), "account_id": "",
              "region": region, "vpcs": [], "eips": [], "enis": [], "errors": []}
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        result["account_id"] = session.client("sts").get_caller_identity()["Account"]
        ec2 = session.client("ec2", region_name=region)
    except Exception as e:
        result["errors"].append(str(e))
        result["account_id"] = info.get("account_id", "unknown")
        return result

    try:
        for vpc in ec2.describe_vpcs()["Vpcs"]:
            vid, vcidr = vpc["VpcId"], vpc["CidrBlock"]
            subs = []
            for sn in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vid]}])["Subnets"]:
                net = ipaddress.IPv4Network(sn["CidrBlock"])
                t = net.num_addresses - 5
                a = sn["AvailableIpAddressCount"]
                subs.append({"subnet_id": sn["SubnetId"], "name": _get_tag(sn.get("Tags", []), "Name") or sn["SubnetId"],
                    "cidr": sn["CidrBlock"], "az": sn["AvailabilityZone"], "total_ips": t,
                    "available_ips": a, "used_ips": t - a, "utilization_pct": round((t - a) / t * 100, 1) if t > 0 else 0})
            net = ipaddress.IPv4Network(vcidr)
            alloc = sum(ipaddress.IPv4Network(s["cidr"]).num_addresses for s in subs)
            result["vpcs"].append({"vpc_id": vid, "vpc_name": _get_tag(vpc.get("Tags", []), "Name") or vid,
                "cidr": vcidr, "is_default": vpc.get("IsDefault", False), "total_ips": net.num_addresses,
                "subnet_allocated_ips": alloc, "unallocated_ips": net.num_addresses - alloc,
                "subnets": sorted(subs, key=lambda s: s["cidr"])})
    except Exception as e:
        result["errors"].append(f"VPC: {e}")

    try:
        for eip in ec2.describe_addresses()["Addresses"]:
            result["eips"].append({"public_ip": eip.get("PublicIp", "N/A"), "allocation_id": eip.get("AllocationId", ""),
                "private_ip": eip.get("PrivateIpAddress"), "name": _get_tag(eip.get("Tags", []), "Name") or "Untagged",
                "in_use": eip.get("AssociationId") is not None, "instance_id": eip.get("InstanceId"),
                "eni_id": eip.get("NetworkInterfaceId")})
    except Exception as e:
        result["errors"].append(f"EIP: {e}")

    try:
        for page in ec2.get_paginator("describe_network_interfaces").paginate():
            for eni in page["NetworkInterfaces"]:
                rt, rid, rn = _identify_resource(eni.get("InterfaceType", ""), eni.get("Description", ""),
                    eni.get("Attachment", {}).get("InstanceId"), eni.get("RequesterId", ""), eni.get("Tags", []))
                pips = [{"ip": p.get("PrivateIpAddress", ""), "primary": p.get("Primary", False),
                    "public_ip": p.get("Association", {}).get("PublicIp")} for p in eni.get("PrivateIpAddresses", [])]
                result["enis"].append({"eni_id": eni["NetworkInterfaceId"], "vpc_id": eni.get("VpcId", ""),
                    "subnet_id": eni.get("SubnetId", ""), "az": eni.get("AvailabilityZone", ""),
                    "resource_type": rt, "resource_id": rid, "resource_name": rn, "private_ips": pips})
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
                results.append({"profile": futs[f], "account_name": futs[f], "account_id": "error",
                    "region": region, "vpcs": [], "eips": [], "enis": [], "errors": [str(e)]})
    return sorted(results, key=lambda r: r["account_name"])


# ─── MCP Tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def list_accounts() -> str:
    """List all registered AWS accounts and auto-discovered profiles."""
    all_p = _get_all_profiles()
    reg = _load_registry()
    accts = [{"profile": p, "name": i.get("name", p), "account_id": i.get("account_id", ""),
              "env": i.get("env", ""), "source": "registry" if p in reg else "aws-config"}
             for p, i in sorted(all_p.items(), key=lambda x: x[1].get("name", x[0]))]
    return json.dumps({"total": len(accts), "registered": len(reg), "accounts": accts}, indent=2)


@mcp.tool()
def add_account(profile: str, name: str = "", env: str = "", account_id: str = "") -> str:
    """Register an AWS profile for IP scanning.

    Args:
        profile: AWS CLI profile name (must exist in ~/.aws/config).
        name: Friendly display name. Defaults to profile name.
        env: Environment tag (PROD, NONPROD, SANDBOX, CORE).
        account_id: AWS account ID (auto-detected on first scan if omitted).
    """
    if profile not in _discover_aws_profiles():
        return json.dumps({"success": False, "error": f"Profile '{profile}' not found in ~/.aws/config."})
    reg = _load_registry()
    reg[profile] = {"name": name or profile, "account_id": account_id, "env": env.upper() if env else "", "source": "registry"}
    _save_registry(reg)
    return json.dumps({"success": True, "message": f"Registered '{name or profile}' ({profile}).", "total": len(reg)})


@mcp.tool()
def remove_account(profile: str) -> str:
    """Remove an AWS profile from the scanning registry.

    Args:
        profile: AWS CLI profile name to remove.
    """
    reg = _load_registry()
    if profile not in reg:
        return json.dumps({"success": False, "error": f"'{profile}' not in registry."})
    reg.pop(profile)
    _save_registry(reg)
    return json.dumps({"success": True, "message": f"Removed '{profile}'.", "total": len(reg)})


@mcp.tool()
def scan_accounts(profiles: str = "", region: str = "") -> str:
    """Scan VPCs, subnets, EIPs, and ENIs across AWS accounts.

    Args:
        profiles: Comma-separated profile names. Empty = all registered.
        region: AWS region. Default: ap-southeast-1.
    """
    results = _scan_all(profiles or None, region or None)
    s = {"accounts_scanned": len(results), "ok": sum(1 for r in results if not r["errors"]),
         "errors": sum(1 for r in results if r["errors"]),
         "vpcs": sum(len(r["vpcs"]) for r in results),
         "subnets": sum(len(v["subnets"]) for r in results for v in r["vpcs"]),
         "eips": sum(len(r["eips"]) for r in results),
         "unused_eips": sum(1 for r in results for e in r["eips"] if not e["in_use"]),
         "enis": sum(len(r["enis"]) for r in results)}
    return json.dumps({"summary": s, "accounts": results}, default=str)


@mcp.tool()
def lookup_ip(ip: str, profiles: str = "", region: str = "") -> str:
    """Look up which resource owns a specific IP address.

    Args:
        ip: IP address to look up.
        profiles: Comma-separated profile names. Empty = all registered.
        region: AWS region. Default: ap-southeast-1.
    """
    results = _scan_all(profiles or None, region or None)
    matches = []
    for r in results:
        for eni in r.get("enis", []):
            for pip in eni.get("private_ips", []):
                if pip.get("ip") == ip or pip.get("public_ip") == ip:
                    matches.append({"account": r["account_name"], "account_id": r["account_id"],
                        "ip": pip["ip"], "public_ip": pip.get("public_ip"), "resource_type": eni["resource_type"],
                        "resource_id": eni["resource_id"], "resource_name": eni["resource_name"],
                        "eni_id": eni["eni_id"], "vpc_id": eni["vpc_id"], "subnet_id": eni["subnet_id"]})
        for eip in r.get("eips", []):
            if eip.get("public_ip") == ip or eip.get("private_ip") == ip:
                matches.append({"account": r["account_name"], "ip": ip, "type": "EIP",
                    "public_ip": eip["public_ip"], "private_ip": eip.get("private_ip"),
                    "in_use": eip["in_use"], "allocation_id": eip["allocation_id"]})
    if not matches:
        return json.dumps({"found": False, "ip": ip, "message": f"IP {ip} not found"})
    return json.dumps({"found": True, "ip": ip, "matches": matches})


@mcp.tool()
def get_unused_eips(profiles: str = "", region: str = "") -> str:
    """Find unused Elastic IPs (~$3.60/month each).

    Args:
        profiles: Comma-separated profile names. Empty = all registered.
        region: AWS region. Default: ap-southeast-1.
    """
    results = _scan_all(profiles or None, region or None)
    unused = [{"account": r["account_name"], "public_ip": e["public_ip"], "allocation_id": e["allocation_id"],
               "cost_usd_month": 3.60} for r in results for e in r.get("eips", []) if not e["in_use"]]
    return json.dumps({"count": len(unused), "waste_usd_month": round(len(unused) * 3.6, 2), "eips": unused})


@mcp.tool()
def get_account_ip_map(profile: str, region: str = "") -> str:
    """Get IP-to-resource map for a specific account.

    Args:
        profile: AWS profile name.
        region: AWS region. Default: ap-southeast-1.
    """
    results = _scan_all(profile, region or None)
    if not results:
        return json.dumps({"error": "No results"})
    r = results[0]
    if r["errors"]:
        return json.dumps({"error": r["errors"][0]})
    ip_map = [{"private_ip": p["ip"], "public_ip": p.get("public_ip"), "resource_type": e["resource_type"],
               "resource_id": e["resource_id"], "resource_name": e["resource_name"], "vpc_id": e["vpc_id"],
               "subnet_id": e["subnet_id"], "eni_id": e["eni_id"]}
              for e in r.get("enis", []) for p in e.get("private_ips", [])]
    counts = {}
    for i in ip_map:
        counts[i["resource_type"]] = counts.get(i["resource_type"], 0) + 1
    return json.dumps({"account": r["account_name"], "total_ips": len(ip_map),
        "by_type": dict(sorted(counts.items(), key=lambda x: -x[1])),
        "ip_map": sorted(ip_map, key=lambda x: x["private_ip"])})


@mcp.tool()
def get_cidr_plan() -> str:
    """Get the CIDR allocation plan. Edit CIDR_PLAN in server.py to customize."""
    return json.dumps(CIDR_PLAN, indent=2)


CIDR_PLAN = {
    "note": "Edit CIDR_PLAN in server.py to match your organization.",
    "supernets": {"10.69.0.0/16": "PROD-SG", "10.99.0.0/16": "NONPROD-SG", "10.127.0.0/16": "SANDBOX"},
    "central_vpcs": {"Inspection": "10.69.2.0/24", "Egress": "10.69.3.0/24",
                     "Network Services": "10.69.4.0/24", "Ingress": "10.69.5.0/24"},
    "allocations": [{"account": "Example-Prod", "env": "PROD", "cidrs": ["10.69.12.0/22"]},
                    {"account": "Example-NonProd", "env": "NONPROD", "cidrs": ["10.99.12.0/22"]}],
}

if __name__ == "__main__":
    mcp.run()
