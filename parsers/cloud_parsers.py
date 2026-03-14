"""
parsers/cloud_parsers.py — Cloud log parsers for AWS, Azure, and GCP.

Each parser extracts security-relevant fields and enriches them with
ATT&CK-relevant keywords so map_iocs() can match techniques.

All parsers return List[str] compatible with map_iocs().
"""

import json
import os
from typing import Dict, List

# ---------------------------------------------------------------------------
# AWS CloudTrail — suspicious event → enrichment keyword mapping
# ---------------------------------------------------------------------------
AWS_SUSPICIOUS_EVENTS: Dict[str, str] = {
    "CreateUser": "create user iam persistence account creation createuser",
    "CreateAccessKey": "create access key credential persistence api key createaccesskey",
    "DeleteAccessKey": "delete access key credential removal",
    "StopLogging": "stop logging indicator removal defense evasion stoplogging disable logging",
    "DeleteTrail": "delete trail indicator removal defense evasion deletetrail log tampering",
    "PutBucketPolicy": "bucket policy modification s3 data access",
    "SendCommand": "ssm send command remote execution lateral movement command shell",
    "ConsoleLogin": "console login authentication valid account consolelogin",
    "GetSecretValue": "get secret credential access unsecured credentials getsecretvalue",
    "DescribeInstances": "describe instances discovery system information describeinstances",
    "RunInstances": "run instances execution resource creation compute",
    "TerminateInstances": "terminate instances impact service stop terminateinstances",
    "AuthorizeSecurityGroupIngress": "security group ingress firewall modification network access",
    "CreateRole": "create role iam persistence privilege escalation",
    "AttachRolePolicy": "attach role policy privilege escalation iam modification",
    "PutBucketAcl": "bucket acl modification s3 permission change",
    "DisableKey": "disable kms key defense evasion crypto key impair defenses",
    "CreateLoginProfile": "create login profile persistence account manipulation",
    "UpdateLoginProfile": "update login profile credential access account manipulation",
    "AssumeRole": "assume role privilege escalation lateral movement credential",
}


def parse_cloudtrail(filepath: str) -> List[str]:
    """
    Parse an AWS CloudTrail JSON log file.

    Extracts: eventName, eventSource, sourceIPAddress, userIdentity.arn, errorCode.
    Enriches suspicious events with ATT&CK-relevant keywords.
    Flags AccessDenied errors as potential brute force.
    Flags failed ConsoleLogin as potential password spray.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # CloudTrail wraps events in a "Records" array
    records = data if isinstance(data, list) else data.get("Records", [])

    iocs: List[str] = []
    for event in records:
        event_name = event.get("eventName", "")
        event_source = event.get("eventSource", "")
        source_ip = event.get("sourceIPAddress", "")
        error_code = event.get("errorCode", "")
        error_msg = event.get("errorMessage", "")

        # Extract user identity ARN
        user_identity = event.get("userIdentity", {})
        arn = user_identity.get("arn", user_identity.get("userName", "unknown"))

        # Base IOC string
        parts = [
            f"CloudTrail:{event_name}",
            f"source={event_source}",
            f"ip={source_ip}",
            f"user={arn}",
        ]

        # Add error info if present
        if error_code:
            parts.append(f"error={error_code}")
        if error_msg:
            parts.append(f"msg={error_msg[:200]}")

        # Enrich with ATT&CK-relevant keywords for suspicious events
        enrichment = AWS_SUSPICIOUS_EVENTS.get(event_name, "")
        if enrichment:
            parts.append(f"[{enrichment}]")

        # Flag AccessDenied as brute force / credential access
        if error_code in ("AccessDenied", "Client.UnauthorizedAccess"):
            parts.append("[brute force accessdenied failed login authentication fail]")

        # Flag failed ConsoleLogin as password spray
        if event_name == "ConsoleLogin":
            resp = event.get("responseElements", {})
            console_login_result = ""
            if isinstance(resp, dict):
                console_login_result = resp.get("ConsoleLogin", "")
            if console_login_result == "Failure" or error_code:
                parts.append("[password spray failed login brute force credential access]")

        iocs.append(" | ".join(parts))

    return iocs


# ---------------------------------------------------------------------------
# Azure Activity Log — suspicious operation mapping
# ---------------------------------------------------------------------------
AZURE_SUSPICIOUS_OPS: Dict[str, str] = {
    "Microsoft.Compute/virtualMachines/write": "create vm execution compute resource",
    "Microsoft.Compute/virtualMachines/delete": "delete vm impact service stop",
    "Microsoft.Authorization/roleAssignments/write": "role assignment privilege escalation persistence",
    "Microsoft.Storage/storageAccounts/listKeys/action": "list storage keys credential access",
    "Microsoft.Network/networkSecurityGroups/securityRules/write": "nsg rule modification firewall network access",
    "Microsoft.KeyVault/vaults/secrets/getSecret/action": "keyvault secret access credential access get secret",
    "Microsoft.Sql/servers/firewallRules/write": "sql firewall rule modification network access",
    "Microsoft.ContainerService/managedClusters/write": "aks cluster modification execution",
    "Microsoft.Authorization/policyAssignments/delete": "policy deletion defense evasion impair defenses",
    "Microsoft.Insights/diagnosticSettings/delete": "diagnostic settings deletion indicator removal disable logging",
}


def parse_azure_activity(filepath: str) -> List[str]:
    """
    Parse an Azure Activity Log JSON file.

    Handles nested operationName.value and status.value fields.
    Flags Failed/Forbidden status as potential credential access.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Azure Activity Log uses a "value" wrapper
    records = data if isinstance(data, list) else data.get("value", data.get("records", []))
    if isinstance(records, dict):
        records = [records]

    iocs: List[str] = []
    for event in records:
        # Handle nested operationName (can be string or {value: ...})
        op_name_raw = event.get("operationName", "")
        if isinstance(op_name_raw, dict):
            op_name = op_name_raw.get("value", str(op_name_raw))
        else:
            op_name = str(op_name_raw)

        # Handle nested status
        status_raw = event.get("status", event.get("resultType", ""))
        if isinstance(status_raw, dict):
            status = status_raw.get("value", str(status_raw))
        else:
            status = str(status_raw)

        caller = event.get("caller", event.get("identity", {}).get("claims", {}).get("name", "unknown"))
        resource_id = event.get("resourceId", "")
        timestamp = event.get("eventTimestamp", event.get("time", ""))

        parts = [
            f"Azure:{op_name}",
            f"status={status}",
            f"caller={caller}",
            f"resource={resource_id[:150]}",
        ]
        if timestamp:
            parts.append(f"time={timestamp}")

        # Enrich suspicious operations
        enrichment = AZURE_SUSPICIOUS_OPS.get(op_name, "")
        if enrichment:
            parts.append(f"[{enrichment}]")

        # Flag failed or forbidden operations
        status_lower = status.lower()
        if any(kw in status_lower for kw in ("failed", "forbidden", "unauthorized")):
            parts.append("[failed authentication brute force credential access accessdenied]")

        iocs.append(" | ".join(parts))

    return iocs


# ---------------------------------------------------------------------------
# GCP Cloud Audit Log — suspicious method mapping
# ---------------------------------------------------------------------------
GCP_SUSPICIOUS_METHODS: Dict[str, str] = {
    "google.iam.admin.v1.CreateServiceAccount": "create service account persistence iam",
    "google.iam.admin.v1.CreateServiceAccountKey": "create service account key credential access persistence",
    "google.compute.instances.insert": "create vm instance execution compute resource",
    "google.compute.instances.delete": "delete vm instance impact service stop",
    "google.compute.firewalls.insert": "create firewall rule network access modification",
    "google.compute.firewalls.delete": "delete firewall rule defense evasion impair defenses",
    "google.logging.v2.ConfigServiceV2.DeleteSink": "delete logging sink indicator removal disable logging",
    "storage.objects.get": "storage object access data collection",
    "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion": "access secret credential access get secret",
    "SetIamPolicy": "set iam policy privilege escalation permission modification",
}


def parse_gcp_audit(filepath: str) -> List[str]:
    """
    Parse a GCP Cloud Audit Log JSON file.

    Handles protoPayload nested structure.
    Flags PERMISSION_DENIED (code 7) as potential credential issue.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # GCP audit logs may be wrapped in "entries" or be a list
    if isinstance(data, dict):
        records = data.get("entries", data.get("logEntries", [data]))
    else:
        records = data

    iocs: List[str] = []
    for event in records:
        proto = event.get("protoPayload", event)
        method = proto.get("methodName", "")
        service = proto.get("serviceName", "")
        resource_name = proto.get("resourceName", "")

        # Caller info
        auth_info = proto.get("authenticationInfo", {})
        principal = auth_info.get("principalEmail", "unknown")

        # Status
        status = proto.get("status", {})
        status_code = status.get("code", 0) if isinstance(status, dict) else 0
        status_msg = status.get("message", "") if isinstance(status, dict) else str(status)

        parts = [
            f"GCP:{method}",
            f"service={service}",
            f"principal={principal}",
            f"resource={resource_name[:150]}",
        ]

        if status_code:
            parts.append(f"status_code={status_code}")
        if status_msg:
            parts.append(f"status_msg={status_msg[:200]}")

        # Enrich suspicious methods
        enrichment = GCP_SUSPICIOUS_METHODS.get(method, "")
        if enrichment:
            parts.append(f"[{enrichment}]")

        # Flag PERMISSION_DENIED (gRPC code 7)
        if status_code == 7 or "PERMISSION_DENIED" in str(status_msg).upper():
            parts.append("[permission denied failed authentication brute force credential access]")

        iocs.append(" | ".join(parts))

    return iocs


# ---------------------------------------------------------------------------
# Auto-detect cloud log format
# ---------------------------------------------------------------------------
def parse_cloud_log(filepath: str) -> List[str]:
    """
    Auto-detect cloud log format and parse.

    Detection heuristics:
    - "Records" key with eventVersion/eventSource → AWS CloudTrail
    - "value" key with operationName → Azure Activity Log
    - "entries" key or protoPayload field → GCP Cloud Audit
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    # If it's a list, peek at the first element
    sample = data
    if isinstance(data, list) and data:
        sample = data[0]
    elif isinstance(data, dict):
        # Check for wrapper keys
        if "Records" in data:
            # Peek inside Records
            records = data["Records"]
            if records and isinstance(records, list):
                sample = records[0]
                if "eventVersion" in sample or "eventSource" in sample:
                    return parse_cloudtrail(filepath)

        if "value" in data and isinstance(data["value"], list):
            peek = data["value"][0] if data["value"] else {}
            if "operationName" in peek or "resourceId" in peek:
                return parse_azure_activity(filepath)

        if "entries" in data:
            entries = data["entries"]
            if entries and isinstance(entries, list):
                peek = entries[0]
                if "protoPayload" in peek:
                    return parse_gcp_audit(filepath)

        # Direct structure checks
        if "protoPayload" in sample:
            return parse_gcp_audit(filepath)
        if "eventVersion" in sample or "eventSource" in sample:
            return parse_cloudtrail(filepath)
        if "operationName" in sample:
            return parse_azure_activity(filepath)

    # Fallback: try CloudTrail first (most common)
    try:
        return parse_cloudtrail(filepath)
    except (KeyError, TypeError):
        pass

    # Last resort: just flatten
    from parsers.log_parsers import parse_json_log
    return parse_json_log(filepath)