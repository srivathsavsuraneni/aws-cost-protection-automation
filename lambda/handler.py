import os
import json
import datetime
import boto3
from typing import Dict, Any, List, Optional

# ---------------------------
# Configuration (safe defaults)
# ---------------------------

# Keep DRY_RUN enabled until you are 100% sure.
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

# Only allow actions on resources explicitly tagged with this key/value.
# Example: CostCleanup=true
REQUIRE_TAG_KEY = os.getenv("REQUIRE_TAG_KEY", "CostCleanup")
REQUIRE_TAG_VALUE = os.getenv("REQUIRE_TAG_VALUE", "true")

# Never touch resources with this tag key/value (hard safety).
PROTECT_TAG_KEY = os.getenv("PROTECT_TAG_KEY", "DoNotDelete")
PROTECT_TAG_VALUE = os.getenv("PROTECT_TAG_VALUE", "true")

# Age thresholds (hours)
STOPPED_EC2_MIN_AGE_HOURS = int(os.getenv("STOPPED_EC2_MIN_AGE_HOURS", "168"))  # 7 days
UNATTACHED_EBS_MIN_AGE_HOURS = int(os.getenv("UNATTACHED_EBS_MIN_AGE_HOURS", "168"))  # 7 days
UNASSOCIATED_EIP_MIN_AGE_HOURS = int(os.getenv("UNASSOCIATED_EIP_MIN_AGE_HOURS", "168"))  # 7 days

# Region is auto from Lambda env; boto3 will use it.
ec2 = boto3.client("ec2")
elbv2 = boto3.client("elbv2")


# ---------------------------
# Helpers
# ---------------------------

def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)

def hours_since(dt: datetime.datetime) -> float:
    return (utcnow() - dt).total_seconds() / 3600.0

def parse_sns_budget_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    AWS Budgets -> SNS -> Lambda delivers SNS Records.
    The budget payload is usually in Records[0].Sns.Message (stringified JSON).
    We parse it safely and return metadata for logging.
    """
    out = {"raw_message": None, "budget_name": None, "account_id": None, "alert_threshold": None}
    try:
        record = event["Records"][0]
        msg = record["Sns"]["Message"]
        out["raw_message"] = msg

        # Some messages are JSON, others are plain text.
        try:
            j = json.loads(msg)
            out["budget_name"] = j.get("budgetName") or j.get("BudgetName")
            out["account_id"] = j.get("accountId") or j.get("AccountId")
            out["alert_threshold"] = j.get("alertThreshold") or j.get("AlertThreshold")
        except json.JSONDecodeError:
            # Keep raw text
            pass
    except Exception:
        pass
    return out

def get_tag_map(tags: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    if not tags:
        return {}
    return {t.get("Key", ""): t.get("Value", "") for t in tags if t.get("Key")}

def has_required_tag(tags: Dict[str, str]) -> bool:
    return tags.get(REQUIRE_TAG_KEY) == REQUIRE_TAG_VALUE

def is_protected(tags: Dict[str, str]) -> bool:
    return tags.get(PROTECT_TAG_KEY) == PROTECT_TAG_VALUE

def log_json(label: str, obj: Any) -> None:
    print(f"{label}: {json.dumps(obj, default=str)}")


# ---------------------------
# Resource checks
# ---------------------------

def find_stopped_ec2_candidates() -> List[Dict[str, Any]]:
    """
    Finds stopped EC2 instances older than threshold.
    We only *report* candidates; terminate is not performed in this example.
    """
    candidates = []
    resp = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
    )

    for r in resp.get("Reservations", []):
        for inst in r.get("Instances", []):
            tags = get_tag_map(inst.get("Tags"))
            if is_protected(tags):
                continue
            if not has_required_tag(tags):
                continue

            stop_time = inst.get("StateTransitionReason", "")
            # Getting exact stop timestamp is not always straightforward; use LaunchTime as fallback.
            # For safer behavior: use LaunchTime-based age as a proxy.
            launch_time = inst.get("LaunchTime")
            if not launch_time:
                continue

            age_h = hours_since(launch_time)
            if age_h >= STOPPED_EC2_MIN_AGE_HOURS:
                candidates.append({
                    "type": "ec2_stopped",
                    "instance_id": inst.get("InstanceId"),
                    "launch_time": str(launch_time),
                    "age_hours_proxy": round(age_h, 2),
                    "tags": tags
                })
    return candidates

def find_unattached_ebs_candidates() -> List[Dict[str, Any]]:
    """
    Finds EBS volumes in 'available' state (unattached) older than threshold.
    """
    candidates = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for vol in page.get("Volumes", []):
            tags = get_tag_map(vol.get("Tags"))
            if is_protected(tags):
                continue
            if not has_required_tag(tags):
                continue

            create_time = vol.get("CreateTime")
            if not create_time:
                continue
            age_h = hours_since(create_time)
            if age_h >= UNATTACHED_EBS_MIN_AGE_HOURS:
                candidates.append({
                    "type": "ebs_unattached",
                    "volume_id": vol.get("VolumeId"),
                    "size_gb": vol.get("Size"),
                    "create_time": str(create_time),
                    "age_hours": round(age_h, 2),
                    "tags": tags
                })
    return candidates

def find_unassociated_eip_candidates() -> List[Dict[str, Any]]:
    """
    Finds Elastic IPs that are not associated with any instance/NIC.
    """
    candidates = []
    resp = ec2.describe_addresses()
    for addr in resp.get("Addresses", []):
        # If it has AssociationId or NetworkInterfaceId, it's in use.
        if addr.get("AssociationId") or addr.get("NetworkInterfaceId"):
            continue

        tags = get_tag_map(addr.get("Tags"))
        if is_protected(tags):
            continue
        if not has_required_tag(tags):
            continue

        # EIP doesn't expose creation time in API; enforce tag-based workflow + report only,
        # or store allocation time elsewhere. We'll report it as a candidate.
        candidates.append({
            "type": "eip_unassociated",
            "allocation_id": addr.get("AllocationId"),
            "public_ip": addr.get("PublicIp"),
            "tags": tags
        })
    return candidates

def find_idle_load_balancers_candidates() -> List[Dict[str, Any]]:
    """
    Best-effort: lists ALBs/NLBs and reports those without listeners or target groups.
    Safe reporting only (no deletes).
    """
    candidates = []
    paginator = elbv2.get_paginator("describe_load_balancers")
    for page in paginator.paginate():
        for lb in page.get("LoadBalancers", []):
            lb_arn = lb.get("LoadBalancerArn")
            lb_name = lb.get("LoadBalancerName")

            # Tags
            tag_desc = elbv2.describe_tags(ResourceArns=[lb_arn])
            tags = get_tag_map(tag_desc["TagDescriptions"][0].get("Tags", []))

            if is_protected(tags) or not has_required_tag(tags):
                continue

            # Check listeners count
            listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn).get("Listeners", [])
            # Check target groups count
            tgs = elbv2.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])

            if len(listeners) == 0 or len(tgs) == 0:
                candidates.append({
                    "type": "lb_potentially_idle",
                    "lb_name": lb_name,
                    "lb_arn": lb_arn,
                    "scheme": lb.get("Scheme"),
                    "lb_type": lb.get("Type"),
                    "listeners": len(listeners),
                    "target_groups": len(tgs),
                    "tags": tags
                })
    return candidates

def nat_gateways_reporting() -> List[Dict[str, Any]]:
    """
    NAT Gateways are expensive; we report candidates based on tags only.
    (Full 'idle' detection requires VPC flow logs / route analysis / CloudWatch metrics.)
    """
    candidates = []
    paginator = ec2.get_paginator("describe_nat_gateways")
    for page in paginator.paginate(Filter=[{"Name": "state", "Values": ["available"]}]):
        for nat in page.get("NatGateways", []):
            tags = get_tag_map(nat.get("Tags"))
            if is_protected(tags) or not has_required_tag(tags):
                continue

            candidates.append({
                "type": "nat_gateway_review",
                "nat_gateway_id": nat.get("NatGatewayId"),
                "subnet_id": nat.get("SubnetId"),
                "vpc_id": nat.get("VpcId"),
                "create_time": str(nat.get("CreateTime")),
                "tags": tags
            })
    return candidates


# ---------------------------
# Actions (kept safe)
# ---------------------------

def delete_ebs_volume(volume_id: str) -> Dict[str, Any]:
    if DRY_RUN:
        return {"action": "delete_volume", "volume_id": volume_id, "status": "dry_run"}
    ec2.delete_volume(VolumeId=volume_id)
    return {"action": "delete_volume", "volume_id": volume_id, "status": "deleted"}

def release_eip(allocation_id: str) -> Dict[str, Any]:
    if DRY_RUN:
        return {"action": "release_eip", "allocation_id": allocation_id, "status": "dry_run"}
    ec2.release_address(AllocationId=allocation_id)
    return {"action": "release_eip", "allocation_id": allocation_id, "status": "released"}


# ---------------------------
# Lambda entrypoint
# ---------------------------

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    meta = parse_sns_budget_event(event)
    print("=== Cost-Protection Automation Triggered ===")
    log_json("TriggerMeta", meta)
    print(f"DRY_RUN={DRY_RUN} REQUIRE_TAG={REQUIRE_TAG_KEY}={REQUIRE_TAG_VALUE} PROTECT_TAG={PROTECT_TAG_KEY}={PROTECT_TAG_VALUE}")

    report = {
        "timestamp_utc": str(utcnow()),
        "dry_run": DRY_RUN,
        "trigger": meta,
        "candidates": {},
        "actions": []
    }

    # 1) Discover candidates
    ebs_candidates = find_unattached_ebs_candidates()
    eip_candidates = find_unassociated_eip_candidates()
    ec2_candidates = find_stopped_ec2_candidates()
    lb_candidates = find_idle_load_balancers_candidates()
    nat_candidates = nat_gateways_reporting()

    report["candidates"]["ebs_unattached"] = ebs_candidates
    report["candidates"]["eip_unassociated"] = eip_candidates
    report["candidates"]["ec2_stopped"] = ec2_candidates
    report["candidates"]["lb_potentially_idle"] = lb_candidates
    report["candidates"]["nat_gateway_review"] = nat_candidates

    # 2) Take safe actions (only EBS + EIP in this starter version)
    for vol in ebs_candidates:
        report["actions"].append(delete_ebs_volume(vol["volume_id"]))

    for eip in eip_candidates:
        # allocation_id may be None for older EIPs; in that case, you'd need PublicIp release with different call.
        alloc_id = eip.get("allocation_id")
        if alloc_id:
            report["actions"].append(release_eip(alloc_id))
        else:
            report["actions"].append({"action": "release_eip", "status": "skipped_no_allocation_id", "eip": eip})

    # 3) Log final report
    print("=== Final Report ===")
    log_json("Report", report)

    # Return summary
    return {
        "statusCode": 200,
        "body": {
            "message": "Cost-protection run completed",
            "dry_run": DRY_RUN,
            "counts": {
                "ebs_unattached": len(ebs_candidates),
                "eip_unassociated": len(eip_candidates),
                "ec2_stopped": len(ec2_candidates),
                "lb_potentially_idle": len(lb_candidates),
                "nat_gateway_review": len(nat_candidates),
                "actions": len(report["actions"])
            }
        }
    }
