"""Compare two stored CA configuration patterns in registered synthetic fixtures."""

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
from uuid import UUID

FIXTURE_FILE = Path(__file__).with_name("registered.json")
FIXTURE_SHA256 = "eb748e3859092e6e405cb283b17f74dd1487b4949012de7051e96a92cc104ebb"
AXES = {117: "signInRiskLevels", 118: "userRiskLevels"}
STATES = ("enabled", "disabled", "enabledForReportingButNotEnforced")
RISK_LEVELS = ("low", "medium", "high", "hidden", "none")
MATCH = "StoredPatternObserved"
DIFFERENT = "StoredPatternDifferent"
UNKNOWN = "Unknown"


def _registered():
    # Neither command-line arguments nor fixture fields can select an input file.
    raw = FIXTURE_FILE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError("Registered fixture bytes changed")
    return json.loads(raw)


def _apply_recipe(template, recipe):
    """Apply only local, hash-pinned fixture edits to a fresh in-memory object."""
    obj = copy.deepcopy(template)
    for path, value in recipe.get("set", {}).items():
        if path in obj:
            obj[path] = copy.deepcopy(value)
            continue
        cursor = obj
        *parents, key = path.split(".")
        for part in parents:
            cursor = cursor[part]
        cursor[key] = copy.deepcopy(value)
    for path in recipe.get("omit", []):
        if path in obj:
            del obj[path]
            continue
        cursor = obj
        *parents, key = path.split(".")
        for part in parents:
            cursor = cursor[part]
        del cursor[key]
    return obj


def _exact(obj, keys):
    return isinstance(obj, dict) and set(obj) == set(keys.split())


def _guid(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
        return False
    return UUID(value).int != 0


def _utc(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        return None


def _list(value, allowed=(), identifiers=False):
    if not isinstance(value, list):
        return False
    seen = set()
    for item in value:
        if not isinstance(item, str) or item.casefold() in seen:
            return False
        if item not in allowed and not (identifiers and _guid(item)):
            return False
        seen.add(item.casefold())
    return True


def _one_policy(policy, axis, other, captured):
    """Return a per-policy result. Never borrow a selector or grant from a peer."""
    if not _exact(policy, "@odata.type id displayName createdDateTime modifiedDateTime templateId "
                          "state conditions grantControls sessionControls"):
        return UNKNOWN, "PolicyProjection"
    created, changed = _utc(policy["createdDateTime"]), _utc(policy["modifiedDateTime"])
    if (policy["@odata.type"] != "#microsoft.graph.conditionalAccessPolicy"
            or not _guid(policy["id"]) or not isinstance(policy["displayName"], str)
            or not policy["displayName"].strip() or not created or not changed or not created <= changed <= captured
            or not (policy["templateId"] is None or _guid(policy["templateId"]))
            or policy["state"] not in STATES or policy["sessionControls"] is not None):
        return UNKNOWN, "UnsupportedPolicy"
    c, g = policy["conditions"], policy["grantControls"]
    if not _exact(c, "users applications clientAppTypes signInRiskLevels userRiskLevels "
                     "devices platforms locations authenticationFlows clientApplications "
                     "servicePrincipalRiskLevels insiderRiskLevels"):
        return UNKNOWN, "ConditionProjection"
    u, a = c["users"], c["applications"]
    if not _exact(u, "includeUsers excludeUsers includeGroups excludeGroups includeRoles excludeRoles "
                     "includeGuestsOrExternalUsers excludeGuestsOrExternalUsers"):
        return UNKNOWN, "PrincipalProjection"
    if not _exact(a, "includeApplications excludeApplications includeUserActions "
                     "includeAuthenticationContextClassReferences applicationFilter"):
        return UNKNOWN, "ResourceProjection"
    if not _exact(g, "operator builtInControls customAuthenticationFactors termsOfUse authenticationStrength"):
        return UNKNOWN, "GrantProjection"
    if not _list(c[axis], RISK_LEVELS) or not _list(c[other], RISK_LEVELS):
        return UNKNOWN, "UnsupportedRiskLevel"
    for key in ("devices", "platforms", "locations", "authenticationFlows", "clientApplications",
                "insiderRiskLevels"):
        if c[key] is not None:
            return UNKNOWN, "UnsupportedCondition." + key
    if c["servicePrincipalRiskLevels"] != []:
        return UNKNOWN, "UnsupportedCondition.servicePrincipalRiskLevels"
    for key in ("includeGuestsOrExternalUsers", "excludeGuestsOrExternalUsers"):
        if u[key] is not None:
            return UNKNOWN, "UnsupportedPrincipal." + key
    for key in ("excludeUsers", "includeGroups", "excludeGroups", "includeRoles", "excludeRoles"):
        if not _list(u[key], identifiers=True):
            return UNKNOWN, "UnsupportedPrincipal." + key
    if not _list(u["includeUsers"], ("All",), identifiers=True):
        return UNKNOWN, "UnsupportedPrincipal.includeUsers"
    if "All" in u["includeUsers"] and u["includeUsers"] != ["All"]:
        return UNKNOWN, "MixedAllUsers"
    if u["includeUsers"] == ["All"] and (u["includeGroups"] or u["includeRoles"]):
        return UNKNOWN, "MixedAllPrincipalSelectors"
    if not any(u[k] for k in ("includeUsers", "includeGroups", "includeRoles")):
        return UNKNOWN, "NoSupportedPrincipal"
    if a["applicationFilter"] is not None or a["includeAuthenticationContextClassReferences"] != []:
        return UNKNOWN, "UnsupportedResourceFilterOrContext"
    if a["includeUserActions"] != []:
        return UNKNOWN, "UnsupportedUserActions"
    if not _list(a["includeApplications"], ("All", "Office365", "MicrosoftAdminPortals"), True):
        return UNKNOWN, "UnsupportedResource.includeApplications"
    if not a["includeApplications"] or ("All" in a["includeApplications"] and a["includeApplications"] != ["All"]):
        return UNKNOWN, "UnsupportedResourceSet"
    if not _list(a["excludeApplications"], ("Office365", "MicrosoftAdminPortals"), True):
        return UNKNOWN, "UnsupportedResource.excludeApplications"
    clients = c["clientAppTypes"]
    if not _list(clients, ("all", "browser", "mobileAppsAndDesktopClients", "exchangeActiveSync",
                           "easSupported", "other")) or not clients or ("all" in clients and clients != ["all"]):
        return UNKNOWN, "UnsupportedClientSet"
    controls = g["builtInControls"]
    if (g["operator"] not in ("AND", "OR") or g["authenticationStrength"] is not None
            or g["customAuthenticationFactors"] != [] or g["termsOfUse"] != []):
        return UNKNOWN, "UnsupportedGrant"
    password_change = (g["operator"] == "AND" and c["userRiskLevels"] and not c["signInRiskLevels"]
                       and controls in (["passwordChange", "mfa"], ["mfa", "passwordChange"]))
    if controls not in (["block"], ["mfa"]) and not password_change:
        return UNKNOWN, "UnsupportedBuiltInControls"

    if policy["state"] != "enabled":
        return DIFFERENT, "State." + policy["state"]
    if controls != ["block"]:
        return DIFFERENT, "GrantDoesNotBlock"
    if "high" not in c[axis]:
        return DIFFERENT, "HighNotSelected." + axis
    if c[other]:
        return DIFFERENT, "ConjoinedRiskAxis." + other
    if (u["includeUsers"] != ["All"] or any(u[k] for k in (
            "excludeUsers", "includeGroups", "excludeGroups", "includeRoles", "excludeRoles"))):
        return DIFFERENT, "DeclaredPrincipalSetDiffers"
    if a["includeApplications"] != ["All"] or a["excludeApplications"]:
        return DIFFERENT, "DeclaredResourceSetDiffers"
    if clients != ["all"]:
        return DIFFERENT, "DeclaredClientTypesDiffer"
    return MATCH, "EnabledSoleBlock." + axis


def _source_problem(source):
    if not _exact(source, "SourceId Group Provider Target Status Count PageCount RequestCount "
                          "Items CollectedAtUtc Reason"):
        return "SourceProjection"
    if (source["SourceId"] != "conditional-access" or source["Group"] != "Core"
            or source["Provider"] != "Graph" or source["Target"] != "/identity/conditionalAccess/policies"
            or source["Status"] != "Collected" or not _utc(source["CollectedAtUtc"])
            or not isinstance(source["Reason"], str)):
        return "SourceIdentityOrState"
    items = source["Items"]
    if (type(source["PageCount"]) is not int or source["PageCount"] != 1
            or type(source["RequestCount"]) is not int or source["RequestCount"] != 1
            or type(source["Count"]) is not int or not isinstance(items, list)
            or source["Count"] != len(items) or not 1 <= len(items) <= 32):
        return "SourceIncompleteOrEmpty"
    ids = set()
    for policy in items:
        if not isinstance(policy, dict) or not _guid(policy.get("id")) or policy["id"].lower() in ids:
            return "InvalidOrDuplicateIdentity"
        ids.add(policy["id"].lower())
    return None


def _aggregate(source, row):
    problem = _source_problem(source)
    axis, other = AXES[row], AXES[118 if row == 117 else 117]
    comparisons = []
    if not problem:
        captured = _utc(source["CollectedAtUtc"])
        comparisons = [_one_policy(policy, axis, other, captured) for policy in source["Items"]]
    if problem:
        result = UNKNOWN
    elif any(status == MATCH for status, _ in comparisons):
        result = MATCH
    elif any(status == UNKNOWN for status, _ in comparisons):
        result = UNKNOWN
    else:
        result = DIFFERENT
    return {"PhysicalRow": row, "SourceId": "conditional-access", "RiskField": "conditions." + axis,
            "StoredComparison": result, "SourceProblem": problem,
            "PolicyResults": [{"RecordOrdinal": i, "Comparison": status, "Reason": reason}
                              for i, (status, reason) in enumerate(comparisons, start=1)],
            "Status": "Not assessed", "EffectiveOutcomeVerified": False, "FullRowMappingCredit": 0}


def compare_fixture(identifier):
    pack = _registered()
    if pack["kind"] != "InventedFixturesOnly" or pack["realInputsEnabled"] is not False:
        raise ValueError("Unsupported fixture contract")
    if not isinstance(identifier, str) or identifier not in pack["cases"]:
        raise ValueError("Unregistered fixture ID")
    recipe = pack["cases"][identifier]
    source = copy.deepcopy(pack["source"])
    source["Items"] = [_apply_recipe(pack["policy"], record) for record in recipe["records"]]
    source["Count"] = len(source["Items"])
    source = _apply_recipe(source, recipe.get("source", {}))
    return {"Fixture": identifier, "SyntheticOnly": True, "Rows": [_aggregate(source, row) for row in AXES]}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Supply one registered fixture ID")
    try:
        print(json.dumps(compare_fixture(sys.argv[1]), indent=2))
    except ValueError as error:
        sys.exit(str(error))
