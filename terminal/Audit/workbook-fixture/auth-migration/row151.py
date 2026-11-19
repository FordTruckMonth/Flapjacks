"""Compare the stored SMS/voice states in one invented native Graph source record."""

import json
import math
import re
from datetime import datetime


PATH = "policies/authenticationMethodsPolicy"
CONFIGS = "authenticationMethodConfigurations"
CONFIG_PATH = PATH + "/" + CONFIGS
METADATA = "https://graph.microsoft.com/v1.0/$metadata#"
GRAPH = "https://graph.microsoft.com/v1.0/"
SYNTHETIC_REASON = "Synthetic fixture, not tenant data."
SOURCE = {
    "SourceId": "authentication-methods-policy",
    "Group": "Authentication",
    "Provider": "Graph",
    "Target": "/" + PATH,
}
ENVELOPE = set(SOURCE) | {
    "Status", "Reason", "CollectedAtUtc", "PageCount", "RequestCount",
    "Count", "Items", "MissingFields", "Notes",
}
POLICY_FIELDS = {
    "id", "@odata.context", "@odata.type", "@odata.id", "@microsoft.graph.tips",
    "displayName", "description", "lastModifiedDateTime", "policyVersion",
    "registrationEnforcement", "systemCredentialPreferences", "reportSuspiciousActivitySettings",
    "policyMigrationState", CONFIGS, CONFIGS + "@odata.context", CONFIGS + "@odata.type",
    CONFIGS + "@odata.count",
}
METHOD_TYPES = {name: "microsoft.graph." + name.lower() + "AuthenticationMethodConfiguration"
                for name in ("Sms", "Voice")}
METHOD_FIELDS = {
    "id", "state", "@odata.type", "@odata.id", "@odata.context", "telecomProviderSettings",
    "includeTargets", "excludeTargets",
} | {field + suffix for field in ("includeTargets", "excludeTargets")
     for suffix in ("@odata.context", "@odata.count")}
VOICE_FIELDS = {"isOfficePhoneAllowed", "callerIdNumber", "isCustomGreetingEnabled"}
PAGING = ("@odata.nextlink", "@odata.deltalink")
CONFLICT_KEYS = {"error", "@odata.error", "casepath", "timeline", "collections", "evidence",
                 "sourceid", "tenantid", "runid", "signins", "targetupn", "messageid",
                 "mailbox_upn", "networkmessageid", "correlations", "@removed", "@odata.removed"}


def result(comparison, reason):
    return {"row": 151, "comparison": comparison, "reason": reason,
            "scope": "stored authentication method states",
            "tenant_assessment": "Not assessed", "effective_enforcement": "Not assessed"}


def utc_ticks(value):
    """UTC timestamps in the native round-trip format, preserving all seven decimals."""
    pattern = r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,7}))?Z"
    match = re.fullmatch(pattern, value) if isinstance(value, str) else None
    if not match:
        return None
    try:
        time = datetime.fromisoformat(match[1])
    except ValueError:
        return None
    seconds = (time.toordinal() * 24 + time.hour) * 3600 + time.minute * 60 + time.second
    return seconds * 10_000_000 + int((match[2] or "").ljust(7, "0"))


def optional(value, field, allowed):
    return field not in value or (isinstance(value[field], str) and value[field] in allowed)


def uri_forms(paths):
    return tuple(prefix + path for prefix in ("", "/v1.0/", GRAPH) for path in paths)


def contexts(fragments):
    return tuple(METADATA + fragment for fragment in fragments)


def conflicts(value, depth=0):
    """Retain the sealed policy-level guard for partial or mixed-provenance evidence."""
    if depth > 24:
        return True
    if isinstance(value, list):
        return any(conflicts(item, depth + 1) for item in value)
    if not isinstance(value, dict):
        return isinstance(value, float) and not math.isfinite(value)
    if any(not isinstance(key, str) for key in value):
        return True
    keys = [key.casefold() for key in value]
    return (len(keys) != len(set(keys)) or any(key in CONFLICT_KEYS or key.endswith(PAGING)
                                                for key in keys) or
            any(conflicts(child, depth + 1) for child in value.values()))


def length_agrees(obj, field, values):
    key = field + "@odata.count"
    return key not in obj or (type(obj[key]) is int and obj[key] == len(values))


def source_issue(record, as_of_utc):
    if not isinstance(record, dict) or set(record) != ENVELOPE:
        return "invalid-native-envelope"
    if any(record[key] != value for key, value in SOURCE.items()):
        return "wrong-native-source"
    if record["Status"] != "Collected" or record["Notes"] != "" or record["MissingFields"] != []:
        return "incomplete-or-conflicting-source"
    for field, allowed in (("Count", (1,)), ("PageCount", (1,))):
        if type(record[field]) is not int or record[field] not in allowed:
            return "invalid-singleton-counters"
    requests = record["RequestCount"]
    if type(requests) is not int or not (
            (record["Reason"] == "" and 1 <= requests <= 4) or
            (record["Reason"] == SYNTHETIC_REASON and requests == 0)):
        return "invalid-request-count-or-reason"
    if not isinstance(record["Items"], list) or len(record["Items"]) != 1:
        return "invalid-singleton-cardinality"
    read, as_of = utc_ticks(record["CollectedAtUtc"]), utc_ticks(as_of_utc)
    if read is None or as_of is None or not 0 <= as_of - read <= 86400 * 10_000_000:
        return "invalid-or-outdated-time"
    return None


def policy_issue(policy):
    if (not isinstance(policy, dict) or policy.keys() - POLICY_FIELDS or
            policy.get("id") != "authenticationMethodsPolicy"):
        return "invalid-policy-singleton"
    if conflicts(policy):
        return "partial-or-conflicting-policy"
    root_type = "microsoft.graph.authenticationMethodsPolicy"
    root_contexts = ("authenticationMethodsPolicy", root_type, PATH, PATH + "/$entity")
    if not (optional(policy, "@odata.id", uri_forms((PATH,))) and
            optional(policy, "@odata.type", (root_type, "#" + root_type)) and
            optional(policy, "@odata.context", contexts(root_contexts))):
        return "contradictory-policy-metadata"
    configs = policy.get(CONFIGS)
    if not isinstance(configs, list) or not 2 <= len(configs) <= 64:
        return "missing-or-unsupported-expansion"
    collection_type = "Collection(microsoft.graph.authenticationMethodConfiguration)"
    if not (optional(policy, CONFIGS + "@odata.context", contexts((CONFIG_PATH, collection_type))) and
            optional(policy, CONFIGS + "@odata.type", (collection_type, "#" + collection_type)) and
            length_agrees(policy, CONFIGS, configs)):
        return "contradictory-expansion-metadata"
    return None


def method_paths(name):
    return (CONFIG_PATH + "/" + name, CONFIG_PATH + "('" + name + "')")


def method_metadata_agrees(config, name, native_type):
    paths = method_paths(name)
    fragments = paths + tuple(path + "/$entity" for path in paths) + (CONFIGS + "/$entity",)
    if native_type:
        fragments += (native_type,)
    return (optional(config, "@odata.id", uri_forms(paths)) and
            optional(config, "@odata.context", contexts(fragments)))


def selected_method_issue(config, name):
    native_type = METHOD_TYPES[name]
    allowed = METHOD_FIELDS | (VOICE_FIELDS if name == "Voice" else set())
    if (config.keys() - allowed or config.get("@odata.type") != "#" + native_type or
            config.get("state") not in ("enabled", "disabled")):
        return "invalid-selected-method"
    if not method_metadata_agrees(config, name, native_type):
        return "contradictory-method-metadata"
    for field in ("includeTargets", "excludeTargets"):
        if field in config or any(k.startswith(field + "@") for k in config):
            targets = config.get(field)
            if (not isinstance(targets, list) or
                    any(not isinstance(target, dict) for target in targets) or
                    not length_agrees(config, field, targets)):
                return "invalid-target-collection"
            locations = tuple(base + cast + "/" + field
                              for base in method_paths(name) for cast in ("", "/" + native_type))
            if not optional(config, field + "@odata.context", contexts(locations)):
                return "contradictory-target-metadata"
    return None


def evaluate(record, *, as_of_utc):
    """Accept a JSON-decoded native result inside the caller's synthetic fixture boundary."""
    issue = source_issue(record, as_of_utc)
    if issue:
        return result("unavailable", issue)
    policy = record["Items"][0]
    issue = policy_issue(policy)
    if issue:
        return result("unavailable", issue)
    seen, states = set(), {}
    for config in policy[CONFIGS]:
        name = config.get("id") if isinstance(config, dict) else None
        if not isinstance(name, str) or not re.fullmatch("[A-Za-z][A-Za-z0-9]{0,63}", name):
            return result("unavailable", "invalid-method-identity")
        key = name.casefold()
        if key in seen:
            return result("unavailable", "duplicate-method-identity")
        seen.add(key)
        if name in METHOD_TYPES:
            issue = selected_method_issue(config, name)
            if issue:
                return result("unavailable", issue)
            states[name] = config["state"]
        else:
            # A third object cannot claim the identity of either selected method by type or URI.
            # Its own state, assignments, and method-specific settings do not enter row 151.
            supplied_type = config.get("@odata.type")
            if "@odata.type" in config and (not isinstance(supplied_type, str) or not re.fullmatch(
                    r"#?microsoft\.graph\.[a-zA-Z][a-zA-Z0-9]*AuthenticationMethodConfiguration", supplied_type)):
                return result("unavailable", "invalid-method-type")
            native_type = supplied_type.lstrip("#") if supplied_type else None
            if (key in ("sms", "voice") or
                    any(k.casefold() in ("id", "@odata.type", "@odata.id", "@odata.context")
                        and k != k.casefold() for k in config) or
                    (native_type and native_type.casefold() in (v.casefold() for v in METHOD_TYPES.values())) or
                    not method_metadata_agrees(config, name, native_type)):
                return result("unavailable", "contradictory-method-identity")
    if states.keys() != METHOD_TYPES.keys():
        return result("unavailable", "required-method-missing")
    if policy.get("policyMigrationState") != "migrationComplete":
        return result("unavailable", "completed-migration-unestablished")
    if "enabled" in states.values():
        return result("difference", "stored-method-enabled")
    return result("match", "both-stored-methods-disabled")


def evaluate_json(record_json, *, as_of_utc):
    """Use at a JSON boundary where duplicate member names must be detected before decoding."""
    def distinct(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("duplicate member")
            obj[key] = value
        return obj

    def reject_constant(_value):
        raise ValueError("unsupported JSON number")

    try:
        record = json.loads(record_json, object_pairs_hook=distinct, parse_constant=reject_constant)
    except (TypeError, ValueError, RecursionError):
        return result("unavailable", "invalid-json-record")
    return evaluate(record, as_of_utc=as_of_utc)
