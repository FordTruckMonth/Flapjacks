"""Bounded review of registered Authentication-group synthetic audit captures."""
import hashlib
import json
from pathlib import Path
import sys
from types import ModuleType
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
SOURCE = 'authentication-methods-policy'
TARGET = '/policies/authenticationMethodsPolicy'
TENANT = 'SYNTHETIC-NOT-A-TENANT'
WORKBOOK = '92b9e3c82bf9980e8055f4f0953ce975ec16d99bb0b25880f9edcaae9b1c1472'
REGISTRY_PIN = 'ea08a41ed0dc1df73b40e65ea0ebee2931d2d608ea472939b913d127ff5395d8'
PREDICATE_PIN = 'd68f41489be0bcc76aef8c8707adb69f6c4b8f0ef6fe6be4e81b3d5b2fc84d63'
DISK = {'Metadata', 'Coverage', 'Observations'}
MEMORY = DISK | {'Evidence', 'Mode', 'TenantId', 'SelectedCount', 'CollectedCount',
                 'IncompleteCount', 'FindingCount', 'OutputPath'}
META = set('SchemaVersion ToolVersion Mode TenantId StartedAtUtc FinishedAtUtc PowerShellVersion '
           'SelectedGroups MaxPages MaxRecords OrganizationWideConfirmed AccountVerification Scope Privacy'.split())
SUMMARY = set('SourceId Group Provider Status Count Reason MissingFields Notes'.split())


def pinned(path, expected):
    data = path.read_bytes()
    if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Fixture package integrity check failed')
    return data


def strict_json(data):
    def unique(pairs):
        record = {}
        names = set()
        for key, value in pairs:
            if key.casefold() in names:
                raise ValueError('Duplicate member')
            record[key] = value
            names.add(key.casefold())
        return record

    def reject(_):
        raise ValueError('Unsupported number')

    return json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=reject)


def same(left, right):
    # JSON type-sensitive equality. Python considers True and 1 equal.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


# Load the checked bytes directly, with no caller-supplied import path.
predicate = ModuleType('reviewed_method_predicate')
exec(compile(pinned(ROOT / 'row151.py', PREDICATE_PIN), 'row151.py', 'exec'), predicate.__dict__)


def claims_singleton(record):
    sid = record.get('SourceId')
    if isinstance(sid, str) and sid.strip().casefold() == SOURCE:
        return True
    target = record.get('Target')
    if not isinstance(target, str):
        return False
    path = urlsplit(unquote(target.strip())).path.strip('/').casefold()
    for version in ('v1.0/', 'beta/'):
        if path.startswith(version):
            path = path[len(version):]
    return path == TARGET.strip('/').casefold()


def compare(raw, fixture, registration, catalog, workbook):
    bind = dict(AuditSha256=hashlib.sha256(raw).hexdigest(), Representation=registration['Representation'],
                ReferenceWorkbookSha256=workbook, StartedAtUtc=None, FinishedAtUtc=None,
                ReviewAtUtc=registration['ReviewAtUtc'], CollectedAtUtc=None, SourceArray=None,
                ClaimantCount=None, SelectedOrdinal=None, SelectionResult='Unbound')

    def unknown(reason):
        bind['SelectionResult'] = reason
        return dict(Row=151, Comparison='Unknown', Reason=reason, Binding=bind)

    if bind['AuditSha256'] != registration['AuditSha256'] or workbook != WORKBOOK:
        return unknown('OriginalAuditBindingMismatch')
    try:
        audit = strict_json(raw)
        input_data = strict_json(fixture)
    except (TypeError, ValueError, RecursionError):
        return unknown('InvalidEvidenceJson')
    if hashlib.sha256(fixture).hexdigest() != registration['InputSha256']:
        return unknown('FixtureInputBindingMismatch')
    if not isinstance(audit, dict) or not isinstance(input_data, dict):
        return unknown('InvalidAuditShape')
    if registration['Representation'] == 'NativeAuditJson' and set(audit) == DISK:
        bank = 'Coverage'
    elif registration['Representation'] == 'SerializedAuditResult' and set(audit) == MEMORY:
        if audit['Mode'] != 'Synthetic' or audit['TenantId'] != TENANT or audit['OutputPath'] != '':
            return unknown('SnapshotOriginMismatch')
        bank = 'Evidence'
    else:
        return unknown('RepresentationMismatch')
    bind['SourceArray'] = bank
    meta = audit['Metadata']
    if (not isinstance(meta, dict) or set(meta) != META or meta['SchemaVersion'] != '1.1'
            or meta['Mode'] != 'Synthetic' or meta['TenantId'] != TENANT
            or meta['SelectedGroups'] != ['Core', 'Authentication'] or meta['OrganizationWideConfirmed'] is not False
            or meta['AccountVerification'] != 'Synthetic: not applicable' or not isinstance(audit['Observations'], list)):
        return unknown('AuditOriginMismatch')
    start, end, review = [predicate.utc_ticks(t) for t in
                          (meta['StartedAtUtc'], meta['FinishedAtUtc'], registration['ReviewAtUtc'])]
    if None in (start, end, review) or not start <= end <= review:
        return unknown('InvalidAuditWindow')
    bind.update(StartedAtUtc=meta['StartedAtUtc'], FinishedAtUtc=meta['FinishedAtUtc'])
    if any(registration[k] != meta[k] for k in ('StartedAtUtc', 'FinishedAtUtc')):
        return unknown('RunWindowBindingMismatch')

    records = audit[bank]
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        return unknown('FullInventoryUnavailable')
    try:
        claimants = [(i, r) for i, r in enumerate(records, 1) if claims_singleton(r)]
    except ValueError:
        return unknown('InvalidSourceIdentity')
    bind['ClaimantCount'] = len(claimants)
    if len(claimants) != 1:
        return unknown('AmbiguousOrMissingSource')
    ordinal, source = claimants[0]
    if any(registration[k] != v or source.get(k) != v for k, v in predicate.SOURCE.items()):
        return unknown('SourceBindingMismatch')
    known = {source['Id']: source for source in catalog}
    by_id = {}
    for record in records:
        sid = record.get('SourceId')
        if not isinstance(sid, str) or sid in by_id or sid not in known or set(record) != predicate.ENVELOPE:
            return unknown('FullInventoryMismatch')
        if any(known[sid][key] != record[key] for key in ('Group', 'Provider', 'Target')):
            return unknown('CatalogBindingMismatch')
        if (not isinstance(record['Items'], list) or type(record['Count']) is not int
                or record['Count'] != len(record['Items'])):
            return unknown('IncompleteRecord')
        by_id[sid] = record
    if set(known) != set(by_id):
        return unknown('FullInventoryMismatch')
    if bank == 'Evidence':
        coverage = audit['Coverage']
        if not isinstance(coverage, list) or len(coverage) != len(records):
            return unknown('CoverageSummaryMismatch')
        seen = set()
        for item in coverage:
            if not isinstance(item, dict) or set(item) != SUMMARY:
                return unknown('CoverageSummaryMismatch')
            sid = item['SourceId']
            if not isinstance(sid, str) or sid not in by_id or sid in seen:
                return unknown('CoverageSummaryMismatch')
            if not same(item, {k: by_id[sid][k] for k in SUMMARY}):
                return unknown('CoverageSummaryMismatch')
            seen.add(sid)
        counters = dict(SelectedCount=sum(r['Status'] != 'NotSelected' for r in records),
                        CollectedCount=sum(r['Status'] == 'Collected' for r in records),
                        IncompleteCount=sum(r['Status'] not in ('Collected', 'NotSelected') for r in records),
                        FindingCount=len(audit['Observations']))
        if any(not same(audit[k], value) for k, value in counters.items()):
            return unknown('SnapshotCountersMismatch')

    bind['SelectedOrdinal'] = ordinal
    capture = predicate.utc_ticks(source['CollectedAtUtc'])
    if capture is None:
        return unknown('InvalidCaptureTime')
    bind['CollectedAtUtc'] = source['CollectedAtUtc']
    if source['CollectedAtUtc'] != registration['CollectedAtUtc'] or not start <= capture <= end:
        return unknown('CaptureBindingMismatch')
    if review - capture > 86400 * 10_000_000:
        return unknown('CaptureOutsideFreshnessWindow')
    # Only Invoke-M365SecurityAudit -Mode Synthetic produced these registered
    # whole audits. The staged single-record comparator also accepts callback
    # counters, which alone cannot attest an injected observation to this run.
    if (type(source['RequestCount']) is not int or source['RequestCount'] != 0
            or source['Reason'] != predicate.SYNTHETIC_REASON):
        return unknown('CaptureSignatureMismatch')
    supplied = input_data.get(SOURCE)
    if not isinstance(supplied, dict) or not same(supplied, {k: source[k] for k in ('Status', 'Reason', 'Items')}):
        return unknown('CaptureInputMismatch')
    bind['SelectionResult'] = 'Selected'
    result = predicate.evaluate(source, as_of_utc=registration['ReviewAtUtc'])
    comparison = {'match': 'Matches', 'difference': 'Differs', 'unavailable': 'Unknown'}[result['comparison']]
    return dict(Row=151, Comparison=comparison, Reason=result['reason'], Binding=bind)


def registered(fixture_id):
    registry = strict_json(pinned(ROOT / 'registry.json', REGISTRY_PIN))
    registration = registry['Cases'][fixture_id]
    raw = pinned(ROOT / registration['AuditPath'], registration['AuditSha256'])
    fixture = pinned(ROOT / registration['InputPath'], registration['InputSha256'])
    return compare(raw, fixture, registration, registry['Catalog'], registry['ReferenceWorkbookSha256'])


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('One registered identifier is required')
    print(json.dumps(registered(sys.argv[1]), allow_nan=False))
