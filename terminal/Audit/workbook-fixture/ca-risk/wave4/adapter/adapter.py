"""Offline report adapter for CA risk rows 117/118. Public inputs are registered synthetic reports."""
import hashlib
import json
from pathlib import Path
import re
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parent
WAVE = ROOT.parent
SOURCE_ID = 'conditional-access'
SYNTHETIC_TENANT = 'SYNTHETIC-NOT-A-TENANT'
MAX_BYTES = 4 * 1024 * 1024
SOURCE_KEYS = frozenset('SourceId Group Provider Target Status Reason CollectedAtUtc '
                        'PageCount RequestCount Count Items MissingFields Notes'.split())
SUMMARY_KEYS = frozenset('SourceId Group Provider Status Count Reason MissingFields Notes'.split())
POLICY_PATH = WAVE.parent / 'wave2/risk/risk.py'
POLICY_SHA = 'a8cf5fe09108a3f3b481fd3785a7cc5ab81159ab7aeabb35ba2a26f154acd5f9'
MANIFEST_SHA = 'b1ef9b2cc6f109fdb4401b8a44654c824ca62a8b8f72142e276c6fc737e7cc8c'
ROW_DEFS = {
    117: ('CA-SIGNIN-RISK-HIGH-BLOCK', 'Independent high sign-in risk block'),
    118: ('CA-USER-RISK-HIGH-BLOCK', 'Independent high user risk block'),
}
REFERENCE = 'https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_policy():
    data = POLICY_PATH.read_bytes()
    if digest(data) != POLICY_SHA:
        raise ValueError('Wave 2 comparator digest mismatch')
    module = ModuleType('staged_wave2_risk')
    module.__file__ = str(POLICY_PATH)
    exec(compile(data, module.__file__, 'exec'), module.__dict__)
    return module


risk = load_policy()


def unique_object(pairs):
    result = {}
    seen = set()
    for key, value in pairs:
        if key.casefold() in seen:
            raise ValueError('Duplicate JSON property')
        seen.add(key.casefold())
        result[key] = value
    return result


def parse(data):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES:
        raise ValueError('Invalid or oversized input')
    def reject_constant(_):
        raise ValueError('Non-finite JSON value')
    try:
        return json.loads(data.decode('utf-8-sig'), object_pairs_hook=unique_object, parse_constant=reject_constant)
    except RecursionError:
        raise ValueError('Excessive JSON depth') from None


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def registry():
    data = (ROOT / 'manifest.json').read_bytes()
    if digest(data) != MANIFEST_SHA:
        raise ValueError('Fixture manifest digest mismatch')
    return parse(data)['Cases']


def time_parts(value):
    """Return comparable .NET 100-ns UTC instant plus comparator-compatible spelling."""
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?Z', value, re.ASCII)
    if not m:
        return None
    frac = (m[2] or '').ljust(7, '0')
    shortened = m[1] + '.' + frac[:6] + 'Z'
    dt = risk._utc(shortened)
    return ((dt, int(frac[6])), shortened) if dt else None


def choose_source(report):
    """Select one complete native evidence bank. Never combine source fields across banks."""
    if not isinstance(report, dict):
        return None, 'Unknown', 'ReportProjection'
    evidence, coverage = report.get('Evidence'), report.get('Coverage')
    if 'Evidence' in report and (not isinstance(evidence, list) or not evidence):
        return None, 'Unknown', 'EvidenceProjection'
    if 'Coverage' in report and not isinstance(coverage, list):
        return None, 'Unknown', 'CoverageProjection'
    if 'Observations' in report and not isinstance(report['Observations'], list):
        return None, 'Unknown', 'ObservationsProjection'
    bank = 'Evidence' if evidence else 'Coverage'
    records = report.get(bank)
    if not isinstance(records, list) or not records:
        return None, bank, 'FullSourcesUnavailable'
    selected = {}
    for rec in records:
        if not isinstance(rec, dict):
            return None, bank, 'SourceProjection'
        source_id = rec.get('SourceId')
        if not isinstance(source_id, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,99}', source_id):
            return None, bank, 'InvalidSourceIdentity'
        if source_id in selected:
            return None, bank, 'DuplicateSourceIdentity'
        selected[source_id] = rec
    ca = selected.get(SOURCE_ID)
    for rec in selected.values():
        if not isinstance(rec.get('Items'), list) or type(rec.get('Count')) is not int or rec['Count'] != len(rec['Items']):
            return ca, bank, 'SummaryOnlyOrInvalidCount'
    if bank == 'Evidence':
        # Invoke-M365SecurityAudit returns full Evidence plus one summary per source.
        # A second full bank, missing source or conflicting summary is ambiguous.
        if not isinstance(coverage, list) or len(coverage) != len(selected):
            return ca, bank, 'EvidenceCoverageDisagreement'
        seen = set()
        for summary in coverage:
            if not isinstance(summary, dict) or set(summary) != SUMMARY_KEYS:
                return ca, bank, 'EvidenceCoverageDisagreement'
            sid = summary['SourceId']
            if not isinstance(sid, str) or sid in seen or sid not in selected:
                return ca, bank, 'EvidenceCoverageDisagreement'
            if canonical(summary) != canonical({k: selected[sid].get(k) for k in SUMMARY_KEYS}):
                return ca, bank, 'EvidenceCoverageDisagreement'
            seen.add(sid)
    return selected.get(SOURCE_ID), bank, None if SOURCE_ID in selected else 'MissingConditionalAccessSource'


def native_gate(metadata, source):
    if not isinstance(metadata, dict) or metadata.get('SchemaVersion') != '1.1':
        return 'UnsupportedReportMetadata'
    if (metadata.get('Mode') != 'Synthetic' or metadata.get('TenantId') != SYNTHETIC_TENANT
            or metadata.get('OrganizationWideConfirmed') is not False):
        return 'UnsupportedDeclaredModeOrIdentity'
    groups = metadata.get('SelectedGroups')
    if not isinstance(groups, list) or 'Core' not in groups:
        return 'CoreSelectionUnverified'
    if set(source) != SOURCE_KEYS:
        return 'NativeSourceProjection'
    if (source['Group'] != 'Core' or source['Provider'] != 'Graph'
            or source['Target'] != '/identity/conditionalAccess/policies'):
        return 'NativeSourceIdentity'
    if source['Status'] != 'Collected':
        return 'SourceNotCollected'
    if source['MissingFields'] != [] or not all(isinstance(source[k], str) for k in ('Reason', 'Notes')):
        return 'NativeSourceQuality'
    # Synthetic mode in Run.ps1 sets PageCount=1 on Collected; no request is made.
    if (type(source['PageCount']) is not int or source['PageCount'] != 1
            or type(source['RequestCount']) is not int or source['RequestCount'] != 0
            or not 1 <= source['Count'] <= 32):
        return 'UnsupportedNativeSyntheticCounts'
    capture = time_parts(source['CollectedAtUtc'])
    if not capture:
        return 'InvalidSourceTimestamp'
    start, end = time_parts(metadata.get('StartedAtUtc')), time_parts(metadata.get('FinishedAtUtc'))
    if not start or not end or not start[0] <= capture[0] <= end[0]:
        return 'SourceOutsideReportedRun'
    ids = set()
    for p in source['Items']:
        if not isinstance(p, dict) or not risk._guid(p.get('id')) or p['id'].casefold() in ids:
            return 'InvalidOrDuplicateIdentity'
        ids.add(p['id'].casefold())
    return None


def compare_policy(policy, row, capture):
    created = time_parts(policy.get('createdDateTime'))
    modified = time_parts(policy.get('modifiedDateTime'))
    if created and modified:
        if not created[0] <= modified[0] <= capture[0]:
            return risk.UNKNOWN, 'InvalidPolicyChronology'
        # The reused policy predicate uses Python microseconds. Perform chronology at the
        # native precision above; the copy changes only the two timestamp spellings.
        policy = dict(policy, createdDateTime=created[1], modifiedDateTime=modified[1])
    return risk._one_policy(policy, risk.AXES[row], risk.AXES[118 if row == 117 else 117], capture[0][0])


def row_result(source, problem, row):
    comparisons = []
    if not problem:
        capture = time_parts(source['CollectedAtUtc'])
        comparisons = [compare_policy(policy, row, capture) for policy in source['Items']]
    verdicts = [status for status, _ in comparisons]
    if risk.MATCH in verdicts:
        comparison = risk.MATCH
    elif not verdicts or risk.UNKNOWN in verdicts:
        comparison = risk.UNKNOWN
    else:
        comparison = risk.DIFFERENT
    return {
        'PhysicalRow': row, 'SourceId': SOURCE_ID, 'RiskField': 'conditions.' + risk.AXES[row],
        'StoredComparison': comparison, 'SourceProblem': problem,
        'PolicyResults': [{'RecordOrdinal': i, 'Comparison': status, 'Reason': reason}
                          for i, (status, reason) in enumerate(comparisons, 1)],
        'Status': 'Not assessed', 'EffectiveOutcomeVerified': False, 'FullRowMappingCredit': 0,
        'LiveVerified': False, 'LiveCredit': 0,
    }


def check_for(row, source):
    number = row['PhysicalRow']
    cid, control = ROW_DEFS[number]
    field = row['RiskField']
    other = 'conditions.' + risk.AXES[118 if number == 117 else 117]
    matches = [p for p in row['PolicyResults'] if p['Comparison'] == risk.MATCH]
    conjoined = any(p['Reason'].startswith('ConjoinedRiskAxis.') for p in row['PolicyResults'])
    if matches:
        detail = 'The invented report contains an enabled block policy for this risk criterion independently.'
    elif row['StoredComparison'] == risk.UNKNOWN:
        detail = 'The invented report supplies insufficient supported evidence for this comparison.'
    elif conjoined:
        detail = 'The invented policies differ from the independent criterion. A policy requires both risk criteria together.'
    else:
        detail = 'The supplied invented policies differ from the selected independent block criterion.'
    return {
        'ControlId': cid, 'Control': control, 'Status': row['Status'], 'SourceId': SOURCE_ID,
        'Field': field, 'SourceStatus': source.get('Status', 'Missing') if source else 'Missing',
        'EvidenceIds': [], 'EvidenceTime': source.get('CollectedAtUtc', '') if source else '',
        'Expected': f'An enabled sole-block policy includes high in {field} and explicitly leaves {other} empty '
                    'for all users, resources and client types without exclusions.',
        'Observed': detail, 'StatusDetailsSafe': detail,
        'Rationale': 'The two risk selectors identify different Conditional Access criteria.',
        'Limitation': 'Effective coverage, enforcement, licensing and workbook scope remain unassessed.',
        'AccessPrerequisites': 'Invented saved configuration only. Tenant applicability and outcomes are unverified.',
        'Reference': REFERENCE, 'ProfileVersion': 'Offline fixture handoff 1',
        'PhysicalRow': number, 'StoredComparison': row['StoredComparison'], 'FullRowMappingCredit': 0,
        'WitnessOrdinals': [p['RecordOrdinal'] for p in matches],
        'PolicyResults': row['PolicyResults'], 'SourceProblem': row['SourceProblem'],
        'LiveCredit': 0, 'LiveVerified': False, 'EffectiveOutcomeVerified': False,
    }


def _evaluate(report, selector, fixture):
    metadata = report.get('Metadata') if isinstance(report, dict) else None
    source, bank, problem = choose_source(report)
    problem = problem or native_gate(metadata, source)
    if not problem and bank == 'Evidence' and not {'Mode', 'TenantId'}.issubset(report):
        problem = 'MissingSnapshotIdentity'
    if not problem and any(k in report and report[k] != metadata.get(k) for k in ('Mode', 'TenantId')):
        problem = 'ReportMetadataDisagreement'
    meta = metadata if isinstance(metadata, dict) else {}
    rows = [row_result(source, problem, row) for row in ROW_DEFS]
    checks = [check_for(row, source) for row in rows]
    observations = [
        {'SourceId': SOURCE_ID, 'ObjectId': '', 'Rule': check['ControlId'], 'Severity': 'Informational',
         'Title': check['Control'], 'Detail': check['Observed']} for check in checks
    ]
    return {
        'Fixture': selector, 'SyntheticOnly': True,
        'ReportProvenance': {
            'Producer': fixture['Producer'], 'CanonicalInputSha256': fixture['CanonicalSha256'],
            'PinnedFileSha256': fixture['FileSha256'], 'SourceBank': bank,
            'DeclaredMode': meta.get('Mode'), 'DeclaredTenantId': meta.get('TenantId'),
            'SchemaVersion': meta.get('SchemaVersion'), 'TenantIdentityVerified': False,
            'OrganizationWideConfirmed': meta.get('OrganizationWideConfirmed'),
            'RootMode': report.get('Mode') if isinstance(report, dict) else None,
            'RootTenantId': report.get('TenantId') if isinstance(report, dict) else None,
            'SelectedGroups': meta.get('SelectedGroups'), 'StartedAtUtc': meta.get('StartedAtUtc'),
            'FinishedAtUtc': meta.get('FinishedAtUtc'),
            'SourceStatus': source.get('Status') if source else None,
            'SourceGroup': source.get('Group') if source else None,
            'SourceProvider': source.get('Provider') if source else None,
            'SourceTarget': source.get('Target') if source else None,
            'MissingFields': source.get('MissingFields') if source else None,
            'CollectedAtUtc': source.get('CollectedAtUtc') if source else None,
            'PageCount': source.get('PageCount') if source else None,
            'RequestCount': source.get('RequestCount') if source else None,
            'Count': source.get('Count') if source else None,
        },
        'Rows': rows, 'Checks': checks, 'Observations': observations,
    }


def adapt_fixture(selector):
    registered = registry()
    if selector not in registered:
        raise ValueError('Unregistered fixture selector')
    fixture = registered[selector]
    data = (WAVE / fixture['Path']).read_bytes()
    if digest(data) != fixture['FileSha256']:
        raise ValueError('Fixture file digest mismatch')
    obj = parse(data)
    if digest(canonical(obj)) != fixture['CanonicalSha256']:
        raise ValueError('Fixture content digest mismatch')
    return _evaluate(obj, selector, fixture)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('Supply one registered fixture selector')
    try:
        result = adapt_fixture(sys.argv[1])
        print(json.dumps(result, indent=2))
    except (ValueError, OSError, RecursionError, OverflowError) as exc:
        sys.exit(str(exc))
