"""Challenge the origin gate using local mutations after digest admission."""
import copy
import hashlib
import json
from pathlib import Path
import runpy


ROOT = Path(__file__).resolve().parents[1] / 'workbook-fixture/auth-migration'
review = runpy.run_path(str(ROOT / 'review.py'))
registry = review['strict_json']((ROOT / 'registry.json').read_bytes())
cases = 0


def encoded(value):
    return json.dumps(value, separators=(',', ':'), allow_nan=False).encode('utf-8')


def check(label, audit, registration, expected, count=None, repin=True, raw=None):
    global cases
    data = encoded(audit) if raw is None else raw
    record = dict(registration)
    if repin:
        # Only this internal test treats the mutant bytes as admitted. Public
        # callers must select one immutable registered original by identifier.
        record['AuditSha256'] = hashlib.sha256(data).hexdigest()
    fixture = (ROOT / record['InputPath']).read_bytes()
    result = review['compare'](data, fixture, record, registry['Catalog'], registry['ReferenceWorkbookSha256'])
    if result['Comparison'] != 'Unknown' or result['Reason'] != expected:
        raise AssertionError((label, result['Comparison'], result['Reason'], expected))
    if count is not None and result['Binding']['ClaimantCount'] != count:
        raise AssertionError((label, result['Binding']['ClaimantCount'], count))
    cases += 1


def change_member(record, key, value):
    record[key] = value


for kind in ('report', 'snapshot'):
    registration = registry['Cases']['typed-disabled-' + kind]
    original = review['strict_json']((ROOT / registration['AuditPath']).read_bytes())
    bank = 'Coverage' if kind == 'report' else 'Evidence'
    source_pos = next(i for i, r in enumerate(original[bank]) if r['SourceId'] == review['SOURCE'])

    def changed():
        audit = copy.deepcopy(original)
        return audit, audit[bank][source_pos]

    for order in ('first', 'last'):
        for variant in ('identical', 'denied', 'partial', 'different-id-absolute-route',
                        'different-id-variant-route', 'case-changed-id'):
            audit, record = changed()
            claimant = dict(record)
            if variant in ('denied', 'partial'):
                claimant['Status'] = 'AccessDenied' if variant == 'denied' else 'Partial'
                claimant['Items'] = []
            if variant.startswith('different-id'):
                claimant['SourceId'] = 'other-source'
                claimant['Target'] = ('https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
                                      if variant == 'different-id-absolute-route' else '/policIes/authenticationMethodsPolicy/')
            if variant == 'case-changed-id':
                claimant['SourceId'] = claimant['SourceId'].upper()
                claimant['Target'] = '/different'
            idx = 0 if order == 'first' else len(audit[bank])
            audit[bank].insert(idx, claimant)
            check((kind, variant, order), audit, registration, 'AmbiguousOrMissingSource', 2)

    for field, value in (('Group','Core'), ('Provider','Exchange'), ('Target','/policies/authorizationPolicy'),
                         ('SourceId','different-id')):
        audit, record = changed()
        record[field] = value
        check((kind, field), audit, registration, 'SourceBindingMismatch', 1)
    for field, value in (('Mode','Live'), ('TenantId','invented-foreign'), ('RunId','unaffiliated'),
                         ('SelectedGroups',['Core']), ('OrganizationWideConfirmed',True)):
        audit, record = changed()
        audit['Metadata'][field] = value
        check((kind, 'metadata', field), audit, registration, 'AuditOriginMismatch')
    audit, record = changed()
    check((kind, 'loose record'), record, registration, 'RepresentationMismatch')
    audit[bank].remove(record)
    check((kind, 'source absent'), audit, registration, 'AmbiguousOrMissingSource', 0)
    audit, record = changed()
    audit[bank].pop()
    check((kind, 'sibling absent'), audit, registration, 'FullInventoryMismatch')
    audit, record = changed()
    audit[bank][0]['SourceId'] = None
    check((kind, 'ambiguous sibling identity'), audit, registration, 'FullInventoryMismatch')
    audit, record = changed()
    audit[bank][0]['Target'] = '/different/path'
    check((kind, 'sibling target mismatch'), audit, registration, 'CatalogBindingMismatch')
    audit, record = changed()
    audit[bank][0]['Count'] = True
    check((kind, 'sibling invalid counter'), audit, registration, 'IncompleteRecord')
    audit, record = changed()
    raw = encoded(audit).replace(b'"Count":', b'"count":0,"Count":', 1)
    check((kind, 'duplicate case-insensitive'), audit, registration, 'InvalidEvidenceJson', raw=raw)
    check((kind, 'wrong original'), audit, registration, 'OriginalAuditBindingMismatch', repin=False, raw=encoded(audit) + b' ')
    for field in ('StartedAtUtc', 'FinishedAtUtc'):
        altered = dict(registration, **{field:'2001-01-01T00:00:00.0000000Z'})
        check((kind, field, 'probe'), audit, altered, 'RunWindowBindingMismatch')
    altered = dict(registration, ReviewAtUtc='2001-01-01T00:00:00.0000000Z')
    check((kind, 'future audit'), audit, altered, 'InvalidAuditWindow')
    for stamp, expected in (('2001-01-01T00:00:00.0000000Z','CaptureBindingMismatch'),
                             ('2099-01-01T00:00:00.0000000Z','CaptureBindingMismatch'),
                             ('no-time','InvalidCaptureTime')):
        audit, record = changed()
        record['CollectedAtUtc'] = stamp
        check((kind, stamp), audit, dict(registration, CollectedAtUtc=stamp), expected)
    audit, record = changed()
    record['RequestCount'], record['Reason'] = 1, ''
    if kind == 'snapshot':
        audit['Coverage'][source_pos]['Reason'] = ''
    check((kind, 'unaffiliated injected probe'), audit, registration, 'CaptureSignatureMismatch')
    audit, record = changed()
    del record['Items'][0]['authenticationMethodConfigurations'][1]
    check((kind, 'unaffiliated policy'), audit, registration, 'CaptureInputMismatch')

snapshot = registry['Cases']['typed-disabled-snapshot']
base = review['strict_json']((ROOT / snapshot['AuditPath']).read_bytes())
for label, update, expected in (
        ('absent summary', lambda a: a.pop('Coverage'), 'RepresentationMismatch'),
        ('empty summary', lambda a: a.update(Coverage=[]), 'CoverageSummaryMismatch'),
        ('second full bank', lambda a: a.update(Coverage=a['Evidence']), 'CoverageSummaryMismatch'),
        ('wrong summary id', lambda a: change_member(a['Coverage'][0], 'SourceId', 'absent'), 'CoverageSummaryMismatch'),
        ('conflicting summary reason', lambda a: change_member(a['Coverage'][0], 'Reason', 'different'), 'CoverageSummaryMismatch'),
        ('noninteger summary', lambda a: change_member(a['Coverage'][0], 'Count', False), 'CoverageSummaryMismatch'),
        ('repeated summary', lambda a: a['Coverage'].__setitem__(0, a['Coverage'][1]), 'CoverageSummaryMismatch'),
        ('incorrect finding count', lambda a: a.update(FindingCount=True), 'SnapshotCountersMismatch'),
        ('top mode', lambda a: a.update(Mode='Live'), 'SnapshotOriginMismatch'),
        ('top tenant', lambda a: a.update(TenantId='other-test'), 'SnapshotOriginMismatch'),
        ('unexpected run', lambda a: a.update(RunId='unbound'), 'RepresentationMismatch')):
    audit = copy.deepcopy(base)
    update(audit)
    check(label, audit, snapshot, expected)

print(json.dumps({'Passed':cases, 'Scope':'invented whole-audit origin mutations'}))
