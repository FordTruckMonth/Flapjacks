function Get-FlapjacksSyntheticCollaborationDefinitions {
 [pscustomobject]@{ Row=132; SourceId='workbook-teams-client'; Target='Get-CsTeamsClientConfiguration'; Field='AllowEmailIntoChannel'; Desired=$false }
 [pscustomobject]@{ Row=144; SourceId='workbook-spo-tenant'; Target='Get-SPOTenant'; Field='DisallowInfectedFileDownload'; Desired=$true }
}

function Get-FlapjacksSyntheticCollaborationComparison {
 [CmdletBinding()]
 param([AllowNull()][AllowEmptyCollection()][object[]]$Evidence)

 function ReadProperty($Record, [string]$Name) {
  if ($Record -is [Collections.IDictionary]) { return ,$Record[$Name] }
  if ($null -ne $Record -and $null -ne $Record.PSObject.Properties[$Name]) { return ,$Record.$Name }
 }

 function CompareRecord($Source, $Definition) {
  $required = @{
   SourceId=$Definition.SourceId; Target=$Definition.Target
   Provider='OfflineSnapshot'; Status='OfflineSnapshot'
  }
  $provenance = ReadProperty $Source 'Provenance'
  foreach ($name in $required.Keys) {
   $value = ReadProperty $Source $name
   if ($value -isnot [string] -or $value -cne $required[$name]) { return 'Unknown' }
  }
  $required = @{Kind='AlreadyCollected'; ScopeVerification='Unverified'; OriginalStatus='Collected'; RequiredNativeCommand=$Definition.Target}
  foreach ($name in $required.Keys) {
   $value = ReadProperty $provenance $name
   if ($value -isnot [string] -or $value -cne $required[$name]) { return 'Unknown' }
  }
  $complete = ReadProperty $Source 'SnapshotComplete'
  $count = ReadProperty $Source 'Count'
  $items = ReadProperty $Source 'Items'
  if ($complete -isnot [bool] -or -not $complete -or
      ($count -isnot [int] -and $count -isnot [long]) -or $count -ne 1 -or
      $items -isnot [Collections.IList] -or $items.Count -ne 1) { return 'Unknown' }

  $stamp = ReadProperty $Source 'CollectedAtUtc'
  $parsed = [datetimeoffset]::MinValue
  if ($stamp -isnot [string] -or $stamp -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,7})?(Z|\+00:00)\z' -or
      -not [datetimeoffset]::TryParse($stamp, [cultureinfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) { return 'Unknown' }

  $requiredFields = @($Definition.Field)
  if ($Definition.Row -eq 132) {
   $requiredFields += 'Identity'
   $identity = ReadProperty $items[0] 'Identity'
   if ($identity -isnot [string] -or $identity -ine 'Global') { return 'Unknown' }
  }
  $missing = ReadProperty $Source 'MissingFields'
  if ($missing -isnot [Collections.IList]) { return 'Unknown' }
  foreach ($field in $missing) {
   if ($field -isnot [string] -or [string]::IsNullOrWhiteSpace($field) -or $field.Trim() -in $requiredFields) { return 'Unknown' }
  }
  $setting = ReadProperty $items[0] $Definition.Field
  if ($setting -isnot [bool]) { return 'Unknown' }
  if ($setting -eq $Definition.Desired) { return 'Matches' }
  return 'Differs'
 }

 foreach ($definition in Get-FlapjacksSyntheticCollaborationDefinitions) {
  $sources = @($Evidence | Where-Object {
   $id = ReadProperty $_ 'SourceId'
   $id -is [string] -and $id -ieq $definition.SourceId
  })
  $comparison = if ($sources.Count -eq 1) { CompareRecord $sources[0] $definition } else { 'Unknown' }
  [pscustomobject][ordered]@{
   Row=$definition.Row; SourceId=$definition.SourceId; Field=$definition.Field
   Comparison=$comparison; Status='Not assessed'; EvidenceKind='OfflineSnapshot'
   LiveVerified=$false; NewCoverageCredit=0
  }
 }
}
