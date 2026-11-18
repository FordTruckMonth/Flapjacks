# Integrity is checked again on module import, even when the documented runner is bypassed.
# The release manifest/hash is an integrity pin, not a signature or source authentication.
function Assert-PortablePayload([string]$Root) {
 $Root=[IO.Path]::GetFullPath($Root)
 $file=Join-Path $Root 'package-manifest.json'
 for($q=$file;$q;$q=[IO.Path]::GetDirectoryName($q)){
  if((Test-Path -LiteralPath $q) -and ([IO.File]::GetAttributes($q) -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked package refused.'}
 }
 $info=[IO.FileInfo]::new($file)
 if(-not $info.Exists -or $info.Length -gt 262144){throw 'Package manifest bound.'}
 $m=[IO.File]::ReadAllText($file)|ConvertFrom-Json -Depth 20
 if($m.SchemaVersion -cne 'FlapjacksPortableManifest/1' -or $m.SyntheticOnly -isnot [bool] -or -not $m.SyntheticOnly){throw 'Package kind refused.'}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($e in $m.Files){
  if($e.Path -isnot [string] -or $e.Path -cmatch '(^/|\\|(^|/)\.\.?(/|$)|:)' -or -not $seen.Add($e.Path)){throw 'Package path refused.'}
  $p=[IO.Path]::GetFullPath((Join-Path $Root $e.Path))
  if(-not $p.StartsWith($Root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::Ordinal)){throw 'Package containment refused.'}
  for($q=$p;$q;$q=[IO.Path]::GetDirectoryName($q)){
   if((Test-Path -LiteralPath $q) -and ([IO.File]::GetAttributes($q) -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked package refused.'}
  }
  $f=[IO.FileInfo]::new($p)
  if(-not $f.Exists -or $f.Length -ne $e.Bytes -or $f.Length -gt 2097152){throw 'Package file bound.'}
  $h=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($p))).ToLowerInvariant()
  if($h -cne $e.Sha256){throw 'Package bytes changed.'}
 }
}
