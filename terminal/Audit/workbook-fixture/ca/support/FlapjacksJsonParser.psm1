function ConvertTo-FjcNumericKey {
    param([string]$Text)
    # Compare mathematical decimal values without letting Decimal parsing silently round
    # or underflow an opaque evidence value. Original JSON text is also retained exactly.
    $match = [regex]::Match($Text, '^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$')
    if (-not $match.Success) { throw 'Unsupported JSON number.' }
    $exponent = 0
    if ($match.Groups[4].Success -and -not [int]::TryParse($match.Groups[4].Value, [ref]$exponent)) { throw 'Unsupported JSON exponent.' }
    if ($exponent -lt -1000000 -or $exponent -gt 1000000) { throw 'Unsupported JSON exponent.' }
    $digits = ($match.Groups[2].Value + $match.Groups[3].Value).TrimStart('0')
    if ($digits.Length -eq 0) { return '0' }
    $significant = $digits.TrimEnd('0')
    $power = $exponent - $match.Groups[3].Value.Length + $digits.Length - $significant.Length
    return $match.Groups[1].Value + $significant + 'e' + $power.ToString([Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-FjcJson {
    param([string]$Json)
    $options = [Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 40
    $document = $null
    function Read-FjcElement([Text.Json.JsonElement]$Node) {
        switch ($Node.ValueKind) {
            'Object' {
                $map = [ordered]@{}
                $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($property in $Node.EnumerateObject()) {
                    if (-not $names.Add($property.Name)) { throw 'Ambiguous JSON property.' }
                    $map.Add($property.Name, (Read-FjcElement $property.Value))
                }
                return ,$map
            }
            'Array' {
                $items = [Collections.Generic.List[object]]::new()
                foreach ($item in $Node.EnumerateArray()) { $items.Add((Read-FjcElement $item)) }
                return ,$items.ToArray()
            }
            'String' { return $Node.GetString() }
            'Number' {
                $integer = [long]0
                if ($Node.TryGetInt64([ref]$integer)) { return $integer }
                $number = [decimal]0
                if ($Node.TryGetDecimal([ref]$number)) {
                    $rawKey = ConvertTo-FjcNumericKey $Node.GetRawText()
                    $valueKey = ConvertTo-FjcNumericKey $number.ToString('G29', [Globalization.CultureInfo]::InvariantCulture)
                    if ($rawKey -ceq $valueKey) { return $number }
                }
                throw 'Unsupported JSON number.'
            }
            'True' { return $true }
            'False' { return $false }
            'Null' { return $null }
            default { throw 'Unsupported JSON value.' }
        }
    }
    try {
        $document = [Text.Json.JsonDocument]::Parse($Json, $options)
        return Read-FjcElement $document.RootElement
    } catch {
        # Do not echo a parser's raw input, property name, path or attacker-supplied text.
        throw 'Invalid JSON: use bounded passive JSON with unique property names and supported numbers.'
    } finally {
        if ($null -ne $document) { $document.Dispose() }
    }
}
