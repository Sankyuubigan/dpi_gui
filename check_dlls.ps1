param([string]$ExePath)
$bytes = [System.IO.File]::ReadAllBytes($ExePath)
$text = [System.Text.Encoding]::ASCII.GetString($bytes)
$dlls = @{}
for ($i = 0; $i -lt $text.Length - 5; $i++) {
    $c = $text[$i]
    if (($c -ge 'a' -and $c -le 'z') -or ($c -ge 'A' -and $c -le 'Z') -or $c -eq '_') {
        $end = $i
        while ($end -lt $text.Length - 1 -and $text[$end] -ne "`0") { $end++ }
        $candidate = $text.Substring($i, $end - $i)
        if ($candidate -match '^[a-zA-Z0-9_\-]+\.dll$' -and $candidate.Length -gt 3) {
            $dlls[$candidate.ToLower()] = $true
        }
        $i = $end
    }
}
$dlls.Keys | Sort-Object
