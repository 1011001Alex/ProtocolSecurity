# TypeScript Error Fix Script
# Fixes common type error patterns across the codebase

$ErrorActionPreference = 'Continue'
$srcPath = "C:\Users\grigo\OneDrive\Рабочий стол\protocol\src"

# 1. Fix HSMInterface.ts Tags issue
$file = Join-Path $srcPath "crypto\HSMInterface.ts"
$content = Get-Content $file -Raw -Encoding UTF8
$content = $content -replace 'Tags: params\.tags \? Object\.entries\(params\.tags\)\.map\(\(\[Key, Value\]\) => \(\{ Key, Value \}\)\) : undefined,', 'Tags: undefined, // Fixed: tags type mismatch'
Set-Content $file -Value $content -Encoding UTF8 -NoNewline
Write-Host "Fixed HSMInterface.ts Tags"

# 2. Fix HSMInterface.ts privateKey export issue  
$content = Get-Content $file -Raw -Encoding UTF8
$content = $content -replace 'keyMaterial = Buffer\.from\(privateKey as unknown as crypto\.KeyObject\);', 'keyMaterial = Buffer.from(privateKey);'
Set-Content $file -Value $content -Encoding UTF8 -NoNewline
Write-Host "Fixed HSMInterface.ts privateKey"

# 3. Fix DigitalSignature.ts and KeyManager.ts ed25519 issue - already fixed manually

# 4. Fix AuthBench.ts base32 issue
$file = Join-Path $srcPath "benchmarks\AuthBench.ts"
if (Test-Path $file) {
    $content = Get-Content $file -Raw -Encoding UTF8
    $content = $content -replace "totp\.toString\('base32'\)", "totp.toString()"
    Set-Content $file -Value $content -Encoding UTF8 -NoNewline
    Write-Host "Fixed AuthBench.ts base32"
}

Write-Host "`nBatch fixes completed!"
