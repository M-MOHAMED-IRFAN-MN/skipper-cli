Write-Host "🔍 Verifying Skipper Rebrand..." -ForegroundColor Cyan

# Check folder name
if (Test-Path ".\skipper") {
    Write-Host "✅ Package folder 'skipper' exists." -ForegroundColor Green
} else {
    Write-Host "❌ Package folder 'skipper' missing!" -ForegroundColor Red
}

# Check for cybersentry references
$matches = Get-ChildItem -Recurse -File -Exclude *.exe,*.png,*.jpg,*.ico | Where-Object {
    (Get-Content $_.FullName -Raw) -match "(?i)cybersentry"
}
if ($matches) {
    Write-Host "❌ Found 'cybersentry' in:" -ForegroundColor Red
    $matches | ForEach-Object { Write-Host "   $($_.FullName)" }
} else {
    Write-Host "✅ No 'cybersentry' references found." -ForegroundColor Green
}

# Check pyproject.toml name
$pyproject = Get-Content .\pyproject.toml -Raw
if ($pyproject -match 'name\s*=\s*"skipper"') {
    Write-Host "✅ pyproject.toml name = skipper" -ForegroundColor Green
} else {
    Write-Host "❌ pyproject.toml name incorrect" -ForegroundColor Red
}

# Check CLI banner
$banner = Get-Content .\skipper\cli.py -Raw
if ($banner -match "Captain's SOC Toolkit") {
    Write-Host "✅ CLI banner updated." -ForegroundColor Green
} else {
    Write-Host "❌ CLI banner not updated." -ForegroundColor Red
}

Write-Host "`n🚀 Run 'skipper --help' to test command." -ForegroundColor Cyan