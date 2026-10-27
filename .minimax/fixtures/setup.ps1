# Make the self-test fixture a git repo with one commit.
# The scanner snapshots COMMITTED HEAD via `git archive`, so the fixture must have a commit
# before you can plan a scan against it.
$ErrorActionPreference = 'Stop'

$fixture = Join-Path (Split-Path -Parent $PSScriptRoot) 'fixtures\teamboard'
Push-Location $fixture
try {
    if (-not (Test-Path '.git')) {
        git init -q
    }
    git add -A
    git -c user.email=swarm@example.com -c user.name='Security Swarm' `
        commit -qm 'self-test fixture' 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Output 'fixture already committed (nothing to do)'
    }
    $short = git rev-parse --short HEAD
    Write-Output "fixture ready at $((Get-Location).Path) @ $short"
}
finally {
    Pop-Location
}
