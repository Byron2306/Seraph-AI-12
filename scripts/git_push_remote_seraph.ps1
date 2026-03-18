$repo = 'C:\Users\User\source\repos\Metatron-cursor-metatron-system-governance-a999'
Set-Location $repo
$remoteUrl = 'https://github.com/Byron2306/Metatron.git'
Write-Host "Repository: $repo"
Write-Host "Setting origin -> $remoteUrl"
try {
    git remote get-url origin > $null 2>&1
    $hasOrigin = $true
} catch {
    $hasOrigin = $false
}
if ($hasOrigin) {
    Write-Host "origin exists, updating URL"
    git remote set-url origin $remoteUrl
} else {
    Write-Host "adding origin"
    git remote add origin $remoteUrl
}
Write-Host "Creating/updating local branch 'Seraph-v11' from HEAD"
git branch -f 'Seraph-v11' HEAD
git checkout 'Seraph-v11'
Write-Host "Pushing branch 'Seraph-v11' to origin (force)"
try {
    git push -u origin 'Seraph-v11' --force
    Write-Host 'Push completed.'
}
catch {
    Write-Error "Push failed: $_"
    Write-Host "If push failed due to authentication, provide a personal access token (use HTTPS URL with token) or add SSH remote."
    exit 1
}
