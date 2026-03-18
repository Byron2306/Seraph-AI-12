$repo = 'C:\Users\User\source\repos\Metatron-cursor-metatron-system-governance-a999'
Set-Location $repo
$b = "seraph-v11-backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Write-Host "Creating local branch: $b"
try {
    $head = (git rev-parse --verify HEAD).Trim()
} catch {
    Write-Error "Failed to resolve HEAD: $_"
    exit 1
}
Write-Host "HEAD commit: $head"
# create/force branch at HEAD
git branch -f $b $head

Write-Host "Pushing $b to origin (force-with-lease)"
try {
    git push -u origin $b --force-with-lease
    Write-Host "Push succeeded. Remote refs:"
    git ls-remote --heads origin $b
} catch {
    Write-Error "Push failed: $_"
    exit 1
}
Write-Host "Backup branch created and pushed: $b"
