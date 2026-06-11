param(
    [string]$DockerContext = $env:DOCKER_CONTEXT
)

Write-Host "Creating offline bundle..."
$args = @("-SkipBuild")
if ($DockerContext) {
    $args += @("-DockerContext", $DockerContext)
}
& (Join-Path $PSScriptRoot "..\..\script\build-offline-bundle.ps1") @args
