param(
    [string]$ImageName = "jasca-offline:latest",
    [string]$BundleName = "",
    [string]$OutputDir = "dist\offline-bundle",
    [string]$DockerContext = $env:DOCKER_CONTEXT,
    [string]$Platform = $(if ($env:TARGET_PLATFORM) { $env:TARGET_PLATFORM } else { "linux/amd64" }),
    [switch]$SkipBuild,
    [switch]$KeepTar
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$OutputPath = Join-Path $ProjectRoot $OutputDir
$TrivyDbPath = Join-Path $ProjectRoot "trivy-db"

if (-not $BundleName) {
    $BundleName = "jasca-offline-" + (Get-Date -Format "yyyyMMdd-HHmmss")
}

$BundlePath = Join-Path $OutputPath $BundleName
$ImageTar = Join-Path $BundlePath "jasca-offline.tar"
$ImageTarGz = "$ImageTar.gz"

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Get-DockerArgs {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    if ($DockerContext) {
        return @("--context", $DockerContext) + $Arguments
    }

    return $Arguments
}

function Assert-ImagePlatform {
    param(
        [Parameter(Mandatory = $true)][string]$Image,
        [Parameter(Mandatory = $true)][string]$ExpectedPlatform
    )

    $inspectArgs = Get-DockerArgs @("image", "inspect", $Image, "--format", "{{.Os}}/{{.Architecture}}")
    $actualPlatform = (& docker @inspectArgs).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to inspect Docker image platform: $Image"
    }

    if ($actualPlatform -ne $ExpectedPlatform) {
        throw "Docker image platform mismatch. Expected $ExpectedPlatform, got $actualPlatform. Rebuild with -Platform $ExpectedPlatform."
    }

    Write-Host "Verified Docker image platform: $actualPlatform"
}

function Compress-TarGzip {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    if (Test-Path -LiteralPath $Destination) {
        Remove-Item -LiteralPath $Destination -Force
    }

    $inputStream = [System.IO.File]::OpenRead($Source)
    try {
        $outputStream = [System.IO.File]::Create($Destination)
        try {
            $gzipStream = [System.IO.Compression.GzipStream]::new($outputStream, [System.IO.Compression.CompressionLevel]::Optimal)
            try {
                $inputStream.CopyTo($gzipStream)
            } finally {
                $gzipStream.Dispose()
            }
        } finally {
            $outputStream.Dispose()
        }
    } finally {
        $inputStream.Dispose()
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker command not found. Install and start Docker before building the offline bundle."
}

if (-not (Test-Path -LiteralPath $TrivyDbPath)) {
    New-Item -ItemType Directory -Path $TrivyDbPath | Out-Null
}

$TrivyDbFile = Join-Path $TrivyDbPath "db\trivy.db"
if (-not (Test-Path -LiteralPath $TrivyDbFile)) {
    Write-Host "[INFO] Trivy DB was not found at trivy-db\db\trivy.db." -ForegroundColor Cyan
    Write-Host "       This bundle expects the target server's Trivy cache to be mounted with start.sh/start.ps1." -ForegroundColor Cyan
}

New-Item -ItemType Directory -Force -Path $BundlePath | Out-Null

Push-Location $ProjectRoot
try {
    if (-not $SkipBuild) {
        Write-Host "Building Docker image: $ImageName ($Platform)"
        Invoke-Native docker (Get-DockerArgs @("build", "--platform", $Platform, "-f", "docker/monolith/Dockerfile", "-t", $ImageName, "."))
    } else {
        Write-Host "Skipping Docker build. Using existing image: $ImageName"
    }

    Assert-ImagePlatform -Image $ImageName -ExpectedPlatform $Platform

    Write-Host "Saving Docker image to $ImageTar"
    Invoke-Native docker (Get-DockerArgs @("save", $ImageName, "-o", $ImageTar))

    Write-Host "Compressing image to $ImageTarGz"
    Compress-TarGzip -Source $ImageTar -Destination $ImageTarGz

    if (-not $KeepTar) {
        Remove-Item -LiteralPath $ImageTar -Force
    }

    Copy-Item -LiteralPath "docker/monolith/start.sh" -Destination (Join-Path $BundlePath "start.sh") -Force
    Copy-Item -LiteralPath "docker/monolith/start.ps1" -Destination (Join-Path $BundlePath "start.ps1") -Force
    Copy-Item -LiteralPath "docker/monolith/deploy-existing-layout.sh" -Destination (Join-Path $BundlePath "deploy-existing-layout.sh") -Force
    Copy-Item -LiteralPath "docker/monolith/deploy-existing-layout.env.example" -Destination (Join-Path $BundlePath "deploy-existing-layout.env.example") -Force
    Copy-Item -LiteralPath "docker/monolith/README-OFFLINE.md" -Destination (Join-Path $BundlePath "README-OFFLINE.md") -Force
    Copy-Item -LiteralPath "docs/Kubernetes_Deployment_Guide_kr.md" -Destination (Join-Path $BundlePath "Kubernetes_Deployment_Guide_kr.md") -Force
    Copy-Item -LiteralPath "k8s/monolith" -Destination (Join-Path $BundlePath "k8s-monolith") -Recurse -Force

    $manifest = [ordered]@{
        name = "JASCA offline deployment bundle"
        image = $ImageName
        archive = "jasca-offline.tar.gz"
        createdAt = (Get-Date).ToUniversalTime().ToString("o")
        webPort = 3000
        apiPort = 3001
        includesTrivyCli = $true
        dockerContext = $DockerContext
        targetPlatform = $Platform
        trivyDbPathInImage = "/app/trivy-db"
        supportsHostTrivyCacheMount = $true
        includesKubernetesManifests = $true
        notes = @(
            "Transfer this whole directory to the closed network.",
            "Run ./start.sh on Linux or .\start.ps1 on Windows.",
            "If Trivy is already installed on the server, mount its cache with TRIVY_CACHE_MOUNT or -TrivyCacheMount.",
            "For a host-path deployment layout, copy deploy-existing-layout.env.example to deploy-existing-layout.env, edit it, then run ./deploy-existing-layout.sh.",
            "For Kubernetes deployment, read Kubernetes_Deployment_Guide_kr.md and k8s-monolith/README_KO.md.",
            "Docker must be installed on the target host.",
            "The container preserves Docker volumes jasca_postgres_data and jasca_redis_data."
        )
    }

    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $BundlePath "manifest.json") -Encoding UTF8

    Write-Host ""
    Write-Host "Offline bundle created:"
    Write-Host "  $BundlePath"
    Write-Host ""
    Write-Host "Transfer the entire folder to the closed network."
} finally {
    Pop-Location
}
