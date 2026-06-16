param(
    [string]$ImageArchive = "jasca-offline.tar.gz",
    [string]$ImageName = "jasca-offline:latest",
    [string]$ContainerName = "jasca",
    [int]$WebPort = 3000,
    [int]$ApiPort = 3001,
    [string]$TrivyCacheMount = "",
    [string]$JwtSecret = $env:JWT_SECRET,
    [string]$DbPassword = $env:DB_PASSWORD,
    [string]$CorsOrigin = $env:CORS_ORIGIN
)

$ErrorActionPreference = "Stop"

function Expand-GzipToTar {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $inputStream = [System.IO.File]::OpenRead($Source)
    try {
        $gzipStream = [System.IO.Compression.GzipStream]::new($inputStream, [System.IO.Compression.CompressionMode]::Decompress)
        try {
            $outputStream = [System.IO.File]::Create($Destination)
            try {
                $gzipStream.CopyTo($outputStream)
            } finally {
                $outputStream.Dispose()
            }
        } finally {
            $gzipStream.Dispose()
        }
    } finally {
        $inputStream.Dispose()
    }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "docker command not found."
}

if (-not $JwtSecret) {
    throw "JwtSecret must be provided, for example: .\start.ps1 -JwtSecret '<long-random-secret>' -DbPassword '<database-password>'"
}

if (-not $DbPassword) {
    throw "DbPassword must be provided, for example: .\start.ps1 -JwtSecret '<long-random-secret>' -DbPassword '<database-password>'"
}

if (-not $CorsOrigin) {
    $CorsOrigin = "http://localhost:$WebPort"
}

if (-not (Test-Path -LiteralPath $ImageArchive)) {
    if (Test-Path -LiteralPath "jasca-offline.tar") {
        $ImageArchive = "jasca-offline.tar"
    } else {
        throw "Image archive not found: $ImageArchive"
    }
}

$tarToLoad = $ImageArchive
$tempTar = $null

if ($ImageArchive.EndsWith(".tar.gz") -or $ImageArchive.EndsWith(".tgz")) {
    $tempTar = Join-Path $env:TEMP ("jasca-offline-" + [guid]::NewGuid().ToString("N") + ".tar")
    Write-Host "Decompressing $ImageArchive ..."
    Expand-GzipToTar -Source $ImageArchive -Destination $tempTar
    $tarToLoad = $tempTar
} elseif (-not $ImageArchive.EndsWith(".tar")) {
    throw "Unsupported archive extension. Use .tar or .tar.gz"
}

try {
    Write-Host "Loading Docker image from $tarToLoad ..."
    docker load -i $tarToLoad
} finally {
    if ($tempTar -and (Test-Path -LiteralPath $tempTar)) {
        Remove-Item -LiteralPath $tempTar -Force
    }
}

Write-Host "Ensuring persistent Docker volumes exist..."
docker volume create jasca_postgres_data | Out-Null
docker volume create jasca_redis_data | Out-Null

$existing = docker ps -aq -f "name=^/$ContainerName$"
if ($existing) {
    Write-Host "Replacing existing container: $ContainerName"
    docker stop $ContainerName | Out-Null
    docker rm $ContainerName | Out-Null
}

Write-Host "Starting JASCA container..."
$dockerRunArgs = @(
    "run", "-d",
    "--name", $ContainerName,
    "--restart", "unless-stopped",
    "-p", "${WebPort}:3000",
    "-p", "${ApiPort}:3001",
    "-e", "JWT_SECRET=$JwtSecret",
    "-e", "DB_PASSWORD=$DbPassword",
    "-e", "CORS_ORIGIN=$CorsOrigin",
    "-v", "jasca_postgres_data:/var/lib/postgresql/data",
    "-v", "jasca_redis_data:/var/lib/redis"
)

if ($TrivyCacheMount) {
    if (-not (Test-Path -LiteralPath $TrivyCacheMount -PathType Container)) {
        throw "TrivyCacheMount does not exist or is not a directory: $TrivyCacheMount"
    }
    Write-Host "Mounting host Trivy cache: $TrivyCacheMount -> /app/trivy-db"
    $dockerRunArgs += @("-v", "${TrivyCacheMount}:/app/trivy-db:ro")
}

$dockerRunArgs += $ImageName
docker @dockerRunArgs

Write-Host "JASCA is running."
Write-Host "Web: http://localhost:$WebPort"
Write-Host "API: http://localhost:$ApiPort"
Write-Host "Logs: docker logs -f $ContainerName"
