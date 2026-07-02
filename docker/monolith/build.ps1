# Create trivy-db directory if it doesn't exist (for environments without offline DB)
if (-not (Test-Path "trivy-db")) { New-Item -ItemType Directory -Path "trivy-db" | Out-Null }

$platform = if ($env:TARGET_PLATFORM) { $env:TARGET_PLATFORM } else { "linux/amd64" }
docker build --platform $platform -f docker/monolith/Dockerfile -t jasca-offline .
