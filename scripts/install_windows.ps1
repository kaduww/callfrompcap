#Requires -Version 5.1
<#
.SYNOPSIS
    Instala as dependências do callfrompcap no Windows e compila o binário.
.DESCRIPTION
    Usa winget para instalar Go e ffmpeg (opcional).
    Compila o binário callfrompcap.exe com go build.
.NOTES
    Requer Windows 10 1709+ ou Windows 11 (winget incluído).
    Execute em PowerShell com:
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
        .\scripts\install_windows.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GoMinMinor = 22   # requer Go 1.22+

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════╗"
Write-Host "║  callfrompcap — instalação Windows       ║"
Write-Host "╚══════════════════════════════════════════╝"
Write-Host ""

# ── Admin ─────────────────────────────────────────────────────────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Reiniciando como Administrador..."
    $argList = "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process powershell $argList -Verb RunAs
    exit
}

# ── Verifica winget ───────────────────────────────────────────────────────────
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Error @"
winget não encontrado.
Instale o 'App Installer' pela Microsoft Store ou atualize o Windows 10/11.
  https://aka.ms/getwinget
"@
    exit 1
}

# ── Função: recarrega PATH na sessão atual ────────────────────────────────────
function Update-SessionPath {
    $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
    $userPath    = [Environment]::GetEnvironmentVariable('PATH', 'User')
    $env:PATH    = "$machinePath;$userPath"
}

# ── Função: verifica versão mínima do Go ─────────────────────────────────────
function Test-GoVersion {
    try {
        $ver = & go version 2>$null
        if ($ver -match 'go1\.(\d+)') {
            return ([int]$Matches[1] -ge $GoMinMinor)
        }
    } catch {}
    return $false
}

# ── 1. Go ─────────────────────────────────────────────────────────────────────
Write-Host "[1/2] Verificando Go..."

if (Test-GoVersion) {
    Write-Host "       $(go version) — OK"
} else {
    Write-Host "       Instalando Go via winget..."
    winget install --id Go.Go `
        --accept-source-agreements --accept-package-agreements `
        --silent
    Update-SessionPath

    if (-not (Test-GoVersion)) {
        # Fallback: adiciona localização padrão ao PATH
        $goDir = Join-Path $env:ProgramFiles 'Go\bin'
        if (Test-Path $goDir) {
            $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
            [Environment]::SetEnvironmentVariable('PATH', "$machinePath;$goDir", 'Machine')
            Update-SessionPath
        }
    }
    Write-Host "       $(go version)"
}

# ── 2. ffmpeg (opcional — G.729 / G.722) ─────────────────────────────────────
Write-Host "[2/2] Instalando ffmpeg (opcional)..."
try {
    winget install --id Gyan.FFmpeg `
        --accept-source-agreements --accept-package-agreements `
        --silent
    Update-SessionPath
    if (Get-Command ffmpeg -ErrorAction SilentlyContinue) {
        Write-Host "       $(ffmpeg -version 2>&1 | Select-Object -First 1)"
    } else {
        Write-Host "       ffmpeg instalado (reinicie o terminal para atualizar o PATH)"
    }
} catch {
    Write-Host "       AVISO: ffmpeg não instalado."
    Write-Host "              G.729 e G.722 não serão decodificados para WAV."
}

# ── Compilar ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "Compilando callfrompcap.exe..."
$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectDir = Split-Path -Parent $scriptDir
Set-Location $projectDir

go build -o callfrompcap.exe .
Write-Host "   Binário gerado: $projectDir\callfrompcap.exe"

# ── Concluído ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════"
Write-Host " Instalação concluída."
Write-Host ""
Write-Host " Para usar:"
Write-Host "   .\callfrompcap.exe <arquivo.pcap> -o .\output"
Write-Host ""
Write-Host " Dica: caminhos com espaços devem estar entre aspas:"
Write-Host '   .\callfrompcap.exe "C:\Capturas\arquivo pcap.pcap" -o .\output'
Write-Host "════════════════════════════════════════════"
