#Requires -Version 5.1
<#
.SYNOPSIS
    Instala as dependências do analise_pcap no Windows.
.DESCRIPTION
    Usa winget para instalar Wireshark (tshark), ffmpeg e Python 3.11.
    Cria um virtualenv local e instala scapy via pip.
.NOTES
    Requer Windows 10 1709+ ou Windows 11 (winget incluído).
    Execute em PowerShell com:
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
        .\install_windows.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════╗"
Write-Host "║  analise_pcap — instalação Windows       ║"
Write-Host "╚══════════════════════════════════════════╝"
Write-Host ""

# ── Admin (winget precisa para instalar Wireshark no sistema) ─────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Reiniciando como Administrador..."
    $args = "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    Start-Process powershell $args -Verb RunAs
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

# ── 1. Wireshark (inclui tshark) ──────────────────────────────────────────────
Write-Host "[1/4] Instalando Wireshark (tshark)..."
winget install --id WiresharkFoundation.Wireshark `
    --accept-source-agreements --accept-package-agreements `
    --silent --scope machine
Update-SessionPath

if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    # Wireshark não adicionou ao PATH ainda — adiciona manualmente
    $wiresharkDir = Join-Path $env:ProgramFiles 'Wireshark'
    if (Test-Path $wiresharkDir) {
        $machinePath = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
        if ($machinePath -notlike "*$wiresharkDir*") {
            [Environment]::SetEnvironmentVariable('PATH', "$machinePath;$wiresharkDir", 'Machine')
            Update-SessionPath
        }
    }
}
Write-Host "       tshark: $(tshark --version | Select-Object -First 1)"

# ── 2. ffmpeg ─────────────────────────────────────────────────────────────────
Write-Host "[2/4] Instalando ffmpeg..."
winget install --id Gyan.FFmpeg `
    --accept-source-agreements --accept-package-agreements `
    --silent
Update-SessionPath
if (Get-Command ffmpeg -ErrorAction SilentlyContinue) {
    Write-Host "       $(ffmpeg -version 2>&1 | Select-Object -First 1)"
} else {
    Write-Host "       ffmpeg instalado (reinicie o terminal para atualizar o PATH)"
}

# ── 3. Python 3.11 ───────────────────────────────────────────────────────────
Write-Host "[3/4] Verificando Python..."
$pythonOk = $false
if (Get-Command python -ErrorAction SilentlyContinue) {
    $ver = python --version 2>&1
    if ($ver -match 'Python 3\.(8|9|10|11|12|13)') {
        Write-Host "       $ver já instalado — pulando"
        $pythonOk = $true
    }
}

if (-not $pythonOk) {
    Write-Host "       Instalando Python 3.11..."
    winget install --id Python.Python.3.11 `
        --accept-source-agreements --accept-package-agreements `
        --silent
    Update-SessionPath
}

# ── 4. Virtualenv + dependências Python ──────────────────────────────────────
Write-Host "[4/4] Criando virtualenv e instalando dependências Python..."
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

python -m venv .venv
& .\.venv\Scripts\pip install --upgrade pip --quiet
& .\.venv\Scripts\pip install -r requirements.txt

# ── Concluído ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════"
Write-Host " Instalação concluída."
Write-Host ""
Write-Host " Para usar (PowerShell):"
Write-Host "   .\.venv\Scripts\Activate.ps1"
Write-Host "   python main.py <arquivo.pcap> -o .\output"
Write-Host ""
Write-Host " Para usar (Prompt de Comando):"
Write-Host "   .\.venv\Scripts\activate.bat"
Write-Host "   python main.py <arquivo.pcap> -o .\output"
Write-Host "════════════════════════════════════════════"
