"""Windows' unattended install: an answer ISO holding autounattend.xml (Setup reads it from the root of any CD) and
fabric-lab\\setup.ps1, which the first (automatic) sign-in runs.

Purpose: manual 3.1.5.3's Windows installs: local administrator labadmin with the generated lab password, no
  Microsoft account and no OOBE pages; then setup.ps1 sets the static address and DNS, installs and starts OpenSSH
  server with key sign-in only, puts the lab key in administrators_authorized_keys with its ACL, and turns the
  automatic sign-in off again.
Inputs: the inventory, the VM, the lab public key, the password (from lab_secret.py), the seed folder.
Returns: the ISO's path.
Fails: CalledProcessError from xorriso.
Feeds: make_seeds.py; install_vm.ps1 attaches the ISO as a second DVD drive.
"""
import base64
import os
import tempfile
from xml.sax.saxutils import escape

from build_iso import data_iso
from lab_inventory import mac

# Microsoft's published generic install key for Windows 11 Pro: it selects the edition and activates nothing
_W11_PRO_GENERIC = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
_IMAGES = {
    "windows-server": "Windows Server 2025 Standard Evaluation (Desktop Experience)",
    "windows-client": "Windows 11 Pro",
}

_SETUP = r"""# fabric lab (manual 3.1.5.3): run once by the first automatic sign-in of labadmin
$ErrorActionPreference = 'Stop'
Start-Transcript -Path C:\Windows\Temp\fabric-lab-setup.log -Append
$nic = Get-NetAdapter | Where-Object { $_.MacAddress -eq '@MAC@' }
if (-not $nic) { throw 'no NIC with the lab MAC @MAC@' }
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object IPAddress -ne '@IP@' | Remove-NetIPAddress -Confirm:$false
Remove-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix 0.0.0.0/0 -Confirm:$false -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
if (-not (Get-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress '@IP@' -ErrorAction SilentlyContinue)) {
    New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress '@IP@' -PrefixLength 24 -DefaultGateway '@GW@' | Out-Null
}
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses '@DNS@'
Set-NetConnectionProfile -InterfaceIndex $nic.ifIndex -NetworkCategory Private -ErrorAction SilentlyContinue
# OpenSSH server: built into Server 2025, a feature on demand (from Windows Update, through the router) on Windows 11
$deadline = (Get-Date).AddMinutes(10)
while (-not (Test-NetConnection 1.1.1.1 -Port 443 -InformationLevel Quiet) -and (Get-Date) -lt $deadline) { Start-Sleep 15 }
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $cap.Name | Out-Null }
$keys = 'C:\ProgramData\ssh\administrators_authorized_keys'
New-Item -ItemType Directory -Force -Path C:\ProgramData\ssh | Out-Null
[IO.File]::WriteAllText($keys, "@KEY@`n", (New-Object Text.UTF8Encoding $false))
icacls.exe $keys /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd          # its first start writes sshd_config and the host keys
$cfg = 'C:\ProgramData\ssh\sshd_config'
$text = Get-Content -Raw $cfg
if ($text -notmatch '(?m)^# fabric lab') {
    # sshd takes a keyword's first value: these lines at the top win
    $head = "# fabric lab (manual 3.1.5.3): key sign-in only`nPasswordAuthentication no`nKbdInteractiveAuthentication no`n"
    [IO.File]::WriteAllText($cfg, $head + $text, (New-Object Text.UTF8Encoding $false))
}
Restart-Service sshd
if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Direction Inbound `
        -Protocol TCP -LocalPort 22 -Action Allow -Profile Any | Out-Null
} else { Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Enabled True -Profile Any }
# the automatic sign-in was for this run only; Setup's copies of the answer file go too
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $wl AutoAdminLogon '0'
Remove-ItemProperty $wl DefaultPassword -ErrorAction SilentlyContinue
Remove-Item C:\Windows\Panther\unattend*.xml, C:\Windows\Panther\autounattend*.xml -Force -ErrorAction SilentlyContinue
Stop-Transcript
"""


def _secret(value, suffix):
    """Windows' answer-file encoding (PlainText false): base64 of UTF-16LE value+suffix. Obscures, does not protect."""
    return base64.b64encode((value + suffix).encode("utf-16-le")).decode()


def _component(name, pass_body):
    return (f'    <component name="{name}" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" '
            f'language="neutral" versionScope="nonSxS">\n{pass_body}    </component>\n')


def autounattend(vm, password):
    client = vm["installer"] == "windows-client"
    intl = ("      <InputLocale>en-US</InputLocale>\n      <SystemLocale>en-US</SystemLocale>\n"
            "      <UILanguage>en-US</UILanguage>\n      <UserLocale>en-US</UserLocale>\n")
    key = (f"        <ProductKey>\n          <Key>{_W11_PRO_GENERIC}</Key>\n"
           "          <WillShowUI>Never</WillShowUI>\n        </ProductKey>\n") if client else ""
    pe = _component("Microsoft-Windows-International-Core-WinPE",
                    "      <SetupUILanguage>\n        <UILanguage>en-US</UILanguage>\n      </SetupUILanguage>\n" + intl)
    pe += _component("Microsoft-Windows-Setup", f"""      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add">
              <Key>/IMAGE/NAME</Key>
              <Value>{escape(_IMAGES[vm["installer"]])}</Value>
            </MetaData>
          </InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
        </OSImage>
      </ImageInstall>
      <UserData>
{key}        <AcceptEula>true</AcceptEula>
      </UserData>
""")
    run = ""
    if client:   # BypassNRO: OOBE never insists on a network or a Microsoft account
        run = ("      <RunSynchronous>\n        <RunSynchronousCommand wcm:action=\"add\">\n          <Order>1</Order>\n"
               "          <Path>reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE /v BypassNRO /t REG_DWORD /d 1 /f</Path>\n"
               "        </RunSynchronousCommand>\n      </RunSynchronous>\n")
    spec = _component("Microsoft-Windows-Shell-Setup",
                      f"      <ComputerName>{vm['name'][:15]}</ComputerName>\n      <TimeZone>UTC</TimeZone>\n")
    if run:
        spec += _component("Microsoft-Windows-Deployment", run)
    first = ("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-PSDrive -PSProvider FileSystem | "
             "ForEach-Object { Join-Path $_.Root 'fabric-lab\\setup.ps1' } | Where-Object { Test-Path $_ } | "
             "Select-Object -First 1 | ForEach-Object { &amp; $_ }\"")
    oobe = _component("Microsoft-Windows-International-Core", intl)
    oobe += _component("Microsoft-Windows-Shell-Setup", f"""      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>labadmin</Name>
            <Group>Administrators</Group>
            <DisplayName>fabric lab admin</DisplayName>
            <Password><Value>{_secret(password, "Password")}</Value><PlainText>false</PlainText></Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Username>labadmin</Username>
        <Password><Value>{_secret(password, "Password")}</Value><PlainText>false</PlainText></Password>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>{first}</CommandLine>
          <Description>fabric lab: address, OpenSSH, the lab key</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
""")
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<unattend xmlns="urn:schemas-microsoft-com:unattend" '
            'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">\n'
            f'  <settings pass="windowsPE">\n{pe}  </settings>\n'
            f'  <settings pass="specialize">\n{spec}  </settings>\n'
            f'  <settings pass="oobeSystem">\n{oobe}  </settings>\n'
            '</unattend>\n')


def setup_script(inv, vm, key):
    net = inv["network"]
    out = _SETUP
    for k, v in (("@MAC@", mac(vm, 1, "-").upper()), ("@IP@", vm["ip"]), ("@GW@", net["gateway"]),
                 ("@DNS@", net["dns"]), ("@KEY@", key.replace("'", "").replace('"', "").replace("`", ""))):
        out = out.replace(k, v)
    return out.replace("\n", "\r\n")


def write_seed(inv, vm, key, password, seed_dir):
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "autounattend.xml"), "w", encoding="utf-8") as f:
            f.write(autounattend(vm, password))
        os.makedirs(os.path.join(d, "fabric-lab"))
        with open(os.path.join(d, "fabric-lab", "setup.ps1"), "w", encoding="utf-8", newline="") as f:
            f.write(setup_script(inv, vm, key))
        out = os.path.join(seed_dir, vm["name"] + ".iso")
        data_iso(d, "LABANSWER", out)
    return out
