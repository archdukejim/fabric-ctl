"""The files tests/lab/dot1x_scripts.sh sends to a Windows VM (manual 3.1.5.12): both generated 802.1X scripts, by the same
function the console uses, and three scripts the check must refuse. Fails if a generated script is not plain ASCII:
Windows PowerShell 5.1 reads a file with no byte-order mark in the machine's code page.

usage: dot1x_scripts_make.py <root CA .pem> <folder to write in>
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "src"))
from fabriclib.radius.windows_setup_script import windows_setup_script  # noqa: E402

CONTROLS = {
    "broken.ps1": 'Write-Host "the quote is never closed\nif ($true) {\n',
    "no-such-command.ps1": "Get-NoSuchThingAtAll -Name x\n",
    "no-such-parameter.ps1": "Remove-Item -NoSuchParameter x\n",
}


def main(pem_path, folder):
    with open(pem_path, encoding="ascii") as f:
        pem = f.read()
    v = {"hostname_radius": "radius.lab.test", "domain": "lab.test"}
    for method in ("tls", "ttls"):
        name, text = windows_setup_script(v, method, pem)
        data = text.encode("utf-8")
        if not data.isascii():
            print(f"FAIL {name} is not plain ASCII")
            return 1
        if data.count(b"\r\n") != data.count(b"\n"):
            print(f"FAIL {name}: not every line ends in CRLF")
            return 1
        print(f"PASS {name}: plain ASCII, {len(data)} bytes, CRLF line ends")
        with open(os.path.join(folder, name), "wb") as f:
            f.write(data)
    for name, text in CONTROLS.items():
        with open(os.path.join(folder, name), "w", encoding="ascii", newline="\n") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
