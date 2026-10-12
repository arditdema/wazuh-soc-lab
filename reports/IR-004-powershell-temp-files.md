# IR-004: PowerShell writing files to Temp (Wazuh rule 92213)

| | |
|---|---|
| **Type** | Alert triage |
| **Verdict** | False positive (lab tooling and normal PowerShell behavior) |
| **Rule** | 92213 "Executable file dropped in folder commonly used by malware", level 15 (critical) |
| **MITRE ATT&CK (as mapped by the rule)** | T1105 Ingress Tool Transfer (Command and Control) |
| **Endpoint** | `win-laptop` (Windows 10 Pro, Sysmon, Wazuh agent 4.14.8) |
| **Occurrences** | 18 alerts on 3 October 2026; further alerts on 5, 9 and 11 October |

## 1. Summary

Rule 92213 also fired on `powershell.exe`. On 3 October, 18 of the 44 alerts from this rule came from PowerShell and came in two different patterns: 17 files from a PowerShell module package, and one PowerShell script-policy test file. Both are benign. I also saw alerts from the same rule and image on later days.

## 2. Pattern A: module package extraction (17 alerts)

| Field | Value |
|---|---|
| Time | 2026-10-03 from 20:03:37 local (18:03:37 UTC) |
| Process image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Example file | `C:\Users\<user>\AppData\Local\Temp\868646910\powershell-yaml\lib\net47\YamlDotNet.dll` |
| Running as | the signed-in interactive user |

The path is the package layout of the `powershell-yaml` module, which Atomic Red Team needs as a dependency, and the 17 alerts came within a few seconds of each other. The other 16 alerts have the same image and the same `Temp\8686...` folder prefix; I reviewed the full file name of one. I confirmed that the module is installed on the endpoint:

```powershell
Get-Module -ListAvailable powershell-yaml | Select-Object Name, Version
```
```
Name            Version
----            -------
powershell-yaml 0.4.12
```

This was the setup of my own lab tooling.

## 3. Pattern B: script-policy test file (1 alert on 3 October, recurring)

| Field | Value |
|---|---|
| Time (example reviewed in detail) | 2026-10-11 12:57:13 UTC |
| Process image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| File | `C:\Users\<user>\AppData\Local\Temp\__PSScriptPolicyTest_<random>.<random>.ps1` |

PowerShell creates a short-lived test script with this name to check whether script execution is allowed. It is known benign behavior and a common false positive for file-creation rules. The same rule and image also alerted on 5 October, on 9 October (at times that overlap with my Atomic Red Team runs) and on 11 October.

## 4. Why the rule fired

Rule 92213 flags executable or script files written to folders such as `Temp`, without checking which process wrote them or what the file is. Normal PowerShell use satisfies that condition.

## 5. Verdict

False positive. Pattern A is lab setup activity confirmed on the endpoint, and pattern B is built-in PowerShell behavior.

**Limitation:** I reviewed the full file name for one alert of pattern A and one of pattern B (11 October). The other alerts were classified by image, folder prefix and timing.

## 6. Tuning recommendation

Add a narrow child rule of 92213 that lowers the level only when the image is `powershell.exe` from `C:\Windows\System32\WindowsPowerShell\v1.0\` and the file name starts with `__PSScriptPolicyTest_` in the user's `Temp` folder. Package extraction (pattern A) is best handled by context, because a legitimate module install and a malicious payload can look similar by path alone.

## 7. Residual risk

Attackers use PowerShell to drop payloads into `Temp`. A broad exclusion for `powershell.exe` would hide that, so tuning must stay limited to the exact file-name pattern, image path and folder.

## 8. Evidence

Files in [`screenshots/`](../screenshots/):

- `04-ir004-non-cleanmgr-breakdown.png`: the 18 non-`cleanmgr` alerts of 3 October
- `04-ir004-guid-temp-files.png`: `YamlDotNet.dll` alert details
- `04-ir004-powershell-temp.png`: `__PSScriptPolicyTest` alert details
- `04-ir004-powershell-yaml-module.png`: `Get-Module` output on the endpoint
