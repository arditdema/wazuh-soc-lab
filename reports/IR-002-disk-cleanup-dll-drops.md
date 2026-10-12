# IR-002: Disk Cleanup (cleanmgr.exe) triggering critical alerts (Wazuh rule 92213)

| | |
|---|---|
| **Type** | Alert triage |
| **Verdict** | False positive (benign Windows behavior) |
| **Rule** | 92213 "Executable file dropped in folder commonly used by malware", level 15 (critical) |
| **MITRE ATT&CK (as mapped by the rule)** | T1105 Ingress Tool Transfer (Command and Control) |
| **Endpoint** | `win-laptop` (Windows 10 Pro, Sysmon, Wazuh agent 4.14.8) |
| **Occurrences** | 26 alerts on 3 October 2026; a second batch on 8 October 2026 |

## 1. Summary

On 3 October 2026 rule 92213 raised 26 critical alerts in a burst starting at 20:06:44 local, all attributed to `cleanmgr.exe` (the built-in Disk Cleanup utility). The alert I reviewed in detail was a DLL created in a GUID-named folder under the user's `Temp` directory. The same pattern repeated on 8 October. I classified the alerts as a false positive, and the main finding is about severity: one harmless action produced a burst of level 15 alerts.

## 2. Alert details

| Field | Value |
|---|---|
| Alert time (first) | 2026-10-03 20:06:44 local (18:06:44 UTC) |
| Sysmon event | Event ID 11 (file created) |
| Process image | `C:\Windows\System32\cleanmgr.exe` |
| Created file | `C:\Users\<user>\AppData\Local\Temp\62076D8C-EE60-4A9B-AD78-BB6D329B3988\WimProvider.dll` |
| Running as | the signed-in interactive user |
| Rule level | 15 |

## 3. Investigation

1. **Scope.** Using a fixed time window (3 October, 00:00 to 24:00 local) I counted the rule 92213 alerts: 44 in total, of which 26 came from `cleanmgr.exe` and 18 from PowerShell. The PowerShell alerts are analyzed in IR-004.
2. **Pattern.** All 26 alerts name `cleanmgr.exe` as the process (this is the filter I used for the count). The alert reviewed in detail shows a DLL inside a GUID-named folder in the user's `Temp` directory; I did not open every alert.
3. **File signature.** On 11 October I checked the signature of the binary on the endpoint. It is validly signed by Microsoft. (The file-creation event does not carry the hash of the writing process, so I could not compare hashes as in IR-001.)

   ```powershell
   Get-AuthenticodeSignature C:\Windows\System32\cleanmgr.exe | Format-List Status, SignerCertificate
   ```
   ```
   Status            : Valid
   SignerCertificate : CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
   Issuer            : CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation
   ```
4. **Recurrence.** On 8 October (19:35 UTC) `cleanmgr.exe` created `TransmogProvider.dll` in another GUID-named `Temp` folder (alert indexed on 9 October). A different DLL name in a new GUID folder each time fits a tool that extracts its helper components at each run.
5. **Process origin.** Sysmon process-creation events (Event ID 1) on the endpoint show how the run started (local time, read with `Get-WinEvent` on the Sysmon log). Wazuh holds no alert for these events, because no rule matches them.
   - 20:06:20: `cleanmgr.exe /autoclean /d C:` was started by `svchost.exe -k netsvcs -p -s Schedule` (the Windows Task Scheduler service), as the signed-in user.
   - 20:06:44: `dismhost.exe` was started from `Temp\62076D8C-EE60-4A9B-AD78-BB6D329B3988\` with `cleanmgr.exe` as its parent. This is the same GUID folder as the alert in section 2.

   There is no PowerShell, installer or Atomic Red Team process in this chain. The command line `cleanmgr.exe /autoclean /d C:` is consistent with the built-in `SilentCleanup` scheduled task. The task's last run on the endpoint was at 20:17 local; I did not match the 20:06 run to the task history. Why Windows ran the cleanup at that moment was not established.
6. **Why the rule fired.** Rule 92213 flags any executable or DLL written to folders such as `Temp`, without checking the writing process or its signature.

## 4. Verdict

False positive. A validly signed Microsoft utility from `System32` wrote helper DLLs to its own temporary folder, repeatedly and with a consistent pattern.

**Limitation:** the launch chain is established (Task Scheduler service, then `cleanmgr.exe`), but why Windows started the cleanup at that moment is not (see point 5).

## 5. Tuning recommendation

26 critical alerts from one action would bury real alerts in a SOC queue. Add a narrow child rule of 92213 that lowers the level only when the image is `C:\Windows\System32\cleanmgr.exe` and the file path matches `...\AppData\Local\Temp\<GUID>\*.dll`. Do not exclude `cleanmgr.exe` entirely, and do not exclude the `Temp` folder in general.

## 6. Residual risk

Attackers can abuse trusted system binaries or plant DLLs for them to load. A tuned rule should keep alerting when `cleanmgr.exe` writes files outside the GUID-folder pattern, or when the process is not the one in `System32`.

## 7. Evidence

Files in [`screenshots/`](../screenshots/):

- `02-ir002-cleanmgr-detail.png`: alert for `WimProvider.dll` (3 October)
- `02-ir002-cleanmgr-26-hits.png`: 26 alerts from `cleanmgr.exe` in the fixed window
