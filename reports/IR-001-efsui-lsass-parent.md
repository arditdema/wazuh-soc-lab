# IR-001: efsui.exe started by lsass.exe (Wazuh rule 61627)

| | |
|---|---|
| **Type** | Alert triage |
| **Verdict** | False positive (benign Windows behavior) |
| **Rule** | 61627 "Sysmon - Suspicious Process - lsass.exe is a Parent Image", level 12 |
| **MITRE ATT&CK (as mapped by the rule)** | T1055 Process Injection (Defense Evasion, Privilege Escalation) |
| **Endpoint** | `win-laptop` (Windows 10 Pro, Sysmon, Wazuh agent 4.14.8) |
| **Occurrences** | 3 October 2026 (first alert); 6 October 2026 (second event, indexed 9 October) |

## 1. Summary

Wazuh raised a level 12 alert because `lsass.exe` was the parent of another process. `lsass.exe` is a high-value target (credential theft, process injection), so a child process is worth checking. The child here was `efsui.exe /efs /keybackup`, a Microsoft-signed Windows component whose file hash was unchanged. I classified the alert as a false positive.

## 2. Alert details

| Field | Value |
|---|---|
| Alert time | 2026-10-03 16:59:50 local (14:59:50 UTC) |
| Process image | `C:\Windows\System32\efsui.exe` |
| Command line | `efsui.exe /efs /keybackup` |
| Description / company | EFS UI Application / Microsoft Corporation |
| File version | 10.0.19041.1 |
| Integrity level | High |
| Parent image | `C:\Windows\System32\lsass.exe`, running as `NT AUTHORITY\SYSTEM` |
| SHA256 | `EC1DC1A2EE200DA0C787328DF4FB91A2B978FD09CA1F83F3E55994C0F9BA1D11` |
| MD5 | `64F5611CC62E65748D140E6F288CE1EA` |
| IMPHASH | `79780253655B3282FD06EA62FCA2F32F` |

## 3. Investigation

1. **Parent process.** The parent path is the real `C:\Windows\System32\lsass.exe`, running as SYSTEM, not a lookalike in a user-writable folder.
2. **File signature.** On the endpoint I checked the signature of the file:

   ```powershell
   Get-AuthenticodeSignature C:\Windows\System32\efsui.exe | Format-List Status, SignerCertificate
   ```
   ```
   Status            : Valid
   SignerCertificate : CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
   Issuer            : CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation
   ```
3. **File hash.** The SHA256 computed locally on 9 October with `Get-FileHash` is identical to the SHA256 recorded in the alert, so the binary was not modified between the alert and the check.
4. **Command line.** `/efs /keybackup` is consistent with the Windows prompt to back up the Encrypting File System (EFS) certificate and key, which `lsass.exe` launches for the signed-in user. The signed-in user has an EFS certificate in their personal certificate store, dated 16 May 2024. That certificate is older than the alerts, so it does not explain why the prompt appeared on these days.
5. **Recurrence.** The same pattern appeared again on 6 October (09:07:57 UTC) with the same image and the same parent (`lsass.exe`, PID 848, SYSTEM), which fits recurring system behavior and not a one-off injection.
6. **Why the rule fired.** Rule 61627 matches any process whose parent is `lsass.exe`, without checking what the child is or whether it is signed.

## 4. Verdict

False positive. The parent is the genuine `lsass.exe`, the child is a validly signed Microsoft binary with a matching hash, and the command line matches a known Windows function.

**Limitation:** I did not identify which user action triggered the EFS prompt on those two days.

## 5. Tuning recommendation

Keep rule 61627 as it is for every other child of `lsass.exe`. Add a narrow child rule that lowers the level only when all of these match: image `C:\Windows\System32\efsui.exe`, parent `C:\Windows\System32\lsass.exe`, command line `/efs /keybackup`, and the known SHA256. Matching on the hash and the full path (not on the file name alone) matters because an attacker can name malware `efsui.exe`.

## 6. Residual risk

A tuned rule must not hide real abuse of `lsass.exe`. Any other child of `lsass.exe`, or an `efsui.exe` with a different hash or path, must still alert at level 12.

## 7. Evidence

Files in [`screenshots/`](../screenshots/):

- `01-ir001-alert-details.png`: alert fields (command line, hashes, integrity level)
- `01-ir001-rule-61627.png`: rule 61627, level 12, T1055
- `01-ir001-parent-lsass.png`: parent image, parent user, second occurrence
