# IR-003: Detection gap for scheduled task persistence (T1053.005)

| | |
|---|---|
| **Type** | Detection gap found in a controlled simulation (no real compromise) |
| **MITRE ATT&CK** | T1053.005 Scheduled Task/Job: Scheduled Task (Execution, Persistence, Privilege Escalation) |
| **Exercise dates** | 3 October 2026 and 9 October 2026 |
| **Environment** | Wazuh 4.14 all-in-one on Ubuntu Server 22.04 (VirtualBox); Windows 10 Pro endpoint `win-laptop` with Sysmon and Wazuh agent 4.14.8 |
| **Tooling** | Atomic Red Team (`Invoke-AtomicTest`) |
| **Outcome** | Gap confirmed, two custom rules written and validated, residual gaps documented |

## 1. Summary

I simulated scheduled task creation with Atomic Red Team and checked whether the default Wazuh ruleset would alert on it. It did not detect the creation of the task itself. The default rules only raised low-severity alerts (level 3-4) on the surrounding shell activity for one variant, and nothing at all for a second variant that uses PowerShell cmdlets.

I wrote two custom rules, **100100** and **100101**, and validated that each fires at level 10 on the variant it targets.

## 2. Timeline (UTC; local time on the endpoint is UTC+2)

| Time (UTC) | Event |
|---|---|
| 2026-10-03 19:04-19:05 | `Invoke-AtomicTest T1053.005 -TestNumbers 2` (`schtasks /create`, task `spawn`). Default rules raised only 92032 (level 3), 92052 (level 4) and 92004 (level 4) on the spawned `cmd.exe`. No alert for the task creation. |
| 2026-10-03 19:19:56 | After adding rule 100100, the same test was repeated and rule **100100** fired (level 10, T1053.005). |
| 2026-10-09 15:10 and 15:15 | `Invoke-AtomicTest T1053.005 -TestNumbers 4` (PowerShell `ScheduledTask` cmdlets, task `AtomicTask`). Sysmon logged Event ID 1 and 11 on the endpoint, but a Wazuh search for `AtomicTask` over the window 15:00-15:30 UTC returned no alerts. Gap confirmed. |
| 2026-10-09 ~15:52 | First version of rule 100101 did not fire (regex problem, see section 4). |
| 2026-10-09 15:57:12 | After correcting the regex, rule **100101** fired (level 10): `svchost.exe` running as SYSTEM created `C:\Windows\System32\Tasks\AtomicTask`. |

## 3. Findings

1. The default ruleset detected shell activity around the test, not the persistence mechanism. A SOC analyst triaging by severity would not have seen it.
2. `schtasks.exe /create` and the PowerShell `ScheduledTask` cmdlets leave different traces. The cmdlet variant never runs `schtasks.exe`, so a rule based on that process cannot see it.
3. In the cmdlet variant the task file is written by the Task Scheduler service (`svchost.exe` as SYSTEM), not by PowerShell. Detection therefore has to key on the file creation, not on the parent process.

## 4. Detection engineering

Both rules are in [`rules/local_rules.xml`](../rules/local_rules.xml).

**Rule 100100** builds on rule 61603 (Sysmon process creation) and matches `schtasks.exe` with `/create` in the command line:

```xml
<rule id="100100" level="10">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/create</field>
  <description>Scheduled task created via schtasks.exe (possible persistence)</description>
  <mitre><id>T1053.005</id></mitre>
</rule>
```

**Rule 100101** builds on rule 61613 (Sysmon file creation) and matches new files under `System32\Tasks`, excluding the `Microsoft\` subfolder to reduce noise from built-in tasks:

```xml
<rule id="100101" level="10">
  <if_sid>61613</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)^C:\\+Windows\\+System32\\+Tasks\\+(?!Microsoft\\+)</field>
  <description>Scheduled task file created in System32\Tasks (possible persistence)</description>
  <mitre><id>T1053.005</id></mitre>
</rule>
```

**Troubleshooting note.** My first version of rule 100101 did not fire. Wazuh stores Windows paths with doubled backslashes (visible in the `full_log` field), and my pattern expected a single one. Changing each separator to `\\+` (one or more backslashes) fixed it.

## 5. Coverage after the change

| Variant | Atomic test | Default rules | Rule 100100 | Rule 100101 |
|---|---|---|---|---|
| `schtasks /create` | T1053.005 #2 | Shell alerts only (level 3-4) | Detected | Not tested |
| PowerShell `ScheduledTask` cmdlets | T1053.005 #4 | No alert | Not applicable | Detected |

## 6. Limitations

- Rule 100101 can fire on legitimate software that registers tasks, such as updaters. It needs an allowlist before production use.
- The `Microsoft\` exclusion reduces noise but means a malicious task placed in that folder would be missed.
- Only two of the technique's variants were tested, on one host. WMI, VBA and registry-based variants were not covered.
- Rule 100100 only matches `/create`; other `schtasks` actions (for example `/change`) are not covered.

## 7. Recommendations

1. Add an allowlist for known updaters and review the `Microsoft\` exclusion.
2. Add detection based on Windows Security Event 4698 (task created) and the Task Scheduler Operational log. These were not tested here.
3. Test the remaining T1053.005 variants and re-validate the rules after each ruleset update.

## 8. Evidence

Files in [`screenshots/`](../screenshots/):

- `03-ir003-default-rules-spawn.png`: default rules 92032, 92052, 92004 (levels 3-4)
- `03-ir003-rule-100100-alert.png`: rule 100100 alert details
- `03-ir003-sysmon-event-log.png`: Sysmon Event ID 1 and 11 for `AtomicTask` on the endpoint
- `03-ir003-no-alert-17-05-17-25.png`: Wazuh search for `AtomicTask` returning no results
- `03-ir003-rule-100101-alert.png`: rule 100101 alert details

Rules file: [`rules/local_rules.xml`](../rules/local_rules.xml)
