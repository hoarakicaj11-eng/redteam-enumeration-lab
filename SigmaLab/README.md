\# SigmaLab — Suspicious PowerShell Detection



\## Project Overview



SigmaLab is a Windows detection-engineering project focused on identifying potentially suspicious PowerShell execution using Sigma, Sysmon, and Splunk query conversion.



The project demonstrates the process of creating, validating, testing, and documenting a detection rule for suspicious PowerShell command-line activity.



\---



\## Objective



The objective of this project was to develop a Sigma detection rule capable of identifying PowerShell processes using command-line arguments commonly associated with suspicious execution.



The detection focuses on:



\* PowerShell and PowerShell Core execution

\* Encoded PowerShell commands

\* No-profile execution

\* Execution Policy Bypass

\* Hidden PowerShell windows



\---



\## Tools \& Technologies



| Technology         | Purpose                                |

| ------------------ | -------------------------------------- |

| Windows PowerShell | Test environment and command execution |

| Sysmon             | Windows process-creation telemetry     |

| Sigma              | Detection-rule development             |

| Sigma CLI          | Rule validation and conversion         |

| Splunk             | Target SIEM query format               |

| MITRE ATT\&CK       | Technique mapping                      |



\---



\## Lab Environment



\*\*Operating System:\*\* Windows



\*\*Project Directory:\*\*



```text

C:\\SigmaLab

```



\*\*Primary files:\*\*



```text

powershell-suspicious.yml

powershell-suspicious-splunk.txt

README.md

```



\---



\## Detection Engineering Approach



The detection follows this workflow:



```text

PowerShell

&#x20;   ↓

Sysmon Event ID 1

&#x20;   ↓

Sigma Detection Rule

&#x20;   ↓

Sigma CLI Validation

&#x20;   ↓

Splunk Backend Conversion

&#x20;   ↓

Splunk Detection Query

```



The rule uses Windows `process\_creation` telemetry and looks for PowerShell processes combined with suspicious command-line indicators.



\---



\## Sigma Detection Rule



The rule identifies:



```text

powershell.exe

pwsh.exe

```



and searches their command lines for:



```text

\-enc

\-encodedcommand

\-nop

\-noprofile

\-executionpolicy bypass

\-windowstyle hidden

```



The detection condition is:



```text

selection AND suspicious\_flags

```



This means both conditions must be satisfied for the event to be considered suspicious.



\### MITRE ATT\&CK Mapping



The rule is mapped to:



\*\*T1059.001 — PowerShell\*\*



This technique is part of the Command and Scripting Interpreter tactic.



\---



\## Sysmon Telemetry



Sysmon Event ID 1, \*\*Process Create\*\*, was used to verify that PowerShell execution generated the expected telemetry.



A real event generated during testing contained:



```text

Event ID: 1

Process Create

Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

```



The Sysmon event also identified the PowerShell technique:



```text

T1059.001 — PowerShell

```



\---



\## Testing



\### 1. Benign Test



A normal PowerShell command was executed:



```powershell

powershell.exe -Command "Write-Output 'BENIGN SigmaLab test'"

```



Expected behavior:



```text

BENIGN SigmaLab test

```



The command executed normally and provided a baseline for comparison.



\---



\### 2. Suspicious Test



A harmless PowerShell command containing one of the rule's suspicious indicators was executed:



```powershell

powershell.exe -ExecutionPolicy Bypass -Command "Write-Output 'SUSPICIOUS SigmaLab test'"

```



Result:



```text

SUSPICIOUS SigmaLab test

```



The command generated Sysmon Event ID 1 telemetry.



The recorded command line contained:



```text

\-ExecutionPolicy Bypass

```



This is one of the indicators monitored by the Sigma rule.



\---



\## Detection Logic Verification



The suspicious test satisfied both parts of the Sigma condition.



\### Selection



The event contained a PowerShell process:



```text

powershell.exe

```



Therefore:



```text

selection = TRUE

```



\### Suspicious Flags



The command line contained:



```text

\-ExecutionPolicy Bypass

```



Therefore:



```text

suspicious\_flags = TRUE

```



\### Final Condition



```text

selection AND suspicious\_flags

```



Result:



```text

TRUE AND TRUE = TRUE

```



The Sysmon telemetry therefore satisfies the detection conditions defined by the Sigma rule.



\---



\## Sigma Rule Validation



The Sigma rule was validated using Sigma CLI.



Validation result:



```text

Found 0 errors, 0 condition errors and 0 issues.

No rule errors found.

No condition errors found.

No validation issues found.

```



This confirmed that the detection rule was syntactically valid and that its condition was accepted by the Sigma validator.



\---



\## Splunk Conversion



The Sigma rule was converted into a Splunk-compatible query using the `splunk\_windows` processing pipeline.



The generated query contains logic equivalent to:



```text

Image IN ("\*\\\\powershell.exe", "\*\\\\pwsh.exe")

CommandLine IN (

&#x20;   "\* -enc \*",

&#x20;   "\* -encodedcommand \*",

&#x20;   "\* -nop \*",

&#x20;   "\* -noprofile \*",

&#x20;   "\* -executionpolicy bypass\*",

&#x20;   "\* -windowstyle hidden\*"

)

```



The generated query was saved as:



```text

powershell-suspicious-splunk.txt

```



\### Important Limitation



The Splunk query was successfully generated and reviewed, but this project did not execute the query against a live Splunk instance.



Therefore, this project demonstrates \*\*Sigma-to-Splunk query generation\*\*, rather than a complete live-SIEM alerting workflow.



\---



\## Results



| Test                                  | Result        |

| ------------------------------------- | ------------- |

| Sigma rule creation                   | Successful    |

| Sigma validation                      | 0 errors      |

| Sysmon Event ID 1                     | Confirmed     |

| Benign PowerShell test                | Successful    |

| Suspicious PowerShell test            | Successful    |

| Suspicious flag detected in telemetry | Confirmed     |

| Splunk query conversion               | Successful    |

| Live Splunk execution                 | Not performed |



\---



\## Skills Demonstrated



This project demonstrates practical experience with:



\* Detection engineering

\* Sigma rule development

\* Windows security telemetry

\* Sysmon Event ID 1 analysis

\* PowerShell security monitoring

\* MITRE ATT\&CK mapping

\* Sigma CLI

\* SIEM query conversion

\* Splunk query development

\* Detection testing

\* Technical documentation

\* False-positive considerations



\---



\## False Positives



Potential legitimate activity may include:



\* Administrative PowerShell scripts

\* Software deployment tools

\* System-management automation

\* Security and IT administration



A production detection would require additional tuning and contextual filtering to reduce false positives.



\---



\## Limitations \& Future Improvements



Possible improvements include:



1\. Deploy the generated query in a live Splunk environment.

2\. Test against larger volumes of Windows telemetry.

3\. Add additional contextual conditions to reduce false positives.

4\. Create additional benign and suspicious test cases.

5\. Add parent-process analysis.

6\. Incorporate user and host context.

7\. Develop additional Sigma rules for related PowerShell behaviors.

8\. Test the detection against a controlled attack-simulation environment.



\---



\## Conclusion



SigmaLab demonstrates a complete introductory detection-engineering workflow, from writing a Sigma rule through validation, telemetry generation, testing, and SIEM query conversion.



The project successfully demonstrated that a PowerShell process containing a suspicious command-line indicator such as `-ExecutionPolicy Bypass` produces Sysmon telemetry that satisfies the detection logic.



The resulting Sigma rule was validated successfully and converted into a Splunk-compatible query.



This project provides a practical foundation for further work in SOC operations, threat detection, SIEM engineering, and defensive cybersecurity.



\---



\## Project Structure



```text

C:\\SigmaLab

│

├── powershell-suspicious.yml

├── powershell-suspicious-splunk.txt

└── README.md

```



\---



\*\*Project:\*\* SigmaLab

\*\*Focus:\*\* PowerShell Detection Engineering

\*\*Detection Format:\*\* Sigma

\*\*SIEM Target:\*\* Splunk

\*\*Telemetry:\*\* Sysmon Event ID 1

\*\*MITRE ATT\&CK:\*\* T1059.001 — PowerShell



