Lets say you want to hunt accross the system for powershell related activity; specifically execution of powershell .ps1 files from a wide net of stuff neatly displayed tabulalr. 

The drawback here is that it catches a wide range of backround bullshit. The solution? We can filter out instances executed by NT Authorityt System. While this may mean an attacker with a 
system shell spawned by psexec is missed; it is worth it for us since the trade off you get a very much higher chance of catching badness and anything that slips through the cracks can easily be caught
by other queries. Every query should never catch everything. 

```sql
index=* ".ps1" (sourcetype=*sysmon* OR sourcetype=*powershell* OR sourcetype=*security* OR sourcetype=*wineventlog* OR sourcetype=*edr* OR sourcetype=*defender* OR sourcetype=*carbon* OR sourcetype=*crowdstrike*) NOT (User="NT AUTHORITY\\SYSTEM" OR Image="C:\\Windows\\Temp\\__PSScriptPolicy*") | eval log_source=case(match(sourcetype,"(?i)sysmon"),"Sysmon", match(sourcetype,"(?i)powershell"),"PowerShell Operational", match(sourcetype,"(?i)security"),"Windows Security", match(sourcetype,"(?i)defender"),"Windows Defender", match(sourcetype,"(?i)carbon|crowdstrike"),"EDR", 1=1,sourcetype) | eval activity_type=case(EventCode=1,"Process Created", EventCode=11,"File Created", EventCode=15,"File Stream Created", EventCode=7,"Image Loaded", EventCode=4688,"Process Created", EventCode=4103,"PowerShell Module", EventCode=4104,"Script Block Executed", EventCode=4105,"Script Started", EventCode=4106,"Script Stopped", 1=1,"Other") | eval script_info=coalesce(TargetFilename,Path,ScriptName,Image) | table _time, Computer, log_source, activity_type, EventCode, script_info, CommandLine, ProcessId, User, ScriptBlockText, ParentImage, ParentCommandLine | sort -_time
```
Another cool check we can do is just looking for all instances of powershell execution. This is just a sort of think it through approach but we generally dont care about events where the execution policy is set to restricted as to run external commands and scripts a TA needs it to be Signed or Bypass. 

The second aspect is .psm1 are used alot by windows but most threat actor tools will be in the .ps1 file format. This isnt perfect but its also meant to be a pivot table that you can expand on: 

```sql
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="*powershell.exe*"
NOT (TargetFilename="*.psm1" OR CommandLine="*Restricted*") | table _time, Image, Company, CommandLine, User | sort -_time
```
