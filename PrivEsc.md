
```sql
index="*" sourcetype="WinEventLog:Security" (EventCode=4672 OR EventCode=4673 OR EventCode=4674) 
| eval user_account=coalesce(SubjectUserName, Account_Name, User)
| stats count, earliest(_time) as first_seen, latest(_time) as last_seen, values(EventCode) as event_codes by user_account
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort -count
```

This will allow us to map out potential evidence of Priv esc. We are focusing on these three event IDs and what they mean in context:

- **EventCode 4672**: "Special privileges assigned to new logon" - Fires when someone logs in with admin rights
- **EventCode 4673**: "A privileged service was called" - Fires when someone uses a specific privileged operation
- **EventCode 4674**: "An operation was attempted on a privileged object" - Fires when someone accesses protected system resources


Lets say we wanted to detect potentially the fact that NT/Authority executed an exe that is not signed then we can use this query. The issue is that we may or may not miss certain things as well as the fact that depending on your enviroment
this may produce too many false positives. You may reduce them easily as the query doesnt show duplicate events as well as providing hashes for easy submission to VT: 

```sql
index=* source="*Sysmon*" EventCode=1 
    User="NT AUTHORITY\\SYSTEM"
    (Signed="false" OR NOT Signed="true")
    NOT Image IN ("*\\Windows\\System32\\*", "*\\Windows\\SysWOW64\\*")
| table _time, Computer, User, Image, CommandLine, ParentImage, Signed, Hashes
| dedup Image
```
The next set of queries are focused around detecting the abuse of potatoe classes of exploits. Note that these queries likely have signifcant issues and may produce false positives however I hope that they provide a base in which one could then build on them to make them more effective:

```sql
index=* source="*Sysmon*" EventCode=8
    (TargetImage="*\\lsass.exe" OR 
     TargetImage="*\\winlogon.exe" OR
     TargetImage="*\\services.exe")
    SourceUser!="NT AUTHORITY\\SYSTEM"
| table _time, Computer, SourceImage, TargetImage, SourceUser, TargetUser
```

This one allows us to detect potential uses with default SeImpersonatePrivlidges preforming what may be priv esc via a potatoe based exploit

```sql
index=* source="*Sysmon*" EventCode=1
| eval PrevIntegrity = [search index=* source="*Sysmon*" EventCode=1 
    Computer=Computer ProcessId=ParentProcessId earliest=-1h 
    | head 1 | return $IntegrityLevel]
| where IntegrityLevel="System" AND PrevIntegrity!="System"
| where User IN ("IIS APPPOOL\\*", "NT AUTHORITY\\IUSR", "NT AUTHORITY\\NETWORK SERVICE", "NT AUTHORITY\\LOCAL SERVICE")
| table _time, Computer, User, Image, ParentImage, CommandLine, IntegrityLevel, PrevIntegrity
```

Finally this query qill allow us to detect any funny bussiness occuring over common Named pipes used by potateo exploits:

```sql
index=* source="*Sysmon*" 
    (EventCode=17 OR EventCode=18)
    (PipeName="\\*\\pipe\\spoolss" OR 
     PipeName="\\*\\pipe\\netsvcs" OR
     PipeName="\\*\\pipe\\efsrpc" OR
     PipeName="\\*\\pipe\\lsarpc" OR
     PipeName="\\*\\pipe\\samr")
    Image!="*\\System32\\*"
| table _time, Computer, EventCode, PipeName, Image, User
```
