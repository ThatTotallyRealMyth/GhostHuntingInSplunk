
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
