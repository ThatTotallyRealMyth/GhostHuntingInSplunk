
Lets start of with hunting for the creation of local accounts: 

```sql
index=* sourcetype="WinEventLog:Security" EventCode=4720
| rex field=Message "New Account:.*?Account Name:\s+(?<new_account>[^\r\n\t]+)"
| rex field=Message "Subject:.*?Account Name:\s+(?<creator>[^\r\n\t]+)"
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table timestamp Computer new_account creator Message
| sort _time
```

This query will thus provide us with the timestamp and message detial of local account creation. Noting that it will show you the earliest instances first. 

We can then use this query to search for all  AD created accounts with the earliest entries first:

```sql
index=* sourcetype="WinEventLog:Security" EventCode=4720
| rex field=Message "New Account:.*?Account Name:\s+(?<new_account>[^\r\n\t]+)"
| rex field=Message "Subject:.*?Account Name:\s+(?<created_by>[^\r\n\t]+)"
| rex field=Message "New Account:.*?Account Domain:\s+(?<target_domain>[^\r\n\t]+)"
| rex field=Message "Subject:.*?Account Domain:\s+(?<creator_domain>[^\r\n\t]+)"
| where target_domain="QUICKFIX"
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table timestamp Computer new_account created_by creator_domain
| sort _time
```

Here we will match using the domain name and thus that should be placed with whatever domain it is youre hunting across


Lets say for a given username, we want to see all their activity conducted from the commandline, in which case we can do: 

```sql
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
User="*helpdesk_1*"
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S"),
       process_name=mvindex(split(Image,"\\"),-1)
| table timestamp Computer User process_name Image CommandLine ParentImage
| sort _time
```

This command will show us modifications done to security enabled global groups, meaning if a user was added to any privlidged AD group; 

```sql
index=* EventCode=4735 OR EventCode=4737 OR EventCode=4745 OR EventCode=4750 OR EventCode=4760 OR EventCode=4764 OR EventCode=4755 OR EventCode=4758
| head 20
| table index, source, sourcetype, EventCode, _time, _raw
```

We can also use this query to look for user creation and group additions on the AD scale: 

```sql
index=* EventCode=4720 OR EventCode=4728 OR EventCode=4732
| head 10
| table index, source, sourcetype, EventCode, _time
```

Lets say we want to hunt for sechuled tasks, in which case we can look for the common ways this is done(including the way impacket does it via atexec):

```sql
index=* source="*WinEventLog:Microsoft-Windows-Sysmon/Operational*" EventCode=1 
    (Image="*\\schtasks.exe" OR Image="*\\at.exe" OR CommandLine="*schtasks*" OR CommandLine="*/Create*" OR CommandLine="*/SC *")
| table _time, Computer, User, CommandLine, ParentImage, ParentCommandLine, Image
| rename Computer AS System, User AS Creator
```
