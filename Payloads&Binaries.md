To get all executables run on all systems that are not by Microsoft or google or vmware can be achieved via:

```sql
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | where NOT match(Company, "(?i)(Microsoft|Google|VMware)") | table _time, Image, Company, CommandLine, User | sort -_time
```

This is insanely high fidelity as it really filters out the bloody noise in the environment. The powerful thing is you can keep adding case insitive names of companies/signers as per your enviroment to consistently reduce the noise 


Lets say we want to hunt for stuff related to hunting for scripts execution and the likes or macros etc etc 

```sql
index=* source=*
(Image="*\\mshta.exe" OR Image="*\\certutil.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR CommandLine="*\\mshta.exe*" OR CommandLine="*\\certutil.exe*" OR CommandLine="*-decode*" OR CommandLine="*-urlcache*" OR CommandLine="*.hta*" OR CommandLine="*.vbs*" OR CommandLine="*.vba*" OR CommandLine="*.doc*" OR CommandLine="*.ps1*")
| table _time, Image, CommandLine, User, ComputerName
| sort -_time
```

We can continue to add to this, for example looking for commandlines that include -Bypass, or IWR or IEX as well as hunting for .xlsx and .docm files and what not. This can introduce alot of false positives or not but 
That is easy to address. It is just as easy to remove all non macro word documents in favor 


```sql
index=* source=*
(Image="*\\mshta.exe" OR Image="*\\certutil.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR 
CommandLine="*\\mshta.exe*" OR CommandLine="*\\certutil.exe*" OR 
CommandLine="*-decode*" OR CommandLine="*-urlcache*" OR CommandLine="*-Bypass*" OR CommandLine="*-EncodedCommand*" OR 
CommandLine="*IEX*" OR CommandLine="*IWR*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*Invoke-Expression*" OR CommandLine="*DownloadString*" OR CommandLine="*DownloadFile*" OR
CommandLine="*.hta*" OR CommandLine="*.vbs*" OR CommandLine="*.vba*" OR CommandLine="*.doc*" OR CommandLine="*.docm*" OR CommandLine="*.docx*" OR CommandLine="*.xls*" OR CommandLine="*.xlsx*" OR CommandLine="*.xlsm*" OR CommandLine="*.ppt*" OR CommandLine="*.pptm*" OR 
CommandLine="*.ps1*" OR CommandLine="*.bat*" OR CommandLine="*.cmd*" OR
CommandLine="*FromBase64String*" OR CommandLine="*Net.WebClient*" OR CommandLine="*hidden*" OR CommandLine="*-nop*" OR CommandLine="*-w hidden*" OR CommandLine="*-noni*" OR CommandLine="*-ec*") NOT (CommandLine="*Restricted*" OR Image="C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe")
| table _time, Image, CommandLine, User, ComputerName, ParentImage
| sort -_time
```

To find the first time, last time, effected hosts, executing users and times a given exe was executed; 

```sql
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
Image="*some.exe"
| stats earliest(_time) as first_seen, 
        latest(_time) as last_executed,
        count as times_executed,
        values(Computer) as affected_hosts,
        values(User) as executing_users
        by Image
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"),
       last_executed=strftime(last_executed, "%Y-%m-%d %H:%M:%S")
```

We can take this further and create seperate lines for each impacted host and executing user if we chose but this is a stable foundation

We can also incorporate addtional sources and logs like so: 

```sql
index=* "*some.exe*"
| eval process_path=coalesce(Image, NewProcessName, ProcessName, FileName, TargetFilename),
       user_account=coalesce(User, SubjectUserName, TargetUserName, AccountName),
       host=coalesce(Computer, ComputerName, host)
| stats earliest(_time) as first_seen,
        latest(_time) as last_seen,
        count as times_executed,
        values(user_account) as executing_users,
        values(host) as affected_hosts
        by process_path
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort first_seen
```

Note that this ends up pooling additional information that may not necessarily, 101% be just the execution of the object 

Another thing is if we have sysmon; whenever process creation occurs for the first time, sysmon will generate a set of hashes for the file whos process was created. 

This means we can find the first time a file was exectuted and a process created as well as any associated hashes to expand our hunt using something like VirusTotal

```sql
index=* "*some.exe" 
| eval all_fields=mvjoin(mvfilter(match(split(tostring(_raw), " "), "(?i)(sha256|md5|sha1|hash)")), " | ")
| where isnotnull(all_fields) AND all_fields!=""
| table _time Computer all_fields
```

lets say we want to hunt across process geneology

Starters lets see a simple check for a given file; what were its child proceses, commandlines, the user who executed and the time: 

```sql
index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
ParentImage="*some.exe" | table _time Computer Image ParentImage CommandLine User
| sort _time
```
| table _time Computer Image ParentImage CommandLine User
| sort _time
```
