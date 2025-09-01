I built this repo as I went through the OffSec OSTH and OSIR certifications. I had learned a whole load about splunk and thought maybe I could share it with others too! Feel free to look at the different files with the relevant hunting queries. The following are also quick tips and references for you to have handy
as splunk is very powerful and you dont need to fully master the *query* language to be able to filter, find and display useful information. 



## Basic Search Structure
```spl
index=* source="*Sysmon*" EventCode=1 "powershell"
```
This searches ALL indexes for Sysmon process creation events containing "powershell" anywhere in the event. You can also remove eventcode argument and the source and search for all events with "powershell"

## Wildcards and Text Matching
```spl
index=* "*net.exe*"                    # Find ANY event containing net.exe
index=* "192.168"                      # Find ANY event with this IP pattern
index=* "powershell" (NOT "*net.exe*")   # Find powershell but exclude net.exe
index=* "HOST123" "*cmd.exe*"          # Find cmd.exe on specific host
```
With the (NOT) you can actually keep having many different things (NOT SOMEA) (NOT SOMEB) etc etc. You dont have to be perfectly; just functional. Espciailly when you want to quickly cunt down on things

The same can be done with AND OR etc or other things, as splunk can be very intutive in allowing you to use plaintext to filter as long as you be mindful of speed of which it takes to process. 
## Field-Specific Searches
```spl
index=* Image="*\\powershell.exe"      # Exact field match with wildcard
index=* Image=*.exe                    # All executables
index=* User="NT AUTHORITY\\SYSTEM"    # Specific user
index=* User!=Administrator            # NOT Administrator
index=* (Image="*cmd.exe" OR Image="*powershell.exe")  # Multiple options
```

## Common Sysmon Fields with | table

### Basic Process Information
```spl
index=* source=* EventCode=1
| table _time, Computer, User, Image, CommandLine
```

### With Parent Process Context
```spl
index=* source="*Sysmon*" EventCode=1
| table _time, Computer, User, ParentImage, ParentCommandLine, Image, CommandLine
```

### Network Connections
```spl
index=* source="*Sysmon*" EventCode=3
| table _time, Computer, Image, User, DestinationIp, DestinationPort, DestinationHostname
```

### File Creation
```spl
index=* source="*Sysmon*" EventCode=11
| table _time, Computer, Image, TargetFilename, CreationUtcTime
```

### Registry Modifications
```spl
index=* source="*Sysmon*" EventCode=13
| table _time, Computer, Image, TargetObject, Details, EventType
```

## Common Sysmon Event Codes
- **EventCode=1** - Process Creation
- **EventCode=3** - Network Connection
- **EventCode=7** - Image Loaded (DLL)
- **EventCode=8** - CreateRemoteThread
- **EventCode=11** - File Created
- **EventCode=13** - Registry Value Set
- **EventCode=15** - File Stream Created (ADS)
- **EventCode=22** - DNS Query

## Useful Filtering Patterns

### Exclude Noise
```spl
index=* source="*Sysmon*" EventCode=1 
    NOT Image="*\\Windows\\System32\\*"
    NOT User="NT AUTHORITY\\SYSTEM"
```

### Focus on Suspicious Paths
```spl
index=* source="*Sysmon*" EventCode=1
    (Image="*\\Temp\\*" OR Image="*\\AppData\\*" OR Image="*\\Public\\*")
```

### Command Line Contains
```spl
index=* source="*Sysmon*" EventCode=1
    CommandLine="*-enc*"              # Encoded commands
    CommandLine="*bypass*"            # Bypass flags
    CommandLine="*http://*"           # URLs in commands
```

## Combining Searches

### Process with Network Activity
```spl
index=* source="*Sysmon*" EventCode=1 Image="*\\rundll32.exe"
| join ProcessGuid 
    [search index=* source="*Sysmon*" EventCode=3]
| table _time, Computer, Image, CommandLine, DestinationIp, DestinationPort
```

### Parent-Child Relationships
```spl
index=* source="*Sysmon*" EventCode=1 
    ParentImage="*\\explorer.exe" 
    Image!="*\\Windows\\*"
| table _time, Computer, ParentImage, Image, CommandLine
```

## Time Filtering
```spl
index=* earliest=-24h                  # Last 24 hours
index=* earliest=-15m                  # Last 15 minutes
index=* earliest="10/01/2024:00:00:00" latest="10/02/2024:00:00:00"  # Specific range
```

## Quick Hunt Examples

### Find PowerShell Downloads
```spl
index=* "IEX" "DownloadString"
| table _time, Computer, User, CommandLine
```

### Find Suspicious Services
```spl
index=* source="WinEventLog:System" EventCode=7045 
    (Service_Name="*temp*" OR Service_Name="*update*")
| table _time, Computer, Service_Name, Service_File_Name
```

### Find Encoded Commands
```spl
index=* (CommandLine="*-enc*" OR CommandLine="*-e *" OR CommandLine="*base64*")
| table _time, Computer, User, Image, CommandLine
```

## Pro Tips
1. **Start broad, then narrow**: Begin with `index=* "keyword"` then add filters
2. **Use NOT to reduce noise**: `NOT Image="*\\trusted.exe*"`
3. **Wildcards are your friend**: `*` matches anything
4. **Case matters sometimes**: Use `(?i)` for case-insensitive regex when needed
5. **Check what fields exist**: Run search then look at "Interesting Fields" on the left
6. **Hunt for IoCs broadly**: For example if you pick up the threat actors used IP then you can use `index=* "*192.168.10.10*"` and see if you pick up other broad stroke activity related to this

## Essential Fields to Remember
- **_time** - When it happened
- **Computer/host** - What machine
- **User** - Who did it
- **Image** - What program
- **CommandLine** - How it was run
- **ParentImage** - What started it
- **TargetFilename** - What file was created/modified
- **DestinationIp** - Where it connected to
- **ProcessId/ProcessGuid** - Unique process identifiers

Feel free to customize this based on your environment and what you find most useful depending on your context. 

These queries next are OSTH/OSIR specific and more so aimed at answering the questions or helping you answer the questions in the labs/exams. 


# OSTH/OSIR Lab Hunt Queries

## Hunt with IOCs (Indicators of Compromise)
```spl
index="*" ("malicious.exe" OR
    "192.168.1.100" OR 
    "evil.com" OR 
    "45.142.212.100" OR 
    "badactor@email.com" OR 
    "C:\\Temp\\payload.ps1" OR 
    "HKLM\\Software\\Evil" OR 
    "mutex_12345" OR 
    "pipe\\evil_pipe" OR 
    "service_backdoor" OR 
    "scheduled_task_evil" OR 
    "SHA256_hash_here" OR
    "MD5_hash_here")
| table _time, host, source, User, Image, CommandLine, Message
```

## File Download Detection

### Web Download Commands
```spl
index="*" ("IWR" OR "Invoke-WebRequest" OR "wget" OR "curl" OR "DownloadString" OR "DownloadFile")
| table _time, host, User, CommandLine, ParentImage
```

### Zone.Identifier (Mark of the Web)
```spl
# All downloaded files
index="*" EventCode=15 TargetFilename="*:Zone.Identifier"
| table _time, host, User, TargetFilename, Image

# Specific dangerous file types
index="*" EventCode=15 (TargetFilename="*.exe:Zone.Identifier" OR 
    TargetFilename="*.ps1:Zone.Identifier" OR 
    TargetFilename="*.zip:Zone.Identifier" OR
    TargetFilename="*.dll:Zone.Identifier" OR
    TargetFilename="*.scr:Zone.Identifier")
| table _time, host, User, TargetFilename, Image

# Chrome downloads in progress
index="*" "*.crdownload" 
| table _time, host, User, TargetFilename
```

## Network Connections

### Top Destinations
```spl
index="*" EventCode=3 
| stats count by DestinationIp 
| sort -count 
| head 20
```

### Investigate Specific IP
```spl
index="*" DestinationIp="192.168.100.100" 
| table _time, User, Image, ProcessId, host, DestinationPort
```

# Track specific user's connections
```sql
index="*" DestinationIp="192.168.100.100" User="domain\\user" 
| table _time, Image, ProcessId, CommandLine, DestinationPort
```

### Connections from Specific Host
```spl
index="*" (SourceHostname="WK3.domain.com" OR host="WK3")
| stats count by DestinationIp 
| sort -count 
| head 20
```

## File Operations

### File Creation (First Instance)
```spl
index="*" EventCode=11 TargetFilename="*some.exe"
| sort _time 
| head 1
| table _time, host, User, Image, TargetFilename
```

### Track Specific File
```spl
index="*" EventCode=11 TargetFilename="C:\\Temp\\malicious.exe"
| table _time, host, User, Image, CreationUtcTime
```

## Process Execution

### First Execution of Binary
```spl
index="*" EventCode=1 Image="*\\some.exe"
| sort _time 
| head 1
| table _time, ComputerName, User, CommandLine, ParentImage, ProcessId
```

### Get Binary Hash
```spl
index="*" EventCode=1 Image="*\\suspicious.exe"

| table _time, ComputerName, User, Image, SHA256, CommandLine
```

## Authentication Events

### Successful Logins (Exclude Computer Accounts)
```spl
index="*" EventCode=4624 host="DB1" 
| regex Account_Name!=".*\$" 
| table _time, Account_Name, Logon_Type, Source_Network_Address, Workstation_Name
```

### Failed Logins
```spl
index="*" EventCode=4625 
| regex Account_Name!=".*\$"
| stats count by Account_Name, Source_Network_Address 
| sort -count
```

### Track Specific User Activity
```spl
index="*" (User="user" OR Account_Name="user")
| table _time, EventCode, ComputerName, Image, CommandLine, ProcessId
| sort _time
```

## User Management

### User Account Created
```spl
index="*" EventCode=4720
| table _time, Account_Name, Target_User_Name, host
```

### User Added to Group
```spl
index="*" (EventCode=4732 OR EventCode=4728)
| table _time, Account_Name, Target_User_Name, Group_Name
```

## Remote Execution Detection

### WinRM/PSRemoting
```spl
index="*" "TaskCategory=Execute a Remote Command"
| table _time, host, User, CommandLine, Message

# Or look for WSMan events
index="*" (EventCode=91 OR EventCode=168 OR "WSMan" OR "WinRM")
| table _time, host, User, Message
```

### Remote Process Creation
```spl
index="*" EventCode=1 (ParentImage="*\\wsmprovhost.exe" OR ParentImage="*\\winrshost.exe")
| table _time, host, User, Image, CommandLine, ParentImage
```

## PowerShell Activity

### All PowerShell Events
```spl
(index="*" source="*PowerShell*") OR 
(index="*" EventCode=1 Image="*powershell.exe") OR
(index="*" EventCode=4104)
| table _time, host, User, ScriptBlockText, CommandLine, Message
```

### Encoded Commands
```spl
index="*" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR ScriptBlockText="*FromBase64String*")
| table _time, host, User, CommandLine, ScriptBlockText
```

## Process Genealogy (Parent-Child)
```spl
index="*" Image="*\\suspicious.exe"
| table _time, ComputerName, User, ProcessId, ParentProcessId, ParentImage, CommandLine
| sort _time
```

## More quick tips:
1. **Always check the first occurrence** - Use `| sort _time | head 1` as that can provide you with a data you can use to create a range to hunt between
2. **Exclude machine accounts** - Use `regex Account_Name!=".*\$"` as alot of times they introduce extra noise for not much added fidality
3. **Track lateral movement** - Focus on Logon_Type 3 (Network) and 10 (RemoteInteractive) as well as corroloating IPs with other events such as when a TAs ip is used in a commandline it may help you find evidence of data exfiltration or downloading of addtional tooling
4. **Check process lineage** - Always include ParentImage and ParentProcessId as that may help idenity things like how a TA gained command execution in the enviroment
5. **Save your IOCs** - Use the first query with the provided IoCs in the threat report

