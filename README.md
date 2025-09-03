I built this repo as I went through the OffSec OSTH and OSIR certifications. The repos README takes you through different ways to use splunk, from simple to more advanced use cases; as well as providing as many references as possible for important fields and filter operators. 

The first segments of the readme will take you through how to use splunk, exploring workflows and ways to get information and view it. The second segment goes over sorting and filtering methods; where i go through using commands like stat, WHERE operator, sort, and the | operator. Overall i hope that it acts as a handy reference for you as you go through using splunk and i will be sure to keep updating the repo/readme as i get more ideas, or develop more queries. 


## Basic Search Structure
```spl
index=* source="*" EventCode=1 "powershell"
```

This searches ALL indexes for process creation events(which is what eventcode 1 is from sysmon) containing "powershell" anywhere in the event. You can also remove eventcode argument and the source and search for all events with "powershell"

What I like to do with this is not specify the source, as often you wont need to unless you have ALOT of sources with coliding eventcodes(since they arent unique in windows). You can jump from specifing source to having a wildcard

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
    (Image="*\\Temp\\*" OR Image="*\\AppData\\*" OR Image="*\\Public\\*" OR Image="*\\Tasks\\*")
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


# Splunk Filtering and formating


## The Pipe Operator - The Building Block of efffective use of splunk

The pipe `|` operator is an incredible weapon of Splunk queries. Its an incredibly simple and easy way to reduce noise and filter out unwanted detials without needing to redo your entrie query and write queries from scratch. I suggest making full use of this to make template queries that are plug and play for you to best operate during your hunt.

```splunk
index=windows | head 10 | table User, Computer
```
**Translation:** 
1. Get all events from the windows index
2. Take only the first 10 events
3. Display only the User and Computer fields

**Key Concept:** Each pipe sends its output to the next command, like connecting LEGO blocks.

---

## Basic Filtering with WHERE

The `where` command filters your results based on conditions. This is very useful when you know what youre looking for roughly, for exmaple you want to see all process creation events that are caused by a certain user, or on a certain host. You can add as many where statements as you like, making it very useful to use when you cast a wide net and want to cut down on the results

### Simple Examples:

**Filter by exact match:**
```splunk
index=windows | where User="Administrator"
```

**Filter by number comparison:**
```splunk
index=firewall | where bytes_sent > 1000000
```

**Filter using NOT (exclude results):**
```splunk
index=windows | where NOT User="SYSTEM"
```

**Filter with multiple conditions:**
```splunk
index=windows | where EventCode=4624 AND User!="SYSTEM"
```

### Advanced WHERE with Functions:

**Using match() for pattern matching (regex):**
```splunk
index=windows | where match(Process, "powershell")
```
This finds any process containing "powershell"

**Case-insensitive matching:**
```splunk
index=windows | where match(Process, "(?i)powershell")
```
The `(?i)` makes it case-insensitive (finds PowerShell, powershell, POWERSHELL, etc.)

**Excluding multiple companies:**
```splunk
index=windows | where NOT match(Company, "(?i)(Microsoft|Google|Adobe)")
```
This excludes any events where Company contains Microsoft, Google, or Adobe (case-insensitive)

---

## Renaming Fields with AS

The `as` operator renames fields to make them more readable. It's commonly used with stats commands.

### Simple Examples:

**Basic renaming:**
```splunk
index=windows | stats count as TotalEvents
```

**Renaming in stats operations:**
```splunk
index=windows 
| stats count(User) as UniqueUsers, 
        avg(Duration) as AverageDuration
```

**Using values() with as:**
```splunk
index=windows EventCode=4624
| stats values(User) as LoggedInUsers, 
        values(Computer) as Computers 
        by SourceIP
```
This groups by SourceIP and shows all unique Users and Computers for each IP

---

## Sorting Results

The `sort` command arranges your results. Use `-` for descending (highest first) and `+` for ascending (lowest first).

### Examples:

**Sort by single field (ascending):**
```splunk
index=windows | table User, EventCode | sort User
```

**Sort by single field (descending):**
```splunk
index=windows | table User, EventCode | sort -EventCode
```

**Sort by multiple fields:**
```splunk
index=windows | table User, _time, EventCode | sort User, -_time
```
This sorts by User alphabetically, then by time (newest first) within each user

---

## Common Data Manipulation Commands

### 1. **table** - Choose which columns to display
```splunk
index=windows | table User, Computer, EventCode, _time
```
Shows only these 4 fields in your results

### 2. **fields** - Include or exclude fields (more efficient than table)
```splunk
index=windows | fields User, Computer | fields - _raw
```
Includes User and Computer, excludes the _raw field

### 3. **dedup** - Remove duplicate entries
```splunk
index=windows | dedup User
```
Keeps only the first occurrence of each unique User

### 4. **eval** - Create or modify fields
```splunk
index=windows 
| eval UserType=if(User="Administrator", "Admin", "Standard")
```
Creates a new field called UserType based on the User field

### 5. **stats** - Aggregate data
```splunk
index=windows 
| stats count by User
```
Counts events for each user

**Common stats functions:**
- `count` - Count events
- `values()` - List all unique values
- `min()` - Minimum value
- `max()` - Maximum value
- `avg()` - Average
- `sum()` - Total

### 6. **coalesce** - Use first non-null value
```splunk
index=windows 
| eval Username=coalesce(User, AccountName, "Unknown")
```
Uses User if it exists, otherwise AccountName, otherwise "Unknown"

---

## Breaking Down a query that uses heavy sorting/filtering

This query is meant to either bubble up payloads used for initial access into an enviroment or identiy laterl movement. It will show us files that created network connections that dont match the specified companeis. The search will only show unique values and so we wont be overwhelmed by output as it should never return more than 2-3 pages; making it very usefult to identify a wide range of threat actor activity:

```splunk
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=3)
| where NOT match(Company, "(?i)(Microsoft|Google|VMware)")
| eval ProcessGuid=coalesce(ProcessGuid, ProcessGuid)
| stats values(Image) as Process, 
        values(CommandLine) as CommandLine,
        values(Company) as Company,
        values(User) as User,
        values(DestinationIp) as DestIP,
        values(DestinationPort) as DestPort,
        values(DestinationHostname) as DestHost,
        values(SourceIp) as SourceIP,
        values(SourcePort) as SourcePort,
        min(_time) as ProcessStart,
        values(EventCode) as EventCodes 
        by ProcessGuid
| where EventCodes="1" AND EventCodes="3"
| table ProcessStart, Process, User, CommandLine, SourceIP, DestIP, DestPort, DestHost, Company
| sort -ProcessStart
```

### Step Breakdown:

**Step 1: Initial Search**
```splunk
index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=1 OR EventCode=3)
```
- Searches all indexes
- Looks for Sysmon logs
- Gets EventCode 1 (Process Creation) OR EventCode 3 (Network Connection)

**Step 2: Filter Out Known Companies**
```splunk
| where NOT match(Company, "(?i)(Microsoft|Google|VMware)")
```
- Excludes processes from Microsoft, Google, or VMware
- Case-insensitive matching
- Reduces noise. You can further had companies based on your enviroment and search to reduce the garbage that clutters your screen

**Step 3: Ensure ProcessGuid Exists**
```splunk
| eval ProcessGuid=coalesce(ProcessGuid, ProcessGuid)
```
- Makes sure ProcessGuid field exists (handles null values)

**Step 4: Group Events by Process**
```splunk
| stats values(Image) as Process, 
        values(CommandLine) as CommandLine,
        ...
        by ProcessGuid
```
- Groups all events by ProcessGuid (unique process identifier)
- `values()` collects all unique values for each field
- Renames fields with `as` for clarity
- `min(_time)` gets the earliest timestamp (when process started)

**Step 5: Find Processes with Both Events**
```splunk
| where EventCodes="1" AND EventCodes="3"
```
- Filters to show ONLY processes that have BOTH:
  - EventCode 1 (process was created)
  - EventCode 3 (process made network connection)
- This finds processes that started AND made network connections

**Step 6: Format Output**
```splunk
| table ProcessStart, Process, User, CommandLine, SourceIP, DestIP, DestPort, DestHost, Company
```
- Displays only the relevant fields in a specific order

**Step 7: Sort by Time**
```splunk
| sort -ProcessStart
```
- Shows newest processes first (descending order)

### What This Query Actually Does:
This query hunts for potentially suspicious processes by finding programs that:
1. Were executed (EventCode 1)
2. Made network connections (EventCode 3)
3. Are NOT from trusted companies (Microsoft, Google, VMware)
4. Shows them in chronological order with network details

---

## Developing Examples

Start with these simple queries and build up:

### Lv 1:
```splunk
# Find all failed logins
index=windows EventCode=4625 | table User, Computer, _time

# Count events by user
index=windows | stats count by User | sort -count

# Find processes containing "cmd"
index=windows | where match(Process, "cmd") | table Process, User
```

### Level 2:
```splunk
# Find users who logged in from multiple computers
index=windows EventCode=4624
| stats values(Computer) as Computers, 
        dc(Computer) as ComputerCount 
        by User
| where ComputerCount > 1

# Find processes and their network connections
index=sysmon (EventCode=1 OR EventCode=3)
| stats values(Image) as Process, 
        values(DestinationIp) as Destinations 
        by ProcessGuid
| where isnotnull(Destinations)
```

The above lv2 is a good step up example to show how querying, tabling and filtering can allow you to go from an overwhelming number of events to being better able to actually pulll out the information you actually need. It will basiclaly: 

- Finds users accessing multiple computers (We normally dont expect a user to access more than TWO computers at most)
- EventCode 4624 = Successful Windows login
- `values(Computer)` = Lists all unique computers that user accessed(this will allow you to reduce how much overwhleming output you get)
- `dc(Computer)` = **d**istinct **c**ount - counts how many different computers
- `by User` = Groups everything by username
- Shows only users who logged into 2+ computers


---

The second part of the above query is showing us processes created and the network connections made by them. This can show you for exmaple of an attacker executed a meterepreter reverse shell that called out to their c2, you would be able to identify that event:
- Correlates process creation with network connections
- EventCode 1 = Process started, EventCode 3 = Network connection made
- `ProcessGuid` = Unique ID that links a process to its network activity
- `values(Image)` = The program name/path
- `values(DestinationIp)` = All IPs this process connected to
- `isnotnull(Destinations)` = Only shows processes that actually made connections


### Lev 3:
```splunk
# Find rare processes making external connections
index=sysmon EventCode=3 
| where NOT match(DestinationIp, "^(10\.|172\.|192\.168\.)")
| stats count by Image
| where count < 5
| sort count
```

The `stats` command performs calculations on your data and groups results - think of it like Excel's pivot table functionality. It can count events, find unique values, calculate averages, and aggregate data by specific fields using functions like `count`, `values()`, `sum()`, `avg()`, etc.


The `count` function simply counts the number of events or occurrences - it's the most basic stats function. When used alone (`stats count`), it counts all events; when used with `by` (`stats count by User`), it counts events for each unique value in that field.

In referece to our level 3 query; The stats count by Image command counts how many external network connections each unique process (Image) has made, creating a frequency table of network activity per program. By filtering for count < 5, we identify "rare" processes that only made a few external connections, which is suspicious because expected programs typically make many connections if they make any network connections, while we might expect a beacon payload or reverse shell might only connect to its c2 server a few times. 

Note that the above may lead to false postivies by the aim is to show you the concepts of splunk, and how to use it to better filter, extract and pull out the information you are expecting

---

## Quick Reference

| Command | Purpose | Example |
|---------|---------|---------|
| `\|` | Pipe data to next command | `index=windows \| head 10` |
| `where` | Filter results | `\| where User="admin"` |
| `where NOT` | Exclude results | `\| where NOT User="SYSTEM"` |
| `match()` | Pattern matching | `\| where match(field, "pattern")` |
| `as` | Rename fields | `\| stats count as Total` |
| `sort` | Order results | `\| sort -count, sort +_time, sort -_time` |
| `table` | Display specific fields | `\| table User, Time, CommandLine, Image` |
| `stats` | Aggregate data | `\| stats count by User` |
| `values()` | Get unique values | `\| stats values(IP) by User` |
| `eval` | Create/modify fields | `\| eval newfield=field1+field2` |
| `coalesce()` | First non-empty/null value | `\| eval x=coalesce(a,b,c)` |

---
## Tips for making your own Querys

1. **Start Simple:** Begin with basic search, then add one pipe at a time to observe what happens and better identify if/when a query you had has anything unintended
2. **Test Each Step:** Run the query after adding each pipe to see the transformation and then filter. Dont focus on making the immediatly perfect query as you can instead cast a huge net and keep adding pipes to chop down and then get a feel for it all
5. **Learn Common Patterns:** You can practically copy/paste most of your query as you will only need to modify a few different fields once you get comofortable with the process of it all 

These queries next are OSTH/OSIR specific and more so aimed at answering the questions or helping you answer the questions in the labs/exams. 


# OSTH/OSIR Lab Hunt Queries

Before that, some general exam applicable advice. For starters, take advantage of the threat intelligence report. As shown below; the first query you should run on exam day is the one listed below. You should not only hunt for the hashes they provide you, but also techniques as much as you can. 

For example, the threat report may mention a group prefers using phising for intial access. Then you should use the queries and techniques shown in this repo to look for all macro enabled files that were executed in the provided period of compromise or looking at processes that were children of word excel etc and try to find powershell/cmd. Or if they state that the group is known to use winrar for data exfil then you should hunt for winrar and .rar file associated events. 

The point is that before you begin "hunting" using anything you know or anything from this repo; you should first have broad stroke queries to look for things the threat report mentions. Once you have looked into those with good enough queries; chances are that you would have developed a pivot point. 

This also works for if you decide to fire away before refering to the threat intel report but then eventually get stuck or run out of ideas. In which case the threat intel report is a really good way to refresh your mind and give you new ideas to look for. 

No matter what you do; make sure that you have thoroughly referenced and hunted across the threat intel report, not just hashes but also any mentioned TTPs. 
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

