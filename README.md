# UEP
### Unwatned Execution Prevention.

Including a full list of Virustotal machines and other commonly known debugging, tampering or sandboxing environments, and attempts to terminate itself once detected. By providing a variety of Functions that helps you to do so.
> This script uses a modified source of known open-source Functions.


| Function | Description |
| ------ | ------ |
| `vt_check()` | Performs a check on a huge list of Virustotal's components including:<br>`CPU Serials`<br>`HWDI List`<br>`PC Name List`<br>`PC Username List`<br>`IP List`<br>`MAC List`<br>`GPU List`<br>`BIOS Serial List`<br>`Baseboard Serial List`<br>`Baseboardmanufacturer List`<br>`CPU Serial List`<br>`Disk Drive Serial List`<br>`hwprofileguidlist`<br>`Machine GUID List`|
| `user_check()` | Performs a check on a list of commonly known Logon Usernames|
| `name_check()` | Performs a check on a list of commonly known Desktop Usernames |
| `path_check()` | Performs a check on a list of commonly most-obvious known execution paths |
| `ip_check()` | Performs a check on a list of commonly known IPs |
|`registry_check()` | Performs multiple check procedures on registry (Including VMware and VBOX detection) |
| `dll_check()` | Self-explanatory |
| `specs_check()` | Performs a check on both the virual memory and the disk usage |
| `proc_check()` | Performs a mostly VMware check |
| `process_check()` | Performs a check on a list of commonly flagged processes that are used for unwanted inspection |
