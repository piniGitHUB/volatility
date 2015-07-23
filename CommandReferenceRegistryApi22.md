

# Introduction #

The RegistryApi allows easier access to registries, keys and values.  It can be very useful when processing complex keys or several registries in memory at once.  This wiki covers each of the functions contained in the RegistryApi.

# Basic Usage #

In order to use the RegistryApi it must be imported and instantiated:

```
import volatility.plugins.registry.registryapi as registryapi
...

def calculate(self):
    regapi = registryapi.RegistryApi(self._config)

```

or from `volshell`:

```
>>> import volatility.plugins.registry.registryapi as registryapi
>>> regapi = registryapi.RegistryApi(self._config)
...
```

At this point any of the RegistryApi functions may be used.


# Functions #

## populate\_offsets(self) ##

Gets and saves all hive offsets so we don't have to scan again.  This is called when the RegistryApi object is instantiated.


## set\_current(self, hive\_name = None, user = None) ##

If we find a hive that fits the given criteria, save its offset so we don't have to scan again. This can be reset using reset\_current if context changes
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `user` is optional if you want to find keys in a user's NTUSER.DAT registry file

## reset\_current(self) ##

This function allows one to switch to a different hive/user/context

## print\_offsets(self) ##

Prints out the offsets of all known registry hives.  This is used for checking hive offsets and which hive(s) was/were chosen.

```
>>> regapi.print_offsets()
0xe1d6cb60 \Device\HarddiskVolume1\Documents and Settings\Administrator\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe1de0b60 \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT
0xe1797b60 \Device\HarddiskVolume1\Documents and Settings\NetworkService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe17a3820 \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT
0xe1526748 \Device\HarddiskVolume1\WINDOWS\system32\config\software
0xe102e008 [no name]
0xe1769b60 \Device\HarddiskVolume1\Documents and Settings\LocalService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe15a3950 \Device\HarddiskVolume1\WINDOWS\system32\config\default
0xe151ea08 \Device\HarddiskVolume1\WINDOWS\system32\config\SAM
0xe1035b60 \Device\HarddiskVolume1\WINDOWS\system32\config\system
0xe139d008 [no name]
0xe153e518 \Device\HarddiskVolume1\WINDOWS\system32\config\SECURITY
0x8066e904 [no name]
0xe17deb60 \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT
```

If a registry is set as current it will show up in the output:

```
>>> regapi.set_current("ntuser.dat")
>>> regapi.print_offsets()
0xe1d6cb60 \Device\HarddiskVolume1\Documents and Settings\Administrator\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe1de0b60 \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT
0xe1797b60 \Device\HarddiskVolume1\Documents and Settings\NetworkService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe17a3820 \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT
0xe1526748 \Device\HarddiskVolume1\WINDOWS\system32\config\software
0xe102e008 [no name]
0xe1769b60 \Device\HarddiskVolume1\Documents and Settings\LocalService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe15a3950 \Device\HarddiskVolume1\WINDOWS\system32\config\default
0xe151ea08 \Device\HarddiskVolume1\WINDOWS\system32\config\SAM
0xe1035b60 \Device\HarddiskVolume1\WINDOWS\system32\config\system
0xe139d008 [no name]
0xe153e518 \Device\HarddiskVolume1\WINDOWS\system32\config\SECURITY
0x8066e904 [no name]
0xe17deb60 \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT
current 0xe1de0b60 \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT   <-- here
current 0xe17a3820 \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT  <-- here
current 0xe17deb60 \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT    <-- here
```

If `reset_current` is called, we can see the update in `print_offsets`:

```
>>> regapi.reset_current()
>>> regapi.print_offsets()
0xe1d6cb60 \Device\HarddiskVolume1\Documents and Settings\Administrator\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe1de0b60 \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT
0xe1797b60 \Device\HarddiskVolume1\Documents and Settings\NetworkService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe17a3820 \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT
0xe1526748 \Device\HarddiskVolume1\WINDOWS\system32\config\software
0xe102e008 [no name]
0xe1769b60 \Device\HarddiskVolume1\Documents and Settings\LocalService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe15a3950 \Device\HarddiskVolume1\WINDOWS\system32\config\default
0xe151ea08 \Device\HarddiskVolume1\WINDOWS\system32\config\SAM
0xe1035b60 \Device\HarddiskVolume1\WINDOWS\system32\config\system
0xe139d008 [no name]
0xe153e518 \Device\HarddiskVolume1\WINDOWS\system32\config\SECURITY
0x8066e904 [no name]
0xe17deb60 \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT
>>>
```

Below the administrator's NTUSER.DAT hive is specifically chosen:

```
>>> regapi.set_current(hive_name = "ntuser.dat", user = "administrator")
>>> regapi.print_offsets()
0xe1d6cb60 \Device\HarddiskVolume1\Documents and Settings\Administrator\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe1de0b60 \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT
0xe1797b60 \Device\HarddiskVolume1\Documents and Settings\NetworkService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe17a3820 \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT
0xe1526748 \Device\HarddiskVolume1\WINDOWS\system32\config\software
0xe102e008 [no name]
0xe1769b60 \Device\HarddiskVolume1\Documents and Settings\LocalService\Local Settings\Application Data\Microsoft\Windows\UsrClass.dat
0xe15a3950 \Device\HarddiskVolume1\WINDOWS\system32\config\default
0xe151ea08 \Device\HarddiskVolume1\WINDOWS\system32\config\SAM
0xe1035b60 \Device\HarddiskVolume1\WINDOWS\system32\config\system
0xe139d008 [no name]
0xe153e518 \Device\HarddiskVolume1\WINDOWS\system32\config\SECURITY
0x8066e904 [no name]
0xe17deb60 \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT
current 0xe1de0b60 \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT 
>>>
```

## reg\_get\_currentcontrolset(self, fullname = True) ##

Returns the CurrentControlSet or None on failure.  If fullname is not specified, we only get the number like "1" or "2" etc.  The default is ControlSet00{#} so we can append it to the desired key path.  Returns None if it fails, so you need to verify before using.

```
>>> print regapi.reg_get_currentcontrolset()
ControlSet001
>>> print regapi.reg_get_currentcontrolset(fullname = False)
1
```

## reg\_get\_key(self, hive\_name, key, user = None, given\_root = None) ##

Returns a key object from a requested hive; assumes this is from a single hive.  If more than one hive is specified, the first key found is returned.
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `key` is the registry key you are looking for (e.g. 'SAM\Domains\Account\Users')
  * `user` is optional if you want to find keys in a user's NTUSER.DAT registry file
  * `given_root` is optional and allows you to specify the keyroot to avoid recursing through keys

```
>>> regapi.reset_current()
>>> key = regapi.reg_get_key(hive_name = "system", key = "controlset001\\Control\\ComputerName\\ComputerName") 
>>> key
<CType pointer to [0x000247F8]>
>>> print key.Name
ComputerName
```

## reg\_yield\_key(self, hive\_name, key, user = None, given\_root = None) ##

Use this function if you are collecting keys from more than one hive.
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `key` is the registry key you are looking for (e.g. 'SAM\Domains\Account\Users')
  * `user` is optional if you want to find keys in a user's NTUSER.DAT registry file
  * `given_root` is optional and allows you to specify the keyroot to avoid recursing through keys

```
>>> for key, current_path in regapi.reg_yield_key("ntuser.dat", "Software\\Microsoft\\Windows\\ShellNoRoam"):
...     print key.Name, current_path
... 
ShellNoRoam \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT 
ShellNoRoam \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT 
ShellNoRoam \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT 
```

## reg\_enum\_key(self, hive\_name, key, user = None) ##

This function enumerates the subkeys of the requested key.
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `key` is the registry key you are looking for (e.g. 'SAM\Domains\Account\Users')
  * `user` is optional if you want to find keys in a user's NTUSER.DAT registry file

```
>>> regapi.reset_current()
>>> regapi.set_current(hive_name = "ntuser.dat", user = "administrator")
>>> for keypath in regapi.reg_enum_key("ntuser.dat", "Software\\Microsoft\\Windows\\ShellNoRoam"):
...     print keypath
... 
Software\Microsoft\Windows\ShellNoRoam\BagMRU
Software\Microsoft\Windows\ShellNoRoam\Bags
Software\Microsoft\Windows\ShellNoRoam\DUIBags
Software\Microsoft\Windows\ShellNoRoam\MUICache
```


## reg\_get\_all\_keys(self, hive\_name, user = None, start = None, end = None, reg = False) ##

This function enumerates all keys in specified hives and collects lastwrite times.
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `user` is optional if you want to find keys in a user's NTUSER.DAT registry file
  * `start` is optional (except when end is supplied) and is the starting point of the timeline. time is of "YYYY-MM-DD HH:MM:SS" format although you can just put "YYYY-MM-DD" as well.
  * `end` is optional (except when start is supplied) and is the ending point of the timeline. time is of same format as start.
  * `reg` is optional, but is used in timeline analysis so we can keep track of the registry name.

```
>>> regapi.reset_current()
>>> for lastwrite, regname, key in regapi.reg_get_all_keys(hive_name = "sam", reg = True):
...     print lastwrite, regname, key
... 
2010-02-25 22:22:08  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM
2010-02-25 22:22:08  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM
2010-02-25 22:22:08  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains
2010-02-25 22:22:08  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\RXACT
2010-02-26 03:28:20  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account
2010-02-25 22:22:43  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Builtin
2010-02-26 03:27:57  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Aliases
2010-02-25 22:22:08  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Groups
2010-02-26 03:28:19  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Users
2010-02-25 22:22:08  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Builtin\Aliases
[snip]
```

If we want to get keys from more than one hive, we can set use `set_current()` to add hives and then specify `hive_name` as `None`:

```
>>> regapi.reset_current()
>>> regapi.set_current(hive_name = "ntuser.dat")
>>> for lastwrite, regname, key in regapi.reg_get_all_keys(None, reg = True):
...     print lastwrite, regname, key
... 
2010-02-26 03:34:45  \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT  $$$PROTO.HIV
2010-02-26 03:31:09  \Device\HarddiskVolume1\Documents and Settings\NetworkService\NTUSER.DAT  $$$PROTO.HIV
2010-02-26 03:31:12  \Device\HarddiskVolume1\Documents and Settings\LocalService\NTUSER.DAT  $$$PROTO.HIV
2010-02-26 03:31:42  \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT  $$$PROTO.HIV\AppEvents
2010-02-26 03:31:42  \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT  $$$PROTO.HIV\Console
2010-02-26 03:33:33  \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT  $$$PROTO.HIV\Control Panel
2010-02-26 03:31:42  \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT  $$$PROTO.HIV\Environment
[snip]
```

## reg\_get\_all\_subkeys(self, hive\_name, key, user = None, given\_root = None) ##

This function enumerates the subkeys of the requested key.
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `key` is the registry key you are looking for (e.g. 'SAM\Domains\Account\Users')
  * `user` is optional if you want to find keys in a user's NTUSER.DAT registry file
  * `given_root` is optional and allows you to specify the keyroot to avoid recursing through keys

```
>>> regapi.set_current(hive_name = "ntuser.dat", user = "administrator") 
>>> for subkey in regapi.reg_get_all_subkeys(None, key = "software\\microsoft\\windows\\currentversion\\explorer"):
...     print subkey.Name
... 
Advanced
BitBucket
CabinetState
CD Burning
CLSID
ComDlg32
Desktop
Discardable
FileExts
HideDesktopIcons
MenuOrder
MountPoints2
MyComputer
NewShortcutHandlers
RunMRU
Shell Folders
StartPage
Streams
StuckRects2
tips
TrayNotify
User Shell Folders
UserAssist
VisualEffects
Wallpaper
WebView
SessionInfo
```


## reg\_yield\_values(self, hive\_name, key, thetype = None, given\_root = None) ##

This function yields all values for a requested registry key.
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `key` is the registry key you are looking for (e.g. 'SAM\Domains\Account\Users')
  * `thetype` allows you to specify a `value` type for example `REG_BINARY`, `REG_SZ`, `REG_MULTI_SZ` etc.
  * `given_root` is optional and allows you to specify the keyroot to avoid recursing through keys

```
>>> regapi.reset_current()
>>> regapi.set_current(hive_name = "ntuser.dat", user = "administrator")
>>> for value, data in regapi.reg_yield_values(hive_name = "ntuser.dat", key = "Software\\Microsoft\\Windows\\ShellNoRoam", thetype = "REG_SZ"):
...     print value, data
... 
 BOB-DCADFEDC55C
```

We can see that this is correct using `printkey`:

```
$ ./vol.py -f Bob.vmem printkey -K "Software\Microsoft\Windows\ShellNoRoam"
[snip]
----------------------------
Registry: \Device\HarddiskVolume1\Documents and Settings\Administrator\NTUSER.DAT
Key name: ShellNoRoam (S)
Last updated: 2010-02-26 03:34:52 

Subkeys:
  (S) BagMRU
  (S) Bags
  (S) DUIBags
  (S) MUICache

Values:
REG_SZ                        : (S) BOB-DCADFEDC55C  <-- here
REG_DWORD     BagMRU Size     : (S) 5000
```

## reg\_get\_value(self, hive\_name, key, value, strcmp = None, given\_root = None) ##

This function returns the requested value of a registry key.
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `key` is the registry key you are looking for (e.g. 'SAM\Domains\Account\Users')
  * `value` is the registry value you are looking for at the above key
  * `strcmp` is optional if you want to check for a particular string value.
  * `given_root` is optional and allows you to specify the keyroot to avoid recursing through keys

```
# get a particular value by name:
>>> val = regapi.reg_get_value(hive_name = "system", key = "controlset001\\Control\\ComputerName\\ComputerName", value = "ComputerName")
>>> print val
BOB-DCADFEDC55C

# get a particular value by name and only if its data contains "BOB-DCADFEDC55C": 
>>> val = regapi.reg_get_value(hive_name = "system", key = "controlset001\\Control\\ComputerName\\ComputerName", value = "ComputerName", strcmp = "BOB-DCADFEDC55C")
>>> print val
BOB-DCADFEDC55C

# check if there's a value "ComputerName" with data value of "BOB-blahblahblah"; the function returns None if it does not exist:
>>> val = regapi.reg_get_value(hive_name = "system", key = "controlset001\\Control\\ComputerName\\ComputerName", value = "ComputerName", strcmp = "BOB-blahblahblah")
>>> print val
None
>>> 
```


## reg\_get\_last\_modified(self, hive\_name, count = 1, user = None, start = None, end = None, reg = False) ##

Wrapper function using reg\_get\_all\_keys. These functions can take a WHILE since all subkeys have to be collected before you can compare lastwrite times.
  * `hive_name` can be None, hklm or a specific registry name (like SYSTEM)
  * `count` is N latest lastwrite times in specified hives
  * `user` is optional if you want to find keys in a user's NTUSER.DAT registry file
  * `start` is optional (except when end is supplied) and is the starting point of the timeline. time is of "YYYY-MM-DD HH:MM:SS" format although you can just put "YYYY-MM-DD" as well.
  * `end` is optional (except when start is supplied) and is the ending point of the timeline. time is of same format as start.
  * `reg` is optional, but is used in timeline analysis so we can keep track of the registry name.

```
>>> for regtime, keyname in regapi.reg_get_last_modified("sam", count = 25):
...     print regtime, keyname
... 
2010-02-26 03:34:47  SAM\SAM\Domains\Account\Users\000001F4
2010-02-26 03:28:20  SAM\SAM\Domains\Account\Users\000003EA
2010-02-26 03:28:20  SAM\SAM\Domains\Account\Aliases\Members\S-1-5-21-789336058-1844823847-839522115\000003EA
2010-02-26 03:28:20  SAM\SAM\Domains\Account\Aliases\Members\S-1-5-21-789336058-1844823847-839522115
2010-02-26 03:28:20  SAM\SAM\Domains\Account\Aliases\Members
2010-02-26 03:28:20  SAM\SAM\Domains\Account\Aliases\000003E9
2010-02-26 03:28:20  SAM\SAM\Domains\Account
2010-02-26 03:28:19  SAM\SAM\Domains\Account\Users\Names\SUPPORT_388945a0
2010-02-26 03:28:19  SAM\SAM\Domains\Account\Users\Names
2010-02-26 03:28:19  SAM\SAM\Domains\Account\Users
2010-02-26 03:28:19  SAM\SAM\Domains\Account\Groups\00000201
2010-02-26 03:27:57  SAM\SAM\Domains\Account\Aliases\Names\HelpServicesGroup
2010-02-26 03:27:57  SAM\SAM\Domains\Account\Aliases\Names
2010-02-26 03:27:57  SAM\SAM\Domains\Account\Aliases
2010-02-26 03:27:11  SAM\SAM\Domains\Account\Users\Names\HelpAssistant
2010-02-26 03:27:11  SAM\SAM\Domains\Account\Users\000003E8
2010-02-25 22:22:43  SAM\SAM\Domains\Builtin\Aliases\Members\S-1-5\0000000B
2010-02-25 22:22:43  SAM\SAM\Domains\Builtin\Aliases\Members\S-1-5\00000004
2010-02-25 22:22:43  SAM\SAM\Domains\Builtin\Aliases\Members\S-1-5
2010-02-25 22:22:43  SAM\SAM\Domains\Builtin\Aliases\Members
2010-02-25 22:22:43  SAM\SAM\Domains\Builtin\Aliases\00000221
2010-02-25 22:22:43  SAM\SAM\Domains\Builtin
2010-02-25 22:22:08  SAM\SAM\RXACT
2010-02-25 22:22:08  SAM\SAM\Domains\Builtin\Users\Names
2010-02-25 22:22:08  SAM\SAM\Domains\Builtin\Users

# now print out with registry path as well:

>>> for regtime, regname, keyname in regapi.reg_get_last_modified("sam", count = 10, reg = True):
...     print regtime, regname, keyname
... 
2010-02-26 03:34:47  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Users\000001F4
2010-02-26 03:28:20  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Users\000003EA
2010-02-26 03:28:20  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Aliases\Members\S-1-5-21-789336058-1844823847-839522115\000003EA
2010-02-26 03:28:20  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Aliases\Members\S-1-5-21-789336058-1844823847-839522115
2010-02-26 03:28:20  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Aliases\Members
2010-02-26 03:28:20  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Aliases\000003E9
2010-02-26 03:28:20  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account
2010-02-26 03:28:19  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Users\Names\SUPPORT_388945a0
2010-02-26 03:28:19  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Users\Names
2010-02-26 03:28:19  \Device\HarddiskVolume1\WINDOWS\system32\config\SAM  SAM\SAM\Domains\Account\Users
>>> 
```