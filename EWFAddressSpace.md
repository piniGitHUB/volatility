

# Introduction #

Memory acquired by EnCase or converted using ewfacquire are stored in Expert Witness Format (EWF).  Volatility supports the "older" EWF format used by EnCase v6 (and prior versions), but not the newer EWF2-EX01 format used in EnCase v7.

# Acquisition #

Click on "Add Device" in EnCase and then make sure that "Physical Memory" is checked.  Depending on your version of EnCase (EE for example), the folders may differ below.

![https://lh5.googleusercontent.com/-i0HmBBIS1HQ/UFD5PSAPYTI/AAAAAAAAA8s/LdiQLXnihgA/s517/EnCase%2520RAM%25201.png](https://lh5.googleusercontent.com/-i0HmBBIS1HQ/UFD5PSAPYTI/AAAAAAAAA8s/LdiQLXnihgA/s517/EnCase%2520RAM%25201.png)

After hitting "Next you should see RAM for the requested machine as an option.  "Blue-check" it and hit "Next".

![https://lh6.googleusercontent.com/-5Hkr3eiyM1c/UFD5PfUIVOI/AAAAAAAAA8o/HytwtyjuF7s/s795/EnCase%2520RAM%25202.png](https://lh6.googleusercontent.com/-5Hkr3eiyM1c/UFD5PfUIVOI/AAAAAAAAA8o/HytwtyjuF7s/s795/EnCase%2520RAM%25202.png)

Then hit "Finish"

![https://lh4.googleusercontent.com/-0tZFfadXXts/UFD5Pne5ioI/AAAAAAAAA80/M-3I4hG2W-M/s800/EnCase%2520RAM%25203.png](https://lh4.googleusercontent.com/-0tZFfadXXts/UFD5Pne5ioI/AAAAAAAAA80/M-3I4hG2W-M/s800/EnCase%2520RAM%25203.png)

You should see the RAM in your evidence entries window.

![https://lh6.googleusercontent.com/--ReUKbACIGc/UFD5P7nKzdI/AAAAAAAAA88/cPNnTtIjzj8/s563/EnCase%2520RAM%25204%2520View.png](https://lh6.googleusercontent.com/--ReUKbACIGc/UFD5P7nKzdI/AAAAAAAAA88/cPNnTtIjzj8/s563/EnCase%2520RAM%25204%2520View.png)

To acquire the sample, right-click, click on "Acquire"  and follow the acquisition dialog that follows.

![https://lh5.googleusercontent.com/-ZPGJArTY6hE/UFD5PwgBd8I/AAAAAAAAA9I/3UOERvGD4lA/s512/EnCase%2520RAM%25205%2520Acquisition.png](https://lh5.googleusercontent.com/-ZPGJArTY6hE/UFD5PwgBd8I/AAAAAAAAA9I/3UOERvGD4lA/s512/EnCase%2520RAM%25205%2520Acquisition.png)



# Notes #

You must have libewf installed for the EWF address space to work correctly.  The address space can be found in the `contrib/plugins/aspaces` folder.  You can use the `--plugins=` parameter in order to use the ewf.py address space without moving it.  The `--plugins=` parameter must come before any other parameters for `vol.py`.  You can see an example below:

```
$ python vol.py --plugins=contrib/plugins -f WinXPSP3x86.E01 --profile=WinXPSP3x86 pslist
Volatile Systems Volatility Framework 2.2_alpha
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                Exit                
---------- -------------------- ------ ------ ------ -------- ------ ------ -------------------- --------------------
0x8aeda660 System                    4      0     99     2022 ------      0                                          
0x89af3da0 smss.exe                912      4      3       19 ------      0 2011-04-08 17:30:59                      
0x894c3720 csrss.exe              1036    912     14     1086      0      0 2011-04-08 17:31:05                      
0x894ceda0 winlogon.exe           1060    912     22      604      0      0 2011-04-08 17:31:07                      
0x86ff4da0 services.exe           1108   1060     16      417      0      0 2011-04-08 17:31:10                      
0x8705a770 lsass.exe              1120   1060     23      531      0      0 2011-04-08 17:31:10                                            
0x86fdbda0 svchost.exe            1368   1108     16      208      0      0 2011-04-08 17:31:12    
[snip]                 
```

# Alternative Methods #

If you are using the compiled version of Volatility (exe), the address space is not available by default.  In this case you can do one of the following:

  * Install libewf and use the address space by supplying the `--plugins` location as previous described.
  * Mount the memory sample with EnCase and run Volatility over the exposed device (see http://volatility-labs.blogspot.com/2013/10/sampling-ram-across-encase-enterprise.html).
  * Mount the memory sample with FTK Imager as "Physical & Logical" and then use an **admin** prompt to run the Volatility on the exposed device.
    * If the "drive" that was mounted is E:\ the proper command would be `vol.exe -f "E:\unallocated space" ` ... etc. An example of this can be seen below:

![https://lh6.googleusercontent.com/-Oh1quwh7nAw/U1g9IgIGdkI/AAAAAAAABUk/G2KkA-moPpw/w709-h365-no/FTK.png](https://lh6.googleusercontent.com/-Oh1quwh7nAw/U1g9IgIGdkI/AAAAAAAABUk/G2KkA-moPpw/w709-h365-no/FTK.png)

# File Format #

File format details can be found in [Joachim Metz's EWF documentation](http://code.google.com/p/libewf/downloads/detail?name=Expert%20Witness%20Compression%20Format%20%28EWF%29.pdf).