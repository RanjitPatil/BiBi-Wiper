# BiBi-Windows-Wiper-Analysis

On 30th October, Security Joes posted its findings about a Wiper malware for Linux systems used in the war in Gaza. It was called the "BiBi-Linux Wiper". And then on November 1 2023, BlackBerry Research and Intelligence Team found its Windows variant.

In this post, we will look at the Windows version of the BiBi Wiper known as the "BiBi-Windows Wiper"

## Malware Sample

> **MD5:** e26bba0304f14ef96beb60376791d32c

> **SHA256:** 40417e937cd244b2f928150cae6fa0eff5551fdb401ea072f6ecdda67a747e17

## Static Analysis

- The timestamp suggests the implant was compiled on Saturday, October 21, 2023, and it's a 64-bit one.

  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/9251f133-59dc-41e5-bfef-c186bdbbe429)

- Below are some intresting strings found in the binary file.

  ```
  [+] Stats: %d | %d
  [!] Waiting For Queue
  [+] Round %d
  lla/ teIuq/ swodahs   eteled nimdassv  c/ exe.dmc
  eteled ypocwodahs cimw c/ exe.dmc
  seruliafllaerongi ycilopsutatstoob }tluafed{ tes / tidedcb c / exe.dmc
  on delbaneyrevocer }tluafed{ tes/ tidedcb c/ exe.dmc
  C:\Users
  [+] Path: %s
  [+] CPU cores: %d, Threads: %d
  .exe
  .dll
  .sys
  .BiBi
  
  ```
  
## Dynamic Analysis 

- Upon execution, the Wiper fetches the number of processors, calculates the threads accordingly using ```GetNativeSystemInfo()``` and prints the target directories and thread information on the console.

  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/6e861f06-9bfa-484b-8e33-9fe210bf5080)

- It reads the hardcoded path: "C:\Users".

  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/2ffc724a-5589-4908-aba7-97d85b3947d8)

- Gets the currently available disk drives using ```GetLogicalDrives()``` where the return value is the bitmask, then it iterates through the A-Z (26) drives. It next does a bittest with the retrieved bitmask to determine the accessible drives on the system and appends ":\" to the drive name.

- Then for the available drives except the C drive it executes the ```GetDriveTypeA()``` which retrives the drive type, The BiBi-Windows Wiper here only targets the following drive types:

  DRIVE_FIXED
  
  DRIVE_REMOVABLE
  
  DRIVE_RAMDISK
  
  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/17c36a31-5357-47c1-9808-d81c5152d290)

- Further it creates a new thread which reads the commands stored in reverse, & then creates a new process using CreateProcessA to execute those commands. 

  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/58b8cf73-4814-4d49-8f21-4e5cc5281e61)

- Following are the commands executed by Bibi.

    > ***`cmd.exe /c bcdedit /set {default} recoveryenabled no`*** - Disables Windows Recovery Environment
    
  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/e46067ef-fec9-49fb-9f9d-501d8f831e30)
    
    > ***`cmd.exe / c bcdedit / set {default} bootstatuspolicy ignoreallfailures`*** - Force the system to boot normally rather than into the Windows Recovery Environment

  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/4703d6f2-c279-42d3-99a5-82e93058c994)
    
    > ***`cmd.exe /c wmic shadowcopy delete`*** - Delete Volume Shadow Copies using WMIC
    
  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/dd7ff501-a1b8-4798-992a-a2e9bc1afb4e)

    > ***`cmd.exe /c vssadmin delete shadows /quIet /all`*** - Delete Volume Shadow Copies using VssAdmin

  ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/ff89dacb-12ef-47fd-9086-21d26c15256b)

 -  Furthermore it creates another thread which executes of the Main Wiper routines. The Wiper routines perform the following actions.

 -  Arg1 - Path of the Directory to be destroyed (Could be provided by the Operator or retrieved as explained before)

 -  Arg2 - Number of threads

 -  Then it initiates an infinite loop where the counter is the Round "[+] Round %d\n" value - therefore once the Wiper is executed it would keep destroying the data infinitely

 -  Further based on the number of threads, it creates multiple threads in a loop which execute the main Wiper function.

 -  The BiBi-Windows wiper excludes the files with ".exe", ".dll" and ".sys" extension

    ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/fa9c594d-d9d0-4329-a369-7b7877436fd0)

-  BiBi-Windows Wiper execution showcasing the Target directory, CPU Cores, Threads, Round Number, Stats, and destroyed file with .BiBi extension

    ![image](https://github.com/RanjitPatil/BiBi-Wiper/assets/43460691/d8e78456-66a9-47fd-a73e-ada5faf7bb9a)



## YARA Rule

```
rule BIBI_Wiper_Windows {

meta:

    description ="BiBi-Windows Wiper used in the Gaza War"
    author ="The BlackBerry Research and Intelligence Team"
    date = "2023-10-31"
    hash ="40417e937cd244b2f928150cae6fa0eff5551fdb401ea072f6ecdda67a747e17"
    version = "1.0"

strings:
    
    $a1 = "[+] Stats: " ascii wide 
    $a2 = "C:\\Users" ascii wide 
    $a3 = "[!] Waiting For Queue " ascii wide
    $a4 = "[+] Round " ascii wide
    $a5 = "[+] Path: " ascii wide
    $a6 = "[+] CPU cores: " ascii wide

condition:
    uint16(0) == 0x5a4d and ((filesize < 2000KB) and all of ($a*))
}

```

## References :

- https://www.linkedin.com/pulse/bibi-wiper-gaza-war-now-goes-windows-dmitry-bestuzhev-yftze/#
