# BiBI-Wiper-Analysis

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

- 

## YARA Rule

```

```

## References :

- https://www.linkedin.com/pulse/bibi-wiper-gaza-war-now-goes-windows-dmitry-bestuzhev-yftze/#
