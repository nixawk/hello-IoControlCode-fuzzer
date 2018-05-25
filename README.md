
# CrashMeat

A simple fuzz demo for windows driver based on io control code. (Some features will be in the future).
A fuzz framework should have:

  - 1. Raw data input
  - 2. Rand raw data
  - 3. Crash targets
  - 4. Recv crash log
  - 5. Analysis log

## :: Help

```
C:\Users\debug\Desktop\CrashMeat\src>..\bin\crashmeat.EXE

   _____               _       __  __            _
  / ____|             | |     |  \/  |          | |
 | |     _ __ __ _ ___| |__   | \  / | ___  __ _| |_
 | |    | '__/ _` / __| '_ \  | |\/| |/ _ \/ _` | __|
 | |____| | | (_| \__ \ | | | | |  | |  __/ (_| | |_
  \_____|_|  \__,_|___/_| |_| |_|  |_|\___|\__,_|\__|

                                             [Nixawk]

  Usage
  -----

  :: Help
     -h/-? Show help information

  :: Enum Drivers
     -l    List all drivers name and status in system.

  :: Load Drivers
     -a    Load all drivers in system automatically
     -d    <SymbolicLinkName> Load a driver with symlink name

  :: Load Io Control Code
     -c    Input available io control code, split with dot (ex: 1,3-5)
     -b    Bruteforce io control code

  :: Fuzz Mode
     -n    Null Pointer Fuzz
     -s    Stack Overflow Fuzz
     -i    Invalid Address Fuzz

  :: Verbose Mode
     -v    Make the operation more talkative

```

## :: Enum Mode

```
C:\Users\debug\Desktop\CrashMeat\src>..\bin\crashmeat.EXE -l | more
{'ObjectName': 'USB#VID_0E0F&PID_0002#6&201153c1&0&7#{f18a0e88-c30c-11d0-8815-00a0c906bed8}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'D:', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'ACPI#PNP0501#1#{4d36e978-e325-11ce-bfc1-08002be10318}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'ACPI#PNP0501#3#{4d36e978-e325-11ce-bfc1-08002be10318}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'VmGenerationCounter', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 5}
{'ObjectName': 'PhysicalDrive0', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 5}
{'ObjectName': 'VDRVROOT', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'DISPLAY1', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 5}
{'ObjectName': 'ROOT#SYSTEM#0000#{97ebaacb-95bd-11d0-a3ea-00a0c9223196}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'gpuenergydrv', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'SWD#IP_TUNNEL_VBUS#ISATAP_0#{ad498944-762f-11d0-8dcb-00c04fc3358c}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'WUDFLpcDevice', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 5}
{'ObjectName': '{28B8F286-E5AB-473E-869E-ADE5F342366F}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'ACPI#PNP0501#1#{86e0d1e0-8089-11d0-9ce4-08003e301f73}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'Volume{a1814082-f32d-4f98-ada4-e073e440b01d}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 5}
{'ObjectName': 'ROOT#spaceport#0000#{ef66a56f-88d1-4cd8-98c4-49faf57ad8af}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'SWD#MMDEVAPI#{0.0.0.00000000}.{cbd0ca6f-1229-4c9f-8dd8-74962834ad71}#{e6327cad-dcec-4949-ae8a-991e976a79d2}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 1}
{'ObjectName': 'PCI#VEN_15AD&DEV_0774&SUBSYS_197615AD&REV_00#4&b70f118&0&0088#{3abf6f2d-71c4-462a-8a92-1e6861e6af27}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'Psched', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 5}
{'ObjectName': 'SWD#RADIO#Bluetooth_c4e3ac32bcac#{a8804298-2d5f-42e3-9531-9c8c39eb29ce}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 1}
{'ObjectName': 'PCI#VEN_15AD&DEV_0405&SUBSYS_040515AD&REV_00#3&18d45aa6&0&78#{1ca05180-a699-450a-9a0c-de4fbe3ddd89}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'No', 'GetLastError': 5}
{'ObjectName': 'ROOT#SYSTEM#0000#{cf1dda2c-9743-11d0-a3ee-00a0c9223196}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
{'ObjectName': 'STORAGE#Volume#{a72219b9-54a9-11e8-9bc2-806e6f6e6963}#0000000022600000#{7f108a28-9833-4b3b-b780-2c6b5fa5c062}', 'ObjectTypeName': 'SymbolicLink', 'AccessStatus': 'Yes', 'GetLastError': 0}
-- More  --
```

## :: Fuzz Mode

```
C:\Users\debug\Desktop\CrashMeat\src>..\bin\crashmeat.EXE -d AUX -c 1 -i -s -n
{'func': 'Fuzz_NULL_Pointer', 'text': 'IoControlCode: 00000001','code': 0,'symlink': 'AUX'}
{'func': 'Fuzz_Stack_Overflow', 'text': 'IoControlCode: 00000001','code': 0,'symlink': 'AUX','bufsize': 65536,}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidAddress: 00000000','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidAddress: FFFFFFFF','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidAddress: 00000000','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidAddress: 00000000','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidAddress: CCCCCCCC','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidAddress: FFFFFFFF','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17BE','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17BD','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17BC','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17BB','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17BA','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B9','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B8','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B7','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B6','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B5','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B4','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B3','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B2','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B1','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17B0','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17AF','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17AE','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17AD','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17AC','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17AB','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17AA','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A9','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A8','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A7','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A6','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A5','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A4','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A3','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A2','symlink': 'AUX','bufsize': 65536}
{'func': 'Fuzz_Invalid_Address', 'text': 'IoControlCode: 00000001, InvalidHeapAddress: 79FC17A1','symlink': 'AUX','bufsize': 65536}
```

## References

- https://github.com/koutto/ioctlbf/
- https://github.com/k0keoyo/kDriver-Fuzzer
- https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
