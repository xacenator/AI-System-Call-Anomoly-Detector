# syscall


# Windows Kernel Event Collector (ETW + KrabsETW)

This project is a lightweight Windows kernel event collector written in C++17 using [KrabsETW](https://github.com/microsoft/krabs-etw).  
It listens to process, file I/O, and network events via ETW and outputs structured JSON to stdout.

---

## Features

- **Process events**: start/stop with image path and command line (when available).
- **File I/O events**: filtered to writes, renames, and metadata changes.
- **Network events**: TCP/UDP connect, send, receive with IP/port pairs.
- **Real-time JSON output**: each event is emitted as a single JSON line.
- **Noise reduction**: skips `OperationEnd` spam, allows optional sampling/deduplication.
- **UTF-8 console output**: safe for piping to file or downstream analysis (Python, etc.).

---

## Requirements

- Windows 10 or later
- Visual Studio 2019/2022 with:
  - **Desktop Development with C++**
  - Windows 10/11 SDK
- [vcpkg](https://github.com/microsoft/vcpkg) with KrabsETW installed:
  ```powershell
  .\vcpkg install krabsetw:x64-windows
  .\vcpkg integrate install
