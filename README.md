# BreadBear
A PoC~ish of https://elastic.github.io/security-research/malware/2022/01/01.operation-bleeding-bear/article/

The goal of this project was to create my own red team campaign that would emulate some of the TTPs from the above campaign analysis.
During my endeavor I decdied to switch from a complete mimick to a substitute / exclude / improve upon certain tactics that I deemed unnecessary.
I will write an accompanying blog post which will be linked here once it is published.

However, here are some features which I believe are worth noting for this project:
- Initial payload delievery is done from an automatic download via a website hosted on IPFS.
- Executed Payload Dynamically resolves all sensitive functions
- Unhooks DLLs using native API's / syscalls & HellsGate technique to bypass AV/EDR.
- Deletes itself from disk while running.
- Hides console window
- Strings obfuscated - but i was super lazy w/ this since it's just a PoC. Somehow still bypasses all detection engines on antiscan.me
- Disables ETW
- Downloads a base64 encoded version of stage3 from discord CDN.
- Reflectively Loads stage3 in memory / executes to launch shell back.
- Stage3 can be swapped between a file encryptor payload or C2 implant as show in the below videos:

