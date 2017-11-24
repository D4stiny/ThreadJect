# ThreadJect
## Description
Proof-of-Concept Manual DLL Injector that hijacks a thread in order to load dll into target process.
## Demonstration
[![Demonstration](https://img.youtube.com/vi/5vbEJr7Yt5U/0.jpg)](https://www.youtube.com/watch?v=5vbEJr7Yt5U)
## How does it work?
1. Open DLL and read content into buffer
2. Make sure the file is a DLL and headers are properly defined
3. Adjust Privilege & open the target process based on PID provided in first cmd argument
4. Copy DLL into target process
5. Copy loader information into target process
6. Copy loader function into target process
7. Find thread to hijack
8. Suspend target thread
9. Modify shellcode with proper addresses (ex: address to loader func, address to inject info)
10. Copy shellcode to call our loader function
11. Modify Thread EIP to go to our shellcode
12. Shellcode calls loader function with injection info as first argument
13. Resume target thread - should be injected now
## Usage
```
ThreadJect.exe <PID> <DLL Name>
```
## Credits
```
@ZwClose7 on Rohitab - Base LoadLibrary Injector (uses Thread Hijacking) and his CreateRemoteThread Manual DLL Injector
@D4stiny (me) - Modified LoadLibrary Injector by adding code from the CreateRemoteThread injector and changing the shellcode that is used in the thread hijacking to support the manual mapping of the DLL.
```