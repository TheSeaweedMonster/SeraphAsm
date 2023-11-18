# SeraphAsm

Full disassembler and assembler for intel-style assembly (x86 and x64) - and soon ARM/ARM64.<br>
Language: <b>C++</b><br>

Features:<br>
✔️ Portable and easy to include<br>
✔️ Text-to-assembly to write instructions and/or function routines<br>
⏳ Analysis of function routines<br>
✔️ Disassembly; text translation as well as text/AST decompilation of instructions<br>
✔️ Memory-editing utilities for both internal and external application<br>
✔️ Open-sourced<br>

Percentage completion: 92%<br>

For more information, see Release Notes<br>

I am open to contributions, but please give credit where due,<br>
if this has been forked or modified. Thanks<br>

# Release Notes

Note for disassembly: the opcode struct does not contain any useful information except for<br>
the text translation of the instruction and the instruction bytes/length.<br>
There will be a lot more functionality soon.<br>

Please report any incorrect outputs or bugs to my discord (jay_howdy).<br>
Feedback much appreciated :)<br>

# Pros/Cons

SeraphAsm uses a hard-coded lookup table for identifying opcodes, which gets initialized<br>
once in every new instance of an "Assembler" class.<br>

This is surely faster than parsing all of the opcodes/information<br>
from a separate file. It also means we don't need to deal with<br>
a reference file in the project directory.<br>

However, that means SeraphAsm will generate quite a bit of code.<br>
This isnt much of a problem if you aren't concerned about project size or compilation speed.<br>

# Documentation

I'll show some brief examples of this API's usage.<br>
First, to demonstrate assembling in x86 mode:<br>
<br>

```cpp
#include "SeraphAsm/Seraph.hpp"

int main()
{
	Seraph::Assembler<Seraph::TargetArchitecture::x86> assembler;
	Seraph::ByteStream stream;

	try
	{
		stream = assembler.compile(R"(
// single-line comments are allowed, but multi-line not supported yet
main: // automatic labeling system
push ebp
mov ebp, esp
mov eax, [ebp+08h] // eax = first arg
add eax, dword ptr[ebp+0Ch] // eax += second arg
pop ebp
retn
		)", 0);
	
		printf("\nOutput: \n\n");
		while (stream.good())
			printf("%02X ", stream.next());
		printf("\n\n");
	}
	catch (Seraph::SeraphException e)
	{
		printf("Error: %s\n", e.what());
	}


	system("pause");
	return 0;
}
```

This will produce the following output:<br>
```
55 8B E5 8B 45 08 03 45 0C 5D C3
```

These bytes represent the assembly instructions. <br>
They can be written to any memory location<br>
and executed. In this particular example we assembled<br>
a function that adds two ints. Equivalent to:<br>
```
int __cdecl add(int a, int b){ return a + b; }
```

It's important to note that there is a syntax to follow<br>
when using Seraph assembler, otherwise bytecode will fail to generate.<br>
For example, hex numbers must be specified as hex by adding <br>
an 'h' at the end. Ex: 0Ch, 0FF03380h, ...<br>
By default, Intel syntax is used.<br>

Notice we use a "ByteStream" class, which is really<br>
just a basic byte-vector container, that offers a lot of<br>
extra control.<br>

I will document the rest of the ByteStream class eventually.<br>


# x64 Mode:

Let's take a look at compiling x64 assembly.<br>
To do this we need to initialize a 64 bit Assembler.<br>
Simply pass TargetArchitecture::x64 as an enum in the template, rather than x86.<br>
Now it will compile 64 bit assembly code:<br>

```
	Seraph::Assembler<Seraph::TargetArchitecture::x64> assembler;
	Seraph::ByteStream stream;

	try
	{
		stream = assembler.compile(R"(
push rbp
mov rbp, rsp
testLabel:
mov rax, [rbp+08h]
add rax, [rbp+0Ch]
mov rax, AC000F0000h
jmp qword ptr[rax]
jmp AF001F0000h
jz testLabel
pop rbp
retn
		)", 0xAF000F0000);

		printf("\nOutput: \n\n");
		while (stream.good())
			printf("%02X ", stream.next());
		printf("\n\n");
	}
	catch (Seraph::SeraphException e)
	{
		printf("Exception: %s\n", e.what());
	}
```

Easy peazy! :-)<br>
Notice, for all relative values (such as `jmp AF001F0000h`), we need to provide an offset to jump relative to.<br>
This is solved with the "offset" parameter of the compile function.<br>

The size of this parameter depends on whether you compile your program as x86 or x64.<br>

# Disassembling

To disassemble, or, convert byte values into readable instructions,<br>
we create a Disassembler. We then feed it our stream (or any stream) that contains byte values.<br>

You can simply add this code to the previous example.<br>
By disassembling it rebuilds the instructions (so, exactly the reverse of compile):<br>


```
    Seraph::Disassembler<Seraph::TargetArchitecture::x64> disassembler;
    disassembler.use(stream);

    for (int i = 0; i < 50; i++)
    {
        auto next1 = disassembler.readNext();
        printf("%i.	%s\n", i, next1.text.c_str());
    }
```

For relative jumps or calls, it has nothing to go off of except a byte stream.<br>
So, if you know the offset or location of the bytes being disassembled,<br>
you can use `disassembler.setOffset(...)` to supply it with that<br>
offset, then jumps and call instructions will be relative to that (Rather than 0 + stream index)<br>


# Utility API

The upcoming utility api is designed for various sorts of debugging,<br>
exploitation (by educational means, of course), and runtime analysis<br>
of other processes.<br>

In the following example, we can inject a function's ASM right<br>
into another process:<br>

```
#include "Seraph/Utility/InjectFunction.hpp"

#pragma FUNCTION_WRAP_BEGIN
// This function will open a message box saying "lol!!"
// from in the injected process
DWORD __stdcall functionToInject(LPVOID param)
{
    GET_FUNCTION_STACK(stack);
    MAKE_STRING("lol!!", str1);
        
    const auto myMessageBoxA = reinterpret_cast<decltype(&MessageBoxA)>(stack[0]);
    

    myMessageBoxA(0, str1, str1, 0)
    return 0;

    MARK_END_FUNCTION
}
#pragma FUNCTION_WRAP_END

int main()
{
    const auto pid = 0; // Do something here, dance, idc!!
    const auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    const auto page = VirtualAllocEx(hProcess, nullptr, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Inject our function, with a reference to the MessageBoxA function.
    // This means MessageBoxA will be at stack[0]
    Seraph::Utility::injectFunction(hProcess, page, functionToInject, { MessageBoxA });
    
    // Run the function!
    CreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(page), 0, 0, nullptr);
    
    // . . .
}
```

If you notice, you can't simply copy a function into another process<br>
and expect it to run the same. This is mainly because the location of<br>
other functions are not the same, and pointers to functions (like DLL<br>
functions) are non-existent, because those are stored elsewhere than <br>
the function.<br>

Well, to overcome this is simple.<br>
With Utility::injectFunction, we can pass a reference to any DLL<br>
functions and call them from the function within the other process.<br>
We can also pass the memory address of other functions we inject,<br>
and call them like normal.<br>
We just have to rebuild their decltype, as demonstrated.<br>

Similarly, strings also rely on a pointer that points to a location in<br>
our process, that is not the same in other processes.<br>
If you injected a function that uses any strings into another process, it<br>
will fail.<br>

Thankfully, I've added a special mechanism to allocate strings and use them,<br>
also shown in the example above.<br>

They are added to the secret stack space that each injected function has.<br>
It's very easy to define and use strings, just use MAKE_STRING or MAKE_WSTRING.<br>

-- EDIT: MAKE_STRING/MAKE_WSTRING are presently being worked on...


# MemView.hpp --> MemView instance: ***

MemView is an api that essentially creates Cheat Engine in the form of a console :)<br>
It's designed to be extremely portable and lightweight.<br>

To start using it, simply initialize an instance and call the start() method:<br>
```
    MemView memView;
    memView.start();
```



# MemScan.hpp --> MemScan instance: ***

Creating a MemScan instance allows you to scan values in the memory of another process.<br>
For example to scan float values throughout a processes memory, <br>
initialize a MemScan instance and call the start method with the desired type and value to scan:<br>
```
    MemScan scan1(Regions::VirtualMemory, sizeof(float_t));
    scan1.start<float_t>(200.0f);
    printf("Scan finished. Results: %i\n", scan1.results().size());
```

You can set up the scanner to only scan on individual sections of a process.<br>
For example, using Regions::VirtualMemory will scan through all of the processes virtual memory.<br>
Using Regions::Code will only scan code sections of the process (pages with the PAGE_EXECUTE flag)<br>
Using Regions::Data will only scan the data section(s) of a process (PAGE_READWRITE)<br>


# *** PLEASE READ:

Before using extension apis of the main utility api like MemScan/MemView/...<br>
please be sure that you included MemUtil.hpp, and have <b>already opened the target process.</b>

To do this, use MemUtil::findProcess and MemUtil::openProcessByEntry:<br>

```
    PROCESSENTRY32 entry;

    while (!entry.th32ProcessID)
    {
        entry = findProcess({ L"Notepad.exe" });
        if (entry.th32ProcessID) break;

        printf("Waiting for process...\n");
        Sleep(250);
        system("CLS");
    }

    if (!openProcessByEntry(entry))
    {
        printf("Failed to open process...\n");
        return;
    }

    printf("Process opened! Process ID: %04X\n"", entry.th32ProcessID);

    // By now, MemUtil has the process handle information saved,
    // which all API's will use
```
