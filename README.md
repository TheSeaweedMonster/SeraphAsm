# SeraphAsm

Functional disassembler and assembler for both x86, x64, and possibly ARM/ARM64.<br>
Language: <b>C++</b><br>

Features:<br>
✔️ Portable and easy to include<br>
✔️ Text-to-assembly to write instructions and/or function routines<br>
⏳ Analysis of function routines<br>
⏳ Disassembly; text translation as well as text/AST decompilation of instructions (incomplete)<br>
⏳ Memory-editing utilities for both internal and external application<br>
✔️ Open-sourced<br>

Expected finish date: 10/10/23<br>
Percentage completion: 55%<br>

Disassembly is not supported yet!<br>
For more information, see Release Notes<br>

I am open to contributions (please give credit where due,<br>
if this has been forked or modified. Thanks!)<br>

# Release Notes

Compilation for x86 and x64 assembly is finished!<br>
x64 may need some further testing (mainly for rex-encoding).<br>

Please report any incorrect output or other problems so I can make improvements.<br>
Input is highly appreciated, and also reasonable, non-negative criticism :).<br>

# Pros/Cons

SeraphAsm uses a hard-coded lookup table for identifying opcodes, which gets initialized<br>
in the constructor for the "Assembler" class.<br>

This is faster and less tedious than parsing all of the opcodes/information<br>
from a separate file. It also means we don't need a separate format or worry about there<br>
being a reference file in the project directory.<br>

However, that means SeraphAsm will generate quite a bit of code.<br>
This isnt much of a problem if you aren't concerned about project size or compilation speed.<br>

# Documentation (x86)

Here we'll go over some examples of this API's usage.<br>
First, let's cover the assembler.<br>

Take the following code:<br>

```cpp
#include "SeraphAsm/Seraph.hpp"

int main()
{
	Seraph::Assembler<Seraph::TargetArchitecture::x86> assembler;
	Seraph::ByteStream stream;

	try
	{
		stream = assembler.compile(R"(
main: // automatic labeling system! also, comments are allowed
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
		printf("\n");
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


# Documentation (x64)

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
Notice, for relative values (such as `jmp AF001F0000h`), we need to provide an offset for it to jump relative to.<br>
This is solved with the "offset" parameter of the compile function.<br>
Note that this parameter is dependant on whether you compile your program in x86 or x64.<br>

That's all I got for right now :)<br>



DM for more information: jayyy#5764<br>

