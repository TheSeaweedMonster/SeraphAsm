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

<br>

Notice, for all relative values in call/jmp instructions (such as `jmp AF001F0000h`), we need to provide an offset to jump relative to,<br>
because otherwise it will just start at 0.<br>
This is solved with the "offset" parameter of the compile function.<br>

Typically, here you would put the base address of the module that this assembly code is located in (like the start of the .text section).<br>
But since we're compiling these instructions to go basically anywhere, it's up to you to provide it with the offset--wherever it is you write these bytes to.<br>

Please note - currently the size of this parameter is based on whether your program is x86 or x64.<br>

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

