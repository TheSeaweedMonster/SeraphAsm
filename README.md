# SeraphAsm

Functional disassembler and assembler for both x86, x64, and ARM.<br>
Language: <b>C++</b><br>

Features:<br>
✔️ Portable and easy to include<br>
✔️ Text-to-assembly to write instructions and/or function routines<br>
⏳ Analysis of function routines<br>
⏳ Disassembly; text translation as well as text/AST decompilation of instructions (incomplete)<br>
⏳ Memory-editing utilities for both internal and external application<br>
✔️ Open-sourced<br>

Release date: N/A<br>
Percentage of progress/completion: 40%<br>

Open to contributions (please give credit where due<br>
if this has been forked or modified. thanks!)<br>

# Release Notes

Currently, compilation for x86 assembly is (technically) done.<br>
Support for all opcodes is almost complete. I estimate<br>
that it's 80% done.<br>

Next step will be to write the disassembler for x86.<br>
From there on, I will transpose both of these to x64.<br>




# Documentation

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
push ebp
mov ebp, esp
mov eax, [ebp+08h]
add eax, dword ptr[ebp+0Ch]
pop ebp
retn
		)", 0);
	
		printf("\nOutput: \n\n");
		while (stream.good())
			printf("%02X ", stream.next());
		printf("\n");
	}
	catch (std::exception e)
	{
		printf("Exception: %s\n", e.what());
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

I will document the rest of the ByteStream class soon<br>

DM for more information: jayyy#5764<br>

