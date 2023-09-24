# SeraphAsm

Functional disassembler and assembler for both x86, x64.<br>
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

CURRENTLY SUPPORTS ASSEMBLING FOR X86!<br>
The rest is currently under development. For more information, keep reading.<br>

I am open to contributions (please give credit where due,<br>
if this has been forked or modified. Thanks!)<br>

# Release Notes

Currently, compilation for x86 assembly is finished.<br>
All opcodes are supported<br>

Please report any problems or incorrect outputs<br>
It is much appreciated so I can fine-tune the compilation output.<br>

The next step will be to optionally compile for individual segments,<br>
and later to fully compile assembly code into an executable program.<br>

After this, I will try to add support for x64 assembly/opcode compilation.<br>

And finally, I will start writing a complete disassembler<br>
for both x86 and x64 asm.<br>

# Pros/Cons

SeraphAsm uses a hard-coded lookup table for identifying opcodes, which gets initialized<br>
in the constructor for the "Assembler" class.<br>

This is faster and less tedious than parsing all of the opcodes/information<br>
from a separate file. It also means we don't need a separate format or worry about there<br>
being a reference file in the project directory.<br>

However, that means SeraphAsm will generate a bit of code.<br>
This isnt much of a problem if you aren't overly concerned about project size or compilation speed.<br>



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

I will document the rest of the ByteStream class soon<br>

DM for more information: jayyy#5764<br>

