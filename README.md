# SeraphAsm

Functional disassembler and assembler for both x86, x64, and ARM.<br>
Language: <b>C++</b><br>

Features:<br>
[+] Portable and easy to include<br>
[+] Text-to-assembly to write instructions and/or function routines<br>
[+] Analysis of function routines<br>
[+] Text translation as well as text (and AST) decompilation of instructions<br>
[+] Memory-editing utilities for both internal and external application<br>
[+] Open-sourced<br>

Release date: N/A<br>
Percentage of progress/completion: 40%<br>

Open to voluntary contributions<br>
DM for details jayyy#5764<br>



# Documentation

Here we'll go over some examples of this API's usage.<br>
First, let's cover the assembler.<br>

Take the following code:<br>

```cpp
#include "SeraphAsm/Seraph.hpp"

int main()
{
	Seraph::Assembler<Seraph::TargetArchitecture::x86> assembler;
	Seraph::ByteStream stream = assembler.compile(R"(
push ebp
mov ebp,esp
mov eax,[ebp+08h]
add eax,[ebp+0Ch]
pop ebp
retn
	)");
	
	printf("\nOutput: \n\n");
	while (stream.good())
		printf("%02X ", stream.next());
	printf("\n");
	system("pause");
 	
	return 0;
}
```

This will produce the following output:<br>
```
55 8B 84 68 00 BB F0 0F 89 9C 68 00 BB F0 0F 8B 81 00 00 00 0C 8B 45 08 03 45 0C 5D C3
```

These bytes represent the assembly instructions, as <br>
they can be manually written to any memory location<br>
and executed. In this particular example we assembled<br>
a function that adds two ints. Equivalent to:<br>
```
int __cdecl add(int a, int b){ return a + b; }
```

It's important to note that there is a syntax to follow<br>
when using seraph assembler, otherwise bytecode will fail to generate.<br>
For example, hex numbers must be specified as hex by adding <br>
an 'h' at the end. Ex: 0Ch, 0FF03380h, ...<br>

Notice we use a "ByteStream" class, which is really<br>
just a basic byte-vector container, that offers a lot of<br>
extra control.<br>



