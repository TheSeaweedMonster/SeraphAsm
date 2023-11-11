#include "InjectFunction.hpp"
#include <Windows.h>

namespace Seraph
{
	namespace MemUtil
	{
		std::pair<uintptr_t, uintptr_t> injectFunction(const HANDLE attachedHandle, uintptr_t location, void* function, size_t functionSize, const std::vector<std::any>& data)
		{
			if (location == 0)
				return { 0, 0 };

			size_t userStackSize = 0;

			for (const auto item : data)
				userStackSize += sizeof(void*);

			if (functionSize == FIND_END_MARKER)
			{
				while (*reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(function) + functionSize) != 0xF4F402EB && functionSize < 10000)
					functionSize++;

				const auto last = functionSize;

				while (functionSize - last < 16)
				{
					const auto b = *reinterpret_cast<uint8_t*>(reinterpret_cast<uintptr_t>(function) + functionSize);

					if (b == 0xCC && functionSize == last + 3)
						break;

					if (b == 0xC2)
					{
						functionSize += 3;
						break;
					}

					if (b == 0xC3)
					{
						functionSize += 1;
						break;
					}

					functionSize++;
				}
			}

			std::vector<std::pair<std::pair<int32_t, int32_t>, const char*>>strings = {};
			std::vector<std::pair<std::pair<int32_t, int32_t>, const wchar_t*>>wstrings = {};

			for (int32_t i = 0; i < functionSize - sizeof(void*); i++)
			{
				// Look for a const char* (string) marker
				if (*reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(function) + i) == 0xF49002EB)
				{
					// grab the pointer in the previous instruction
					// which will point to the string in THIS EXE.
					//
					// -6 because of the second jmp (EB 04)
					auto stringPointer = reinterpret_cast<uintptr_t>(function) + i;

					//if (*reinterpret_cast<uint16_t*>(stringPointer - 2) == 0x04EB)
					stringPointer -= 2;

					char* str = nullptr;

					if (*reinterpret_cast<uint16_t*>(stringPointer - 5) == 0x8948 && *reinterpret_cast<uint8_t*>(stringPointer - 2) == 0x24)
					{
						const auto relStart = stringPointer - 5;
						stringPointer = relStart + *reinterpret_cast<uint32_t*>(stringPointer - 9);
						str = reinterpret_cast<char*>(stringPointer);
						strings.push_back({ { 0, relStart }, str });
					}
					else if (*reinterpret_cast<uint16_t*>(stringPointer - 8) == 0x8948 && *reinterpret_cast<uint8_t*>(stringPointer - 5) == 0x24)
					{
						const auto relStart = stringPointer - 8;
						stringPointer = relStart + *reinterpret_cast<uint32_t*>(stringPointer - 12);
						str = reinterpret_cast<char*>(stringPointer);
						strings.push_back({ { 0, relStart }, str });
					}
					else
					{
						str = *reinterpret_cast<char**>(stringPointer - sizeof(void*));
						strings.push_back({ { stringPointer - sizeof(void*), 0 }, str });
					}

					printf("Found string marker at %p. String: `%s`\n", reinterpret_cast<uintptr_t>(function) + i, str);

					userStackSize += (lstrlenA(str) + sizeof(void*) + (lstrlenA(str) % sizeof(void*)));
					i += 4;

					continue;
				}

				// Look for a const wchar_t* (wstring) marker
				if (*reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(function) + i) == 0x90F402EB)
				{
					// -6 because of the second jmp (EB 04)
					auto stringPointer = reinterpret_cast<uintptr_t>(function) + i;

					//if (*reinterpret_cast<uint16_t*>(stringPointer - 2) == 0x04EB)
					stringPointer -= 2;

					if (*reinterpret_cast<uint16_t*>(stringPointer - 5) == 0x8948 && *reinterpret_cast<uint8_t*>(stringPointer - 2) == 0x24)
						stringPointer = (stringPointer - 5) + *reinterpret_cast<uint32_t*>(stringPointer - 9);
					else if (*reinterpret_cast<uint16_t*>(stringPointer - 8) == 0x8948 && *reinterpret_cast<uint8_t*>(stringPointer - 5) == 0x24)
						stringPointer = (stringPointer - 8) + *reinterpret_cast<uint32_t*>(stringPointer - 12);

					//const auto stringPointer = *reinterpret_cast<uintptr_t*>((reinterpret_cast<uintptr_t>(function) + i) - (2 + sizeof(void*)));
					const auto wstr = reinterpret_cast<const wchar_t*>(stringPointer);

					//wprintf(L"Found string marker at %p. String: `%s`\n", reinterpret_cast<uintptr_t>(function) + i, wstr);

					//wstrings.push_back({ i - (2 + sizeof(void*)), wstr });
					userStackSize += ((lstrlenW(wstr) * 2) + sizeof(void*) + ((lstrlenW(wstr) * 2) % sizeof(void*)));

					i += 4;

					continue;
				}
			}

			size_t numWrites;

			// Append user pointers/values
			auto stackStart = location + functionSize + sizeof(void*);
			stackStart += (stackStart % sizeof(void*));

			auto stackAt = stackStart;

			for (const auto item : data)
			{
				WriteProcessMemory(attachedHandle, reinterpret_cast<void*>(stackAt), &item, sizeof(void*), &numWrites);
				stackAt += sizeof(void*);
			}

			uint8_t* functionBytes = new uint8_t[functionSize];
			memcpy(functionBytes, function, functionSize);

			for (int32_t i = 0; i < functionSize - sizeof(void*); i++)
			{
				// Overwrite the mask (present when GET_FUNCTION_STACK is called)
				// with the real pointer to the user values.
				// This way, values can be carried over externally
				// with no hassle
				if (*reinterpret_cast<uintptr_t*>(&functionBytes[i]) == FUNCTION_STACK_VALUE)
				{
					*reinterpret_cast<uintptr_t*>(&functionBytes[i]) = stackStart;
					i += sizeof(void*);
					continue;
				}
			}

			// Replace string pointers with new string location,
			// which is appended to the "user" stack
			for (const auto& injectableString : strings)
			{
				if (injectableString.first.first)
					// Direct pointer to string (32-bit)
					*reinterpret_cast<uintptr_t*>(&functionBytes[injectableString.first.first]) = stackAt;
				else
				{
					// Relative offset? (64-bit)
					const auto newPos = (injectableString.first.second - reinterpret_cast<uintptr_t>(function));
					const auto newRel = stackAt - newPos;
					*reinterpret_cast<uintptr_t*>(&functionBytes[newPos - 4]) = newRel; // Overwrite the rel32 value in the (lea) instruction
				}


				const auto paddedLength = (lstrlenA(injectableString.second) + sizeof(void*) + (lstrlenA(injectableString.second) % sizeof(void*)));

				uint8_t* bytes = new uint8_t[paddedLength];
				ZeroMemory(bytes, paddedLength);

				strncpy(reinterpret_cast<char*>(bytes), injectableString.second, lstrlenA(injectableString.second));

				WriteProcessMemory(attachedHandle, reinterpret_cast<void*>(stackAt), bytes, paddedLength, &numWrites);
				delete[] bytes;

				//printf("Assigned string `%s` to %p\n", injectableString.second, stackAt);

				stackAt += paddedLength;
			}

			for (const auto& injectableWideString : wstrings)
			{
				*reinterpret_cast<uintptr_t*>(&functionBytes[injectableWideString.first.first]) = stackAt;

				const auto paddedLength = ((lstrlenW(injectableWideString.second) * sizeof(wchar_t)) + sizeof(void*) + ((lstrlenW(injectableWideString.second) * sizeof(wchar_t)) % sizeof(void*)));

				uint8_t* bytes = new uint8_t[paddedLength];
				ZeroMemory(bytes, paddedLength);

				lstrcpynW(reinterpret_cast<wchar_t*>(bytes), injectableWideString.second, lstrlenW(injectableWideString.second) * sizeof(wchar_t));

				WriteProcessMemory(attachedHandle, reinterpret_cast<void*>(stackAt), bytes, paddedLength, &numWrites);
				delete[] bytes;

				//wprintf(L"Assigned string `%s` to %p\n", injectableWideString.second, stackAt);

				stackAt += paddedLength;
			}

			// Now apply our modified bytes to the function in the other process
			WriteProcessMemory(attachedHandle, reinterpret_cast<void*>(location), functionBytes, functionSize, &numWrites);

			delete[] functionBytes;

			stackAt += (stackAt % sizeof(void*));

			//printf("Injected function %p to %p. Stack end: %p\n", function, location, stackAt);
			//system("pause");

			return { location, stackStart };
		}

		std::pair<uintptr_t, uintptr_t> injectFunction(const HANDLE attachedHandle, uintptr_t location, void* function, const std::vector<std::any>& data)
		{
			return injectFunction(attachedHandle, location, function, FIND_END_MARKER, data);
		}
	}
}
