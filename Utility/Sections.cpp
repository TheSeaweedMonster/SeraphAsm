#include <Windows.h>
#include "Sections.hpp"

namespace Seraph
{
	namespace MemUtil
	{
		struct SegmentData
		{
			char name[8];
			SIZE_T size;
			DWORD offset;
			DWORD padding[6];
		};

		std::vector<ProcessSection> getSections(const HANDLE hProcess, const uintptr_t baseModule)
		{
			std::vector<ProcessSection> results = {};

			size_t nbytes;

			uint8_t* data = new uint8_t[0x3F0];

			DWORD oldProtect;

			MEMORY_BASIC_INFORMATION64 page = { 0 };
			VirtualQueryEx(hProcess, reinterpret_cast<void*>(baseModule), (PMEMORY_BASIC_INFORMATION)&page, sizeof(page));
			printf("Queried. Base address: %p. Region size: %p. Protect: %p. State: %p.\n", page.BaseAddress, page.RegionSize, page.Protect, page.State);
			printf("Process handle: %p\n", hProcess);
			printf("Last error: %d\n", GetLastError());
			printf("Last error: %d\n", GetLastError());
			printf("Read result: %i\n", ReadProcessMemory(hProcess, reinterpret_cast<void*>(baseModule), data, 0x3F0, &nbytes));
			printf("Last error: %d\n", GetLastError());

			uint32_t segmentsStart = 0;

			while (*reinterpret_cast<uint64_t*>(&data[segmentsStart]) != 0x000000747865742E)
			{
				printf("(%016llX) --> %016llX\n", baseModule + segmentsStart, *reinterpret_cast<uint64_t*>(&data[segmentsStart]));
				if (segmentsStart >= 0x3F0)
					break;
				else
					segmentsStart += 4;
			}

			printf("Got: %016llX\n", baseModule + segmentsStart);

			for (auto at = reinterpret_cast<SegmentData*>(&data[segmentsStart]); at->offset && at->size && segmentsStart < 0x3F0; at++, segmentsStart += sizeof(SegmentData))
			{
				ProcessSection res;
				res.name = at->name;
				res.start = baseModule + at->offset;
				res.end = (baseModule + at->offset) + at->size;
				results.push_back(res);
			}

			delete[] data;

			return results;
		}

		ProcessSection getSection(const HANDLE hProcess, const uintptr_t baseModule, const char* const name)
		{
			ProcessSection result = { name, 0, 0 };

			size_t nbytes;

			uint8_t* data = new uint8_t[0x1000];
			memset(data, '\0', 0x1000);
			ReadProcessMemory(hProcess, reinterpret_cast<void*>(baseModule), data, 0x1000, &nbytes);

			uintptr_t segmentsStart = 0;
			while (*reinterpret_cast<std::uint64_t*>(data + segmentsStart) != 0x000000747865742E)
				segmentsStart += 4;

			for (auto at = reinterpret_cast<SegmentData*>(&data[segmentsStart]); (at->offset != 0 && at->size != 0); at++)
			{
				if (strncmp(at->name, name, strlen(name) + 1) == 0)
				{
					result.start = baseModule + at->offset;
					result.end = (baseModule + at->offset) + at->size;

					break;
				}
			}

			delete[] data;

			return result;
		}
	}
}