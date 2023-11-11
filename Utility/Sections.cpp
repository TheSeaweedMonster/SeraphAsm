#include <Windows.h>
#include "Sections.hpp"
#include "MemUtil.hpp"

namespace Seraph
{
	namespace MemUtil
	{
		std::vector<ProcessSection> getSections()
		{
			std::vector<ProcessSection> results = {};

			uint8_t* data = new uint8_t[1000];
			memset(data, '\0', 1000);

			size_t nbytes;

			ReadProcessMemory(hProcess, hBaseModule, data, 1000, &nbytes);

			// Size: 0x28 bytes (for x86 and x64 applications)
			struct SegmentData
			{
				char name[8];
				DWORD size;
				DWORD offset;
				DWORD padding[6];
			};

			uint32_t segmentsStart = 0;

			while (*reinterpret_cast<uint64_t*>(reinterpret_cast<uintptr_t>(data) + segmentsStart) != 0x000000747865742E)
			{
				if (segmentsStart >= 1000)
					break;
				else
					segmentsStart += 4;
			}

			const auto pModule = reinterpret_cast<uintptr_t>(hBaseModule);

			for (auto at = reinterpret_cast<SegmentData*>(reinterpret_cast<uintptr_t>(data) + segmentsStart); at->offset && at->size && segmentsStart < 1000; at++, segmentsStart += sizeof(SegmentData))
			{
				Seraph::MemUtil::ProcessSection res;
				res.name = at->name;
				res.start = pModule + at->offset;
				res.end = (pModule + at->offset) + at->size;
				results.push_back(res);
			}

			delete[] data;

			return results;
		}

		ProcessSection getSection(const char* const name)
		{
			for (const auto& section : getSections())
				if (section.name == name)
					return section;

			return { "???", 0, 0 };
		}
	}
}
