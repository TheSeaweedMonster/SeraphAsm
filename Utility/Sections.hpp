#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace Seraph
{
	namespace MemUtil
	{
		struct ProcessSection
		{
			std::string name;
			std::uintptr_t start;
			std::uintptr_t end;
		};

		std::vector<ProcessSection> getSections();
		ProcessSection getSection(const char* const name);
	}
}
