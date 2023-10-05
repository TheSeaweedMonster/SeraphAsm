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

		std::vector<ProcessSection> getSections(const HANDLE hProcess, const  uintptr_t baseModule);
		ProcessSection getSection(const HANDLE hProcess, const uintptr_t baseModule, const char* const name);
	}
}
