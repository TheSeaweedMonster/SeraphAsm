#include "MemScan.hpp"
#include "MemUtil.hpp"
#include "Sections.hpp"

namespace Seraph
{
	namespace MemUtil
	{
		ScanResults MemScan::results()
		{
			return prevRes;
		}

		ScanResults MemScan::start(const std::string& aob, const std::string& mask)
		{
			ScanResults newResults = {};

			switch (bounds.second)
			{
			case Regions::Code.second:
			{
				const auto code = MemUtil::getSection(".text");
				bounds = { code.start, code.end };
				break;
			}
			case Regions::Data.second:
			{
				const auto data = MemUtil::getSection(".data");
				bounds = { data.start, data.end };
				break;
			}
			case Regions::VirtualMemory.second:
			{
				SYSTEM_INFO info = { 0 };
				GetSystemInfo(&info);
				bounds = { reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress), reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress) };
				break;
			}
			}

			uintptr_t start = bounds.first;

			while (start < bounds.second)
			{
				MEMORY_BASIC_INFORMATION64 memRegion = { 0 };
				VirtualQueryEx(MemUtil::hProcess, reinterpret_cast<void*>(start), reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&memRegion), sizeof(memRegion));

				const auto remainingBytes = memRegion.RegionSize - (start - memRegion.BaseAddress);

				if ((memRegion.State & MEM_COMMIT) && (memRegion.Protect & MemUtil::READABLE_MEMORY))
				{
					size_t nothing, i = 0;
					uint8_t* buffer = new uint8_t[remainingBytes];

					ReadProcessMemory(MemUtil::hProcess, reinterpret_cast<void*>(start), buffer, remainingBytes, &nothing);

					while (i < remainingBytes && start + i < bounds.second)
					{
						bool isMatched = true;

						for (size_t j = 0; j < mask.length(); j++)
						{
							if (buffer[i + j] != aob[j] && mask[j] == '.')
							{
								isMatched = false;
								break;
							}
						}

						if (isMatched)
						{
							ScanResult res;
							res.address = start + i;
							newResults.push_back(res);
						}

						i += align;
					}

					delete[] buffer;
				}

				if (start + remainingBytes < start)
					break;

				start += remainingBytes;
			}

			prevRes = newResults;

			return newResults;
		}
	}
}
