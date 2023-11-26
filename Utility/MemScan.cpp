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

		ScanResults MemScan::start(const ScanRegion& region, const std::string& aob, const std::string& mask)
		{
			ScanRegion bounds = region;
			ScanResults newResults = {};

			uint32_t protectFlag = MemUtil::READABLE_MEMORY | MemUtil::EXECUTABLE_MEMORY;

			switch (bounds.second)
			{
			case Regions::Data.second:
				protectFlag = MemUtil::READABLE_MEMORY;
				bounds = MemUtil::getSection(".data");
				break;
			case Regions::Code.second:
				//bounds = MemUtil::getSection(".text");
				//break;
				protectFlag = MemUtil::EXECUTABLE_MEMORY; // Scan all executable memory in the process
				break;
			case Regions::VirtualMemory.second:
			{
				protectFlag = MemUtil::READABLE_MEMORY;
				SYSTEM_INFO info = { 0 };
				GetSystemInfo(&info);
				bounds = { reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress), reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress) };
				break;
			}
			}

			uintptr_t start = bounds.first;

			while (start < bounds.second)
			{
				MEMORY_BASIC_INFORMATION memRegion = { 0 };
				VirtualQueryEx(MemUtil::hProcess, reinterpret_cast<void*>(start), &memRegion, sizeof(memRegion));

				const auto remainingBytes = memRegion.RegionSize - (start - reinterpret_cast<uintptr_t>(memRegion.BaseAddress));

				if ((memRegion.State & MEM_COMMIT) && (memRegion.Protect & protectFlag))
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
