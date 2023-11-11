#pragma once
#include "MemUtil.hpp"
#include "Sections.hpp"
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>

namespace Seraph
{
	namespace MemUtil
	{
		struct ScanResult
		{
			uintptr_t address;
		};

		typedef std::string AOB_SCAN;
		typedef std::vector<ScanResult> ScanResults;
		typedef std::pair<uintptr_t, uintptr_t> ScanRegion;
		
		namespace Regions
		{
			constexpr ScanRegion Default = { 0, 0 };
			constexpr ScanRegion Code = { 0, 1 };
			constexpr ScanRegion Data = { 0, 2 };
			constexpr ScanRegion VirtualMemory = { 0, UINTPTR_MAX };
		};

		class MemScan
		{
		protected:
			ScanResults prevRes = { };
			ScanRegion bounds = Regions::Default;
			size_t align = 1;
		public:
			MemScan(const ScanRegion region, const size_t alignment = 1) : bounds(region), align(alignment) {};

			ScanResults results();
			ScanResults start(const std::string& aob, const std::string& mask);

			template <typename T>
			ScanResults start(T value)
			{
				std::string tempMask(sizeof(T), '.');
				std::string aob(sizeof(T), '\0');
				memcpy(&aob[0], &value, sizeof(T));
				return start(aob, tempMask);
			}

			/// <summary>
			/// Ranged value scan...
			/// </summary>
			template <typename T>
			ScanResults start(T from, T to)
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
					bounds = { 0, INTPTR_MAX };
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
						uint8_t* buffer = new uint8_t[remainingBytes + sizeof(T)];

						ReadProcessMemory(MemUtil::hProcess, reinterpret_cast<void*>(start), buffer, remainingBytes + sizeof(T), &nothing);

						while (i < remainingBytes && start + i < bounds.second)
						{
							if (*reinterpret_cast<T*>(&buffer[i]) >= from && *reinterpret_cast<T*>(&buffer[i]) <= to)
							{
								ScanResult res;
								res.address = start + i;
								newResults.push_back(res);
							}

							i += align;
						}

						delete[] buffer;
					}

					// sign check
					if (start + remainingBytes < start)
						break;

					start += remainingBytes;
				}

				prevRes = newResults;

				return newResults;
			}

			ScanResults next();
		};
	}
}
