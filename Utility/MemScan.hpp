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

		class ScanRegion : public std::pair<uintptr_t, uintptr_t>
		{
		public:
			constexpr ScanRegion(const uintptr_t start, const uintptr_t end)
			{
				first = start;
				second = end;
			}

			ScanRegion(const ProcessSection& section)
			{
				first = section.start;
				second = section.end;
			}
		};
		
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
			size_t align = 1;
		public:
			MemScan(const size_t alignment = 1) : align(alignment) {};
			~MemScan() {};

			ScanResults results();
			ScanResults start(const ScanRegion& region, const std::string& aob, const std::string& mask);

			template <typename T>
			ScanResults start(const ScanRegion& region, T value)
			{
				std::string tempMask(sizeof(T), '.');
				std::string aob(sizeof(T), '\0');
				memcpy(&aob[0], &value, sizeof(T));
				return start(region, aob, tempMask);
			}

			ScanResults start(const ScanRegion& region, const std::string& str)
			{
				std::string tempMask(str.length(), '.');
				std::string aob(str.length(), '\0');
				memcpy(&aob[0], &str[0], str.length());
				return start(region, aob, tempMask);
			}

			ScanResults start(const ScanRegion& region, const uintptr_t offset, const bool isCodeOffset = false)
			{
				if (!isCodeOffset)
					return start<uintptr_t>(region, offset);

				ScanResults newResults = {};
				ScanRegion bounds = region;
				switch (bounds.second)
				{
				case Regions::Code.second:
					bounds = MemUtil::getSection(".text");
					break;
				}

				uintptr_t start = bounds.first;

				while (start < bounds.second)
				{
					MEMORY_BASIC_INFORMATION memRegion = { 0 };
					VirtualQueryEx(MemUtil::hProcess, reinterpret_cast<void*>(start), &memRegion, sizeof(memRegion));

					const auto remainingBytes = memRegion.RegionSize - (start - reinterpret_cast<uintptr_t>(memRegion.BaseAddress));

					if ((memRegion.State & MEM_COMMIT) && (memRegion.Protect & MemUtil::EXECUTABLE_MEMORY))
					{
						size_t nothing, i = 0;
						uint8_t* buffer = new uint8_t[remainingBytes + sizeof(uint32_t)];

						ReadProcessMemory(MemUtil::hProcess, reinterpret_cast<void*>(start), buffer, remainingBytes + sizeof(uint32_t), &nothing);

						while (i < remainingBytes && start + i < bounds.second)
						{
							if (start + i + sizeof(uint32_t) + *reinterpret_cast<uint32_t*>(&buffer[i]) == offset)
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

			/// <summary>
			/// Ranged value scan...
			/// </summary>
			template <typename T>
			ScanResults start(const ScanRegion& region, T from, T to)
			{
				ScanRegion bounds = region;
				ScanResults newResults = {};

				switch (bounds.second)
				{
				case Regions::Code.second:
					bounds = MemUtil::getSection(".text");
					break;
				case Regions::Data.second:
					bounds = MemUtil::getSection(".data");
					break;
				case Regions::VirtualMemory.second:
					bounds = { 0, INTPTR_MAX };
					break;
				}

				uintptr_t start = bounds.first;

				while (start < bounds.second)
				{
					MEMORY_BASIC_INFORMATION memRegion = { 0 };
					VirtualQueryEx(MemUtil::hProcess, reinterpret_cast<void*>(start), &memRegion, sizeof(memRegion));

					const auto remainingBytes = memRegion.RegionSize - (start - reinterpret_cast<uintptr_t>(memRegion.BaseAddress));

					if ((memRegion.State & MEM_COMMIT) && (memRegion.Protect & (MemUtil::READABLE_MEMORY | MemUtil::EXECUTABLE_MEMORY)))
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
