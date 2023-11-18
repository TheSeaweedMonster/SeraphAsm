#pragma once
#include "MemScan.hpp"
#include <vector>
#include <cstdint>

namespace Seraph
{
	namespace MemUtil
	{
		class MemView
		{
		private:
			constexpr static uint8_t EXIT_MODE = 0;
			constexpr static uint8_t SELECTION_MODE = 1;
			constexpr static uint8_t HEXVIEW_MODE = 2;
			constexpr static uint8_t MAINMENU_MODE = 3;
			constexpr static uint8_t GOTO_MODE = 4;
			constexpr static uint8_t SCANNER_MODE = 5;
			constexpr static uint8_t SCAN_AOB_MODE = 6;
			constexpr static uint8_t SCAN_RANGED_INT16_MODE = 7;
			constexpr static uint8_t SCAN_RANGED_INT32_MODE = 8;
			constexpr static uint8_t SCAN_RANGED_INT64_MODE = 9;
			constexpr static uint8_t SCAN_RANGED_FLOAT_MODE = 10;
			constexpr static uint8_t SCAN_RANGED_DOUBLE_MODE = 11;

			constexpr static uint8_t SCAN_ALL = 0;
			constexpr static uint8_t SCAN_CODE = 1;

			constexpr static size_t maxRows = 8;
			constexpr static size_t maxCols = 16;

			int selectionIndex = 0;
			int viewIndex = 0;
			int editSlotIndex = 0;
			uintptr_t viewing = 0;

			std::vector<uintptr_t> locations;
		public:
			MemView(const uintptr_t location)
			{
				locations.push_back(location);
			};

			MemView(const ScanResults _locations = {})
			{
				for (const auto x : _locations)
					locations.push_back(x.address);
			};

			MemView(const std::vector<uintptr_t> _locations)
			{
				locations = _locations;
			};

			~MemView() {};

			void start();
		};
	}

}