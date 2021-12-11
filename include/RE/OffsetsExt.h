#pragma once

namespace Offset
{
	namespace GASActionBufferData
	{
		// SkyrimSE 1.5.97.0: 0x17BC3F0
		inline static std::uintptr_t Vtbl =
			REL::Relocation<std::uintptr_t>(REL::ID(291566), 0x38).address();
	}

	namespace GASDoAction
	{
		// SkyrimSE 1.5.97.0: 0x17BC9C0
		inline constexpr REL::ID Vtbl(291613);
	}

	namespace GFxInitImportActions
	{
		// SkyrimSE 1.5.97.0: 0x17DC4C8
		inline static std::uintptr_t Vtbl =
			REL::Relocation<std::uintptr_t>(REL::ID(292202), 0x2C0).address();
	}

	namespace GFxMovieDefImpl
	{
		// SkyrimSE 1.5.97.0: 0x17DD860
		inline static std::uintptr_t Vtbl =
			REL::Relocation<std::uintptr_t>(REL::ID(292388), 0x278).address();
	}

	namespace GFxPlaceObject2
	{
		// SkyrimSE 1.5.97.0: 0x17BE0E0
		inline static std::uintptr_t Vtbl =
			REL::Relocation<std::uintptr_t>(REL::ID(291775), 0x128).address();
	}

	namespace GFxPlaceObject3
	{
		// SkyrimSE 1.5.97.0: 0x17BE138
		inline static std::uintptr_t Vtbl =
			REL::Relocation<std::uintptr_t>(REL::ID(291775), 0x180).address();
	}

	namespace GFxRemoveObject
	{
		// SkyrimSE 1.5.97.0: 0x17DC408
		inline static std::uintptr_t Vtbl =
			REL::Relocation<std::uintptr_t>(REL::ID(292202), 0x200).address();
	}

	namespace GFxRemoveObject2
	{
		// SkyrimSE 1.5.97.0: 0x17DC448
		inline static std::uintptr_t Vtbl =
			REL::Relocation<std::uintptr_t>(REL::ID(292202), 0x240).address();
	}

	namespace HUDMenu
	{
		// SkyrimSE 1.5.97.0: 0x87CDD0
		inline constexpr REL::ID Ctor(50716);
	}

	namespace HUDNotifications
	{
		// SkyrimSE 1.5.97.0: 0x881383
		inline constexpr REL::ID ProcessMessage(50758);
	}

	namespace LocalMapMenu
	{
		// SkyrimSE 1.5.97.0: 0x8DBF30
		inline constexpr REL::ID PopulateData(52081);
	}

	namespace MapMenu
	{
		// SkyrimSE 1.5.97.0: 0x8E3500
		inline constexpr REL::ID Ctor(52206);
	}
}
