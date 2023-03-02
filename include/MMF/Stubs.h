#pragma once

#include <cstdint>

namespace RE
{
	class BGSLocation;
	class TESObjectREFR;
}

namespace MMF
{
	enum MESSAGE_TYPE : std::uint32_t
	{
		kMapMarkerInterface,
	};

	namespace detail
	{
		struct MARKER_INFO
		{
			std::int32_t VanillaMarker;
			char SourcePath[260];
			char ExportName[260];
			char ExportNameUndiscovered[260];
			float IconScale;
			bool HideFromHUD;
		};
		static_assert(sizeof(MARKER_INFO) == 0x318);

		struct MapMarkerInterface
		{
			std::uint32_t interfaceVersion;
			std::uint16_t (*GetVanillaMarkerType)(RE::TESObjectREFR* a_refr);
			const char* (*GetCustomMarkerName)(RE::TESObjectREFR* a_refr);
			void (*GetMapMarkerInfo)(RE::TESObjectREFR* a_refr, MARKER_INFO* a_infoOut);
			void (*GetLocalMarkerInfo)(RE::BGSLocation* a_location, MARKER_INFO* a_infoOut);
		};
		static_assert(sizeof(MapMarkerInterface) == 0x28);
	}
}
