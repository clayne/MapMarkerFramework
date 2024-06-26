#pragma once

#pragma warning(disable : 5105)
#pragma warning(push, 0)
#include <RE/Skyrim.h>
#include <REL/Relocation.h>
#include <SKSE/SKSE.h>

#include "RE/Offset.Ext.h"

#ifdef NDEBUG
#include <spdlog/sinks/basic_file_sink.h>
#else
#include <spdlog/sinks/msvc_sink.h>
#endif

#include <tsl/ordered_map.h>
#include <unordered_set>
#include <xbyak/xbyak.h>

#include <SimpleIni.h>
#pragma warning(pop)

using namespace std::literals;

namespace logger = SKSE::log;

namespace util
{
	using SKSE::stl::report_and_fail;
}

#define DLLEXPORT __declspec(dllexport)

#include "Plugin.h"
