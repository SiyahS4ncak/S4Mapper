#pragma once
#include "utils.hpp"
#include <type_traits>
#include <dbghelp.h>

#pragma comment(lib, "Dbghelp.lib")
namespace drv
{
	using kalloc_t = std::function<decltype(malloc)>;
	using kmemcpy_t = std::function<decltype(memcpy)>;
	using kmemset_t = std::function<decltype(memset)>;

	using image_base_t = std::uintptr_t;
	using image_entry_t = std::uintptr_t;
	using mapper_routines_t = std::pair<kalloc_t, kmemcpy_t>;
	using drv_buffer_t = std::vector<std::uint8_t>;

	class hmdm_ctx
	{
	public:
		explicit hmdm_ctx(const mapper_routines_t& routines);
		auto map_module(drv_buffer_t& drv_buffer, bool zero_headers = true)->std::pair<image_base_t, image_entry_t>;

		const kalloc_t kalloc;
		const kmemcpy_t kmemcpy;
	private:
		auto resolve_imports(drv_buffer_t& drv_buffer) const -> void;
		auto fix_relocs(drv_buffer_t& drv_buffer, uint8_t* alloc_base) const -> void;
	};
}