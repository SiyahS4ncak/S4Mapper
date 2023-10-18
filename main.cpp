#include "hmdm_ctx.h"
#include "msrexec.hpp"
#include "vdm.hpp"

int __cdecl main(int argc, char** argv)
{
	std::printf("> SiyahS4ncak...\n");
	if (argc < 2)
	{
		std::printf("> please provide a path to a driver...\n");
		return -1;
	}

	const auto [drv_handle, drv_key, drv_status] = vdm::load_drv();
	if (drv_status != STATUS_SUCCESS || drv_handle == INVALID_HANDLE_VALUE)
	{
		std::printf("> failed to load driver... reason -> 0x%x\n", drv_status);
		return -1;
	}

	writemsr_t _write_msr = 
		[&](std::uint32_t key, std::uint64_t value) -> bool
	{
		return vdm::writemsr(key, value);
	};

	vdm::msrexec_ctx msrexec(_write_msr);
	drv::kalloc_t _kalloc = [&](std::size_t size) -> void*
	{
		void* alloc_base;
		msrexec.exec([&](void* krnl_base, get_system_routine_t get_kroutine) -> void
		{
			using ex_alloc_pool_t = 
				void* (*)(std::uint32_t, std::size_t);

			const auto ex_alloc_pool = 
				reinterpret_cast<ex_alloc_pool_t>(
					get_kroutine(krnl_base, "ExAllocatePool"));

			alloc_base = ex_alloc_pool(NULL, size);
		});
		return alloc_base;
	};

	drv::kmemcpy_t _kmemcpy = 
		[&](void* dest, const void* src, std::size_t size) -> void*
	{
		void* result = nullptr;
		msrexec.exec([&](void* krnl_base, get_system_routine_t get_kroutine) -> void
		{
			const auto kmemcpy = 
				reinterpret_cast<decltype(&memcpy)>(
					get_kroutine(krnl_base, "memcpy"));

			result = kmemcpy(dest, src, size);
		});
		return result;
	};

	drv::drv_buffer_t drv_buffer;
	utils::open_binary_file(argv[1], drv_buffer);
	drv::hmdm_ctx drv_mapper({ _kalloc, _kmemcpy });

	const auto [drv_base, drv_entry] = drv_mapper.map_module(drv_buffer);
	std::printf("> driver base -> 0x%p, driver entry -> 0x%p\n", drv_base, drv_entry);

	if (!drv_base || !drv_entry)
	{
		std::printf("> failed to map driver...\n");
		return -1;
	}

	// call driver entry... its up to you to do this using whatever method...
	// with VDM you can syscall into it... with msrexec you will use msrexec::exec...
	NTSTATUS result;
	msrexec.exec([&result, drv_entry = drv_entry, drv_base = drv_base]
		(void* krnl_base, get_system_routine_t get_kroutine) -> void
	{
		using drv_entry_t = NTSTATUS(*)(std::uintptr_t);
		result = reinterpret_cast<drv_entry_t>(drv_entry)(drv_base);
	});

	std::printf("> drv entry result -> 0x%x\n", result);
	const auto unload_status = vdm::unload_drv(drv_handle, drv_key);
	if (unload_status != STATUS_SUCCESS)
	{
		std::printf("> failed to unload driver... reason -> 0x%x\n", unload_status);
		return -1;
	}
}