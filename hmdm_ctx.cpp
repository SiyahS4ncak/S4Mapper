#include "hmdm_ctx.h"

namespace drv
{
	hmdm_ctx::hmdm_ctx(const mapper_routines_t& routines)
		: 
		kalloc(std::get<0>(routines)),
		kmemcpy(std::get<1>(routines))
	{}

	auto hmdm_ctx::map_module(drv_buffer_t& drv_buffer, bool zero_headers)->std::pair<image_base_t, image_entry_t>
	{
		if (drv_buffer.empty())
			return { {}, {} };

		const auto dos_header = 
			reinterpret_cast<PIMAGE_DOS_HEADER>(drv_buffer.data());

		const auto nt_header = 
			reinterpret_cast<PIMAGE_NT_HEADERS>(
				drv_buffer.data() + dos_header->e_lfanew);

		const auto section_header = 
			reinterpret_cast<IMAGE_SECTION_HEADER*>(
				reinterpret_cast<std::uintptr_t>(&nt_header->OptionalHeader) +
					nt_header->FileHeader.SizeOfOptionalHeader);

		drv_buffer_t image_mapped;
		image_mapped.resize(nt_header->OptionalHeader.SizeOfImage);
		std::copy_n(drv_buffer.begin(), nt_header->OptionalHeader.SizeOfHeaders, image_mapped.begin());

		for (auto idx = 0u; idx < nt_header->FileHeader.NumberOfSections; ++idx)
		{
			const auto& section = section_header[idx];
			const auto target = 
				reinterpret_cast<std::uintptr_t>(
					image_mapped.data() + section.VirtualAddress);

			const auto source = 
				reinterpret_cast<std::uintptr_t>(
					dos_header + section.PointerToRawData);

			std::copy_n(drv_buffer.begin() + section.PointerToRawData, 
				section.SizeOfRawData, image_mapped.begin() + section.VirtualAddress);
		}

		const auto alloc_base =
			reinterpret_cast<std::uint8_t*>(
				kalloc(nt_header->OptionalHeader.SizeOfImage));

		DBG_PRINT("> alloc base -> 0x%p\n", alloc_base);

		if (!alloc_base)
			return { {}, {} };

		resolve_imports(image_mapped);
		fix_relocs(image_mapped, alloc_base);

		if (zero_headers)
		{
			const auto module_base =
				nt_header->OptionalHeader.SizeOfHeaders + image_mapped.data();
			
			const auto module_size = 
				nt_header->OptionalHeader.SizeOfImage - 
					nt_header->OptionalHeader.SizeOfHeaders;

			kmemcpy(alloc_base + nt_header->OptionalHeader.SizeOfHeaders, module_base, module_size);
		}
		else
		{
			const auto module_size =
				nt_header->OptionalHeader.SizeOfImage;

			kmemcpy(alloc_base, image_mapped.data(), module_size);
		}

		return
		{
			reinterpret_cast<std::uintptr_t>(alloc_base),
			reinterpret_cast<std::uintptr_t>(alloc_base +
				nt_header->OptionalHeader.AddressOfEntryPoint)
		};
	}

	auto hmdm_ctx::fix_relocs(drv_buffer_t& drv_buffer, uint8_t* alloc_base) const -> void
	{
		const auto dos_header =
			reinterpret_cast<PIMAGE_DOS_HEADER>(drv_buffer.data());

		const auto nt_header =
			reinterpret_cast<PIMAGE_NT_HEADERS>(
				drv_buffer.data() + dos_header->e_lfanew);

		const auto base_reloc_dir = 
			reinterpret_cast<PIMAGE_DATA_DIRECTORY>(
				&nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);

		if (base_reloc_dir->VirtualAddress)
		{
			auto reloc = 
				reinterpret_cast<PIMAGE_BASE_RELOCATION>(
					drv_buffer.data() + base_reloc_dir->VirtualAddress);

			for (auto current_size = 0u; current_size < base_reloc_dir->Size;)
			{
				const auto reloc_count = 
					(reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);

				auto reloc_data = reinterpret_cast<std::uint16_t*>(
					reinterpret_cast<std::uintptr_t>(reloc) + sizeof(IMAGE_BASE_RELOCATION));

				const auto reloc_base = 
					drv_buffer.data() + reloc->VirtualAddress;

				for (auto idx = 0u; idx < reloc_count; ++idx, ++reloc_data)
				{
					const auto data = *reloc_data;
					const auto type = data >> 12;
					const auto offset = data & 0xFFF;

					switch (type)
					{
					case IMAGE_REL_BASED_ABSOLUTE:
						break;
					case IMAGE_REL_BASED_DIR64:
					{
						const auto rva = reinterpret_cast<std::uintptr_t*>(reloc_base + offset);

						*rva = reinterpret_cast<std::uintptr_t>(
							alloc_base + (*rva - nt_header->OptionalHeader.ImageBase));
						break;
					}
					default:
						return;
					}
				}

				current_size += reloc->SizeOfBlock;
				reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reloc_data);
			}
		}
	}

	auto hmdm_ctx::resolve_imports(drv_buffer_t& drv_buffer) const -> void
	{
		ULONG size;
		auto import_descriptors = static_cast<PIMAGE_IMPORT_DESCRIPTOR>(
			::ImageDirectoryEntryToData(drv_buffer.data(), 
				TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size));

		if (!import_descriptors)
			return;

		for (; import_descriptors->Name; import_descriptors++)
		{
			IMAGE_THUNK_DATA* image_thunk_data;
			const auto module_name = 
				reinterpret_cast<const char*>(
					drv_buffer.data() + import_descriptors->Name);

			if (import_descriptors->OriginalFirstThunk)
				image_thunk_data = 
					reinterpret_cast<PIMAGE_THUNK_DATA>(
						drv_buffer.data() + import_descriptors->OriginalFirstThunk);
			else
				image_thunk_data = 
					reinterpret_cast<PIMAGE_THUNK_DATA>(
						drv_buffer.data() + import_descriptors->FirstThunk);

			auto image_func_data = 
				reinterpret_cast<PIMAGE_THUNK_DATA>(
					drv_buffer.data() + import_descriptors->FirstThunk);

			for (; image_thunk_data->u1.AddressOfData; image_thunk_data++, image_func_data++)
			{
				const auto image_import_by_name = 
					reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
						drv_buffer.data() + (*(DWORD*)image_thunk_data));

				const auto name_of_import = 
					static_cast<char*>(image_import_by_name->Name);

				image_func_data->u1.Function = 
					utils::kmodule::get_export(
						module_name, name_of_import);

				DBG_PRINT("> resolved import... %s!%s -> 0x%p\n", 
					module_name, name_of_import, image_func_data->u1.Function);
			}
		}
	}
}