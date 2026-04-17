#include "pe_imgui.h"
#include "imgui.h"

RenderImGui::RenderImGui(PE64* _PE)
{
	PE = _PE;
	currentAdress = 0;
	data = (Data*)PE->GetAdressData(currentAdress, sizeof(Data));
}

void RenderImGui::RenderTick()
{
	RenderMenuBar();
	RenderSideBar();
	RenderInfo();
	RenderBinary();
	RenderHex();
}
void RenderImGui::RenderMenuBar()
{
	if (ImGui::BeginMainMenuBar())
	{
		if (ImGui::BeginMenu("File"))
		{
			if (ImGui::MenuItem("Open")) {}
			if (ImGui::MenuItem("Close")) {}
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("View"))
		{
			if (ImGui::MenuItem("Hex")) {}
			if (ImGui::MenuItem("ASCII")) {}
			ImGui::EndMenu();
		}
		if (ImGui::BeginMenu("Settings"))
		{
			ImGui::EndMenu();
		}
		ImGui::EndMainMenuBar();
	}
}

void RenderImGui::RenderSideBar()
{
	float indent = 25.0f;

	ImGui::Begin("STRUCTURE");

	if (ImGui::CollapsingHeader(".exe", ImGuiTreeNodeFlags_DefaultOpen))
	{
		ImGui::Indent(indent);


		if (PE->PEFILE_DOS_HEADER.e_magic == 23117) // MZ
		{
			if (ImGui::Button("DOS Header"))
			{
				currentAdress = 0;
				data = (Data*)PE->GetAdressData(currentAdress, sizeof(Data));
			}

			if (ImGui::Button("DOS stub"))
			{
				currentAdress = sizeof(PE->PEFILE_DOS_HEADER);
				data = (Data*)PE->GetAdressData(currentAdress, sizeof(Data));
			}
		}
		else
		{
			ImGui::Text("File is not a valid PE, MZ signature is missing..");
			return;
		}

		if (ImGui::CollapsingHeader("NT Headers", ImGuiTreeNodeFlags_DefaultOpen))
		{
			ImGui::Indent(indent);

			if (ImGui::Button("PE Signature"))
			{
				currentAdress = static_cast<int>(PE->FILE_HEADER_ENTRY - (sizeof(BYTE) * 4));
				data = (Data*)PE->GetAdressData(currentAdress, sizeof(Data));
			}

			if (ImGui::Button("File Header"))
			{
				currentAdress = static_cast<int>(PE->FILE_HEADER_ENTRY);
				data = (Data*)PE->GetAdressData(currentAdress, sizeof(Data));
			}
			if (ImGui::Button("Optional Header"))
			{
				currentAdress = static_cast<int>(PE->OPTIONAL_HEADER_ENTRY);
				data = (Data*)PE->GetAdressData(currentAdress, sizeof(Data));
			}
			ImGui::Unindent(indent);
		}

		if (ImGui::Button("Section Headers"))
		{
			currentAdress = static_cast<int>(PE->OPTIONAL_HEADER_ENTRY + PE->OPTIONAL_HEADER_SIZE);
		}

		if (ImGui::CollapsingHeader("Sections", ImGuiTreeNodeFlags_DefaultOpen))
		{
			ImGui::Indent(indent);

			for (int i = 0; i < static_cast<int>(PE->NUMBER_OF_SECTIONS); i++)
			{
				// ugly but eh..
				char sectionName[9] = { 0 };
				memcpy(sectionName, PE->PEFILE_SECTION_HEADERS[i].Name, 8);
				std::string pestring(sectionName);

				if (ImGui::Button(pestring.c_str()))
				{
					currentAdress = static_cast<int>(PE->PEFILE_SECTION_HEADERS[i].PointerToRawData);
					data = (Data*)PE->GetAdressData(currentAdress, sizeof(Data));
				}
			}
			ImGui::Unindent(indent);
		}
		ImGui::Unindent(indent);
	}

	
	
	ImGui::End();
}

// Ugly function dont look
void RenderImGui::RenderInfo()
{
	ImGui::Begin("PE INFO");
	if (ImGui::BeginTabBar("PE file information"))
	{
		if (ImGui::BeginTabItem("General"))
		{
			ImGui::EndTabItem();
		}




		if (ImGui::BeginTabItem("DOS Hdr"))
		{
			const auto& dos = PE->PEFILE_DOS_HEADER;
			if (ImGui::BeginTable("DOS", 2))
			{
				ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 300.f);
				ImGui::TableSetupColumn("Value");
				ImGui::TableHeadersRow();

				// Magic Number
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Magic Number");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_magic);

				// Bytes on last page of file
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Bytes on last page of file");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_cblp);

				// Pages in file
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Pages in file");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_cp);

				// Relocations
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Relocations");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_crlc);

				// Size of header in paragraphs
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of header in paragraphs");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_cparhdr);

				// Minimum extra paragraphs needed
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Minimum extra paragraphs needed");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_minalloc);

				// Maximum extra paragraphs needed
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Maximum extra paragraphs needed");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_maxalloc);

				// Initial (relative) SS value
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Initial SS value (relative)");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_ss);

				// Initial SP value
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Initial SP value");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_sp);

				// Checksum
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Checksum");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_csum);

				// Initial IP value
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Initial IP value");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_ip);

				// Initial (relative) CS value
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Initial CS value (relative)");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_cs);

				// File address of relocation table
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("File address of relocation table");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_lfarlc);

				// Overlay number
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Overlay number");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_ovno);

				// Reserved words [4]
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Reserved words [4]");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X, %X, %X, %X",
					dos.e_res[0], dos.e_res[1], dos.e_res[2], dos.e_res[3]);

				// OEM identifier
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("OEM identifier");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_oemid);

				// OEM information
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("OEM information");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_oeminfo);

				// Reserved words [10]
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Reserved words [10]");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X, %X, %X, %X, %X, %X, %X, %X, %X, %X",
					dos.e_res2[0], dos.e_res2[1], dos.e_res2[2], dos.e_res2[3], dos.e_res2[4],
					dos.e_res2[5], dos.e_res2[6], dos.e_res2[7], dos.e_res2[8], dos.e_res2[9]);

				// File address of new exe header
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("File address of new exe header");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", dos.e_lfanew);

				ImGui::EndTable();
			}
			ImGui::EndTabItem();

		}

		if (ImGui::BeginTabItem("Optional Hdr"))
		{
			const auto& opt = PE->PEFILE_OPTIONAL_HEADER64;
			if (ImGui::BeginTable("OptionalHdr", 2))
			{
				ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 300.f);
				ImGui::TableSetupColumn("Value");
				ImGui::TableHeadersRow();

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Magic");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.Magic);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Major Linker Version");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.MajorLinkerVersion);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Minor Linker Version");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.MinorLinkerVersion);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Code");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.SizeOfCode);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Initialized Data");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.SizeOfInitializedData);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Uninitialized Data");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.SizeOfUninitializedData);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Address of Entry Point");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.AddressOfEntryPoint);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Base of Code");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.BaseOfCode);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Image Base");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%llX", opt.ImageBase);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Section Alignment");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.SectionAlignment);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("File Alignment");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.FileAlignment);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Major OS Version");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.MajorOperatingSystemVersion);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Minor OS Version");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.MinorOperatingSystemVersion);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Major Image Version");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.MajorImageVersion);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Minor Image Version");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.MinorImageVersion);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Major Subsystem Version");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.MajorSubsystemVersion);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Minor Subsystem Version");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.MinorSubsystemVersion);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Win32 Version Value");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.Win32VersionValue);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Image");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.SizeOfImage);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Headers");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.SizeOfHeaders);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Checksum");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.CheckSum);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Subsystem");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.Subsystem);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("DLL Characteristics");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.DllCharacteristics);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Stack Reserve");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%llX", opt.SizeOfStackReserve);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Stack Commit");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%llX", opt.SizeOfStackCommit);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Heap Reserve");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%llX", opt.SizeOfHeapReserve);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Size of Heap Commit");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%llX", opt.SizeOfHeapCommit);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Loader Flags");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.LoaderFlags);

				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("Number of RVA and Sizes");
				ImGui::TableSetColumnIndex(1); ImGui::Text("%X", opt.NumberOfRvaAndSizes);

				// DataDirectory — IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
				static const char* dataDirNames[16] = {
					"Export Table",        "Import Table",       "Resource Table",     "Exception Table",
					"Certificate Table",   "Base Relocation",    "Debug",              "Architecture",
					"Global Ptr",          "TLS Table",          "Load Config",        "Bound Import",
					"IAT",                 "Delay Import",       "CLR Runtime Header", "Reserved"
				};
				for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
				{
					ImGui::TableNextRow();
					ImGui::TableSetColumnIndex(0); ImGui::Text("DataDirectory[%d] %s", i, dataDirNames[i]);
					ImGui::TableSetColumnIndex(1); ImGui::Text("RVA: %X  Size: %X",
						opt.DataDirectory[i].VirtualAddress, opt.DataDirectory[i].Size);
				}

				ImGui::EndTable();
			}
			ImGui::EndTabItem();
		}

		if (ImGui::BeginTabItem("Section Hdrs"))
		{
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Imports"))
		{
			ImGui::EndTabItem();
		}
		if (ImGui::BeginTabItem("Resources Hdr"))
		{
			ImGui::EndTabItem();
		}

		ImGui::EndTabBar();
	}
	ImGui::End();
}

void RenderImGui::RenderBinary()
{
	ImGui::Begin("HEX");

	if (!data)
		return;

	if (ImGui::BeginTable("table_id", 17, ImGuiTableFlags_None, ImVec2(400.0f, 0.0f)))
	{
		ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 50.0f);
		ImGui::TableSetupColumn("0");
		ImGui::TableSetupColumn("1");
		ImGui::TableSetupColumn("2");
		ImGui::TableSetupColumn("3");
		ImGui::TableSetupColumn("4");
		ImGui::TableSetupColumn("5");
		ImGui::TableSetupColumn("6");
		ImGui::TableSetupColumn("7");
		ImGui::TableSetupColumn("8");
		ImGui::TableSetupColumn("9");
		ImGui::TableSetupColumn("A");
		ImGui::TableSetupColumn("B");
		ImGui::TableSetupColumn("C");
		ImGui::TableSetupColumn("D");
		ImGui::TableSetupColumn("E");
		ImGui::TableSetupColumn("F");
		ImGui::TableHeadersRow();

		for (int i = 0; i < rows; i++)
		{
			ImGui::TableNextRow();
			ImGui::TableSetColumnIndex(0); ImGui::Text("%llX", currentAdress + i * 16);

			for (int j = 0; j < 16; j++)
			{
				ImGui::TableSetColumnIndex(j+1); 
				ImGui::TableSetBgColor(ImGuiTableBgTarget_CellBg, IM_COL32(255, 255, 255, 255));
				ImGui::TextColored(ImVec4(0.0f, .0f, 0.0f, 1.0f), "%02llX", data->data[(i * 16) + j]);

			}
		}


		ImGui::EndTable();
	}
	ImGui::End();
}

void RenderImGui::RenderHex()
{
	ImGui::Begin("ASCII");

	if (!data)
		return;

	if (ImGui::BeginTable("table_id", 16, ImGuiTableFlags_None, ImVec2(300.0f, 0.0f)))
	{
		ImGui::TableSetupColumn("0");
		ImGui::TableSetupColumn("1");
		ImGui::TableSetupColumn("2");
		ImGui::TableSetupColumn("3");
		ImGui::TableSetupColumn("4");
		ImGui::TableSetupColumn("5");
		ImGui::TableSetupColumn("6");
		ImGui::TableSetupColumn("7");
		ImGui::TableSetupColumn("8");
		ImGui::TableSetupColumn("9");
		ImGui::TableSetupColumn("A");
		ImGui::TableSetupColumn("B");
		ImGui::TableSetupColumn("C");
		ImGui::TableSetupColumn("D");
		ImGui::TableSetupColumn("E");
		ImGui::TableSetupColumn("F");
		ImGui::TableHeadersRow();

		for (int i = 0; i < rows; i++)
		{
			ImGui::TableNextRow();

			for (int j = 0; j < 16; j++)
			{
				BYTE b = data->data[(i * 16) + j];
				// safe ascii convertion, replace zeros with a '.'
				char c = (b >= 32 && b < 127) ? (char)b : '.';
				ImGui::TableSetColumnIndex(j);
				ImGui::Text("%c", c);
			}
		}


		ImGui::EndTable();
	}

	ImGui::End();
}
