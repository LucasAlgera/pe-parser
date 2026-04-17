#include "../include/pe.h"
#include "../include/pe_imgui.h"

#include <d3d11.h>
#include <windows.h>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

// DX11 globals
static ID3D11Device* g_device = nullptr;
static ID3D11DeviceContext* g_context = nullptr;
static IDXGISwapChain* g_swapchain = nullptr;
static ID3D11RenderTargetView* g_rendertarget = nullptr;

void CreateRenderTarget()
{
    ID3D11Texture2D* backbuffer = nullptr;
    g_swapchain->GetBuffer(0, IID_PPV_ARGS(&backbuffer));
    g_device->CreateRenderTargetView(backbuffer, nullptr, &g_rendertarget);
    backbuffer->Release();
}

bool InitDX11(HWND hwnd)
{
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL level;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        nullptr, 0, D3D11_SDK_VERSION,
        &sd, &g_swapchain, &g_device, &level, &g_context
    );
    if (FAILED(hr)) return false;
    CreateRenderTarget();
    return true;
}

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);
LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wp, lp)) return true;
    if (msg == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int main()
{
    // Load PE
    FILE* fptr = fopen("D:/Projects/Year3/pe-parser/executables/udbest.exe", "rb");
    if (!fptr) { printf("Failed to open file.\n"); return 1; }
    PE64 pe(fptr);

    RenderImGui peRender(&pe);

    // Register window class
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0, 0,
                       GetModuleHandle(nullptr), nullptr, nullptr, nullptr,
                       nullptr, L"pe-parser", nullptr };
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"PE Parser",
        WS_OVERLAPPEDWINDOW, 100, 100, 1280, 720,
        nullptr, nullptr, wc.hInstance, nullptr);

    if (!InitDX11(hwnd)) return 1;

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    // ImGui init
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);

    // Main loop
    bool running = true;
    while (running)
    {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) running = false;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGuiIO& io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

        ImGui::NewFrame();

        ImGui::DockSpaceOverViewport(ImGui::GetMainViewport()->ID);

        // --- your UI here ---
        peRender.RenderTick();
        // --------------------

        ImGui::Render();
        const float clear[4] = { 0.1f, 0.1f, 0.1f, 1.0f };
        g_context->OMSetRenderTargets(1, &g_rendertarget, nullptr);
        g_context->ClearRenderTargetView(g_rendertarget, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_swapchain->Present(1, 0);
    }

    // Cleanup
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    g_rendertarget->Release();
    g_swapchain->Release();
    g_context->Release();
    g_device->Release();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    fclose(fptr);
    return 0;
}
//int main()
//{
//    FILE* fptr;
//    fptr = fopen("D:/Projects/Year3/pe-parser/executables/udbest.exe", "r");
//
//    if (fptr == NULL) {
//        printf("The file is not opened.");
//        return 0;
//    }
//
//    PE64 PE( fptr );
//}