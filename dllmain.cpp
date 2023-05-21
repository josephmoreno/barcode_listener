// dllmain.cpp : Defines the entry point for the DLL application.

/*
Ver. 2:
Uses 2D char array input as the VID_PID array for identifying barcode scanners.
*/

// HINSTACE within a DLL:   https://stackoverflow.com/questions/21718027/getmodulehandlenull-vs-hinstance
// HMODULE and HINSTANCE:   https://stackoverflow.com/questions/2126657/how-can-i-get-hinstance-from-a-dll
// Using HMODULE:           https://stackoverflow.com/questions/2396328/get-hmodule-from-inside-a-dll
#include "pch.h"    // To use malloc, must include header in pch.h for pre-compilation.

#define BARCODE_LENGTH 256

HMODULE g_hModule;

RAWINPUTDEVICE rid;

char barcode[BARCODE_LENGTH];
char* vid_pid_ptr;      // Points to the char array passed by ListenForBarcode().
unsigned int vid_pid_r; // Global unsigned int for vid_pid_rows passed by ListenForBarcode().
unsigned int vid_pid_c; // Global unsigned int for vid_pid_c passed by ListenForBarcode().

extern "C" __declspec(dllexport)unsigned int ListenForBarcode(unsigned int enable, char* vid_pid, unsigned int vid_pid_rows, unsigned int vid_pid_col);

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wparam, LPARAM lparam);
static int scan2ascii(DWORD scancode, LPWORD result);
void barcode_append(char* bc, char c);
BOOL GetMessageWithTimeout(MSG* msg);

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;    // When the DLL is loaded, assign hModule to global memory.
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

unsigned int ListenForBarcode(unsigned int enable, char* vid_pid, unsigned int vid_pid_rows, unsigned int vid_pid_col) {
    if (enable == 1) {
        memset(barcode, '\0', BARCODE_LENGTH);
        vid_pid_ptr = vid_pid;      // Copy the necessary data to global memory.
        vid_pid_r = vid_pid_rows;
        vid_pid_c = vid_pid_col;

        // Initialize data for creating a window and assigning that window a process.
        WNDCLASS wc = {};
        wc.lpfnWndProc = WndProc;
        wc.hInstance = g_hModule;
        wc.lpszClassName = TEXT("RawInputWnd");

        RegisterClass(&wc);

        // Create the window.
        LPCWSTR wnd_name = TEXT("Barcode Listener");
        HWND hwnd0 = CreateWindowEx(0, wc.lpszClassName, wnd_name, NULL, 0, 0, 0, 0, NULL, NULL, g_hModule, NULL);

        // Hide the window.
        ShowWindow(hwnd0, SW_HIDE);

        // Initialize data for raw input listening. (Reference: https://docs.microsoft.com/en-us/windows-hardware/drivers/hid/hid-usages#usage-page)
        rid.usUsage = 0x06;             // Listen for keyboards.
        rid.usUsagePage = 0x01;
        rid.dwFlags = RIDEV_INPUTSINK;  // Listen even if the window is in the background.
        rid.hwndTarget = hwnd0;         // Assign the window that will listen for raw input.

        RegisterRawInputDevices(&rid, 1, sizeof(rid));  // Register the raw input devices.

        // Enter the listening loop
        MSG msg = {};
        while (GetMessageWithTimeout(&msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        DestroyWindow(hwnd0);
    }

    return(unsigned int(strlen(barcode)));
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wparam, LPARAM lparam) {
    switch (uMsg) {
        case WM_INPUT: {
            UINT dwSize = NULL;
            LPVOID data_ptr = NULL;
            WORD make_code_char;
            unsigned int data_length;

            GetRawInputData((HRAWINPUT)lparam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));
            LPBYTE lpb = new BYTE[dwSize];

            GetRawInputData((HRAWINPUT)lparam, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER));
            RAWINPUT* raw = (RAWINPUT*)lpb;

            if (raw->header.dwType == RIM_TYPEKEYBOARD)
            {
                // This 1st GetRawInputDeviceInfoA() will write the length of the device name data to the address pointed to
                // by &data_length. LPVOID parameter must be NULL.
                if (GetRawInputDeviceInfoA(raw->header.hDevice, RIDI_DEVICENAME, NULL, (PUINT)&data_length) == -1)
                    break;

                // This 2nd GetRawInputDeviceInfoA() will write the device name to the address pointed to by the LPVOID
                // parameter (data_ptr). The length is being read from the address &data_length.
                data_ptr = (LPVOID)malloc(data_length);
                if (GetRawInputDeviceInfoA(raw->header.hDevice, RIDI_DEVICENAME, data_ptr, (PUINT)&data_length) == -1)
                    break;

                unsigned int i;
                unsigned char found = 0x00;
                for (i = 0; i < vid_pid_r; ++i) {
                    if (strstr((const char*)data_ptr, &vid_pid_ptr[i * vid_pid_c]) != NULL) {   // Look for the VID/PID of the barcode scanner.
                        found = 0x01;                                                           // Set found to 0x01;
                        break;                                                                  // Break the loop if found.
                    }
                }

                if ((found == 0x01) && (raw->data.keyboard.Flags == 0x01)) {    // When Flags == 0x00, key is pressed down. When Flags == 0x01, key is up.
                    scan2ascii(raw->data.keyboard.MakeCode, &make_code_char);

                    // Append the character to the barcode string if it's not a new line and not a carriage return.
                    if (((char)make_code_char != '\n') && ((char)make_code_char != '\r')
                        && ((((char)make_code_char >= 'a') && ((char)make_code_char <= 'z')) || (((char)make_code_char >= 'A') && ((char)make_code_char <= 'Z'))
                        || (((char)make_code_char >= '0') && ((char)make_code_char <= '9'))))
                        barcode_append(barcode, (char)make_code_char);
                    else if (((char)make_code_char == '\n') || ((char)make_code_char == '\r'))
                        PostQuitMessage(0); // This will make the ListenForBarcode function exit the message loop.
                }
            }

            free(data_ptr);
            data_ptr = NULL;

            delete[] lpb;

            break;
        }

        case WM_CLOSE: {
            PostQuitMessage(0);
            break;
        }

        default:
            break;
    }

    return DefWindowProc(hwnd, uMsg, wparam, lparam);
}

static int scan2ascii(DWORD scancode, LPWORD result) {
    static HKL layout = GetKeyboardLayout(0);
    static BYTE State[256];

    if (GetKeyboardState(State) == FALSE)
        return 0;

    UINT vk = MapVirtualKeyEx(scancode, 1, layout);

    return ToAsciiEx(vk, scancode, State, result, 0, layout);
}

void barcode_append(char* bc, char c) {
    if (strlen(bc) < (BARCODE_LENGTH - 1)) {
        bc[strlen(bc)] = c;
        bc[strlen(bc) + 1] = '\0';
    }

    return;
}

BOOL GetMessageWithTimeout(MSG* msg) {
    BOOL received;
    UINT_PTR timerId = SetTimer(NULL, NULL, 1000, NULL);

    received = GetMessage(msg, NULL, 0, 0);
    KillTimer(NULL, timerId);

    if (!received)
        return FALSE;

    if (msg->message == WM_TIMER && msg->hwnd == NULL && msg->wParam == timerId)
        return FALSE; // Timeout

    return TRUE;
}