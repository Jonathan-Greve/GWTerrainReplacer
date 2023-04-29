import ctypes
import os
from ctypes.wintypes import DWORD, HANDLE

import psutil


# Define the MODULEENTRY32 structure
class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("th32ModuleID", DWORD),
        ("th32ProcessID", DWORD),
        ("GlblcntUsage", DWORD),
        ("ProccntUsage", DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", DWORD),
        ("hModule", HANDLE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


def get_module_names(process_name):
    target_process = None
    for process in psutil.process_iter():
        if process.name() == process_name:
            target_process = process
            break

    if not target_process:
        raise Exception(f"Process {process_name} not found.")

    module_names = [module.path for module in target_process.memory_maps(grouped=True)]
    return module_names


def get_process_base_address(process_name, module_name):
    # Get the process handle
    target_process = None
    for process in psutil.process_iter():
        if process.name() == process_name:
            target_process = process
            break

    if not target_process:
        raise Exception(f"Process {process_name} not found.")

    process_id = target_process.pid

    # Create a snapshot of the target process modules
    h_snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x8, DWORD(process_id))
    if h_snapshot == ctypes.c_void_p(-1).value:
        raise Exception("Failed to create snapshot.")

    # Iterate over the modules and find the desired module base address
    module_entry = MODULEENTRY32()
    module_entry.dwSize = ctypes.sizeof(MODULEENTRY32)
    success = ctypes.windll.kernel32.Module32FirstW(h_snapshot, ctypes.byref(module_entry))

    base_address = None
    while success:
        if module_entry.szModule == module_name:
            base_address = module_entry.modBaseAddr
            break
        success = ctypes.windll.kernel32.Module32NextW(h_snapshot, ctypes.byref(module_entry))

    # Close the snapshot handle
    ctypes.windll.kernel32.CloseHandle(h_snapshot)

    if not base_address:
        raise Exception(f"Module {module_name} not found.")

    return ctypes.addressof(base_address.contents)
