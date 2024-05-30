"""
tool to modify process memory

Features:
- get_pid_from_exe(exe)
- get_address_from_module(pid, modName)
- open_process(pid)
- read_memory(address, length<=8)
- write_memory(address, length<=8, value)

Author: tabethereal
License: MIT License
"""

from ctypes import *
from ctypes.wintypes import *

CreateToolhelp32Snapshot= ctypes.windll.kernel32.CreateToolhelp32Snapshot
Process32First = ctypes.windll.kernel32.Process32First
Process32Next = ctypes.windll.kernel32.Process32Next
Module32First = ctypes.windll.kernel32.Module32First
Module32Next = ctypes.windll.kernel32.Module32Next
CloseHandle = ctypes.windll.kernel32.CloseHandle
GetLastError = ctypes.windll.kernel32.GetLastError
OpenProcess = ctypes.windll.kernel32.OpenProcess
WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_ALL_ACCESS = 0x1F0FFF
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

class PROCESSENTRY32(Structure):
    _fields_ = [('dwSize', DWORD),
                ('cntUsage', DWORD),
                ('th32ProcessID', DWORD),
                ('th32DefaultHeapID', LPVOID),
                ('th32ModuleID', DWORD),
                ('cntThreads', DWORD),
                ('th32ParentProcessID', DWORD),
                ('pcPriClassBase', LONG),
                ('dwFlags', DWORD), 
                ('szExeFile', c_char * 260)]

class MODULEENTRY32(Structure):
    _fields_ = [('dwSize', DWORD),
                ('th32ModuleID', DWORD),
                ('th32ProcessID', DWORD),
                ('GlblcntUsage', DWORD),
                ('ProccntUsage', DWORD),
                ('modBaseAddr', POINTER(BYTE)),
                ('modBaseSize', DWORD), 
                ('hModule', HMODULE),
                ('szModule', c_char * 256),
                ('szExePath', c_char * 260)]

def get_pid_from_exe(exe):
    if type(exe) != bytes: exe = exe.encode()
    pid = 0
    handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, None)
    process = PROCESSENTRY32()
    process.dwSize = sizeof(process)
    if Process32First(handle, byref(process)):
        while True:
            if process.szExeFile == exe:
                pid = process.th32ProcessID
                break
            if not Process32Next(handle, byref(process)):
                break
    CloseHandle(handle)
    return pid

def get_address_from_module(pid, modName):
    modBaseAddr = 0
    handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    module = MODULEENTRY32()
    module.dwSize = sizeof(module)
    if Module32First(handle, byref(module)):
        while True:
            if module.szModule == modName.encode():
                modBaseAddr = cast(module.modBaseAddr, LPVOID).value
                break
            if not Module32Next(handle, byref(module)):
                break
    CloseHandle(handle)
    return modBaseAddr

def open_process(pid):
    open_process.process = OpenProcess(PROCESS_ALL_ACCESS, False, pid)

def read_memory(address, length):
    ans = c_longlong()
    ReadProcessMemory(open_process.process, LPVOID(address), byref(ans), length, None)
    return ans.value

def write_memory(address, length, value):
    WriteProcessMemory(open_process.process, LPVOID(address), byref(c_longlong(value)), length, None)

