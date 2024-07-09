package main

import (
    "syscall"
    "unsafe"
    "fmt"
    "unicode/utf16"
    "golang.org/x/sys/windows"
    "os"
    "flag"
)


// Structures
type PROCESS_BASIC_INFORMATION struct {
    ExitStatus                   uint32
    PebBaseAddress               uintptr
    AffinityMask                 uintptr
    BasePriority                 int32
    UniqueProcessID              uintptr
    InheritedFromUniqueProcessID uintptr
}

type UNICODE_STRING struct {
    Length        uint16
    MaximumLength uint16
    Buffer        *uint16
}

type OBJECT_ATTRIBUTES struct {
    Length                   uint32
    RootDirectory            windows.Handle
    ObjectName               *UNICODE_STRING
    Attributes               uint32
    SecurityDescriptor       uintptr
    SecurityQualityOfService uintptr
}

type STARTUPINFO struct {
    cb            uint32
    lpReserved    *uint16
    lpDesktop     *uint16
    lpTitle       *uint16
    dwX           uint32
    dwY           uint32
    dwXSize       uint32
    dwYSize       uint32
    dwXCountChars uint32
    dwYCountChars uint32
    dwFillAttribute uint32
    dwFlags         uint32
    wShowWindow     uint16
    cbReserved2     uint16
    lpReserved2     *byte
    hStdInput       windows.Handle
    hStdOutput      windows.Handle
    hStdError       windows.Handle
}

type PROCESS_INFORMATION struct {
    hProcess    windows.Handle
    hThread     windows.Handle
    dwProcessId uint32
    dwThreadId  uint32
}


func ntQueryInformationProcess(processHandle windows.Handle, processInformationClass uint32, processInformation uintptr, processInformationLength uint32, returnLength *uint32) (ntstatus uint32) {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    ntQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

    r1, _, _ := ntQueryInformationProcess.Call(
        uintptr(processHandle),
        uintptr(processInformationClass),
        processInformation,
        uintptr(processInformationLength),
        uintptr(unsafe.Pointer(returnLength)),
    )

    return uint32(r1)
}


func ntReadVirtualMemory(processHandle windows.Handle, baseAddress uintptr, buffer uintptr, size uintptr, bytesRead *uintptr) (ntstatus uint32) {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    ntReadVirtualMemory := ntdll.NewProc("NtReadVirtualMemory")
    r1, _, _ := ntReadVirtualMemory.Call(
        uintptr(processHandle),
        baseAddress,
        buffer,
        size,
        uintptr(unsafe.Pointer(bytesRead)),
    )
    return uint32(r1)
}


func NtOpenSection(sectionHandle *windows.Handle, desiredAccess uint32, objectAttributes *OBJECT_ATTRIBUTES) (ntstatus uint32) {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    ntOpenSection := ntdll.NewProc("NtOpenSection")
    r1, _, _ := syscall.Syscall(
        ntOpenSection.Addr(),
        3,
        uintptr(unsafe.Pointer(sectionHandle)),
        uintptr(desiredAccess),
        uintptr(unsafe.Pointer(objectAttributes)))
    return uint32(r1)
}

func VirtualProtect(lpAddress uintptr, dwSize uintptr, flNewProtect uint32, lpflOldProtect *uint32) bool {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    ret, _, _ := VirtualProtect.Call(
        lpAddress,
        dwSize,
        uintptr(flNewProtect),
        uintptr(unsafe.Pointer(lpflOldProtect)),
    )
    return ret != 0
}


func CreateProcess(
    applicationName *uint16,
    commandLine *uint16,
    processAttributes *windows.SecurityAttributes,
    threadAttributes *windows.SecurityAttributes,
    inheritHandles bool,
    creationFlags uint32,
    environment *uint16,
    currentDirectory *uint16,
    startupInfo *STARTUPINFO,
    processInformation *PROCESS_INFORMATION,
) (bool, error) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    CreateProcess := kernel32.NewProc("CreateProcessW")
    inherit := uint32(0)
    if inheritHandles {
        inherit = 1
    }

    r1, _, e1 := syscall.Syscall12(
        CreateProcess.Addr(),
        10,
        uintptr(unsafe.Pointer(applicationName)),
        uintptr(unsafe.Pointer(commandLine)),
        uintptr(unsafe.Pointer(processAttributes)),
        uintptr(unsafe.Pointer(threadAttributes)),
        uintptr(inherit),
        uintptr(creationFlags),
        uintptr(unsafe.Pointer(environment)),
        uintptr(unsafe.Pointer(currentDirectory)),
        uintptr(unsafe.Pointer(startupInfo)),
        uintptr(unsafe.Pointer(processInformation)),
        0,
        0,
    )

    if r1 == 0 {
        if e1 != 0 {
            return false, syscall.Errno(e1)
        } else {
            return false, syscall.EINVAL
        }
    }

    return true, nil
}


func DebugActiveProcessStop(dwProcessID uint32) (bool, error) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    DebugActiveProcessStop := kernel32.NewProc("DebugActiveProcessStop")
    r1, _, e1 := syscall.Syscall(DebugActiveProcessStop.Addr(), 1, uintptr(dwProcessID), 0, 0)
    if r1 == 0 {
        if e1 != 0 {
            return false, syscall.Errno(e1)
        } else {
            return false, syscall.EINVAL
        }
    }
    return true, nil
}


func TerminateProcess(hProcess windows.Handle, uExitCode uint32) (bool, error) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    TerminateProcess := kernel32.NewProc("TerminateProcess")
    r1, _, e1 := syscall.Syscall(TerminateProcess.Addr(), 2, uintptr(hProcess), uintptr(uExitCode), 0)
    if r1 == 0 {
        if e1 != 0 {
            return false, syscall.Errno(e1)
        } else {
            return false, syscall.EINVAL
        }
    }
    return true, nil
}


func read_remoteintptr(process_handle windows.Handle, base_address uintptr, size uintptr) uintptr {
    buffer := make([]byte, size)
    var bytesRead uintptr
    status := ntReadVirtualMemory(process_handle, base_address, uintptr(unsafe.Pointer(&buffer[0])), size,&bytesRead)
    if status != 0 {
        fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
        return 0
    }
    read_value := *(*uintptr)(unsafe.Pointer(&buffer[0]))
    return read_value
}


func utf16BytesToUTF8(utf16Bytes []byte) []byte {
    u16s := make([]uint16, len(utf16Bytes)/2)
    for i := range u16s {
        u16s[i] = uint16(utf16Bytes[i*2]) | uint16(utf16Bytes[i*2+1])<<8
    }
    return []byte(string(utf16.Decode(u16s)))
}


func read_remoteWStr(process_handle windows.Handle, base_address uintptr, size uintptr) string {
    buffer := make([]byte, size)
    var bytesRead uintptr
    status := ntReadVirtualMemory(process_handle, base_address, uintptr(unsafe.Pointer(&buffer[0])), size,&bytesRead)
    if status != 0 {
        fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
        return ""
    }
    for i := 0; i < int(bytesRead)-1; i += 1 {
        if buffer[i] == 0x00 && buffer[i+1] == 0x00 {
            return string(utf16BytesToUTF8(buffer[:i+2]))
        }
    }
    return ""
}


func get_local_lib_address(dll_name string) uintptr {
    var ProcessBasicInformation uint32 = 0
    var ldr_offset uintptr = 0x18
    var inInitializationOrderModuleList_offset uintptr = 0x30
    var dll_base uintptr = 1337
    var flink_dllbase_offset uintptr = 0x20
    var flink_buffer_offset uintptr = 0x50

    // GetCurrentProcess
    process_handle, _ := windows.GetCurrentProcess()
    fmt.Printf("[+] Process Handle: \t%d\n", process_handle)
    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32

    // NtQueryInformationProcess
    status := ntQueryInformationProcess(
        process_handle,
        ProcessBasicInformation,
        uintptr(unsafe.Pointer(&pbi)),
        uint32(unsafe.Sizeof(pbi)),
        &returnLength,
    )
    if status != 0 {
        fmt.Printf("NtQueryInformationProcess failed with status: 0x%x\n", status)
        return 0
    }
    fmt.Printf("[+] Process ID: \t%d\n", pbi.UniqueProcessID)
    fmt.Printf("[+] PEB Base Address: \t0x%x\n", pbi.PebBaseAddress)

    // Ldr Address
    peb_baseaddress := pbi.PebBaseAddress
    ldr_pointer := peb_baseaddress + ldr_offset
    ldr_address := read_remoteintptr(process_handle, ldr_pointer, 8)
    fmt.Printf("[+] ldr_pointer: \t0x%x\n", ldr_pointer)
    fmt.Printf("[+] Ldr Address: \t0x%x\n", ldr_address)
    
    // next_flink
    InInitializationOrderModuleList:= ldr_address + inInitializationOrderModuleList_offset
    next_flink := read_remoteintptr(process_handle, InInitializationOrderModuleList, 8)
    fmt.Printf("[+] next_flink: \t0x%x\n", next_flink)

    // Loop modules
    for dll_base != 0 {
        next_flink = next_flink - 0x10
        dll_base = read_remoteintptr(process_handle, (next_flink + flink_dllbase_offset), 8)
        // fmt.Printf("[+] dll_base: \t\t0x%x\n", dll_base)
        if (dll_base == 0){
            break    
        }
        buffer := read_remoteintptr(process_handle, (next_flink + flink_buffer_offset), 8)
        base_dll_name := read_remoteWStr(process_handle, buffer, 256)
        // fmt.Printf("[+] base_dll_name: \t%s\n", base_dll_name)
        if (base_dll_name == dll_name){
            return dll_base
        }
        next_flink = read_remoteintptr(process_handle, (next_flink + 0x10), 8)
    }
    return 0
}


func get_section_info(base_address uintptr) (uintptr,uintptr) {
    process_handle, _ := windows.GetCurrentProcess()
    fmt.Printf("[+] Process Handle: \t%d\n", process_handle)
    var e_lfanew_addr uintptr = base_address + 0x3C
    var e_lfanew uintptr = read_remoteintptr(process_handle, e_lfanew_addr, 4)
    var sizeofcode_addr uintptr = base_address + e_lfanew + 24 + 4
    var sizeofcode uintptr = read_remoteintptr(process_handle, sizeofcode_addr, 4)
    var baseofcode_addr uintptr  = base_address + e_lfanew + 24 + 20
    var baseofcode uintptr = read_remoteintptr(process_handle, baseofcode_addr, 4)
    return baseofcode, sizeofcode
}


func copyMemory(dst uintptr, src uintptr, size uintptr) {
    for i := uintptr(0); i < size; i++ {
        *(*byte)(unsafe.Pointer(dst + i)) = *(*byte)(unsafe.Pointer(src + i))
    }
}


func replace_ntdll_section(unhooked_ntdll_text uintptr, local_ntdll_txt uintptr, local_ntdll_txt_size uintptr){
    var PAGE_EXECUTE_WRITECOPY uint32 = 0x80
    var oldProtect uint32
    if !VirtualProtect(local_ntdll_txt, local_ntdll_txt_size, PAGE_EXECUTE_WRITECOPY, &oldProtect) {
        fmt.Println("Failed to change memory protection to PAGE_EXECUTE_WRITECOPY")
        return
    }
    // fmt.Scanln()
    // Copy bytes to the address
    copyMemory(local_ntdll_txt, unhooked_ntdll_text, local_ntdll_txt_size)
    // fmt.Scanln()
    // Restore the original protection
    if !VirtualProtect(local_ntdll_txt, local_ntdll_txt_size, oldProtect, &oldProtect) {
        fmt.Println("Failed to restore the original memory protection")
        return
    }
}


func overwrite_disk(file_name string) uintptr {
    // Constants
    var SEC_IMAGE_NO_EXECUTE uintptr = 0x11000000
    var offset_mappeddll uintptr = 4096

    // Functions
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    createFile := kernel32.NewProc("CreateFileA")
    createFileMapping := kernel32.NewProc("CreateFileMappingA")
    mapViewOfFile := kernel32.NewProc("MapViewOfFile")

    // CreateFileA
    fileNamePtr, _ := syscall.BytePtrFromString(file_name)
    file_handle, _, err := createFile.Call(uintptr(unsafe.Pointer(fileNamePtr)), windows.GENERIC_READ, windows.FILE_SHARE_READ, 0, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
    if windows.Handle(file_handle) == windows.InvalidHandle {
        fmt.Printf("Error creating file: %v\n", err)
        return 0
    }
    fmt.Printf("[+] File handle: \t%d\n", file_handle)
    defer windows.CloseHandle(windows.Handle(file_handle))

    // CreateFileMappingA
    // mapping_handle =  CreateFileMappingA(file_handle, 0, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, None)
    mapping_handle, _, err := createFileMapping.Call(file_handle, 0, (windows.PAGE_READONLY | SEC_IMAGE_NO_EXECUTE), 0, 0, 0)
    if mapping_handle == 0 {
        fmt.Printf("Error creating file mapping: %v\n", err)
        return 0
    }
    defer windows.CloseHandle(windows.Handle(mapping_handle))
    fmt.Printf("[+] Mapping handle: \t%d\n", mapping_handle)

    // MapViewOfFile
    unhooked_ntdll, _, err := mapViewOfFile.Call(mapping_handle, windows.FILE_MAP_READ, 0, 0, 0)

    if unhooked_ntdll == 0 {
        fmt.Printf("Error mapping view of file: %v\n", err)
        return 0
    }
    fmt.Printf("[+] Mapped Ntdll:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll))

    // CloseHandle
    windows.CloseHandle(windows.Handle(file_handle))
    windows.CloseHandle(windows.Handle(mapping_handle))
    
    // Add Offset
    var unhooked_ntdll_text uintptr = unhooked_ntdll + offset_mappeddll
    return unhooked_ntdll_text
}


func overwrite_knowndlls() uintptr {
    // Constants
    var SECTION_MAP_READ uint32 = 0x04 
    var offset_mappeddll uintptr = 4096
    
    // Functions
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    mapViewOfFile := kernel32.NewProc("MapViewOfFile")

    // NtOpenSection
    var s string = "\\KnownDlls\\ntdll.dll"
    us := UNICODE_STRING{}
    us.Length = uint16(len(s) * 2)
    us.MaximumLength = us.Length + 2
    us.Buffer = windows.StringToUTF16Ptr(s)
    oa := OBJECT_ATTRIBUTES{
        Length:      uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
        RootDirectory: 0,
        ObjectName: &us,
        Attributes: 0,
    }
    var section_handle windows.Handle
    status := NtOpenSection(&section_handle, SECTION_MAP_READ, &oa)
    if status != 0 {
        fmt.Printf("[-] NtOpenSection failed\n")
        os.Exit(0)
        return 0
    }
    fmt.Printf("[+] Section handle: \t0x%x\n", section_handle)

    // MapViewOfFile
    unhooked_ntdll, _, err := mapViewOfFile.Call(uintptr(section_handle), uintptr(SECTION_MAP_READ), 0, 0, 0)
    if unhooked_ntdll == 0 {
        fmt.Printf("[-] Error mapping view of file: %v\n", err)
        os.Exit(0)
        return 0
    }

    // CloseHandle
    windows.CloseHandle(windows.Handle(section_handle))
    
    // Add offset
    var unhooked_ntdll_text uintptr = unhooked_ntdll + offset_mappeddll
    return unhooked_ntdll_text
}


func overwrite_debugproc(file_path string, local_ntdll_txt uintptr, local_ntdll_txt_size uintptr) uintptr {
    var DEBUG_PROCESS uint32 = 0x00000001
    
    // CreateProcess
    var si STARTUPINFO
    var pi PROCESS_INFORMATION
    si.cb = uint32(unsafe.Sizeof(si))
    applicationName := windows.StringToUTF16Ptr(file_path)
    success, err := CreateProcess(applicationName, nil, nil, nil, false, DEBUG_PROCESS, nil, nil, &si, &pi,)
    if !success {
        fmt.Printf("CreateProcess failed: %v\n", err)
        os.Exit(0)
    }
    
    // NtReadVirtualMemory: debugged_process ntdll_handle = local ntdll_handle --> debugged_process .text section ntdll_handle = local .text section ntdll_handle
    buffer := make([]byte, local_ntdll_txt_size)
    var bytesRead uintptr
    status := ntReadVirtualMemory(pi.hProcess, local_ntdll_txt, uintptr(unsafe.Pointer(&buffer[0])), local_ntdll_txt_size, &bytesRead)
    if status != 0 {
        fmt.Printf("NtReadVirtualMemory failed with status: 0x%x\n", status)
        os.Exit(0)
    }

    // TerminateProcess + DebugActiveProcessStop
    tp_bool, _ := TerminateProcess(pi.hProcess, 0)
    daps_bool, _ := DebugActiveProcessStop(pi.dwProcessId)
    if (tp_bool != true || daps_bool != true){
        fmt.Printf("[-] TerminateProcess or DebugActiveProcessStop failed")
        os.Exit(0)
    }

    return uintptr(unsafe.Pointer(&buffer[0]))
}


func main() {
    optionFlag := flag.String("o", "default", "Option for library overwrite: \"disk\", \"knowndlls\" or \"debugproc\"")
    pathFlag   := flag.String("p", "default", "Path to ntdll file in disk (for \"disk\" option) or program to open in debug mode (\"debugproc\" option)")
    flag.Parse()

    var local_ntdll uintptr = get_local_lib_address("ntdll.dll")
    fmt.Printf("[+] Local Ntdll:\t0x%s\n", fmt.Sprintf("%x", local_ntdll))
    local_ntdll_txt_addr, local_ntdll_txt_size := get_section_info(local_ntdll)
    fmt.Printf("[+] Local Ntdll Size:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt_size))
    fmt.Printf("[+] Local Ntdll Addr:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt_addr))
    var local_ntdll_txt uintptr = local_ntdll + local_ntdll_txt_addr
    fmt.Printf("[+] Local Ntdll Text:\t0x%s\n", fmt.Sprintf("%x", local_ntdll_txt))
    var unhooked_ntdll_text uintptr = 0

    if *optionFlag == "disk" {
        file_name := "C:\\Windows\\System32\\ntdll.dll"
        if *pathFlag != "default" {
            file_name = *pathFlag
        }
        fmt.Printf("[+] Option \"disk\" - Getting clean version from file in disk %s\n", file_name)
        unhooked_ntdll_text = overwrite_disk(file_name)
        if (unhooked_ntdll_text != 0){
            fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)
        }
    } else if *optionFlag == "knowndlls" {
        fmt.Println("[+] Option \"knowndlls\" - Getting clean version from KnownDlls folder")
        unhooked_ntdll_text = overwrite_knowndlls()
        if (unhooked_ntdll_text != 0){
            fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)       
        }
    } else if *optionFlag == "debugproc" {
        program_path := "c:\\Windows\\System32\\notepad.exe"
        if *pathFlag != "default" {
            program_path = *pathFlag
        }
        fmt.Printf("[+] Option \"debugproc\" - Getting clean version from debugged process %s\n", program_path)
        unhooked_ntdll_text = overwrite_debugproc(program_path, local_ntdll_txt, local_ntdll_txt_size)
        if (unhooked_ntdll_text != 0){
            fmt.Printf("[+] Mapped Ntdll .Text:\t0x%s\n", fmt.Sprintf("%x", unhooked_ntdll_text))
        } else {
            fmt.Printf("[-] Error getting the .text section address")
            os.Exit(0)       
        }
    } else {
        fmt.Println("[-] Parameter -o (Library overwrite option) is mandatory. Possible values: \"disk\", \"knowndlls\" or \"debugproc\" ")
        os.Exit(0)
    }

    replace_ntdll_section(unhooked_ntdll_text, local_ntdll_txt, local_ntdll_txt_size)
}