use std::{mem, io::{self, Write}};
use windows::Win32::System::{Diagnostics::ToolHelp::*, Threading::*, Diagnostics::Debug::ReadProcessMemory};

// 0xFF = Wildcard
fn main() {
    let process_name = "game.exe";
    let signature: Vec<u8> = vec![0x20, 0x3b, 0x1f, 0x44]; // example signature

    match find_process_by_name(process_name) {
        Some(pid) => {
            println!("Found process {} with PID: {}", process_name, pid);

            let action = get_user_input("Do you want to specify base address by a hex value? (Y/N): ");

            if action.eq_ignore_ascii_case("N") {
                list_modules(pid);
                let module_name = get_user_input("Enter one of the module names, listed above: ");
                if let Some((base_addr, module_size)) = get_module_address(pid, &module_name) {
                    scan_memory(pid, base_addr, module_size, &signature);
                } else {
                    println!("Failed to get module {} for the process.", module_name);
                }
            } else if action.eq_ignore_ascii_case("Y") {
                let base_addr_str = get_user_input("Enter the base address (hex): ");
                if let Ok(base_addr) = usize::from_str_radix(&base_addr_str, 16) {
                    scan_memory_unknown_size(pid, base_addr, &signature);
                } else {
                    println!("Invalid hex input for base address.");
                }
            } else {
                println!("Invalid action specified.");
            }
        }
        None => println!("Process {} not found!", process_name),
    }
}

fn find_process_by_name(target_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut proc_entry: PROCESSENTRY32 = mem::zeroed();
        proc_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut proc_entry).is_ok() {
            loop {
                let exe_name = String::from_utf8_lossy(&proc_entry.szExeFile.iter().map(|&c| c as u8).collect::<Vec<u8>>())
                    .trim_end_matches(char::from(0))
                    .to_string();
                if exe_name.contains(target_name) {
                    return Some(proc_entry.th32ProcessID);
                }
                if Process32Next(snapshot, &mut proc_entry).is_err() {
                    break;
                }
            }
        }
    }
    None
}

fn get_module_address(pid: u32, module_name: &str) -> Option<(usize, usize)> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid).ok()?;
        let mut mod_entry: MODULEENTRY32 = mem::zeroed();
        mod_entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

        if Module32First(snapshot, &mut mod_entry).is_ok() {
            loop {
                let mod_name = extract_module_name(&mod_entry.szModule);
                if mod_name.eq_ignore_ascii_case(module_name.trim()) {
                    return Some((mod_entry.modBaseAddr as usize, mod_entry.modBaseSize as usize));
                }
                if Module32Next(snapshot, &mut mod_entry).is_err() {
                    break;
                }
            }
        }
        println!("Module {} not found in process {}", module_name, pid);
    }
    None
}

fn list_modules(pid: u32) {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid).expect("Failed to create snapshot");
        let mut mod_entry: MODULEENTRY32 = mem::zeroed();
        mod_entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

        if Module32First(snapshot, &mut mod_entry).is_ok() {
            println!("Module list:");
            loop {
                let mod_name = extract_module_name(&mod_entry.szModule);
                println!(" - {}", mod_name);
                if Module32Next(snapshot, &mut mod_entry).is_err() {
                    break;
                }
            }
        } else {
            println!("Failed to enumerate modules for process {}", pid);
        }
    }
}

fn extract_module_name(raw_name: &[i8]) -> String {
    let mut end = 0;
    let raw_name_u8: Vec<u8> = raw_name.iter().map(|&c| c as u8).collect();
    for (i, &c) in raw_name_u8.iter().enumerate() {
        if c == 0 {
            break;
        }
        end = i + 1;
    }
    String::from_utf8_lossy(&raw_name_u8[..end]).to_string()
}

fn scan_memory(pid: u32, base_addr: usize, module_size: usize, signature: &[u8]) {
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if process.is_err() {
            println!("Failed to open process: {}", pid);
            return;
        }
        let process_handle = process.unwrap();

        let mut buffer = vec![0u8; module_size];
        let mut bytes_read = 0;

        if ReadProcessMemory(process_handle, base_addr as _, buffer.as_mut_ptr() as _, buffer.len(), Some(&mut bytes_read)).is_ok() {
            println!("Scanning module memory region starting at: 0x{:X}", base_addr);
            if let Some(i) = (0..bytes_read).next() {
                if matches_pattern(&buffer[i..], signature) {
                    println!("Match found at: 0x{:X}", base_addr + i);
                }
                else {
                    println!("No matching address found.");
                }
            }
        } else {
            println!("Failed to read memory at: 0x{:X}", base_addr);
        }
    }
}

fn scan_memory_unknown_size(pid: u32, base_addr: usize, signature: &[u8]) {
    const CHUNK_SIZE: usize = 4096; // 4KB chunks
    let mut current_addr = base_addr;

    unsafe {
        let process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if process.is_err() {
            println!("Failed to open process: {}", pid);
            return;
        }
        let process_handle = process.unwrap();

        loop {
            let mut buffer = vec![0u8; CHUNK_SIZE];
            let mut bytes_read = 0;

            if ReadProcessMemory(process_handle, current_addr as _, buffer.as_mut_ptr() as _, buffer.len(), Some(&mut bytes_read)).is_err() {
                println!("Reached an invalid memory region or failed to read memory at: 0x{:X}", current_addr);
                break;
            }

            for i in 0..bytes_read {
                if matches_pattern(&buffer[i..], signature) {
                    println!("Match found at: 0x{:X}", current_addr + i);
                    return;
                }
            }

            current_addr += CHUNK_SIZE;
        }
    }
}

fn matches_pattern(data: &[u8], pattern: &[u8]) -> bool {
    if data.len() < pattern.len() {
        return false;
    }
    for (d, &p) in data.iter().zip(pattern) {
        if p != 0xFF && *d != p {
            return false;
        }
    }
    true
}

fn get_user_input(prompt: &str) -> String {
    let mut input = String::new();
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    input.trim().to_string()
}