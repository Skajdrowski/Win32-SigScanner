use std::{mem};
use windows::Win32::System::{Diagnostics::ToolHelp::*, Threading::*, Diagnostics::Debug::ReadProcessMemory};


// 0xFF = Wildcard
fn main() {
    let process_name = "game.exe";
    let signature: Vec<u8> = vec![0x3a, 0x1e, 0x75, 0xFF, 0x84, 0xd2, 0x74]; // example signature

    match find_process_by_name(process_name) {
        Some(pid) => {
            println!("Found process {} with PID: {}", process_name, pid);
            if let Some((base_addr, module_size)) = get_base_module(pid, process_name) {
                scan_memory(pid, base_addr, module_size, &signature);
            } else {
                println!("Failed to get base module for the process.");
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
                let exe_name = String::from_utf8_lossy(&proc_entry.szExeFile.iter().map(|&c| c as u8).collect::<Vec<u8>>()).trim_end_matches(char::from(0)).to_string();
                if exe_name.contains(target_name) {
                    return Some(proc_entry.th32ProcessID);
                }
                if !Process32Next(snapshot, &mut proc_entry).is_ok() {
                    break;
                }
            }
        }
    }
    None
}

fn get_base_module(pid: u32, module_name: &str) -> Option<(usize, usize)> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid).ok()?;
        let mut mod_entry: MODULEENTRY32 = mem::zeroed();
        mod_entry.dwSize = mem::size_of::<MODULEENTRY32>() as u32;

        if Module32First(snapshot, &mut mod_entry).is_ok() {
            loop {
                let mod_name = String::from_utf8_lossy(&mod_entry.szModule.iter().map(|&c| c as u8).collect::<Vec<u8>>()).trim_end_matches(char::from(0)).to_string();
                if mod_name.eq_ignore_ascii_case(module_name) {
                    return Some((mod_entry.modBaseAddr as usize, mod_entry.modBaseSize as usize));
                }
                if !Module32Next(snapshot, &mut mod_entry).is_ok() {
                    break;
                }
            }
        }
    }
    None
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
            println!("Scanning base module memory region starting at: 0x{:X}", base_addr);
            for i in 0..bytes_read {
                if matches_pattern(&buffer[i..], signature) {
                    println!("Match found at: 0x{:X}", base_addr + i);
                }
            }
        } else {
            println!("Failed to read memory at: 0x{:X}", base_addr);
        }
        println!("Memory scan completed.");
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