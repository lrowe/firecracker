// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod uffd_utils;

use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr;

use serde::Deserialize;
use uffd_utils::{Runtime, UffdHandler};
use vmm_sys_util::sock_ctrl_msg::ScmSocket;

const MAX_REQUEST_SIZE: usize = 1024;

#[derive(Deserialize)]
struct UffdRequest {
    uffd_shared: bool,
}

fn read_request(stream: &mut UnixStream) -> io::Result<UffdRequest> {
    let mut reader = BufReader::new(stream);
    let mut request = String::with_capacity(MAX_REQUEST_SIZE);
    let bytes_read = reader.read_line(&mut request)?;
    if bytes_read == 0 || !request.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "UFFD shared request is not newline-terminated",
        ));
    }
    request.pop();
    if request.len() > MAX_REQUEST_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UFFD shared request is too large",
        ));
    }

    let request: UffdRequest = serde_json::from_str(&request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if !request.uffd_shared {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "UFFD shared request flag is false",
        ));
    }
    Ok(request)
}

fn create_memfd(source: &File) -> io::Result<File> {
    let name = CString::new("firecracker-uffd-snapshot").unwrap();
    // SAFETY: `name` is a valid NUL-terminated string and flags are valid.
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) as i32 };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is freshly created and owned here.
    let mut memfd = unsafe { File::from_raw_fd(fd) };
    let size = source.metadata()?.len();
    memfd.set_len(size)?;
    memfd.seek(SeekFrom::Start(0))?;
    Ok(memfd)
}

fn mmap_file(source: &File, protection: i32, flags: i32) -> io::Result<*mut u8> {
    let size = source.metadata()?.len() as usize;
    // SAFETY: The source file is valid and its size is non-zero.
    let mapping = unsafe {
        libc::mmap(
            ptr::null_mut(),
            size,
            protection,
            flags,
            source.as_raw_fd(),
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(mapping.cast())
}

fn main() {
    let mut args = std::env::args();
    let socket_path = args.nth(1).expect("No socket path given");
    let snapshot_path = args.next().expect("No memory file given");
    let snapshot = File::open(snapshot_path).expect("Cannot open memfile");

    let listener = UnixListener::bind(socket_path).expect("Cannot bind to socket path");
    let (mut stream, _) = listener.accept().expect("Cannot listen on UDS socket");
    read_request(&mut stream).expect("Invalid shared UFFD request");

    let memfd = create_memfd(&snapshot).expect("Cannot create shared memfd");
    stream
        .send_with_fd(&br#"{"memfd":true}
"#[..], memfd.as_raw_fd())
        .expect("Cannot send shared memfd");

    let source_memory = mmap_file(&snapshot, libc::PROT_READ, libc::MAP_SHARED).expect("Cannot mmap snapshot memory");
    let shared_memory = mmap_file(
        &memfd,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED
    )
    .expect("Cannot mmap shared memfd");
    let memory_size = snapshot
        .metadata()
        .expect("Cannot stat snapshot memory")
        .len() as usize;
    let mut runtime = Runtime::new(stream, memory_size);
    runtime.install_panic_hook();
    runtime.run(|uffd_handler: &mut UffdHandler| {
        let mut deferred_events = Vec::new();
        loop {
            let mut events_to_handle = Vec::from_iter(deferred_events.drain(..));
            while let Some(event) = uffd_handler.read_event().expect("Failed to read uffd_msg") {
                events_to_handle.push(event);
            }
            for event in events_to_handle.drain(..) {
                match event {
                    userfaultfd::Event::Pagefault { addr, .. } => {
                        let fault = uffd_handler.fault_page(addr.cast(), uffd_handler.page_size);
                        let source = unsafe {
                            source_memory.add(fault.backing_offset as usize)
                        };
                        let destination = unsafe {
                            shared_memory.add(fault.backing_offset as usize)
                        };
                        // SAFETY: The mappings and fault range were validated by UFFD.
                        unsafe { ptr::copy_nonoverlapping(source, destination, fault.len) };
                        uffd_handler.continue_fault(fault);
                    }
                    userfaultfd::Event::Remove { start, end } => {
                        uffd_handler.unregister_range(start, end)
                    }
                    _ => panic!("Unexpected event on userfaultfd"),
                }
            }
            if deferred_events.is_empty() {
                break;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn reads_shared_request() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"{\"uffd_shared\":true}\n").unwrap();

        assert!(read_request(&mut reader).unwrap().uffd_shared);
    }

    #[test]
    fn rejects_non_shared_request() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"{\"uffd_shared\":false}\n").unwrap();

        assert!(read_request(&mut reader).is_err());
    }

    #[test]
    fn rejects_unterminated_request_at_eof() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(b"{\"uffd_shared\":true}").unwrap();
        drop(writer);

        assert!(read_request(&mut reader).is_err());
    }
}
