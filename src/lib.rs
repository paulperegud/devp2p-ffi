// Copyright 2016 GolemFactory GMBH (Switzerland).

// DevP2P-FFI is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// DevP2P-FFI is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with DevP2P-FFI. If not, see <http://www.gnu.org/licenses/>.

extern crate libc;
extern crate ethcore_network as net;
use net::*;

use std::sync::Arc;
use std::ffi::CString;
use std::ffi::CStr;
use libc::c_void;
use std::os::raw::c_char;
use std::str;

const PROTOCOL_VERSION: u32 = 4;

const ERR_OK: u8 = 0;
const ERR_UNKNOWN_PEER: u8 = 1;
const ERR_ERROR: u8 = 255;

// TODO: make this a parameter
const TMP_PROTOCOL: [u8; 3] = *b"myp";
const TMP_CAPABILITIES: [u8; 1] = [1u8];


// TODO: check if errno is needed
#[no_mangle]
pub unsafe extern fn network_service(errno: *mut u8) -> *mut c_void {
    let conf = NetworkConfiguration::new_local();
    match NetworkService::new(conf) {
        Ok(service) => {
            *errno = ERR_OK;
            Box::into_raw(Box::new(service)) as *mut c_void
        },
        Err(_) => {
            *errno = ERR_ERROR;
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern fn network_service_free(x: *mut c_void) {
    Box::from_raw(x as *mut NetworkService);
    return
}

#[no_mangle]
pub unsafe extern fn network_service_start(service: *mut c_void) -> u8 {
    let ns = &mut *(service as *mut NetworkService);
    match ns.start() {
        Ok(()) => ERR_OK,
        Err(_) => ERR_ERROR
    }
}

#[no_mangle]
pub extern fn network_service_add_protocol(sp: *mut c_void,
                                           userdata: FFIObjectPtr,
                                           protocol_id: *mut i8,
                                           max_packet_id: u8,
                                           cbs: *mut FFICallbacks
) -> u8 {
    let service = unsafe { &mut *(sp as *mut NetworkService) };
    let pid = cast_protocol_id(protocol_id);
    let ffiobject = FFIObject(userdata);
    let pinger = unsafe { Arc::new(FFIHandler::new(ffiobject,
                                                   (*cbs).initialize,
                                                   (*cbs).connected,
                                                   (*cbs).read,
                                                   (*cbs).disconnected)) };
    match service.register_protocol(pinger,
                                    pid,
                                    max_packet_id,
                                    &TMP_CAPABILITIES) {
        Ok(()) => {
            ERR_OK
        },
        Err(_) => {
            ERR_ERROR
        }
    }
}

fn cast_protocol_id(protocol_id: *mut i8) -> [u8; 3] {
    let c_str: &CStr = unsafe { CStr::from_ptr(protocol_id) };
    let buf: &[u8] = c_str.to_bytes();
    [buf[0], buf[1], buf[2]]
}

#[no_mangle]
pub unsafe extern fn network_service_add_reserved_peer(sp: *mut c_void,
                                                       peer_p: *mut c_char) -> u8 {
    let service = &mut *(sp as *mut NetworkService);
    let peer_name = raw_into_str(peer_p);
    match service.add_reserved_peer(&&peer_name) {
        Ok(()) => ERR_OK,
        Err(_) => ERR_ERROR
    }
}

#[no_mangle]
pub unsafe extern fn network_service_node_name(sp: *mut c_void) -> *mut c_char {
    let service = &mut *(sp as *mut NetworkService);
    match service.local_url() {
        Some(raw) => {
            str_into_raw(raw)
        },
        None => {
            std::ptr::null_mut()
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern fn protocol_send(ns_ptr: *mut c_void, protocol_id: *mut i8,
                                   peer: PeerId, packet_id: u8, data_ptr: *mut u8,
                                   length: usize) {
    let service = &mut *(ns_ptr as *mut NetworkService);
    let bytes = std::slice::from_raw_parts(data_ptr, length).clone().to_vec();
    let pid = cast_protocol_id(protocol_id);
    service.with_context(pid, |io| {
        match io.send(peer, packet_id, bytes.clone()) {
            Ok(()) => (),
            Err(_) => ()
        }
    });
}

#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern fn protocol_reply(io_ptr: *mut c_void, peer: PeerId,
                                    packet_id: u8, data_ptr: *mut u8,
                                    length: usize) {
    let io = &mut *(io_ptr as *mut NetworkContext);
    let bytes = std::slice::from_raw_parts(data_ptr, length).clone().to_vec();
    match io.send(peer, packet_id, bytes) {
        Ok(()) => (),
        Err(_) => ()
    }
}

#[no_mangle]
pub unsafe extern fn peer_protocol_version(io_ptr: *const c_void, peer: PeerId, errno: *mut u8) {
    let io = &mut *(io_ptr as *mut NetworkContext);
    match io.protocol_version(TMP_PROTOCOL, peer) {
        Some(pv) => {
            *errno = ERR_OK;
            pv
        },
        None => {
            *errno = ERR_UNKNOWN_PEER;
            u8::max_value()
        }
    };
}

type InitializeFN = extern fn(*const c_void, &NetworkContext);
type ConnectedFN = extern fn(*const c_void, &NetworkContext, PeerId);
type ReadFN = extern fn(*const c_void, &NetworkContext, PeerId, u8, *const u8, usize);
type DisconnectedFN = extern fn(*const c_void, &NetworkContext, PeerId);

/// implementation of devp2p sub-protocol handler for interfacing with FFI
pub struct FFIHandler {
    userdata: FFIObject,
    initialize_fun: InitializeFN,
    connected_fun: ConnectedFN,
    read_fun: ReadFN,
    disconnected_fun: DisconnectedFN,
}

pub struct FFICallbacks {
    initialize: InitializeFN,
    connected: ConnectedFN,
    read: ReadFN,
    disconnected: DisconnectedFN,
}

pub struct FFIObject(*const c_void);
type FFIObjectPtr = *const c_void;

unsafe impl Send for FFIObject {}
unsafe impl Sync for FFIObject {}

impl FFIHandler {
    pub fn new(userdata: FFIObject, initf: InitializeFN, cf: ConnectedFN,
               rf: ReadFN, df: DisconnectedFN) -> Self {
        FFIHandler {
            userdata: userdata,
            initialize_fun: initf,
            connected_fun: cf,
            read_fun: rf,
            disconnected_fun: df,
        }
    }
}

impl NetworkProtocolHandler for FFIHandler {
    fn initialize(&self, io: &NetworkContext) {
        (self.initialize_fun)(self.userdata.0, io)
    }

    fn read(&self, io: &NetworkContext, peer: &PeerId, packet_id: u8, data: &[u8]) {
        (self.read_fun)(self.userdata.0, io, *peer, packet_id,
                        data.as_ptr(), data.len() as usize)
    }

    fn connected(&self, io: &NetworkContext, peer: &PeerId) {
        (self.connected_fun)(self.userdata.0, io, *peer);
    }

    fn disconnected(&self, io: &NetworkContext, peer: &PeerId) {
        (self.disconnected_fun)(self.userdata.0, io, *peer);
    }
    // implementation of timeout callback is skipped since it's hardly useful across FFI
}

// some helper functions
pub fn str_ptr(slice: String) -> *const u8 {
    let res = slice + "\0";
    res.as_ptr()
}

pub fn str_into_raw(slice: String) -> *mut c_char{
    CString::new(slice).unwrap().into_raw()
}

pub fn raw_into_str(ptr: *const c_char) -> String {
    let c_str: &CStr = unsafe { CStr::from_ptr(ptr) };
    let buf: &[u8] = c_str.to_bytes();
    let str_slice: &str = str::from_utf8(buf).unwrap();
    let str_buf: String = str_slice.to_owned();
    str_buf
}
