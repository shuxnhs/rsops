pub use crate::module::bpf::*;
use bpf_sys::*;
use core::ffi::c_void;
use std::slice;
use std::time::Duration;

pub trait SampleCb: FnMut(i32, &[u8]) + 'static {}
impl<T> SampleCb for T where T: FnMut(i32, &[u8]) + 'static {}

pub trait LostCb: FnMut(i32, u64) + 'static {}
impl<T> LostCb for T where T: FnMut(i32, u64) + 'static {}

struct CbStruct {
    sample_cb: Option<Box<dyn SampleCb>>,
    lost_cb: Option<Box<dyn LostCb>>,
}

pub struct PerfEventBuilder<'a> {
    map: &'a Map,
    pages: usize,
    sample_cb: Option<Box<dyn SampleCb>>,
    lost_cb: Option<Box<dyn LostCb>>,
}

impl<'a> PerfEventBuilder<'a> {
    pub fn new(map: &'a Map) -> Self {
        Self {
            map,
            pages: 64,
            sample_cb: None,
            lost_cb: None,
        }
    }

    pub fn sample_cb<NewCb: SampleCb>(self, cb: NewCb) -> Self {
        Self {
            map: self.map,
            pages: self.pages,
            sample_cb: Some(Box::new(cb)),
            lost_cb: self.lost_cb,
        }
    }

    pub fn lost_cb<NewCb: LostCb>(self, cb: NewCb) -> Self {
        Self {
            map: self.map,
            pages: self.pages,
            sample_cb: self.sample_cb,
            lost_cb: Some(Box::new(cb)),
        }
    }

    pub fn pages(&mut self, pages: usize) -> &mut Self {
        self.pages = pages;
        self
    }
    pub fn build(self) -> Result<PerfBuffer> {
        // if self.map.map_type() != MapType::PerfEventArray {
        //     return Err(Error::InvalidInput(
        //         "Must use a PerfEventArray map".to_string(),
        //     ));
        // }

        // if !is_power_of_two(self.pages) {
        //     return Err(Error::InvalidInput(
        //         "Page count must be power of two".to_string(),
        //     ));
        // }
        let c_sample_cb: bpf_sys::perf_buffer_sample_fn = if self.sample_cb.is_some() {
            Some(Self::call_sample_cb)
        } else {
            None
        };

        let c_lost_cb: bpf_sys::perf_buffer_lost_fn = if self.lost_cb.is_some() {
            Some(Self::call_lost_cb)
        } else {
            None
        };

        let callback_struct_ptr = Box::into_raw(Box::new(CbStruct {
            sample_cb: self.sample_cb,
            lost_cb: self.lost_cb,
        }));

        let opts = bpf_sys::perf_buffer_opts {
            sample_cb: c_sample_cb,
            lost_cb: c_lost_cb,
            ctx: callback_struct_ptr as *mut _,
        };

        let ptr =
            unsafe { bpf_sys::perf_buffer__new(self.map.fd, self.pages as bpf_sys::size_t, &opts) };
        let err = unsafe { bpf_sys::libbpf_get_error(ptr as *const _) };
        if err != 0 {
            Err(Error::System(err as i32))
        } else {
            Ok(PerfBuffer {
                ptr,
                _cb_struct: unsafe { Box::from_raw(callback_struct_ptr) },
            })
        }
    }

    unsafe extern "C" fn call_sample_cb(ctx: *mut c_void, cpu: i32, data: *mut c_void, size: u32) {
        let callback_struct = ctx as *mut CbStruct;

        if let Some(cb) = &mut (*callback_struct).sample_cb {
            cb(cpu, slice::from_raw_parts(data as *const u8, size as usize));
        }
    }

    unsafe extern "C" fn call_lost_cb(ctx: *mut c_void, cpu: i32, count: u64) {
        let callback_struct = ctx as *mut CbStruct;

        if let Some(cb) = &mut (*callback_struct).lost_cb {
            cb(cpu, count);
        }
    }
}

pub struct PerfBuffer {
    ptr: *mut bpf_sys::perf_buffer,
    // Hold onto the box so it'll get dropped when PerfBuffer is dropped
    _cb_struct: Box<CbStruct>,
}

impl PerfBuffer {
    pub fn poll(&self, timeout: Duration) -> Result<()> {
        let ret = unsafe { bpf_sys::perf_buffer__poll(self.ptr, timeout.as_millis() as i32) };
        if ret < 0 {
            Err(Error::System(-ret))
        } else {
            Ok(())
        }
    }
}

impl Drop for PerfBuffer {
    fn drop(&mut self) {
        unsafe {
            bpf_sys::perf_buffer__free(self.ptr);
        }
    }
}

// impl perfEvent {}
