use bpf_sys::{
    XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_MASK, XDP_FLAGS_MODES, XDP_FLAGS_SKB_MODE,
    XDP_FLAGS_UPDATE_IF_NOEXIST,
};
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum Flags {
    Unset = 0,
    UpdateIfNoExist = XDP_FLAGS_UPDATE_IF_NOEXIST,
    SkbMode = XDP_FLAGS_SKB_MODE,
    DrvMode = XDP_FLAGS_DRV_MODE,
    HwMode = XDP_FLAGS_HW_MODE,
    Modes = XDP_FLAGS_MODES,
    Mask = XDP_FLAGS_MASK,
}
