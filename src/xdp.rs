#[derive(Debug)]
#[repr(u8)]
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
}
impl From<u8> for xdp_action {
    fn from(val: u8) -> Self {
        assert!(val < 5);
        unsafe { core::ptr::read_unaligned(&(val as u8) as *const u8 as *const xdp_action) }
    }
}
#[derive(Debug)]
#[repr(C)]
struct xdp_md {
    data: u32,
    data_end: u32,
    // data_meta: u32,
    // Below access go through struct xdp_rxq_info
    // u32 ingress_ifindex, /* rxq->dev->ifindex */
    // u32 rx_queue_index,  /* rxq->queue_index  */
    // u32 egress_ifindex,  /* txq->dev->ifindex */
}
