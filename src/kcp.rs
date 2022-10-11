use std::io::Write;

const IKCP_RTO_NDL: u32 = 30; // no delay min rto
const IKCP_RTO_MIN: u32 = 100; // normal min rto
const IKCP_RTO_DEF: u32 = 200;
const IKCP_RTO_MAX: u32 = 60000;
const IKCP_CMD_PUSH: u32 = 81; // cmd: push data
const IKCP_CMD_ACK: u32 = 82; // cmd: ack
const IKCP_CMD_WASK: u32 = 83; // cmd: window probe (ask)
const IKCP_CMD_WINS: u32 = 84; // cmd: window size (tell)
const IKCP_ASK_SEND: u32 = 1; // need to send IKCP_CMD_WASK
const IKCP_ASK_TELL: u32 = 2; // need to send IKCP_CMD_WINS
const IKCP_WND_SND: u32 = 32;
const IKCP_WND_RCV: u32 = 128; // must >= max fragment size
const IKCP_MTU_DEF: u32 = 1400;
const IKCP_ACK_FAST: u32 = 3;
const IKCP_INTERVAL: u32 = 100;
const IKCP_OVERHEAD: u32 = 24;
const IKCP_DEADLINK: u32 = 20;
const IKCP_THRESH_INIT: u32 = 2;
const IKCP_THRESH_MIN: u32 = 2;
const IKCP_PROBE_INIT: u32 = 7000; // 7 secs to probe window size
const IKCP_PROBE_LIMIT: u32 = 120000; // up to 120 secs to probe window
const IKCP_FASTACK_LIMIT: u32 = 5; // max times to trigger fastack

#[derive(Default,Clone,Copy)]
#[repr(C)]
pub struct Segment {
    conv: u32,
    cmd: u8,
    frg: u8,
    wnd: u32,
    ts: u32,
    sn: u32,
    una: u32,
    resendts: u32,
    rto: u32,
    fastack: u32,
    xmit: u32,
}

impl Segment {}


#[derive(Default,Clone,Copy)]
#[repr(C)]
pub struct Kcb<W: Write> {
    conv: u32,
    mtu: u32,
    mss: u32,
    state: u32,

    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,

    ts_recent: u32,
    ts_lastack: u32,
    ssthresh: u32,

    rx_rttval: i32,
    rx_srtt: i32,
    rx_rto: i32,
    rx_minrto: i32,

    snd_wnd: u32,
    rcv_wnd: u32,
    rmt_wnd: u32,
    cwnd: u32,
    probe: u32,

    current: u32,
    interval: u32,
    ts_flush: u32,
    xmit: u32,

    nrcv_buf: u32,
    nsnd_buf: u32,

    nrcv_que: u32,
    nsnd_que: u32,

    nodelay: u32,
    updated: u32,

    ts_probe: u32,
    probe_wait: u32,

    dead_link: u32,
    incr: u32,

    output: W,
}

impl<W: Write> Kcb<W> {}
