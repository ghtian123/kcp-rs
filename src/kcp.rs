use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;
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

#[derive(Default, Clone)]
#[repr(C)]
pub struct Segment {
    //conv唯一标识一个会话
    conv: u32,

    //用来区分分片的作用 IKCP_CMD_PUSH,IKCP_CMD_ACK,IKCP_CMD_WASK,IKCP_CMD_WINS
    cmd: u8,

    //frag标识segment分片ID（在message中的索引，由大到小，0表示最后一个分片）。
    frg: u8,

    // 剩余接收窗口大小（接收窗口大小-接收队列大小），发送方的发送窗口不能超过接收方给出的数值。
    wnd: u16,

    // message发送时刻的时间戳
    ts: u32,

    //message分片segment的序号，按1累次递增。
    sn: u32,

    //待接收消息序号(接收滑动窗口左端)。对于未丢包的网络来说，una是下一个可接收的序号，如收到sn=10的包，una为11。
    una: u32,

    // 数据长度。
    len: u32,

    //下次超时重传的时间戳。
    resendts: u32,

    // 该分片的超时重传等待时间，其计算方法同TCP。
    rto: u32,

    // 收到ack时计算的该分片被跳过的累计次数，此字段用于快速重传，自定义需要几次确认开始快速重传。
    fastack: u32,

    //发送分片的次数，每发送一次加一。发送的次数对RTO的计算有影响，但是比TCP来说，影响会小一些，计算思想类似
    xmit: u32,

    data: Vec<u8>,
}

impl Segment {}

#[derive(Default, Clone)]
#[repr(C)]
pub struct Kcb<W: Write> {
    //标识这个会话ID
    conv: u32,

    //最大传输单元，默认数据为1400，最小为50；
    mtu: u32,

    // 最大分片大小，不大于mtu；
    mss: u32,

    //连接状态（0xFFFFFFFF表示断开连接）
    state: u32,

    //第一个未确认的包
    snd_una: u32,

    // 下一个待分配的包的序号
    snd_nxt: u32,

    //待接收消息序号。为了保证包的顺序，接收方会维护一个接收窗口，接收窗口有一个起始序号rcv_nxt（待接收消息序号）以及尾序号 rcv_nxt + rcv_wnd（接收窗口大小）
    rcv_nxt: u32,

    ts_recent: u32,
    ts_lastack: u32,

    // 拥塞窗口阈值，以包为单位（TCP以字节为单位）
    ssthresh: u32,

    //RTT的变化量，代表连接的抖动情况
    rx_rttval: i32,

    //smoothed round trip time，平滑后的RTT
    rx_srtt: i32,

    //由ACK接收延迟计算出来的重传超时时间
    rx_rto: i32,

    //最小重传超时时间
    rx_minrto: i32,

    //发送窗口大小
    snd_wnd: u32,

    //接收窗口大小
    rcv_wnd: u32,

    //远端接收窗口大小
    rmt_wnd: u32,

    //拥塞窗口大小
    cwnd: u32,

    //探查变量，IKCP_ASK_TELL表示告知远端窗口大小。IKCP_ASK_SEND表示请求远端告知窗口大小
    probe: u32,

    current: u32,

    //内部flush刷新间隔，对系统循环效率有非常重要影响
    interval: u32,

    //下次flush刷新时间戳
    ts_flush: u32,

    //发送segment的次数，当segment的xmit增加时，xmit增加（第一次或重传除外）
    xmit: u32,

    //接收消息的缓存数量
    nrcv_buf: u32,
    //发送缓存中消息数量
    nsnd_buf: u32,

    //接收队列中消息数量
    nrcv_que: u32,

    // 发送消息的队列数量
    nsnd_que: u32,

    // 是否启动无延迟模式。无延迟模式rtomin将设置为0，拥塞控制不启动；
    nodelay: bool,

    //是否调用过update函数的标识
    updated: bool,

    // 下次探查窗口的时间戳
    ts_probe: u32,

    //探查窗口需要等待的时间
    probe_wait: u32,

    //最大重传次数，被认为连接中断
    dead_link: u32,

    //可发送的最大数据量
    incr: u32,

    snd_queue: VecDeque<Segment>,
    rcv_queue: VecDeque<Segment>,
    snd_buf: VecDeque<Segment>,
    rcv_buf: VecDeque<Segment>,

    //待发送的ack列表
    acklist: Vec<(u32, u32)>,

    // acklist中ack的数量，每个ack在acklist中存储ts，sn两个量
    ackcount: u32,

    //2的倍数，标识acklist最大可容纳的ack数量；
    ackblock: u32,

    // 存储消息字节流；
    buffer: Vec<u8>,

    //触发快速重传的重复ACK个数；
    fastresend: u32,

    // 取消拥塞控制；
    nocwnd: bool,

    //是否采用流传输模式；
    stream: bool,

    fastlimit: u32,

    output: W,
}

impl<W: Write+Default> Kcb<W> {
    pub fn ickp_create(w: W,conv:u32) -> Self {
        let mut kcp = Kcb::default();
        kcp.output = w;
        kcp.conv = conv;
        kcp.snd_wnd = IKCP_WND_SND;
        kcp.rcv_wnd = IKCP_WND_RCV;
        kcp.rmt_wnd = IKCP_WND_RCV;
        kcp.mtu = IKCP_MTU_DEF;
        kcp.mss = kcp.mtu - IKCP_OVERHEAD;

        kcp.snd_queue = VecDeque::new();
        kcp.rcv_queue = VecDeque::new();
        kcp.snd_buf = VecDeque::new();
        kcp.rcv_buf = VecDeque::new();

        kcp.acklist = Vec::new();

        kcp.rx_rto = IKCP_RTO_DEF as i32;
        kcp.rx_minrto = IKCP_RTO_MIN as i32;

        kcp.interval = IKCP_INTERVAL;
        kcp.ts_flush = IKCP_INTERVAL;

        kcp.ssthresh = IKCP_THRESH_INIT;
        kcp.fastlimit = IKCP_FASTACK_LIMIT;
        kcp.dead_link = IKCP_DEADLINK;

        kcp

    }



    // user/upper level recv: returns size, returns below zero for EAGAIN
    pub fn ikcp_recv(&mut self) {
        unimplemented!()
    }

    // peek data size
    fn ikcp_peeksize(&self) {
        unimplemented!()
    }

    // user/upper level send, returns below zero for error
    pub fn ikcp_send(&mut self) {
        unimplemented!()
    }

    // update ack
    fn ikcp_update_ack(&mut self) {
        unimplemented!()
    }

    //ack append
    fn ack_push(&mut self) {
        unimplemented!()
    }

    //parse data
    fn parse_data(&mut self) {
        unimplemented!()
    }

    // input data
    fn input(&mut self) {
        unimplemented!()
    }

    // ikcp_flush
    fn flush(&mut self) {
        unimplemented!()
    }

    //---------------------------------------------------------------------
    // update state (call it repeatedly, every 10ms-100ms), or you can ask
    // ikcp_check when to call it again (without ikcp_input/_send calling).
    // 'current' - current timestamp in millisec.
    //---------------------------------------------------------------------
    fn update(&mut self) {
        unimplemented!()
    }

    //---------------------------------------------------------------------
    // Determine when should you invoke ikcp_update:
    // returns when you should invoke ikcp_update in millisec, if there
    // is no ikcp_input/_send calling. you can call ikcp_update in that
    // time, instead of call update repeatly.
    // Important to reduce unnacessary ikcp_update invoking. use it to
    // schedule ikcp_update (eg. implementing an epoll-like mechanism,
    // or optimize ikcp_update when handling massive kcp connections)
    //---------------------------------------------------------------------
    fn check(&mut self) {
        unimplemented!()
    }

    fn set_mtu(&mut self) {
        unimplemented!()
    }

    fn set_interval(&mut self) {
        unimplemented!()
    }

    fn nodelay(&mut self) {
        unimplemented!()
    }

    fn wndsize(&mut self) {
        unimplemented!()
    }

    fn waitsnd(&mut self) {
        unimplemented!()
    }
}

impl<W> Drop for Kcb<W>
where
    W: Write,
{
    fn drop(&mut self) {
        unimplemented!()
    }
}


