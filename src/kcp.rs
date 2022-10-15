use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::io::{self, Write};

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
    pub conv: u32,

    //用来区分分片的作用 IKCP_CMD_PUSH,IKCP_CMD_ACK,IKCP_CMD_WASK,IKCP_CMD_WINS
    pub cmd: u8,

    //frag标识segment分片ID（在message中的索引，由大到小，0表示最后一个分片）。
    pub frg: u8,

    // 剩余接收窗口大小（接收窗口大小-接收队列大小），发送方的发送窗口不能超过接收方给出的数值。
    pub wnd: u16,

    // message发送时刻的时间戳
    pub ts: u32,

    //message分片segment的序号，按1累次递增。
    pub sn: u32,

    //待接收消息序号(接收滑动窗口左端)。对于未丢包的网络来说，una是下一个可接收的序号，如收到sn=10的包，una为11。
    pub una: u32,

    // 数据长度。
    pub len: u32,

    //下次超时重传的时间戳。
    pub resendts: u32,

    // 该分片的超时重传等待时间，其计算方法同TCP。
    pub rto: u32,

    // 收到ack时计算的该分片被跳过的累计次数，此字段用于快速重传，自定义需要几次确认开始快速重传。
    pub fastack: u32,

    //发送分片的次数，每发送一次加一。发送的次数对RTO的计算有影响，但是比TCP来说，影响会小一些，计算思想类似
    pub xmit: u32,

    pub data: Vec<u8>,
}



impl Segment {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32_le(self.conv);
        buf.put_u8(self.cmd);
        buf.put_u8(self.frg);
        buf.put_u16_le(self.wnd);
        buf.put_u32_le(self.ts);
        buf.put_u32_le(self.sn);
        buf.put_u32_le(self.una);
        buf.put_u32_le(self.len);
    }

    pub fn decode(&mut self) {
        todo!()
    }
}

#[derive(Default, Clone)]
#[repr(C)]
struct Kcb<W: Write> {
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
    rx_rttval: u32,

    //smoothed round trip time，平滑后的RTT
    rx_srtt: u32,

    //由ACK接收延迟计算出来的重传超时时间
    rx_rto: u32,

    //最小重传超时时间
    rx_minrto: u32,

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
    buffer: BytesMut,

    //触发快速重传的重复ACK个数；
    fastresend: u32,

    // 取消拥塞控制；
    nocwnd: bool,

    //是否采用流传输模式；
    stream: bool,

    fastlimit: u32,

    output: W,
}

impl<W: Write> Kcb<W> {
    pub fn ickp_create(w: W, conv: u32) -> Self {
        Self {
            conv: conv,
            mtu: IKCP_MTU_DEF,
            mss: IKCP_MTU_DEF - IKCP_OVERHEAD,
            state: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ts_recent: 0,
            ts_lastack: 0,
            ssthresh: IKCP_THRESH_INIT,
            rx_rttval: 0,
            rx_srtt: 0,
            rx_rto: IKCP_RTO_DEF,
            rx_minrto: IKCP_RTO_MIN,
            snd_wnd: IKCP_WND_SND,
            rcv_wnd: IKCP_WND_RCV,
            rmt_wnd: IKCP_WND_RCV,
            cwnd: 0,
            probe: 0,
            current: 0,
            interval: IKCP_INTERVAL,
            ts_flush: IKCP_INTERVAL,
            xmit: 0,
            nodelay: false,
            updated: false,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: IKCP_DEADLINK,
            incr: 0,
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: Vec::new(),
            ackcount: 0,
            ackblock: 0,
            buffer: BytesMut::new(),
            fastresend: 0,
            nocwnd: false,
            stream: false,
            fastlimit: IKCP_FASTACK_LIMIT,
            output: w,
        }
    }

    // user/upper level recv: returns size, returns below zero for EAGAIN
    pub fn ikcp_recv(&mut self) {
        unimplemented!()
    }

    // user/upper level send, returns below zero for error
    pub fn ikcp_send(&mut self, buffer: &[u8]) -> isize {
        assert!(self.mss > 0);

        unimplemented!()
    }

    // input data
    pub fn ickp_input(&mut self, buf :&[u8]) {

        unimplemented!()
    }

    //---------------------------------------------------------------------
    // update state (call it repeatedly, every 10ms-100ms), or you can ask
    // ikcp_check when to call it again (without ikcp_input/_send calling).
    // 'current' - current timestamp in millisec.
    //---------------------------------------------------------------------
    pub fn ikcp_update(&mut self) {
        unimplemented!()
    }

    fn ickp_output(&mut self, data: &[u8]) -> io::Result<()> {
        self.output.write_all(data)
    }

    pub fn ikcp_peeksize(&self) -> Result<u32, i32> {
        let seg = match self.rcv_queue.front() {
            Some(x) => x,
            None => return Err(-1),
        };

        if seg.frg == 0 {
            return Ok(seg.len);
        }

        if self.rcv_queue.len() < (seg.frg + 1) as usize {
            return Err(-1);
        }

        let mut length = 0;
        for seg in (&self.rcv_queue).into_iter() {
            length += seg.len;
            if seg.frg == 0 {
                break;
            }
        }

        Ok(length)
    }

    // update ack
    fn ikcp_update_ack(&mut self, rtt: u32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let mut delta = if rtt > self.rx_srtt {
                rtt - self.rx_srtt
            } else {
                self.rx_srtt - rtt
            };

            self.rx_rttval = (3 * self.rx_rttval + delta) / 4;
            self.rx_srtt = (7 * self.rx_srtt + rtt) / 8;
            if self.rx_srtt < 1 {
                self.rx_srtt = 1;
            }
        }

        let rto = self.rx_srtt + max(self.interval, 4 * self.rx_rttval);
        self.rx_rto = ibound(self.rx_minrto, rto, IKCP_RTO_MAX);
    }

    //ack append
    fn ikcp_ack_push(&mut self,sn:u32,ts:u32) {
        self.acklist.push((sn,ts))        
    }

    //parse data
    fn ikcp_parse_data(&mut self) {
        unimplemented!()
    }

    // ikcp_flush
    pub fn ikcp_flush(&mut self) {
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
    pub fn ikcp_check(&mut self, current: u32) -> i32 {
        let ts_flush = self.ts_flush;
        let tm_flush = 0x7fffffff;
        let tm_packet = 0x7fffffff;
        let minimal = 0;

        // if !self.updated {
        //     return current;
        // }

        unimplemented!()
    }

    // change MTU size, default is 1400
    pub fn ikcp_setmtu(&mut self, mtu: u32) -> Result<(), i32> {
        if mtu < 50 || mtu < IKCP_OVERHEAD {
            return Err(-1);
        }

        self.mtu = mtu;
        self.mss = mtu - IKCP_OVERHEAD;

        return Ok(());
    }

    pub fn ikcp_interval(&mut self, internal: u32) {
        self.interval = if internal > 5000 {
            5000
        } else if internal < 10 {
            10
        } else {
            internal
        }
    }

    // fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
    // nodelay: 0:disable(default), 1:enable
    // interval: internal update timer interval in millisec, default is 100ms
    // resend: 0:disable fast resend(default), 1:enable fast resend
    // nc: 0:normal congestion control(default), 1:disable congestion control
    pub fn ikcp_nodelay(&mut self, nodelay: bool, internal: u32, resend: u32, nc: bool) {
        self.nodelay = nodelay;
        self.fastresend = resend;
        self.nocwnd = nc;

        self.rx_minrto = if self.nodelay {
            IKCP_RTO_NDL
        } else {
            IKCP_RTO_MIN
        };

        self.interval = if internal > 5000 {
            5000
        } else if internal < 10 {
            10
        } else {
            internal
        }
    }

    //set maximum window size: sndwnd=32, rcvwnd=32 by default
    pub fn ikcp_wndsize(&mut self, sndwnd: u32, rcvwnd: u32) {
        if sndwnd > 0 {
            self.snd_wnd = sndwnd;
        }
        if rcvwnd > 0 {
            // must >= max fragment size
            self.rcv_wnd = if rcvwnd > IKCP_WND_RCV {
                rcvwnd
            } else {
                IKCP_WND_RCV
            };
        }
    }

    // get how many packet is waiting to be sent
    pub fn ikcp_waitsnd(&self) -> usize {
        self.snd_buf.len() + self.snd_queue.len()
    }
}

// release kcp control object
impl<W> Drop for Kcb<W>
where
    W: Write,
{
    fn drop(&mut self) {
        unimplemented!()
    }
}

#[inline]
fn ibound(lower: u32, middle: u32, upper: u32) -> u32 {
    return min(max(lower, middle), upper);
}

#[inline]
fn timediff(later: u32, earlier: u32) -> u32 {
    later - earlier
}
