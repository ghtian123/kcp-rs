use bytes::{Buf, BufMut, BytesMut};
use std::cmp::{max, min};
use std::collections::VecDeque;
use std::io::{Cursor, Read, Write};

const IKCP_RTO_NDL: u32 = 30; // no delay min rto
const IKCP_RTO_MIN: u32 = 100; // normal min rto
const IKCP_RTO_DEF: u32 = 200;
const IKCP_RTO_MAX: u32 = 60000;
const IKCP_CMD_PUSH: u8 = 81; // cmd: push data
const IKCP_CMD_ACK: u8 = 82; // cmd: ack
const IKCP_CMD_WASK: u8 = 83; // cmd: window probe (ask)
const IKCP_CMD_WINS: u8 = 84; // cmd: window size (tell)
const IKCP_ASK_SEND: u32 = 1; // need to send IKCP_CMD_WASK
const IKCP_ASK_TELL: u32 = 2; // need to send IKCP_CMD_WINS
const IKCP_WND_SND: u32 = 32;
const IKCP_WND_RCV: u32 = 128; // must >= max fragment size
const IKCP_MTU_DEF: u32 = 1400;
// const IKCP_ACK_FAST: u32 = 3;
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
struct Segment {
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
}

#[derive(Default, Clone)]
#[repr(C)]
pub struct Kcp<W: Write> {
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

    //待发送的ack列表(sn,ts)
    acklist: Vec<(u32, u32)>,

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

impl<W: Write> Kcp<W> {
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
            ackblock: 0,
            buffer: BytesMut::with_capacity((IKCP_MTU_DEF as usize + IKCP_OVERHEAD as usize) * 3),
            fastresend: 0,
            nocwnd: false,
            stream: false,
            fastlimit: IKCP_FASTACK_LIMIT,
            output: w,
        }
    }

    // user/upper level recv: returns size, returns below zero for EAGAIN
    pub fn ikcp_recv(&mut self, buf: &mut [u8]) -> Result<usize, i32> {
        if self.rcv_queue.is_empty() {
            return Err(-1);
        }
        let peeksize = match self.ikcp_peeksize() {
            Ok(x) => x,
            Err(_) => return Err(-1),
        };

        if peeksize as usize > buf.len() {
            return Err(-1);
        }

        let recover = self.rcv_queue.len() >= self.rcv_wnd as usize;

        // merge fragment
        let mut buf = Cursor::new(buf);
        let mut index: usize = 0;
        for seg in &self.rcv_queue {
            if buf.write_all(&seg.data).is_err() {
                return Err(-1);
            }
            index += 1;
            if seg.frg == 0 {
                break;
            }
        }
        if index > 0 {
            let new_rcv_queue = self.rcv_queue.split_off(index);
            self.rcv_queue = new_rcv_queue;
        }
        assert!(buf.position() as usize == peeksize as usize);

        // move available data from rcv_buf -> rcv_queue
        index = 0;
        let mut nrcv_que = self.rcv_queue.len();
        for seg in &self.rcv_buf {
            if seg.sn == self.rcv_nxt && nrcv_que < self.rcv_wnd as usize {
                nrcv_que += 1;
                self.rcv_nxt += 1;
                index += 1;
            } else {
                break;
            }
        }

        if index > 0 {
            let new_rcv_buf = self.rcv_buf.split_off(index);
            self.rcv_queue.append(&mut self.rcv_buf);
            self.rcv_buf = new_rcv_buf;
        }

        // fast recover
        if self.rcv_queue.len() < self.rcv_wnd as usize && recover {
            // ready to send back KCP_CMD_WINS in `flush`
            // tell remote my window size
            self.probe |= IKCP_ASK_TELL;
        }
        Ok(buf.position() as usize)
    }

    // user/upper level send, returns below zero for error
    pub fn ikcp_send(&mut self, buf: &[u8]) -> Result<usize, i32> {
        let n = buf.len();
        if n == 0 {
            return Err(-1);
        }
        let mut buf = Cursor::new(buf);

        // append to previous segment in streaming mode (if possible)
        if self.stream {
            if let Some(seg) = self.snd_queue.back_mut() {
                let l = seg.data.len();
                if l < self.mss as usize {
                    let new_len = min(l + n, self.mss as usize);
                    seg.data.resize(new_len, 0);
                    if buf.read_exact(&mut seg.data[l..new_len]).is_err() {
                        return Err(-1);
                    };
                    seg.frg = 0;
                    if buf.remaining() == 0 {
                        return Ok(1);
                    }
                }
            };
        }

        let count = if buf.remaining() <= self.mss as usize {
            1
        } else {
            (buf.remaining() + self.mss as usize - 1) / self.mss as usize
        };

        if count > 255 {
            return Err(-1);
        }
        assert!(count > 0);
        let count = count as u8;

        // fragment
        for i in 0..count {
            let size = min(self.mss as usize, buf.remaining());
            let mut seg = Segment::default();
            seg.data.resize(size, 0);
            if buf.read_exact(&mut seg.data).is_err() {
                return Err(-1);
            };
            seg.frg = if !self.stream { count - i - 1 } else { 0 };
            self.snd_queue.push_back(seg);
        }
        Ok(n - buf.remaining())
    }

    // update state (call it repeatedly, every 10ms-100ms), or you can ask
    // ikcp_check when to call it again (without ikcp_input/_send calling).
    // 'current' - current timestamp in millisec.
    pub fn ikcp_input(&mut self, buf: &[u8]) -> Result<usize, i32> {
        let n = buf.len();
        let mut buf = Cursor::new(buf);

        if buf.remaining() < IKCP_OVERHEAD as usize {
            return Err(-1);
        }
        let old_una = self.snd_una;
        let mut flag = false;
        let mut maxack: u32 = 0;
        while buf.remaining() >= IKCP_OVERHEAD as usize {
            let conv = buf.get_u32_le();
            if conv != self.conv {
                return Err(-1);
            }

            let cmd = buf.get_u8();
            let frg = buf.get_u8();
            let wnd = buf.get_u16_le();
            let ts = buf.get_u32_le();
            let sn = buf.get_u32_le();
            let una = buf.get_u32_le();
            let len = buf.get_u32_le();

            let len = len as usize;
            if buf.remaining() < len {
                return Err(-1);
            }

            if cmd != IKCP_CMD_PUSH
                && cmd != IKCP_CMD_ACK
                && cmd != IKCP_CMD_WASK
                && cmd != IKCP_CMD_WINS
            {
                return Err(-1);
            }

            self.rmt_wnd = wnd as u32;
            self.ikcp_parse_una(una);
            self.ikcp_shrink_buf();
            if cmd == IKCP_CMD_ACK {
                let rtt = diff(self.current, ts);
                if rtt >= 0 {
                    self.ikcp_update_ack(rtt as u32);
                }
                self.ikcp_parse_ack(sn);
                self.ikcp_shrink_buf();
                if !flag {
                    flag = true;
                    maxack = sn;
                } else {
                    if sn > maxack {
                        maxack = sn;
                    }
                }
            } else if cmd == IKCP_CMD_PUSH {
                if sn < self.rcv_nxt + self.rcv_wnd {
                    self.acklist.push((sn, ts));
                    if sn >= self.rcv_nxt {
                        let mut seg = Segment::default();
                        seg.conv = conv;
                        seg.cmd = cmd;
                        seg.frg = frg;
                        seg.wnd = wnd;
                        seg.ts = ts;
                        seg.sn = sn;
                        seg.una = una;
                        seg.data.resize(len, 0);
                        println!("debug-->{:?}",buf);
                        if buf.read_exact(&mut seg.data).is_err() {
                            return Err(-2);
                        }
                        self.ikcp_parse_data(seg);
                    }
                }
            } else if cmd == IKCP_CMD_WASK {
                // ready to send back KCP_CMD_WINS in `flush`
                // tell remote my window size
                self.probe |= IKCP_ASK_TELL;
            } else if cmd == IKCP_CMD_WINS {
                // do nothing
            } else {
                return Err(-1);
            }
        }
        if flag {
            self.ikcp_parse_fastack(maxack);
        }

        if self.snd_una > old_una {
            if self.cwnd < self.rmt_wnd {
                let mss = self.mss as u32;
                if self.cwnd < self.ssthresh {
                    self.cwnd += 1;
                    self.incr += mss;
                } else {
                    if self.incr < mss {
                        self.incr = mss;
                    }
                    self.incr += (mss * mss) / self.incr + (mss / 16);
                    if (self.cwnd + 1) * mss <= self.incr {
                        self.cwnd += 1;
                    }
                }
                if self.cwnd > self.rmt_wnd {
                    self.cwnd = self.rmt_wnd;
                    self.incr = self.rmt_wnd * mss;
                }
            }
        }
        Ok(n - buf.remaining())
    }

    fn ikcp_parse_una(&mut self, una: u32) {
        let mut index: usize = 0;
        for seg in &self.snd_buf {
            if una > seg.sn {
                index += 1;
            } else {
                break;
            }
        }
        if index > 0 {
            let new_snd_buf = self.snd_buf.split_off(index);
            self.snd_buf = new_snd_buf;
        }
    }

    fn ikcp_parse_fastack(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        for seg in &mut self.snd_buf {
            if sn < seg.sn {
                break;
            } else if sn != seg.sn {
                seg.fastack += 1;
            }
        }
    }

    fn ikcp_parse_ack(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        for i in 0..self.snd_buf.len() {
            if sn == self.snd_buf[i].sn {
                self.snd_buf.remove(i);
                break;
            } else if sn < self.snd_buf[i].sn {
                break;
            }
        }
    }

    fn ikcp_parse_data(&mut self, newseg: Segment) {
        let sn = newseg.sn;
        if sn >= self.rcv_nxt + self.rcv_wnd || sn < self.rcv_nxt {
            // ikcp_segment_delete(kcp, newseg);
            return;
        }

        let mut repeat = false;
        let mut index: usize = self.rcv_buf.len();
        for seg in self.rcv_buf.iter().rev() {
            if sn == seg.sn {
                repeat = true;
                break;
            } else if sn > seg.sn {
                break;
            }
            index -= 1;
        }

        if !repeat {
            self.rcv_buf.insert(index, newseg);
        } else {
            // ikcp_segment_delete(kcp, newseg);
        }

        // move available data from rcv_buf -> rcv_queue
        index = 0;
        let mut nrcv_que = self.rcv_queue.len();
        for seg in &self.rcv_buf {
            if seg.sn == self.rcv_nxt && nrcv_que < self.rcv_wnd as usize {
                nrcv_que += 1;
                self.rcv_nxt += 1;
                index += 1;
            } else {
                break;
            }
        }
        if index > 0 {
            let new_rcv_buf = self.rcv_buf.split_off(index);
            self.rcv_queue.append(&mut self.rcv_buf);
            self.rcv_buf = new_rcv_buf;
        }
    }

    //---------------------------------------------------------------------
    // update state (call it repeatedly, every 10ms-100ms), or you can ask
    // ikcp_check when to call it again (without ikcp_input/_send calling).
    // 'current' - current timestamp in millisec.
    //---------------------------------------------------------------------
    pub fn ikcp_update(&mut self, current: u32) {
        self.current = current;

        if !self.updated {
            self.updated = true;
            self.ts_flush = current;
        }

        let mut slap = diff(self.current, self.ts_flush);

        if slap > 10000 || slap < -10000 {
            self.ts_flush = self.current;
            slap = 0;
        }

        if slap >= 0 {
            self.ts_flush += self.interval;
            if diff(self.current, self.ts_flush) >= 0 {
                self.ts_flush = self.current + self.interval;
            }
            self.ikcp_flush();
        }
    }

    fn ikcp_shrink_buf(&mut self) {
        self.snd_una = match self.snd_buf.front() {
            Some(x) => x.sn,
            None => self.snd_nxt,
        }
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

    // ikcp_flush
    pub fn ikcp_flush(&mut self) {
        // 'ikcp_update' haven't been called.
        if !self.updated {
            return;
        }

        let mut seg = Segment::default();
        seg.conv = self.conv;
        seg.cmd = IKCP_CMD_ACK;
        seg.wnd = self.ikcp_wnd_unused();
        seg.una = self.rcv_nxt;

        // flush acknowledges
        for ack in &self.acklist {
            if (self.buffer.capacity() - self.buffer.len()) + IKCP_OVERHEAD as usize
                > self.mtu as usize
            {
                self.output.write_all(&self.buffer);
                self.buffer.clear();
            }
            seg.sn = ack.0;
            seg.ts = ack.1;
            seg.encode(&mut self.buffer);
        }
        self.acklist.clear();

        // probe window size (if remote window size equals zero)
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = IKCP_PROBE_INIT;
                self.ts_probe = self.current + self.probe_wait;
            } else {
                if diff(self.current, self.ts_probe) >= 0 {
                    if self.probe_wait < IKCP_PROBE_INIT {
                        self.probe_wait = IKCP_PROBE_INIT;
                    }
                    self.probe_wait += self.probe_wait / 2;
                    if self.probe_wait > IKCP_PROBE_LIMIT {
                        self.probe_wait = IKCP_PROBE_LIMIT;
                    }
                    self.ts_probe = self.current + self.probe_wait;
                    self.probe |= IKCP_ASK_SEND
                }
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }

        // flush window probing commands
        if (self.probe & IKCP_ASK_SEND) != 0 {
            seg.cmd = IKCP_CMD_WASK;
            if (self.buffer.capacity() - self.buffer.len()) + IKCP_OVERHEAD as usize
                > self.mtu as usize
            {
                self.output.write_all(&self.buffer);
                self.buffer.clear();
            }
            seg.encode(&mut self.buffer);
        }

        // flush window probing commands
        if (self.probe & IKCP_ASK_TELL) != 0 {
            seg.cmd = IKCP_CMD_WINS;
            if (self.buffer.capacity() - self.buffer.len()) + IKCP_OVERHEAD as usize
                > self.mtu as usize
            {
                self.output.write_all(&self.buffer);
                self.buffer.clear();
            }
            seg.encode(&mut self.buffer);
        }

        self.probe = 0;

        // calculate window size
        let mut cwnd = min(self.snd_wnd, self.rmt_wnd);
        if !self.nocwnd {
            cwnd = min(self.cwnd, cwnd);
        }

        // move data from snd_queue to snd_buf
        while diff(self.snd_nxt, self.snd_una + cwnd) < 0 {
            if let Some(mut newseg) = self.snd_queue.pop_front() {
                newseg.conv = self.conv;
                newseg.cmd = IKCP_CMD_PUSH;
                newseg.wnd = seg.wnd;
                newseg.ts = self.current;
                newseg.sn = self.snd_nxt;
                self.snd_nxt += 1;
                newseg.una = self.rcv_nxt;
                newseg.resendts = self.current;
                newseg.rto = self.rx_rto;
                newseg.fastack = 0;
                newseg.xmit = 0;
                self.snd_buf.push_back(newseg);
            } else {
                break;
            }
        }

        // calculate resent
        let resent = if self.fastresend > 0 {
            self.fastresend
        } else {
            0xffffffff
        };

        let rtomin = if !self.nodelay { self.rx_rto >> 3 } else { 0 };

        let mut lost = false;
        let mut change = false;
        // flush data segments
        for segment in &mut self.snd_buf {
            let mut needsend = false;

            if segment.xmit == 0 {
                needsend = true;
                segment.xmit += 1;
                segment.rto = self.rx_rto;
                segment.resendts = self.current + segment.rto + rtomin;
            } else if diff(self.current, segment.resendts) >= 0 {
                needsend = true;
                segment.xmit += 1;
                self.xmit += 1;
                if !self.nodelay {
                    segment.rto += self.rx_rto;
                } else {
                    segment.rto += self.rx_rto / 2;
                }
                segment.resendts = self.current + segment.rto;
                lost = true;
            } else if segment.fastack >= resent {
                needsend = true;
                segment.xmit += 1;
                segment.fastack = 0;
                segment.resendts = self.current + segment.rto;
                change = true;
            }

            if needsend {
                segment.ts = self.current;
                segment.wnd = seg.wnd;
                segment.una = self.rcv_nxt;

                if ((self.buffer.capacity() - self.buffer.len())
                    + IKCP_OVERHEAD as usize
                    + segment.data.len() as usize)
                    > self.mtu as usize
                {
                    self.output.write_all(&self.buffer);
                    self.buffer.clear();
                }

                segment.encode(&mut self.buffer);

                if segment.xmit >= self.dead_link {
                    self.state = u32::MAX;
                }
            }
        }

        // flush remain segments
        if self.buffer.capacity() - self.buffer.len() > 0 {
            self.output.write_all(&self.buffer);
            self.buffer.clear();
        }

        // update ssthresh
        if change {
            let inflight = self.snd_nxt - self.snd_una;
            self.ssthresh = inflight / 2;
            if (self.ssthresh < IKCP_THRESH_MIN) {
                self.ssthresh = IKCP_THRESH_MIN;
            }
            self.cwnd = self.ssthresh + resent;
            self.incr = self.cwnd * self.mss;
        }

        if (lost) {
            self.ssthresh = cwnd / 2;
            if (self.ssthresh < IKCP_THRESH_MIN) {
                self.ssthresh = IKCP_THRESH_MIN;
            }
            self.cwnd = 1;
            self.incr = self.mss;
        }

        if (self.cwnd < 1) {
            self.cwnd = 1;
            self.incr = self.mss;
        }
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

    // 剩余接收窗口大小
    fn ikcp_wnd_unused(&self) -> u16 {
        if self.rcv_queue.len() < self.rcv_wnd as usize {
            return (self.rcv_wnd as usize - self.rcv_queue.len()) as u16;
        }
        return 0;
    }
}

#[inline]
fn ibound(lower: u32, middle: u32, upper: u32) -> u32 {
    return min(max(lower, middle), upper);
}

#[inline]
fn diff(later: u32, earlier: u32) -> i64 {
    later as i64 - earlier as i64
}
