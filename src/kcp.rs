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
const IKCP_INTERVAL: u32 = 100;
const IKCP_OVERHEAD: u32 = 24;
const IKCP_THRESH_INIT: u32 = 2;
const IKCP_THRESH_MIN: u32 = 2;
const IKCP_PROBE_INIT: u32 = 7000; // 7 secs to probe window size
const IKCP_PROBE_LIMIT: u32 = 120000; // up to 120 secs to probe window

#[derive(Default)]
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
        buf.put_slice(&self.data)
    }
}


#[repr(C)]
pub struct Kcp<W: Write> {
    //标识这个会话ID
    conv: u32,

    //最大传输单元，默认数据为1400，最小为50；
    mtu: u32,

    // 最大分片大小，不大于mtu；
    mss: u32,

    //第一个未确认的包
    snd_una: u32,

    // 下一个待分配的包的序号
    snd_nxt: u32,

    //待接收消息序号。为了保证包的顺序，接收方会维护一个接收窗口，接收窗口有一个起始序号rcv_nxt（待接收消息序号）以及尾序号 rcv_nxt + rcv_wnd（接收窗口大小）
    rcv_nxt: u32,

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

    //可发送的最大数据量
    incr: u32,

    // snd_queue --> snd_buf
    snd_queue: VecDeque<Segment>,
    rcv_queue: VecDeque<Segment>,
    snd_buf: VecDeque<Segment>,

    //rcv_buf --> rcv_queue
    rcv_buf: VecDeque<Segment>,

    //待发送的ack列表(sn,ts)
    acklist: Vec<(u32, u32)>,

    // 存储消息字节流；
    buffer: BytesMut,

    //触发快速重传的重复ACK个数；
    fastresend: u32,

    // 取消拥塞控制；
    nocwnd: bool,

    //是否采用流传输模式；
    stream: bool,

    output: W,
}

impl<W: Write> Kcp<W> {
    pub fn ickp_create(w: W, conv: u32) -> Self {
        Self {
            conv: conv,
            mtu: IKCP_MTU_DEF,
            mss: IKCP_MTU_DEF - IKCP_OVERHEAD,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
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
            incr: 0,
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: Vec::new(),
            buffer: BytesMut::with_capacity((IKCP_MTU_DEF as usize + IKCP_OVERHEAD as usize) * 3),
            fastresend: 0,
            nocwnd: false,
            stream: false,
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

        //移动 rcv_buf 数据到 rcv_queue
        if index > 0 {
            let new_rcv_buf = self.rcv_buf.split_off(index);
            self.rcv_queue.append(&mut self.rcv_buf);
            self.rcv_buf = new_rcv_buf;
        }

        //最后进行窗口恢复。此时如果 recover 标记为1，表明在此次接收之前，可用接收窗口为0，
        //如果经过本次接收之后，可用窗口大于0，将主动发送 IKCP_ASK_TELL 数据包来通知对方已可以接收数据：
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

        // 1. 如果当前的 KCP 开启流模式，取出 `snd_queue` 中的最后一个报文将其填充到 mss 的长度，并设置其 frg 为 0.
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

        // 2. 计算剩下的数据需要分成几段
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


        // 3. 为剩下的数据创建 KCP segment
        for i in 0..count {
            let size = min(self.mss as usize, buf.remaining());
            let mut seg = Segment::default();
            //fix bug
            seg.len = size as u32;
            seg.data.resize(size, 0);
            if buf.read_exact(&mut seg.data).is_err() {
                return Err(-1);
            };

            // 流模式情况下分片编号不用填写
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
        //记录当前收到的最大的 ACK 编号，在快重传的过程计算已发送的数据包被跳过的次数；
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
                //1. 对于来自于对方的标准数据包，首先需要检测该报文的编号 sn 是否在窗口范围内；
                if sn < self.rcv_nxt + self.rcv_wnd {
                    //2. 调用 ikcp_ack_push 将对该报文的确认 ACK 报文放入 ACK 列表中，ACK 列表的组织方式在前文中已经介绍；
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
                        //fix bug
                        seg.len = len as u32;
                        seg.data.resize(len, 0);
                        if buf.read_exact(&mut seg.data).is_err() {
                            return Err(-2);
                        }
                        //3. 最后调用 ikcp_parse_data 将该报文插入到 rcv_buf 链表中；
                        self.ikcp_parse_data(seg);
                    }
                }
            } else if cmd == IKCP_CMD_WASK {
                //对于接收到的 IKCP_CMD_WASK 报文，直接标记下次将发送窗口通知报文
                self.probe |= IKCP_ASK_TELL;
            } else if cmd == IKCP_CMD_WINS {
                //而对于报文 IKCP_CMD_WINS 无需做任何特殊操作;
            } else {
                return Err(-1);
            }
        }
        if flag {
            // 根据记录的最大的 ACK 编号 maxack 来更新 snd_buf 中的报文的 fastack，
            // 这个过程在介绍 ikcp_flush 中提到过，对于 fastack 大于设置的 resend 参数时，将立马进行快重传；
            self.ikcp_parse_fastack(maxack);
        }

        //最后，根据接收到报文的 una 和 KCP 控制块的 una 参数进行流控
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

    //当接收到 una 信息后，表明 sn 小于 una 的数据包都已经被对方接收到，
    //因此可以直接从 snd_buf 中删除。同时调用 ikcp_shrink_buf 来更新 KCP 控制块的 snd_una 数值。
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

    //之后调用函数 ikcp_parse_ack 来根据 ACK 的编号确认对方收到了哪个数据包；
    //注意KCP 中同时使用了 UNA 以及 ACK 编号的报文确认手段。
    //UNA 表示此前所有的数据都已经被接收到，而 ACK 表示指定编号的数据包被接收到；
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

    // 调用 ikcp_update_ack 来根据 ACK 时间戳更新本地的 rtt，这类似于 TCP 协议；
    fn ikcp_update_ack(&mut self, rtt: u32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let delta = if rtt > self.rx_srtt {
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

        // 发送确认ACK 包
        for ack in &self.acklist {
            if (self.buffer.capacity() - self.buffer.len()) + IKCP_OVERHEAD as usize
                > self.mtu as usize
            {
                self.output.write_all(&self.buffer).unwrap();
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
                self.output.write_all(&self.buffer).unwrap();
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
                self.output.write_all(&self.buffer).unwrap();
                self.buffer.clear();
            }
            seg.encode(&mut self.buffer);
        }

        self.probe = 0;

        // 设置nocwnd cwnd 只会由发送窗口和对端接收端口决定
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

        // 是否设置了快重传次数
        let resent = if self.fastresend > 0 {
            self.fastresend
        } else {
            u32::MAX
        };

        // 是否开启了 nodelay 
        let rtomin = if !self.nodelay { self.rx_rto >> 3 } else { 0 };

        let mut lost = false;
        let mut change = false;
        // flush data segments
        for segment in &mut self.snd_buf {
            let mut needsend = false;

             // 1. 如果该报文是第一次传输，那么直接发送
            if segment.xmit == 0 {
                needsend = true;
                segment.xmit += 1;
                segment.rto = self.rx_rto;
                segment.resendts = self.current + segment.rto + rtomin;

            // 2. 如果已经到了该报文的重传时间，那么发送该报文
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

                // 标识重传
                lost = true;

             // 3. 如果该报文被跳过的次数超过了设置的快重传次数，发送该报文
            } else if segment.fastack >= resent {
                needsend = true;
                segment.xmit += 1;
                segment.fastack = 0;
                segment.resendts = self.current + segment.rto;

                // 标识快重传发生
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
                    self.output.write_all(&self.buffer).unwrap();
                    self.buffer.clear();
                }

                segment.encode(&mut self.buffer);
            }
        }

        // flush remain segments
        if self.buffer.len() > 0 {
            self.output.write_all(&self.buffer).unwrap();
            self.buffer.clear();
        }

        // 快重传和丢包时的窗口更新算法不一致，这一点类似于 TCP 协议的拥塞控制和快恢复算法；
        // 根据change 更新窗口大小
        if change {
            let inflight = self.snd_nxt - self.snd_una;
            self.ssthresh = inflight / 2;
            if self.ssthresh < IKCP_THRESH_MIN {
                self.ssthresh = IKCP_THRESH_MIN;
            }
            self.cwnd = self.ssthresh + resent;
            self.incr = self.cwnd * self.mss;
        }

        // 根据设置的 lost 更新窗口大小
        if lost {
            self.ssthresh = cwnd / 2;
            if self.ssthresh < IKCP_THRESH_MIN {
                self.ssthresh = IKCP_THRESH_MIN;
            }
            self.cwnd = 1;
            self.incr = self.mss;
        }

        if self.cwnd < 1 {
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
    pub fn ikcp_check(&mut self, _current: u32) -> i32 {
        todo!()
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



#[test]
fn test(){
    
}