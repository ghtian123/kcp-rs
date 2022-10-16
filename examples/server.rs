use kcp_rs::Kcp;
use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::rc::Rc;
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct KcpOutput {
    udp: Rc<UdpSocket>,
    peer: SocketAddr,
}

impl Write for KcpOutput {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        println!("write");
        self.udp.send_to(buf, &self.peer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn main() {
    let socket = UdpSocket::bind("127.0.0.1:8080").expect("failed to bind host socket");
    socket.set_nonblocking(true);

    let ss = Rc::new(socket);

    let kcpo = KcpOutput {
        udp: ss.clone(),
        peer: "127.0.0.1:7070".parse().unwrap(),
    };

    let mut kcp = Kcp::ickp_create(kcpo, 1);
    // kcp.ikcp_nodelay(true, 1, 10, true);

    let mut ss_buf = [0; 100];
    let mut read_buf = [0; 100];

    loop {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        kcp.ikcp_update(current);

        loop {
            match ss.recv_from(&mut ss_buf) {
                Ok((a, b)) => {
                    if a > 0 {
                        println!("recv-->{:?}",&ss_buf[..a]);
                        kcp.ikcp_input(&ss_buf[..a]).unwrap();
                    }
                }
                Err(_x) => {
                    break;
                }
            }
        }

        loop {
            match kcp.ikcp_recv(&mut read_buf) {
                Ok(x) => {
                    if x > 0 {
                        println!("recive-->{:?}", read_buf);
                    }
                    kcp.ikcp_send(b"hello world").unwrap();
                }
                Err(x) => {
                    break;
                }
            }
        }

        sleep(Duration::from_secs(2));
    }
}
