extern crate rayon;

use std::{net, env, thread, time, fs, collections};
use pnet::packet::{tcp, ip};
use pnet::transport::{self, TransportProtocol};

const TCP_SIZE: usize = 20;
const MAXIMUM_PORT_NUM: u16 = 1023;


struct PacketInfo{
    my_ipaddr: net::Ipv4Addr,
    target_ipaddr: net::Ipv4Addr,
    my_port: u16,
    scan_type: ScanType,
}

#[derive(Copy, Clone)]
enum ScanType {
    SynScan = tcp::TcpFlags::SYN as isize,
    FinScan = tcp::TcpFlags::FIN as isize,
    XmasScan = tcp::TcpFlags::FIN as isize | tcp::TcpFlags::URG as isize | tcp::TcpFlags::PSH as isize,
    NullScan = 0

}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("The number of arguments must be 3");
        std::process::exit(1);
    }

    

    // .envファイルから取得
    let mut packet_info: PacketInfo = {
        let contents = fs::read_to_string(".env").expect("Faild to read env file");
        let lines: Vec<_> = contents.split("\n").collect();
        let mut map = collections::HashMap::new();
        for line in lines {
            let elm: Vec<_> = line.split("=").map(|s| s.trim()).collect();
            if elm.len() == 2 {
                map.insert(elm[0], elm[1]);
            }
        }
        PacketInfo {
            my_ipaddr:      map.get("MY_IPADDR").expect("missing my_ipaddr").parse().expect("invalid ipaddr"),
            target_ipaddr:  "0.0.0.0".parse().unwrap(),
            my_port:        map.get("MY_PORT").expect("missing my_port").parse().expect("invalid my_port"),
            scan_type:      ScanType::SynScan
        }
    };

    packet_info.target_ipaddr = args[1].parse().expect("invalid target ipaddr");
    packet_info.scan_type = match args[2].as_str(){
        "sS" => ScanType::SynScan,
        "sF" => ScanType::FinScan,
        "sX" => ScanType::XmasScan,
        "sN" => ScanType::NullScan,
        _    => panic!("Undefined scan method")
    };

    let (mut ts, mut tr) = transport::transport_channel(1024, transport::TransportChannelType::Layer4(TransportProtocol::Ipv4(ip::IpNextHeaderProtocols::Tcp))).unwrap();

    // 2つのスレッドで並行処理
    rayon::join(|| send_packet(&mut ts, &packet_info),
                || receive_packet(&mut tr, &packet_info)
            );
    
}
