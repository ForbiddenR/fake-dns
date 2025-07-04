use std::{
    error::{self, Error},
    fmt::Display,
    net::Ipv4Addr,
};

use chrono::Local;
use clap::Parser;
use hickory_resolver::proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{RData, Record},
    serialize::binary::{BinDecodable, BinEncodable},
};
use tokio::net::UdpSocket;

macro_rules! log {
    ($($arg:tt)*) => {
        println!("{} {}", Local::now().format("%Y-%m-%d %H:%M:%S"), format!($($arg)*))
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error>> {
    let cli = Cli::parse();

    let ipv4 = Ipv4::from_cidr(&cli.cidr)?;

    log!("start listening on {}", &cli.listen);

    let socket = UdpSocket::bind(&cli.listen).await?;
    let mut buf = [0u8; 512];

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        let request_bytes = &buf[..size];

        match query(request_bytes, || ipv4.get_ip()) {
            Ok(m) => match &m.to_bytes() {
                Ok(b) => {
                    if let Err(e) = socket.send_to(b, &src).await {
                        log!("failed to send dns response {:?}", e)
                    }
                }
                Err(e) => log!("failed to parse message: {:?}", e),
            },
            Err(e) => log!("failed to parse request bytes {:?}", e),
        };
    }
}

fn query<F>(data: &[u8], fake_ip: F) -> Result<Message, MyError>
where
    F: Fn() -> Ipv4Addr,
{
    let request = Message::from_bytes(data).or(Err(MyError::Proto))?;
    let query = request.queries().first().ok_or(MyError::EmptyQuery)?;
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::NoError);
    response.add_query(query.clone());

    let record = Record::from_rdata(query.name().clone(), 600, RData::A(fake_ip().into()));
    response.add_answer(record);
    Ok(response)
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about=None)]
struct Cli {
    #[arg(long, short)]
    cidr: String,
    #[arg(long, short)]
    listen: String,
}

struct Ipv4 {
    base: u32,
    range: u32,
}

impl Ipv4 {
    pub fn from_cidr(cidr: &str) -> Result<Self, MyError> {
        use ipnetwork::Ipv4Network;
        let network = cidr.parse::<Ipv4Network>().or(Err(MyError::Ipv4Network))?;

        let mask = network.prefix();

        let range = 1u32
            .checked_shl(32 - mask as u32)
            .and_then(|r| if r <= 2 { None } else { Some(r) })
            .ok_or(MyError::IpNotEnough)?;

        Ok(Self {
            base: u32::from(network.network()),
            range,
        })
    }

    pub fn get_ip(&self) -> Ipv4Addr {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let offset = rng.gen_range(1..self.range - 1);
        Ipv4Addr::from(self.base + offset)
    }
}

#[derive(Debug, Default)]
enum MyError {
    #[default]
    IpNotEnough,
    Proto,
    Ipv4Network,
    EmptyQuery,
}

impl Display for MyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for MyError {}

#[cfg(test)]
mod tests {
    use crate::Ipv4;

    #[test]
    fn parse_ip_cidr() {
        let ipv4 = Ipv4::from_cidr("192.167.0.0/16").unwrap();
        for _ in 1..100 {
            println!("{}", ipv4.get_ip());
        }
    }
}
