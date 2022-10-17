use bytes::BytesMut;




fn main(){

    let mut b = BytesMut::from(&b"hello"[..]);

    println!("{:?}",b.capacity());
    println!("{:?}",b.len());

    b.clear();


    println!("{:?}",b.capacity());
    println!("{:?}",b.len());
}