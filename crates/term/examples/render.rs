//! `render <rows> <cols> < bytes`: feeds stdin to the emulator the Core's snapshots are built for and prints
//! the screen in front (`ALT=true|false`, then its rows as text). The E2 exit gate compares screens with it.
use std::io::Read;

fn main() {
    let arg = |n: usize| std::env::args().nth(n).and_then(|s| s.parse::<u16>().ok());
    let (Some(rows), Some(cols)) = (arg(1), arg(2)) else {
        eprintln!("usage: render <rows> <cols> < bytes");
        std::process::exit(2);
    };
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).expect("stdin");
    let mut parser = vt100::Parser::new(
        std::num::NonZero::new(rows).expect("rows"),
        std::num::NonZero::new(cols).expect("cols"),
        0,
    );
    parser.process(&bytes);
    let screen = parser.screen();
    println!("ALT={}", screen.alternate_screen());
    println!("{}", screen.contents());
}
