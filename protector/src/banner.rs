pub fn print_banner() {
    let rs   = "\x1b[0m";
    let pal  = |c: char| -> &'static str {
        match c {
            'K' => "\x1b[38;2;15;15;15m",
            'D' => "\x1b[38;2;26;74;74m",
            'M' => "\x1b[38;2;42;110;110m",
            'L' => "\x1b[38;2;58;138;138m",
            'R' => "\x1b[38;2;176;32;32m",
            'N' => "\x1b[38;2;212;168;112m",
            _   => "",
        }
    };
    let bold = "\x1b[1;38;2;230;230;230m";
    let dim  = "\x1b[38;2;140;140;140m";
    let grn  = "\x1b[38;2;80;200;120m";

    let grid: [&str; 16] = [
        "....RRRRRR........",
        "....RRRRRR........",
        "...DMMMMMMD.......",
        "..DMMMMMMMMD......",
        ".DMMDMMMMDMMD.....",
        ".DMMDMMMMDMMD.....",
        ".DKKKKKKKKKKD.....",
        ".DKKKKKKKKKKD.....",
        ".DMMDMMMMDMMD.DMMD",
        ".DMMMMMMMMMMD.DLLD",
        "NDDDDDDDDDDDDNDLLD",
        "NDDKKKKKKKKDDNDLLD",
        ".DDKKKKKKKKDD.DLLD",
        ".DD........DD.DLLD",
        ".DD........DD.DMMD",
        ".DD........DD.....",
    ];

    let info: [String; 16] = [
        String::new(),
        String::new(),
        String::new(),
        String::new(),
        format!("{bold}sAinep{rs}"),
        format!("{dim}AI Agent Security Guard{rs}"),
        format!("{dim}──────────────────────{rs}"),
        format!("{dim}eBPF · execve intercept{rs}"),
        String::new(),
        format!("{dim}Guarding:{rs}"),
        format!("{grn}✓{rs} git · psql · mysql · sqlite3"),
        format!("{grn}✓{rs} redis-cli · docker · kubectl"),
        String::new(),
        format!("{dim}Status:{rs}  {grn}● ACTIVE{rs}"),
        String::new(),
        String::new(),
    ];

    println!();
    for (row, side) in grid.iter().zip(info.iter()) {
        let mut out = String::from("  ");
        let mut cur: Option<char> = None;
        for ch in row.chars() {
            if ch == '.' {
                if cur.is_some() {
                    out.push_str(rs);
                    cur = None;
                }
                out.push_str("  ");
            } else {
                if cur != Some(ch) {
                    out.push_str(pal(ch));
                    cur = Some(ch);
                }
                out.push_str("██");
            }
        }
        if cur.is_some() {
            out.push_str(rs);
        }
        if !side.is_empty() {
            out.push_str("   ");
            out.push_str(side);
        }
        println!("{out}");
    }
    println!();
}
