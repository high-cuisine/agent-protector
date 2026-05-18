pub fn print_banner() {
    // ── ANSI colours ─────────────────────────────────────────────────────────
    let b   = "\x1b[34m";    // dark blue  — outlines / visor bars
    let c   = "\x1b[96m";    // cyan       — armour fill
    let f   = "\x1b[97m";    // bright white — feather
    let n   = "\x1b[1;97m";  // bold white — product name
    let g   = "\x1b[92m";    // green      — status tick / bullet
    let dim = "\x1b[2;37m";  // dim grey   — section labels
    let r   = "\x1b[0m";     // reset

    // Knight (left column ~34 chars) + info (right column, starts at col 36)
    // Blank info slots keep the knight lines that don't need a side annotation.
    let rows: &[(&str, &str)] = &[
        // knight line                          info line
        (r"                                 ", ""),
        (r"           {f}` .{r}                    ", ""),
        (r"          {f}.` `.{r}                   ", ""),
        (r"         {f}.` . `.{r}                  ", ""),
        (r"        {f}.`  .  `.{r}                 ", "{n}  sAinep{r}"),
        (r"       {b}.`{c}  .----.  {b}`.{r}             ", "{dim}  AI Agent Security Guard{r}"),
        (r"      {b}/  {c} /      \  {b} \{r}            ", "{dim}  ──────────────────────────{r}"),
        (r"     {b}|  {c} | {b}||||||{c} |  {b}|{r}           ", "{dim}  eBPF · execve intercept{r}"),
        (r"     {b}|  {c} | {b}||||||{c} |  {b}|{r}           ", ""),
        (r"     {b}|  {c} | {b}||||||{c} |  {b}|{r}           ", "{dim}  Guarding:{r}"),
        (r"      {b}\  {c} \      /  {b} /{r}            ", "{g}  ✓{r} git · psql · mysql · sqlite3"),
        (r"       {b}`-{c}.`------`.{b}-`{r}           ", "{g}  ✓{r} redis-cli · docker · kubectl"),
        (r"       {b}/\{r}           {b}/\{r}           ", ""),
        (r"      {b}/  \           /  \{r}          ", "{dim}  Status:{r}  {g}● ACTIVE{r}"),
        (r"     {b}/    \         /    \{r}    {b}.---------.{r}", ""),
        (r"    {b}/   {c}..|..........|..{b}\{r}   {b}/  {c} /\{b}     \{r}", ""),
        (r"   {b}|    {c}  |         |  {b} |{r}  {b}|  {c}/  \{b}     |{r}", ""),
        (r"   {b}|    {c}  |   {b}[]{c}   |  {b} |{r}  {b}|  {c}/    \{b}    |{r}", ""),
        (r"   {b}|    {c}  |         |  {b} |{r}  {b}| {c}/  /\ \{b}   |{r}", ""),
        (r"    {b}\   {c}..|..........|..{b}/{r}   {b}| {c}\ /  \ /{b}   |{r}", ""),
        (r"     {b}'--|          |--`{r}    {b}\  {c}`----`{b}  /{r}", ""),
        (r"        {b}|          |{r}        {b}`---------`{r}", ""),
        (r"       {b}/|          |\{r}       ", ""),
        (r"      {b}/ |          | \{r}      ", ""),
        (r"     {b}/__|          |__\{r}     ", ""),
        (r"                                 ", ""),
    ];

    println!();
    for (knight, info) in rows {
        // substitute colour placeholders manually (raw strings keep \ as-is)
        let line = knight
            .replace("{b}", b).replace("{c}", c).replace("{f}", f)
            .replace("{r}", r);
        let info = info
            .replace("{n}", n).replace("{g}", g).replace("{dim}", dim)
            .replace("{b}", b).replace("{c}", c).replace("{r}", r);
        println!("{line}{info}");
    }
    println!();
}
