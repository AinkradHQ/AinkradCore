//! A small POSIX-shell reader shared by the runner's permission policy and the Core's allow rules:
//! words with their quotes removed and list/pipe operators, or nothing at all for anything beyond
//! them (redirections, expansions, substitutions, globs, backgrounding, grouping, escapes).

/// A shell token: a word with its quotes removed, or a list or pipe operator.
#[derive(Debug, PartialEq)]
pub enum Token {
    Word(String),
    Op(&'static str),
}

/// Splits `command` the way a POSIX shell would, or `None` when it uses anything beyond plain
/// words, quotes, `2>/dev/null` and `;` `&&` `||` `|`: redirections, expansions, substitutions, globs,
/// backgrounding, grouping, escapes outside double quotes, or an unterminated quote.
pub fn tokens(command: &str) -> Option<Vec<Token>> {
    let mut out = vec![];
    let mut word: Option<String> = None;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        let op = match c {
            ' ' | '\t' => None,
            '\n' | ';' => Some(";"),
            '&' if chars.next_if_eq(&'&').is_some() => Some("&&"),
            '|' if chars.next_if_eq(&'|').is_some() => Some("||"),
            '|' if chars.peek() != Some(&'&') => Some("|"),
            // Discarding stderr touches nothing: `2>/dev/null` (or `2> /dev/null`) is dropped.
            '2' if word.is_none() && dev_null(&mut chars) => None,
            '\'' => {
                let w = word.get_or_insert_default();
                loop {
                    match chars.next()? {
                        '\'' => break,
                        c => w.push(c),
                    }
                }
                continue;
            }
            '"' => {
                let w = word.get_or_insert_default();
                loop {
                    match chars.next()? {
                        '"' => break,
                        '$' | '`' => return None,
                        '\\' => match chars.next()? {
                            c @ ('$' | '`' | '"' | '\\') => w.push(c),
                            '\n' => return None,
                            c => w.extend(['\\', c]),
                        },
                        c => w.push(c),
                    }
                }
                continue;
            }
            c if "&|<>()`$\\*?[]{}~#!".contains(c) => return None,
            c => {
                word.get_or_insert_default().push(c);
                continue;
            }
        };
        out.extend(word.take().map(Token::Word));
        out.extend(op.map(Token::Op));
    }
    out.extend(word.map(Token::Word));
    Some(out)
}

/// The script of `<shell> [-flags] -c <script> [$0 $1 ...]`, when `tokens` is exactly that: Codex
/// hands over the whole `bash -lc '<script>'` it is about to run. The shell is `sh`, `bash`, `zsh`,
/// `dash` or `ksh` (any case, by bare name or under `/bin` or `/usr/bin`), the flags are short
/// letter groups, one of which holds `c`; the words after the script only become `$0`, `$1`, ...,
/// which a script that [`tokens`] accepts cannot expand. Any other shape is not looked through, so
/// the shell stays the command's first word.
fn shell_script(tokens: &[Token]) -> Option<String> {
    let mut words = tokens.iter().map(|t| match t {
        Token::Word(w) => Some(w.as_str()),
        Token::Op(_) => None,
    });
    let shell = words.next()??;
    let name = shell.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
    let known = ["sh", "bash", "zsh", "dash", "ksh"].contains(&name.as_str());
    let placed =
        shell.starts_with("/bin/") || shell.starts_with("/usr/bin/") || !shell.contains('/');
    if !known || !placed {
        return None;
    }
    loop {
        let flag = words.next()??;
        let letters = flag.len() > 1
            && flag.starts_with('-')
            && flag[1..].bytes().all(|b| b.is_ascii_alphabetic());
        match (letters, flag.contains('c')) {
            (true, true) => break,
            (true, false) => {}
            _ => return None,
        }
    }
    let script = words.next()??;
    // Whatever follows must be words, not operators.
    words.all(|w| w.is_some()).then(|| script.to_owned())
}

/// The pipelines of `command` joined by `;`, `&&`, `||` or newlines, each a list of simple
/// commands (its words) joined by `|`, or `None` for anything [`tokens`] refuses or a dangling
/// operator. Codex's `bash -lc '<script>'` wrapper is looked through.
pub fn pipelines(command: &str) -> Option<Vec<Vec<Vec<String>>>> {
    let tokens = tokens(command)?;
    if let Some(script) = shell_script(&tokens) {
        return pipelines(&script);
    }
    let mut out = vec![];
    let mut stages: Vec<Vec<String>> = vec![vec![]];
    let mut before = ";";
    // Each list operator (and the end, `;`) closes the pipeline before it.
    for token in tokens.into_iter().chain([Token::Op(";")]) {
        match token {
            Token::Word(w) => stages.last_mut().expect("never empty").push(w),
            Token::Op("|") => stages.push(vec![]),
            Token::Op(op) => {
                if stages == [Vec::<String>::new()] {
                    // `;` and newlines may repeat or trail; `&&` and `||` need two sides.
                    if before != ";" || op != ";" {
                        return None;
                    }
                } else if stages.iter().any(Vec::is_empty) {
                    return None;
                } else {
                    out.push(std::mem::replace(&mut stages, vec![vec![]]));
                }
                before = op;
            }
        }
    }
    Some(out)
}

/// Consumes `>/dev/null` (after the `2` of `2>/dev/null`) when it is whole, ending at a blank,
/// a list or pipe operator, or the end; anything else is left alone.
fn dev_null(chars: &mut std::iter::Peekable<std::str::Chars>) -> bool {
    let mut ahead = chars.clone();
    if ahead.next() != Some('>') {
        return false;
    }
    while ahead.next_if_eq(&' ').is_some() {}
    let whole = "/dev/null".chars().all(|c| ahead.next() == Some(c))
        && ahead.peek().is_none_or(|c| " \t\n;&|".contains(*c));
    if whole {
        *chars = ahead;
    }
    whole
}
