pub mod parse;

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, PartialEq, Eq)]
enum MxPattern {
    Equals(String),
    StartsWith(String),
}

#[derive(Debug, PartialEq, Eq)]
struct MtaSts {
    id: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Policy {
    id: String,
    mode: Mode,
    mx: Vec<MxPattern>,
}
