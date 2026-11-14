//! Seeded hostile JSON for parser tests: what a compromised or broken server might send. Each parser
//! that reads a server response gets thousands of these, built from names and values it knows plus
//! wrong types, extreme numbers, odd strings, and deep or wide nesting, and must answer every one
//! without panicking. Seeded, so a failure names the seed that reproduces it.

use serde_json::{Map, Number, Value};

use crate::retry::{Rng, SplitMix64};

/// How many values each parser test feeds its parser.
pub const CASES: u64 = 3_000;

/// Values that have broken parsers before, or might: the edges of every integer type, floats, and
/// strings with control, bidi, and non-ASCII characters or option-like and path-like text.
const STRINGS: &[&str] = &[
    "",
    " ",
    "0",
    "-1",
    "1.0.0",
    "99999999999999999999.0.0",
    "1.2.3+build",
    "1.2.3-rc.1",
    "https://",
    "https://example.com/x",
    "http://example.com/x",
    "https://example.com/ x",
    "file:///etc/shadow",
    "../../etc/passwd",
    "--help",
    "-",
    "$(reboot)",
    "; reboot",
    "\u{0}",
    "\u{1b}[31m",
    "\u{202e}gnp.exe",
    "\u{feff}",
    "é",
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-00000000000G",
    "2026-11-14T12:00:00Z",
    "9999-99-99T99:99:99Z",
    "restart_service",
    "nginx.service",
    "ssh.service",
    "config",
    "inventory",
    "packages",
    "running",
];

const NUMBERS: &[i128] = &[
    0,
    1,
    -1,
    9,
    10,
    255,
    256,
    300,
    301,
    3600,
    86_400,
    86_401,
    i32::MAX as i128,
    i32::MIN as i128,
    u32::MAX as i128,
    u32::MAX as i128 + 1,
    i64::MAX as i128,
    i64::MIN as i128,
    u64::MAX as i128,
];

/// A generator of hostile values whose object keys are drawn from `keys` (the names the parser under
/// test looks for) and some it does not know.
pub struct Hostile {
    rng: SplitMix64,
    keys: Vec<String>,
}

impl Hostile {
    pub fn new(seed: u64, keys: &[&str]) -> Self {
        let mut keys: Vec<String> = keys.iter().map(|k| (*k).to_owned()).collect();
        keys.extend(["", "__proto__", "unknown", "\u{202e}x"].map(str::to_owned));
        Self {
            rng: SplitMix64::new(seed),
            keys,
        }
    }

    fn below(&mut self, n: usize) -> usize {
        (self.rng.next_u64() % n as u64) as usize
    }

    fn key(&mut self) -> String {
        let index = self.below(self.keys.len());
        self.keys[index].clone()
    }

    fn number(&mut self) -> Value {
        match self.below(4) {
            0 => {
                let n = NUMBERS[self.below(NUMBERS.len())];
                if let Ok(n) = i64::try_from(n) {
                    Value::from(n)
                } else if let Ok(n) = u64::try_from(n) {
                    Value::from(n)
                } else {
                    Value::from(0)
                }
            }
            1 => Number::from_f64(f64::from_bits(self.rng.next_u64()))
                .map_or(Value::Null, Value::Number),
            2 => Value::from(-1.5),
            _ => Value::from(self.rng.next_u64()),
        }
    }

    fn string(&mut self) -> Value {
        match self.below(32) {
            0 => Value::from("x".repeat(self.below(70_000))),
            _ => Value::from(STRINGS[self.below(STRINGS.len())]),
        }
    }

    /// A hostile value at most `depth` containers deep.
    pub fn value(&mut self, depth: usize) -> Value {
        let pick = if depth == 0 {
            self.below(4)
        } else {
            self.below(7)
        };
        match pick {
            0 => Value::Null,
            1 => Value::Bool(self.below(2) == 0),
            2 => self.number(),
            3 => self.string(),
            // A wide list holds scalars only, so the size stays bounded.
            4 if self.below(8) == 0 => Value::Array((0..300).map(|_| self.value(0)).collect()),
            4 => {
                let len = self.below(4);
                Value::Array((0..len).map(|_| self.value(depth - 1)).collect())
            }
            _ => {
                let len = self.below(6);
                let mut map = Map::new();
                for _ in 0..len {
                    let key = self.key();
                    map.insert(key, self.value(depth - 1));
                }
                Value::Object(map)
            }
        }
    }

    /// An object whose fields are the known keys, each with a hostile value: the shape a parser expects,
    /// with wrong contents.
    pub fn object(&mut self, depth: usize) -> Value {
        let mut map = Map::new();
        for key in self.keys.clone() {
            if self.below(4) != 0 {
                map.insert(key, self.value(depth));
            }
        }
        Value::Object(map)
    }

    /// Deep nesting: `depth` arrays or objects inside each other.
    pub fn deep(&mut self, depth: usize) -> Value {
        let mut value = Value::Null;
        for _ in 0..depth {
            value = if self.below(2) == 0 {
                Value::Array(vec![value])
            } else {
                let key = self.key();
                Value::Object(Map::from_iter([(key, value)]))
            };
        }
        value
    }
}

/// Runs `check` on [`CASES`] hostile values, objects, and deep nestings built from `keys`. A panic
/// names the seed and the value.
pub fn each(keys: &[&str], mut check: impl FnMut(&Value)) {
    for seed in 0..CASES {
        let mut hostile = Hostile::new(seed, keys);
        let value = match seed % 4 {
            0 => hostile.value(4),
            1 | 2 => hostile.object(3),
            _ => hostile.deep(64 + (seed as usize % 200)),
        };
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&value)));
        if caught.is_err() {
            let shown: String = value.to_string().chars().take(2_000).collect();
            panic!("seed {seed} panicked the parser on: {shown}");
        }
    }
}

/// One step into a value: an object's field, or a list's item.
#[derive(Debug, Clone)]
enum Step {
    Field(String),
    Item(usize),
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Field(key) => write!(f, ".{key}"),
            Self::Item(index) => write!(f, "[{index}]"),
        }
    }
}

/// The path (outermost first) of every object field and list item in `value`.
fn paths(value: &Value, prefix: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    let children: Vec<(Step, &Value)> = match value {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| (Step::Field(k.clone()), v))
            .collect(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| (Step::Item(i), v))
            .collect(),
        _ => Vec::new(),
    };
    for (step, inner) in children {
        prefix.push(step);
        out.push(prefix.clone());
        paths(inner, prefix, out);
        prefix.pop();
    }
}

/// `valid` with the part at `path` replaced by `with`, or removed when `with` is `None`.
fn mutated(valid: &Value, path: &[Step], with: Option<Value>) -> Value {
    let mut value = valid.clone();
    let (last, parents) = path.split_last().expect("a path is never empty");
    let mut parent = &mut value;
    for step in parents {
        parent = match step {
            Step::Field(key) => parent.get_mut(key.as_str()),
            Step::Item(index) => parent.get_mut(*index),
        }
        .expect("the path exists in the valid value");
    }
    match (last, parent, with) {
        (Step::Field(key), Value::Object(map), Some(with)) => {
            map.insert(key.clone(), with);
        }
        (Step::Field(key), Value::Object(map), None) => {
            map.remove(key);
        }
        (Step::Item(index), Value::Array(items), Some(with)) => items[*index] = with,
        (Step::Item(index), Value::Array(items), None) => {
            items.remove(*index);
        }
        _ => unreachable!("a path's parent is an object or a list"),
    }
    value
}

/// Runs `check` on [`CASES`] copies of `valid`, each with one field or list item (at any depth) replaced by a hostile
/// value or removed, so that hostile values also reach the checks a parser makes after its first ones.
/// A panic names the seed, the field, and the value.
pub fn each_mutation(valid: &Value, keys: &[&str], mut check: impl FnMut(&Value)) {
    let mut all = Vec::new();
    paths(valid, &mut Vec::new(), &mut all);
    assert!(!all.is_empty(), "the valid value has parts to change");
    for seed in 0..CASES {
        let mut hostile = Hostile::new(seed, keys);
        let path = &all[hostile.below(all.len())];
        let with = match hostile.below(6) {
            0 => None,
            1 | 2 => Some(hostile.value(0)),
            _ => Some(hostile.value(2)),
        };
        let value = mutated(valid, path, with);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&value)));
        if caught.is_err() {
            let shown: String = value.to_string().chars().take(2_000).collect();
            let at: String = path.iter().map(ToString::to_string).collect();
            panic!("seed {seed} (at {at}) panicked the parser on: {shown}");
        }
    }
}
