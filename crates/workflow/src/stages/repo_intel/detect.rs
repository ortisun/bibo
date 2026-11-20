//! Which languages and build systems a repository uses, and which build and test commands follow
//! from that. Everything here is a table, so a new language is a new row and no new code.
//!
//! # What detection will and will not do
//!
//! A command comes from exactly one of two places: the project manifest the repository keeps at
//! the protected base (`.factory/project.yaml`), or a row of [`RULES`] whose marker files are in
//! the repository. A row names its command itself. No part of a command is ever taken from the
//! text of a repository file, except that a row may be told to offer a command only when a file
//! holds a given word (a `package.json` that has a `"test"` script).
//!
//! When no row matches, or two rows both offer a command, there is no command. The stage then
//! records why, and the baseline gate reports `BLOCKED`. Guessing a build command is exactly the
//! kind of thing that makes a green baseline mean nothing.

use std::collections::BTreeMap;

/// Where a fact was read: a file and the lines of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    /// The path, relative to the repository root.
    pub path: String,
    /// The first line, from 1.
    pub start: u32,
    /// The last line, from 1.
    pub end: u32,
}

impl Place {
    /// A whole-file place on line 1, for a fact that a file's existence or name states.
    #[must_use]
    pub fn file(path: &str) -> Self {
        Self {
            path: path.to_owned(),
            start: 1,
            end: 1,
        }
    }
}

/// A command the rule offers only when a file holds a word.
#[derive(Debug, Clone, Copy)]
pub struct Needs {
    /// The file, relative to the repository root.
    pub file: &'static str,
    /// The text that must be in it.
    pub needle: &'static str,
}

/// One build system.
#[derive(Debug, Clone, Copy)]
pub struct BuildSystemRule {
    /// The identifier.
    pub id: &'static str,
    /// The language it builds.
    pub language: &'static str,
    /// Files at the root whose presence says the repository uses it.
    pub markers: &'static [&'static str],
    /// The build command, or none.
    pub build: Option<&'static [&'static str]>,
    /// Offered only when this holds.
    pub build_needs: Option<Needs>,
    /// The test command, or none.
    pub test: Option<&'static [&'static str]>,
    /// Offered only when this holds.
    pub test_needs: Option<Needs>,
    /// The program the commands start, which the sandbox image must have.
    pub toolchain: &'static str,
}

/// The build systems the factory knows. Add a row to teach it another.
pub const RULES: &[BuildSystemRule] = &[
    BuildSystemRule {
        id: "cargo",
        language: "rust",
        markers: &["Cargo.toml"],
        build: Some(&["cargo", "build", "--locked"]),
        build_needs: None,
        test: Some(&["cargo", "test", "--locked"]),
        test_needs: None,
        toolchain: "cargo",
    },
    BuildSystemRule {
        id: "go-modules",
        language: "go",
        markers: &["go.mod"],
        build: Some(&["go", "build", "./..."]),
        build_needs: None,
        test: Some(&["go", "test", "./..."]),
        test_needs: None,
        toolchain: "go",
    },
    BuildSystemRule {
        id: "npm",
        language: "javascript",
        markers: &["package.json"],
        build: Some(&["npm", "run", "build"]),
        build_needs: Some(Needs {
            file: "package.json",
            needle: "\"build\"",
        }),
        test: Some(&["npm", "test"]),
        test_needs: Some(Needs {
            file: "package.json",
            needle: "\"test\"",
        }),
        toolchain: "npm",
    },
    BuildSystemRule {
        id: "pytest",
        language: "python",
        markers: &["pytest.ini", "pyproject.toml"],
        build: None,
        build_needs: None,
        test: Some(&["python", "-m", "pytest"]),
        test_needs: Some(Needs {
            file: "pyproject.toml",
            needle: "[tool.pytest",
        }),
        toolchain: "python",
    },
];

/// File extensions and the language they mean.
pub const EXTENSIONS: &[(&str, &str)] = &[
    ("rs", "rust"),
    ("go", "go"),
    ("py", "python"),
    ("js", "javascript"),
    ("jsx", "javascript"),
    ("ts", "typescript"),
    ("tsx", "typescript"),
    ("java", "java"),
    ("kt", "kotlin"),
    ("rb", "ruby"),
    ("c", "c"),
    ("h", "c"),
    ("cpp", "cpp"),
    ("cs", "csharp"),
    ("swift", "swift"),
];

/// How a test file is recognised: a directory it lives in or a name pattern.
pub const TEST_MARKERS: &[&str] = &["tests/", "test/", "__tests__/", "_test.", ".test.", "test_"];

/// A command and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandChoice {
    /// `build` or `test`.
    pub role: &'static str,
    /// The program and arguments.
    pub argv: Vec<String>,
    /// `project-manifest` or `detected`.
    pub origin: &'static str,
    /// Where the command comes from.
    pub place: Place,
    /// The program the sandbox image must have.
    pub toolchain: String,
    /// How long it may run, in seconds.
    pub timeout_seconds: u32,
}

/// Why there is no command. A closed set, so the report can say it in a fixed sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoCommand {
    /// No row matches and the project manifest names none.
    NothingRecognised,
    /// More than one build system offers a command, and nothing says which is the project's.
    SeveralBuildSystems,
}

impl NoCommand {
    /// The code the report carries.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NothingRecognised => "nothing-recognised",
            Self::SeveralBuildSystems => "several-build-systems",
        }
    }

    /// What is missing, in a phrase.
    #[must_use]
    pub const fn missing(self) -> &'static str {
        match self {
            Self::NothingRecognised => {
                "a build and test command for this repository: none of its files names a build system the factory knows, and it has no project manifest"
            }
            Self::SeveralBuildSystems => {
                "a choice between build systems: the repository uses more than one, and no project manifest says which commands to run"
            }
        }
    }
}

/// What detection found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Languages with the number of files and the first file.
    pub languages: Vec<(String, u32, Place)>,
    /// Build systems whose marker files are present.
    pub systems: Vec<(String, Place)>,
    /// The commands, build first.
    pub commands: Vec<CommandChoice>,
    /// Why there are none, when there are none.
    pub none: Option<NoCommand>,
}

/// The line, from 1, of the first line of `text` that holds `needle`.
#[must_use]
pub fn line_of(text: &str, needle: &str) -> Option<u32> {
    text.lines()
        .position(|line| line.contains(needle))
        .and_then(|index| u32::try_from(index + 1).ok())
}

/// Finds the languages, the build systems and the commands.
///
/// `paths` is every path the model may see, `read` returns the text of a file at the root (or
/// `None`), and `default_timeout` is the time a detected command may run.
pub fn detect(
    paths: &[String],
    read: &mut dyn FnMut(&str) -> Option<String>,
    default_timeout: u32,
) -> Detection {
    let mut counts: BTreeMap<&str, (u32, &str)> = BTreeMap::new();
    for path in paths {
        let Some(extension) = path.rsplit('.').next().filter(|e| *e != path) else {
            continue;
        };
        if let Some((_, language)) = EXTENSIONS.iter().find(|(ext, _)| *ext == extension) {
            let entry = counts.entry(language).or_insert((0, path.as_str()));
            entry.0 += 1;
        }
    }
    let mut languages: Vec<(String, u32, Place)> = counts
        .into_iter()
        .map(|(language, (count, first))| (language.to_owned(), count, Place::file(first)))
        .collect();
    languages.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut systems = Vec::new();
    let mut offered: Vec<(&BuildSystemRule, Vec<CommandChoice>)> = Vec::new();
    for rule in RULES {
        let Some(marker) = rule.markers.iter().find(|m| paths.iter().any(|p| p == *m)) else {
            continue;
        };
        systems.push((rule.id.to_owned(), Place::file(marker)));
        let mut commands = Vec::new();
        for (role, argv, needs) in [
            ("build", rule.build, rule.build_needs),
            ("test", rule.test, rule.test_needs),
        ] {
            let Some(argv) = argv else { continue };
            let place = match needs {
                None => Some(Place::file(marker)),
                Some(need) => read(need.file).and_then(|text| {
                    line_of(&text, need.needle).map(|line| Place {
                        path: need.file.to_owned(),
                        start: line,
                        end: line,
                    })
                }),
            };
            if let Some(place) = place {
                commands.push(CommandChoice {
                    role,
                    argv: argv.iter().map(|word| (*word).to_owned()).collect(),
                    origin: "detected",
                    place,
                    toolchain: rule.toolchain.to_owned(),
                    timeout_seconds: default_timeout,
                });
            }
        }
        if !commands.is_empty() {
            offered.push((rule, commands));
        }
    }
    let (commands, none) = match offered.len() {
        0 => (Vec::new(), Some(NoCommand::NothingRecognised)),
        1 => (offered.remove(0).1, None),
        _ => (Vec::new(), Some(NoCommand::SeveralBuildSystems)),
    };
    Detection {
        languages,
        systems,
        commands,
        none,
    }
}

/// True for a path that looks like a test file.
#[must_use]
pub fn is_test_path(path: &str) -> bool {
    TEST_MARKERS.iter().any(|marker| {
        if let Some(dir) = marker.strip_suffix('/') {
            path.starts_with(marker) || path.contains(&format!("/{dir}/"))
        } else {
            path.contains(marker)
        }
    })
}
