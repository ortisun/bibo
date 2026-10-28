//! The errors of prompt assembly. Both sets are closed, and no message carries input text, so an
//! error written to a log cannot become a way to smuggle untrusted text into one.

use factory_domain::values::Sha256Digest;

/// Why a prompt template cannot be used. The template is factory-authored and pinned by hash, so
/// each of these is a defect in an agent definition, found when the definition is first used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    /// A required section heading is not there.
    #[error("the template has no `{heading}` section")]
    MissingSection {
        /// The heading, such as `## Untrusted data`.
        heading: &'static str,
    },
    /// A section heading appears twice.
    #[error("the template has the `{heading}` section more than once")]
    DuplicateSection {
        /// The heading.
        heading: &'static str,
    },
    /// The data section is not between the input contract and the end of data.
    #[error("the sections are out of order: input contract, untrusted data, end of data")]
    SectionOrder,
    /// The text that tells the model how blocks are marked is missing.
    #[error(
        "the template does not tell the model how a block opens, how it closes and that every line is quoted"
    )]
    BlockRulesMissing,
    /// A row of the input table cannot be read.
    #[error("line {line}: the input table row is not `| `name` | class | yes or no | meaning |`")]
    BadTableRow {
        /// The line number, from 1.
        line: usize,
    },
    /// A class in the table is not one of the policy's classes.
    #[error("line {line}: the class is not one of the classes of the security policy")]
    UnknownClass {
        /// The line number, from 1.
        line: usize,
    },
    /// An input or slot name is not 1 to 64 lowercase letters, digits and underscores starting with a letter.
    #[error(
        "line {line}: a name must be 1 to 64 lowercase letters, digits and underscores, starting with a letter"
    )]
    BadName {
        /// The line number, from 1.
        line: usize,
    },
    /// The table lists an input twice.
    #[error("line {line}: the table lists an input more than once")]
    DuplicateInput {
        /// The line number, from 1.
        line: usize,
    },
    /// Two placeholder lines name the same input.
    #[error("line {line}: a placeholder line repeats an input")]
    DuplicatePlaceholder {
        /// The line number, from 1.
        line: usize,
    },
    /// A placeholder line names an input the table does not list.
    #[error("line {line}: the placeholder names an input that is not in the table")]
    PlaceholderNotInTable {
        /// The line number, from 1.
        line: usize,
    },
    /// A row of the table has no placeholder line.
    #[error("the table lists an input that has no placeholder line")]
    InputWithoutPlaceholder,
    /// A placeholder is outside the place its kind may appear.
    #[error("line {line}: a placeholder is outside the section where it may appear")]
    PlaceholderOutsideData {
        /// The line number, from 1.
        line: usize,
    },
    /// Placeholder syntax that is not a whole line (data) or a closed slot (trusted).
    #[error(
        "line {line}: placeholder syntax that is neither a whole placeholder line nor a closed trusted slot"
    )]
    StrayPlaceholder {
        /// The line number, from 1.
        line: usize,
    },
    /// The table lists more inputs than a prompt may have.
    #[error("the table lists more than {max} inputs")]
    TooManyInputs {
        /// The most inputs.
        max: usize,
    },
}

/// Why a prompt could not be assembled. The set is closed. The assembler returns no prompt in any
/// of these cases: it never sends a prompt that it could not check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssemblyError {
    /// The template is not usable.
    #[error("the prompt template is not usable: {0}")]
    Template(#[from] TemplateError),
    /// The prompt text does not match the hash in the manifest.
    #[error("the prompt text does not match the hash in the manifest of the agent")]
    PromptHashMismatch {
        /// The hash the manifest declares.
        expected: Sha256Digest,
        /// The hash of the text that was given.
        actual: Sha256Digest,
    },
    /// The loaded prompt is not the one the manifest names.
    #[error("the loaded prompt is not the template that the manifest names")]
    PromptNotForManifest,
    /// The agent reviews work independently, so it takes only independent inputs.
    #[error("this agent reviews independently: assemble it with `assemble_independent`")]
    IndependentRoleNeedsIndependentInputs,
    /// An input has a name the template does not declare.
    #[error("an input is named `{name}`, which the template does not declare")]
    UnknownInput {
        /// The name, escaped.
        name: String,
    },
    /// Two inputs have the same name.
    #[error("two inputs are named `{name}`")]
    DuplicateInput {
        /// The name, escaped.
        name: String,
    },
    /// A required input is not there.
    #[error("the required input `{name}` was not given")]
    MissingRequiredInput {
        /// The name.
        name: String,
    },
    /// The class of an input differs from the class in the template's table.
    #[error("the input `{name}` has a different class from the one the template declares")]
    ClassMismatch {
        /// The name.
        name: String,
    },
    /// An untrusted input was offered for a trusted slot, or a trusted slot has no value.
    #[error("the trusted slot `{name}` needs a trusted value")]
    TrustedSlot {
        /// The slot.
        name: String,
    },
    /// A value offered as trusted is not a plain identifier.
    #[error("a trusted value must be 1 to 256 characters of letters, digits and `._:/@+-`")]
    TrustedValueRefused,
    /// An input belongs to another tenant.
    #[error("the input `{name}` belongs to a different tenant from the job")]
    ForeignTenant {
        /// The name.
        name: String,
    },
    /// An input is bytes that are not UTF-8. The assembler refuses them and does not repair them.
    #[error("the input `{name}` is not valid UTF-8 (valid up to byte {valid_up_to})")]
    InvalidUtf8 {
        /// The name.
        name: String,
        /// How many leading bytes are valid.
        valid_up_to: usize,
    },
    /// An input is larger than the assembler will read.
    #[error("the input `{name}` is larger than the {limit} bytes the assembler will read")]
    InputTooLarge {
        /// The name.
        name: String,
        /// The limit in bytes.
        limit: usize,
    },
    /// The inputs together are larger than the assembler will read.
    #[error("the inputs together are larger than the {limit} bytes the assembler will read")]
    InputsTooLarge {
        /// The limit in bytes.
        limit: usize,
    },
    /// The redactor failed, so the text could not be checked and was dropped.
    #[error(
        "the redactor could not check the input `{name}`, so it was dropped and the assembly failed"
    )]
    RedactionFailed {
        /// The name, or `prompt` for the final check of the whole text.
        name: String,
    },
    /// A secret is still in the finished prompt after redaction.
    #[error("the finished prompt still holds a secret after redaction, so it was not released")]
    SecretInPrompt,
    /// An input equals a text that must never reach this prompt.
    #[error("the input `{name}` is a text that must never reach a prompt")]
    WithheldContent {
        /// The name.
        name: String,
    },
    /// A required input was left out because the path policy hides its file.
    #[error("the required input `{name}` was excluded by the path policy")]
    ExcludedRequiredInput {
        /// The name.
        name: String,
    },
    /// An independent reviewer was offered the author's own account of the work.
    #[error("an independent reviewer does not take the author's own account of the work")]
    SelfAssessmentRefused,
    /// The template and the fixed parts of the blocks do not fit the budget.
    #[error("the instructions alone need {needed} bytes and the budget is {available}")]
    BudgetTooSmall {
        /// What the fixed text needs.
        needed: usize,
        /// What the budget allows.
        available: usize,
    },
    /// The finished text did not pass the assembler's own check of its structure. This is a
    /// defect in the assembler, and the prompt is not released.
    #[error("the finished prompt failed the assembler's own structure check ({0})")]
    Containment(&'static str),
}
