use crate::types::Shell;

// ========================================================
// Types
// ========================================================

#[derive(Debug, Clone)]
pub struct ParsedCommand {
    pub segments: Vec<CommandSegment>,
    pub chain_operators: Vec<ChainOperator>,
    pub parse_warnings: Vec<ParseWarning>,
}

#[derive(Debug, Clone)]
pub struct CommandSegment {
    pub raw: String,
    pub executable: Option<String>,
    pub args: Vec<Argument>,
    pub redirections: Vec<Redirection>,
    pub assignments: Vec<Assignment>,
    pub is_subshell: bool,
}

#[derive(Debug, Clone)]
pub struct Argument {
    pub value: String,
    pub is_quoted: bool,
    pub quote_type: Option<QuoteType>,
    pub has_expansion: bool,
    pub expansion_type: Option<ExpansionType>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteType {
    Single,
    Double,
    AnsiC,
    Heredoc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpansionType {
    Variable,
    Command,
    Arithmetic,
    Process,
    Brace,
    Tilde,
    Glob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainOperator {
    Pipe,
    And,
    Or,
    Sequence,
    Background,
}

#[derive(Debug, Clone)]
pub struct Redirection {
    pub fd: Option<u32>,
    pub direction: RedirDirection,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirDirection {
    In,
    Out,
    Append,
    HereDoc,
    HereString,
}

#[derive(Debug, Clone)]
pub struct Assignment {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseWarning {
    ControlCharacters(Vec<u8>),
    UnicodeWhitespace(Vec<char>),
    UnbalancedQuotes,
    AnsiCQuoting,
    EscapedOperators,
    CarriageReturn,
    TreeSitterError(String),
}

// ========================================================
// Pre-processing: scan for suspicious patterns
// ========================================================

fn collect_warnings(command: &str) -> Vec<ParseWarning> {
    let mut warnings = Vec::new();

    // Control characters (0x00-0x08, 0x0E-0x1F, 0x7F) excluding \t(0x09), \n(0x0A), \r(0x0D)
    let control_chars: Vec<u8> = command
        .bytes()
        .filter(|&b| (b < 0x09) || (b > 0x0A && b < 0x0D) || (b > 0x0D && b < 0x20) || b == 0x7F)
        .collect();
    if !control_chars.is_empty() {
        warnings.push(ParseWarning::ControlCharacters(control_chars));
    }

    // Unicode whitespace (non-ASCII whitespace characters)
    let unicode_ws: Vec<char> = command
        .chars()
        .filter(|c| c.is_whitespace() && !c.is_ascii())
        .collect();
    if !unicode_ws.is_empty() {
        warnings.push(ParseWarning::UnicodeWhitespace(unicode_ws));
    }

    // Carriage return
    if command.contains('\r') {
        warnings.push(ParseWarning::CarriageReturn);
    }

    // ANSI-C quoting ($'...') -- as quoting, not a `$` anchor that happens
    // to end a single-quoted regex (`'^libz\.dylib$'`). This warning marks
    // *every* segment as obfuscated, so a substring match here is costly.
    if crate::rules::injection::has_ansi_c_quoting(command) {
        warnings.push(ParseWarning::AnsiCQuoting);
    }

    // Escaped operators (\;, \|, \&)
    if command.contains("\\;") || command.contains("\\|") || command.contains("\\&") {
        warnings.push(ParseWarning::EscapedOperators);
    }

    warnings
}

// ========================================================
// Helpers for collecting child nodes via cursor
// ========================================================

/// Collect all direct children (named and anonymous) of a node.
fn all_children(node: tree_sitter::Node) -> Vec<tree_sitter::Node> {
    let mut cursor = node.walk();
    node.children(&mut cursor).collect()
}

/// Collect only named direct children of a node.
fn named_children(node: tree_sitter::Node) -> Vec<tree_sitter::Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

// ========================================================
// Public entry point
// ========================================================

pub fn parse(command: &str, _shell: Shell) -> ParsedCommand {
    parse_nested(command, 0)
}

/// How deep `sh -c '<script>'` nesting is followed before giving up.
const MAX_SCRIPT_DEPTH: usize = 4;

fn parse_nested(command: &str, depth: usize) -> ParsedCommand {
    let mut warnings = collect_warnings(command);

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("failed to set tree-sitter-bash language");

    let tree = match parser.parse(command, None) {
        Some(tree) => tree,
        None => {
            warnings.push(ParseWarning::TreeSitterError(
                "tree-sitter parse returned None".into(),
            ));
            return ParsedCommand {
                segments: vec![fallback_segment(command)],
                chain_operators: vec![],
                parse_warnings: warnings,
            };
        }
    };

    let root = tree.root_node();

    if root.has_error() {
        warnings.push(ParseWarning::TreeSitterError(
            "parse tree contains error nodes".into(),
        ));
    }

    let mut segments = Vec::new();
    let mut operators = Vec::new();

    let src = command.as_bytes();
    walk_program(root, src, &mut segments, &mut operators);

    // Command and process substitutions run commands of their own
    // (`X=$(cat ~/.ssh/id_rsa)`, `echo "$(rm -rf /)"`, `diff <(ls a) <(ls b)`).
    // `walk_program` deliberately does not descend into them -- a
    // substitution's output is an *argument*, so splicing its commands into
    // the pipeline in place would invent data flow that isn't there -- so
    // they are analyzed here instead, as trailing segments joined by
    // `Sequence`.
    let mut substitutions = Vec::new();
    collect_substitutions(root, &mut substitutions);
    for sub in substitutions {
        for child in named_children(sub) {
            walk_sequenced(child, src, &mut segments, &mut operators);
        }
    }

    // A script handed to a shell (`bash -c '<script>'`, also as a payload:
    // `find -exec sh -c '...'`, `xargs sh -c '...'`, `kubectl exec pod --
    // sh -c '...'`) or to `eval` is code, even though it arrives as a single
    // quoted argument. Parse it and analyze its commands too.
    if depth < MAX_SCRIPT_DEPTH {
        let scripts: Vec<String> = segments.iter().flat_map(embedded_scripts).collect();
        for script in scripts {
            let inner = parse_nested(&script, depth + 1);
            if inner.segments.iter().all(|seg| seg.raw.trim().is_empty()) {
                continue;
            }
            if !segments.is_empty() {
                operators.push(ChainOperator::Sequence);
            }
            segments.extend(inner.segments);
            operators.extend(inner.chain_operators);
        }
    }

    // If we got nothing out of the walk, produce a single empty segment
    if segments.is_empty() {
        segments.push(empty_segment());
    }

    ParsedCommand {
        segments,
        chain_operators: operators,
        parse_warnings: warnings,
    }
}

// ========================================================
// CST walking
// ========================================================

fn walk_program(
    node: tree_sitter::Node,
    src: &[u8],
    segments: &mut Vec<CommandSegment>,
    operators: &mut Vec<ChainOperator>,
) {
    let kind = node.kind();
    match kind {
        "program" => {
            for child in named_children(node) {
                walk_sequenced(child, src, segments, operators);
            }
        }
        "list" => {
            walk_list(node, src, segments, operators);
        }
        "pipeline" => {
            walk_pipeline(node, src, segments, operators);
        }
        "command" => {
            segments.push(extract_command(node, src));
        }
        "redirected_statement" => {
            // A redirect can wrap a plain command (the common case) or a
            // whole pipeline / loop / group (`cmd | sort > out`,
            // `while read l; do ...; done < file`). Only the former fits in
            // one segment; for the rest, analyze the wrapped statement and
            // hang the redirects on the segment that actually reads or
            // writes them.
            let body = named_children(node).into_iter().find(|c| {
                !matches!(
                    c.kind(),
                    "file_redirect" | "heredoc_redirect" | "herestring_redirect"
                )
            });
            match body {
                Some(b) if b.kind() != "command" => {
                    let first = segments.len();
                    walk_sequenced(b, src, segments, operators);
                    let redirs: Vec<Redirection> = all_children(node)
                        .into_iter()
                        .filter_map(|c| extract_redirection(c, src))
                        .collect();
                    if segments.len() > first {
                        let last = segments.len() - 1;
                        for r in redirs {
                            let target = if matches!(
                                r.direction,
                                RedirDirection::In
                                    | RedirDirection::HereDoc
                                    | RedirDirection::HereString
                            ) {
                                first
                            } else {
                                last
                            };
                            segments[target].redirections.push(r);
                        }
                    }
                }
                _ => segments.push(extract_redirected_statement(node, src)),
            }
        }
        "subshell" => {
            // Every command inside runs; merging them into one segment (as
            // this used to) kept only the first executable and pooled all
            // their arguments, so `(cd /tmp && rm -rf x)` read as a `cd`.
            let first = segments.len();
            for child in named_children(node) {
                walk_sequenced(child, src, segments, operators);
            }
            for seg in &mut segments[first..] {
                seg.is_subshell = true;
            }
        }
        "declaration_command" | "unset_command" => {
            // `export` / `declare` / `typeset` / `local` / `readonly` /
            // `unset` are commands with rules of their own; without this
            // arm they fell through to their bare assignment children and
            // were never classified as themselves.
            let mut seg = empty_segment();
            seg.raw = node_text(node, src).to_string();
            for child in all_children(node) {
                match child.kind() {
                    "export" | "declare" | "typeset" | "local" | "readonly" | "unset"
                    | "unsetenv" => {
                        seg.executable = Some(node_text(child, src).to_string());
                    }
                    "variable_assignment" => {
                        if let Some(assignment) = extract_assignment(child, src) {
                            seg.assignments.push(assignment);
                        }
                    }
                    _ if child.is_named() => seg.args.push(extract_argument(child, src)),
                    _ => {}
                }
            }
            segments.push(seg);
        }
        "variable_assignment" => {
            let mut seg = empty_segment();
            seg.raw = node_text(node, src).to_string();
            if let Some(assignment) = extract_assignment(node, src) {
                seg.assignments.push(assignment);
            }
            segments.push(seg);
        }
        // Control flow and grouping: analyze the commands they contain.
        // These used to become a single opaque, executable-less segment,
        // which defaulted to `Intent::Execute` -- so `if true; then ls; fi`
        // was DANGER while `for f in x; do rm -rf /; done` was *also* only
        // DANGER, because the body was never looked at.
        "negated_command"
        | "compound_statement"
        | "if_statement"
        | "elif_clause"
        | "else_clause"
        | "while_statement"
        | "for_statement"
        | "c_style_for_statement"
        | "do_group"
        | "case_statement"
        | "case_item"
        | "function_definition"
        | "test_command" => {
            for child in named_children(node) {
                walk_sequenced(child, src, segments, operators);
            }
        }
        // Handled after the main walk (see `parse`).
        "command_substitution" | "process_substitution" => {}
        _ => {
            for child in named_children(node) {
                walk_program(child, src, segments, operators);
            }
        }
    }
}

fn walk_list(
    node: tree_sitter::Node,
    src: &[u8],
    segments: &mut Vec<CommandSegment>,
    operators: &mut Vec<ChainOperator>,
) {
    for child in all_children(node) {
        match child.kind() {
            "&&" => operators.push(ChainOperator::And),
            "||" => operators.push(ChainOperator::Or),
            ";" => operators.push(ChainOperator::Sequence),
            "&" => operators.push(ChainOperator::Background),
            _ => {
                walk_program(child, src, segments, operators);
            }
        }
    }
}

fn walk_pipeline(
    node: tree_sitter::Node,
    src: &[u8],
    segments: &mut Vec<CommandSegment>,
    operators: &mut Vec<ChainOperator>,
) {
    for child in all_children(node) {
        match child.kind() {
            "|" | "|&" => {
                operators.push(ChainOperator::Pipe);
            }
            _ if child.is_named() => {
                walk_program(child, src, segments, operators);
            }
            _ => {}
        }
    }
}

// ========================================================
// Command extraction
// ========================================================

fn extract_command(node: tree_sitter::Node, src: &[u8]) -> CommandSegment {
    let mut seg = empty_segment();
    seg.raw = node_text(node, src).to_string();

    for child in all_children(node) {
        let kind = child.kind();
        match kind {
            "command_name" => {
                seg.executable = Some(node_text(child, src).to_string());
            }
            "variable_assignment" => {
                if let Some(assignment) = extract_assignment(child, src) {
                    seg.assignments.push(assignment);
                }
            }
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                if let Some(redir) = extract_redirection(child, src) {
                    seg.redirections.push(redir);
                }
            }
            _ if child.is_named() && kind != "command_name" => {
                let arg = extract_argument(child, src);
                seg.args.push(arg);
            }
            _ => {}
        }
    }

    seg
}

fn extract_redirected_statement(node: tree_sitter::Node, src: &[u8]) -> CommandSegment {
    let mut seg = empty_segment();
    seg.raw = node_text(node, src).to_string();

    for child in all_children(node) {
        match child.kind() {
            "command" => {
                let inner = extract_command(child, src);
                seg.executable = inner.executable;
                seg.args = inner.args;
                seg.assignments = inner.assignments;
                seg.redirections.extend(inner.redirections);
            }
            "pipeline" => {
                seg.raw = node_text(child, src).to_string();
            }
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                if let Some(redir) = extract_redirection(child, src) {
                    seg.redirections.push(redir);
                }
            }
            _ => {}
        }
    }

    seg
}

// ========================================================
// Argument extraction with expansion/quote detection
// ========================================================

fn extract_argument(node: tree_sitter::Node, src: &[u8]) -> Argument {
    let text = node_text(node, src).to_string();
    let kind = node.kind();

    let (is_quoted, quote_type) = match kind {
        "string" | "translated_string" => (true, Some(QuoteType::Double)),
        "raw_string" => (true, Some(QuoteType::Single)),
        "ansi_c_string" => (true, Some(QuoteType::AnsiC)),
        "heredoc_body" => (true, Some(QuoteType::Heredoc)),
        "concatenation" => {
            let mut found_quote = false;
            let mut qt = None;
            for child in named_children(node) {
                match child.kind() {
                    "string" | "translated_string" => {
                        found_quote = true;
                        qt = Some(QuoteType::Double);
                    }
                    "raw_string" => {
                        found_quote = true;
                        qt = Some(QuoteType::Single);
                    }
                    "ansi_c_string" => {
                        found_quote = true;
                        qt = Some(QuoteType::AnsiC);
                    }
                    _ => {}
                }
            }
            (found_quote, qt)
        }
        _ => (false, None),
    };

    let (has_expansion, expansion_type) = detect_expansion(node, src, &text);

    Argument {
        value: text,
        is_quoted,
        quote_type,
        has_expansion,
        expansion_type,
    }
}

fn detect_expansion(
    node: tree_sitter::Node,
    src: &[u8],
    text: &str,
) -> (bool, Option<ExpansionType>) {
    // First check child nodes for tree-sitter recognized expansions
    if let Some(exp) = detect_expansion_from_children(node, src) {
        return (true, Some(exp));
    }

    // Fallback: text pattern matching
    detect_expansion_from_text(text)
}

fn detect_expansion_from_children(node: tree_sitter::Node, _src: &[u8]) -> Option<ExpansionType> {
    fn walk(node: tree_sitter::Node) -> Option<ExpansionType> {
        match node.kind() {
            "simple_expansion" | "expansion" => return Some(ExpansionType::Variable),
            "command_substitution" => return Some(ExpansionType::Command),
            "arithmetic_expansion" => return Some(ExpansionType::Arithmetic),
            "process_substitution" => return Some(ExpansionType::Process),
            _ => {}
        }
        for child in named_children(node) {
            if let Some(exp) = walk(child) {
                return Some(exp);
            }
        }
        None
    }
    walk(node)
}

fn detect_expansion_from_text(text: &str) -> (bool, Option<ExpansionType>) {
    // Check for backtick command substitution
    if text.contains('`') {
        return (true, Some(ExpansionType::Command));
    }

    // Check for $(...) or ${...} or $VAR
    if text.contains("$((") {
        return (true, Some(ExpansionType::Arithmetic));
    }
    if text.contains("$(") {
        return (true, Some(ExpansionType::Command));
    }
    if text.contains("${") || (text.contains('$') && text.len() > 1) {
        return (true, Some(ExpansionType::Variable));
    }

    // Tilde expansion
    if text.starts_with('~') {
        return (true, Some(ExpansionType::Tilde));
    }

    // Glob patterns
    if text.contains('*') || text.contains('?') || text.contains('[') {
        return (true, Some(ExpansionType::Glob));
    }

    // Brace expansion
    if text.contains('{') && text.contains('}') && text.contains(',') {
        return (true, Some(ExpansionType::Brace));
    }

    (false, None)
}

// ========================================================
// Redirection extraction
// ========================================================

fn extract_redirection(node: tree_sitter::Node, src: &[u8]) -> Option<Redirection> {
    match node.kind() {
        "file_redirect" => {
            let mut fd = None;
            let mut direction = RedirDirection::Out;
            let mut target = String::new();

            for child in all_children(node) {
                let child_text = node_text(child, src);
                match child.kind() {
                    "file_descriptor" => {
                        fd = child_text.parse::<u32>().ok();
                    }
                    ">" => {
                        direction = RedirDirection::Out;
                    }
                    "<" => {
                        direction = RedirDirection::In;
                    }
                    ">>" => {
                        direction = RedirDirection::Append;
                    }
                    "&>" | "&>>" | ">&" => {
                        direction = RedirDirection::Out;
                    }
                    "<&" => {
                        direction = RedirDirection::In;
                    }
                    "word" | "number" | "string" | "raw_string" | "concatenation" => {
                        target = child_text.to_string();
                    }
                    _ if child.is_named() => {
                        target = child_text.to_string();
                    }
                    _ => {}
                }
            }

            Some(Redirection {
                fd,
                direction,
                target,
            })
        }
        "heredoc_redirect" => Some(Redirection {
            fd: None,
            direction: RedirDirection::HereDoc,
            target: node_text(node, src).to_string(),
        }),
        "herestring_redirect" => Some(Redirection {
            fd: None,
            direction: RedirDirection::HereString,
            target: node_text(node, src).to_string(),
        }),
        _ => None,
    }
}

// ========================================================
// Variable assignment extraction
// ========================================================

fn extract_assignment(node: tree_sitter::Node, src: &[u8]) -> Option<Assignment> {
    if node.kind() != "variable_assignment" {
        return None;
    }

    let mut name = String::new();
    let mut value = String::new();

    for child in named_children(node) {
        match child.kind() {
            "variable_name" => {
                name = node_text(child, src).to_string();
            }
            _ => {
                value = node_text(child, src).to_string();
            }
        }
    }

    // If we didn't find a variable_name child, try parsing from text
    if name.is_empty() {
        let text = node_text(node, src);
        if let Some(eq_pos) = text.find('=') {
            name = text[..eq_pos].to_string();
            value = text[eq_pos + 1..].to_string();
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(Assignment { name, value })
}

// ========================================================
// Helpers
// ========================================================

const SCRIPT_SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"];

/// True when this segment *is* a shell/`eval` invocation whose program is
/// an inline script (`bash -c '...'`, `eval '...'`). Its commands are
/// analyzed as segments of their own, so the invocation itself is just the
/// launcher.
pub(crate) fn runs_inline_script(seg: &CommandSegment) -> bool {
    let Some(exe) = seg.executable.as_deref() else {
        return false;
    };
    let base = exe.rsplit('/').next().unwrap_or(exe);
    if base != "eval" && !SCRIPT_SHELLS.contains(&base) {
        return false;
    }
    !embedded_scripts(seg).is_empty()
}

/// Script strings a segment hands to a shell or to `eval`: the argument
/// after `-c` (or a combined short flag containing `c`, like `-lc`) that
/// follows a shell name anywhere in the argv, and `eval`'s joined arguments.
fn embedded_scripts(seg: &CommandSegment) -> Vec<String> {
    let mut tokens: Vec<&str> = Vec::new();
    if let Some(exe) = seg.executable.as_deref() {
        tokens.push(exe);
    }
    tokens.extend(seg.args.iter().map(|a| a.value.as_str()));

    let unquote = |t: &str| -> String {
        let t = t.trim();
        let stripped = t
            .strip_prefix('\'')
            .and_then(|x| x.strip_suffix('\''))
            .or_else(|| t.strip_prefix('"').and_then(|x| x.strip_suffix('"')));
        stripped.unwrap_or(t).to_string()
    };
    let base = |t: &str| -> String {
        let u = unquote(t);
        u.rsplit('/').next().unwrap_or(&u).to_string()
    };

    let mut scripts = Vec::new();
    if tokens.first().map(|t| base(t)) == Some("eval".to_string()) && tokens.len() > 1 {
        scripts.push(
            tokens[1..]
                .iter()
                .map(|t| unquote(t))
                .collect::<Vec<_>>()
                .join(" "),
        );
        return scripts;
    }
    for (i, tok) in tokens.iter().enumerate() {
        if !SCRIPT_SHELLS.contains(&base(tok).as_str()) {
            continue;
        }
        let mut j = i + 1;
        while j < tokens.len() && tokens[j].starts_with('-') {
            let flag = tokens[j];
            let is_c = !flag.starts_with("--") && flag[1..].contains('c');
            if is_c {
                if let Some(script) = tokens.get(j + 1) {
                    scripts.push(unquote(script));
                }
                break;
            }
            j += 1;
        }
    }
    scripts
}

/// Walk `node` as the next statement, joining whatever segments it yields to
/// the ones before it with `Sequence` -- unless the walk already supplied
/// that connecting operator itself (a `list`'s `&&`, a pipeline's `|`).
///
/// `operators[k]` joins `segments[k]` and `segments[k + 1]`, so the
/// connector has to be *inserted* ahead of any operators the child pushed
/// for its own internals; appending it afterwards (as the program walk used
/// to) misorders `a; b | c` as `[Pipe, Sequence]`.
fn walk_sequenced(
    node: tree_sitter::Node,
    src: &[u8],
    segments: &mut Vec<CommandSegment>,
    operators: &mut Vec<ChainOperator>,
) {
    let prev_segments = segments.len();
    let prev_operators = operators.len();
    walk_program(node, src, segments, operators);

    let added_segments = segments.len() - prev_segments;
    let added_operators = operators.len() - prev_operators;
    if added_segments > 0 && prev_segments > 0 && added_operators < added_segments {
        operators.insert(prev_operators, ChainOperator::Sequence);
    }
}

/// Every command/process substitution node in the tree, outermost first.
/// Nested substitutions are included too: `walk_program` skips them, so
/// each body is walked exactly once, from its own entry here.
fn collect_substitutions<'t>(node: tree_sitter::Node<'t>, out: &mut Vec<tree_sitter::Node<'t>>) {
    if matches!(node.kind(), "command_substitution" | "process_substitution") {
        out.push(node);
    }
    for child in all_children(node) {
        collect_substitutions(child, out);
    }
}

fn node_text<'a>(node: tree_sitter::Node, src: &'a [u8]) -> &'a str {
    node.utf8_text(src).unwrap_or("")
}

fn empty_segment() -> CommandSegment {
    CommandSegment {
        raw: String::new(),
        executable: None,
        args: vec![],
        redirections: vec![],
        assignments: vec![],
        is_subshell: false,
    }
}

fn fallback_segment(command: &str) -> CommandSegment {
    CommandSegment {
        raw: command.to_string(),
        executable: None,
        args: vec![],
        redirections: vec![],
        assignments: vec![],
        is_subshell: false,
    }
}
