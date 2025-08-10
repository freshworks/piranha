/*
Copyright (c) 2023 Uber Technologies, Inc.

 <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
 except in compliance with the License. You may obtain a copy of the License at
 <p>http://www.apache.org/licenses/LICENSE-2.0

 <p>Unless required by applicable law or agreed to in writing, software distributed under the
 License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 express or implied. See the License for the specific language governing permissions and
 limitations under the License.
*/
use std::{
  collections::{HashMap, VecDeque},
  path::{Path, PathBuf},
};

use colored::Colorize;
use itertools::Itertools;
use log::{debug, error};

use tree_sitter::{InputEdit, Node, Parser, Tree};

use crate::{
  models::capture_group_patterns::CGPattern,
  models::rule_graph::{GLOBAL, PARENT, PARENT_ITERATIVE},
  utilities::tree_sitter_utilities::{
    get_node_for_range, get_replace_range, get_tree_sitter_edit, number_of_errors,
  },
};

use super::{
  edit::Edit,
  matches::{Match, Range},
  piranha_arguments::PiranhaArguments,
  rule::InstantiatedRule,
  rule_store::RuleStore,
};
use getset::{CopyGetters, Getters, MutGetters, Setters};
// Maintains the updated source code content and AST of the file
#[derive(Clone, Getters, CopyGetters, MutGetters, Setters)]
pub(crate) struct SourceCodeUnit {
  // The tree representing the file
  ast: Tree,
  // The original content of a file
  #[get = "pub"]
  #[set = "pub(crate)"]
  original_content: String,
  // The content of a file
  #[get = "pub"]
  #[set = "pub(crate)"]
  code: String,
  // The tag substitution cache.
  // This map is looked up to instantiate new rules.
  #[get = "pub"]
  substitutions: HashMap<String, String>,
  // The path to the source code.
  #[get = "pub"]
  #[set = "pub(crate)"]
  path: PathBuf,

  // Rewrites applied to this source code unit
  #[get = "pub"]
  #[get_mut = "pub"]
  rewrites: Vec<Edit>,
  // Matches for the read_only rules in this source code unit
  #[get = "pub"]
  #[get_mut = "pub"]
  matches: Vec<(String, Match)>,
  // Piranha Arguments passed by the user
  #[get = "pub"]
  piranha_arguments: PiranhaArguments,
}

impl SourceCodeUnit {
  pub(crate) fn new(
    parser: &mut Parser, code: String, substitutions: &HashMap<String, String>, path: &Path,
    piranha_arguments: &PiranhaArguments,
  ) -> Self {
    let ast = if Self::is_erb_file(path) {
      Self::parse_erb_with_ranges(parser, &code)
    } else {
      parser.parse(&code, None).expect("Could not parse code")
    };

    println!(
      "Initializing source code with {}, ast {}, and source code {}",
      path.display(),
      ast.root_node().to_sexp(),
      code
    );

    let source_code_unit = Self {
      ast,
      original_content: code.to_string(),
      code,
      substitutions: substitutions.clone(),
      path: path.to_path_buf(),
      rewrites: Vec::new(),
      matches: Vec::new(),
      piranha_arguments: piranha_arguments.clone(),
    };
    // Panic if allow dirty ast is false and the tree is syntactically incorrect
    if !piranha_arguments.allow_dirty_ast() && source_code_unit._number_of_errors() > 0 {
      error!("{}: {}", "Syntax Error".red(), path.to_str().unwrap().red());
      _ = &source_code_unit._panic_for_syntax_error();
    }

    source_code_unit
  }

  /// Check if the file is an ERB file
  fn is_erb_file(path: &Path) -> bool {
    path.extension()
      .and_then(|ext| ext.to_str())
      .map(|ext| ext == "erb")
      .unwrap_or(false)
  }

  /// Parse ERB file using Tree-sitter ranges
  fn parse_erb_with_ranges(parser: &mut Parser, erb_content: &str) -> Tree {
    // First, parse as ERB to extract ranges
    parser.set_language(tree_sitter_embedded_template::language()).unwrap();
    parser.set_included_ranges(&[]).unwrap(); // Clear any existing ranges

    let erb_tree = parser.parse(erb_content, None).expect("Could not parse ERB");
    let erb_root = erb_tree.root_node();

    // Extract Ruby ranges from ERB tree
    let ruby_ranges = Self::extract_ruby_ranges_from_erb(&erb_root, erb_content);

    if ruby_ranges.is_empty() {
      // If no Ruby ranges found, create a minimal AST that won't cause syntax errors
      // We'll create an empty Ruby program that the parser can understand
      parser.set_language(tree_sitter_ruby::language()).unwrap();
      parser.set_included_ranges(&[]).unwrap(); // Clear ranges to parse entire content
      
      // Try parsing as plain text - create a minimal valid Ruby program
      let minimal_ruby = "# Empty Ruby program for ERB without Ruby code";
      return parser.parse(minimal_ruby, None).expect("Could not create minimal Ruby AST");
    }

    // Parse Ruby content using ranges
    parser.set_language(tree_sitter_ruby::language()).unwrap();
    parser.set_included_ranges(&ruby_ranges).unwrap();

    let ruby_tree = parser.parse(erb_content, None).expect("Could not parse Ruby with ranges");

    // Debug: Print the AST to understand the structure
    println!("ERB Range-based Ruby AST: {}", ruby_tree.root_node().to_sexp());

    ruby_tree
  }

  /// Extract Ruby code ranges from ERB tree with proper boundary handling
  fn extract_ruby_ranges_from_erb(erb_root: &tree_sitter::Node, content: &str) -> Vec<tree_sitter::Range> {
    let mut ruby_ranges = Vec::new();

    // Traverse the ERB tree to find Ruby code nodes
    Self::traverse_erb_node_for_ranges(erb_root, &mut ruby_ranges);

    // Sort ranges by start position to ensure they're in order
    ruby_ranges.sort_by_key(|range| range.start_byte);

    // Debug: Print the extracted ranges for troubleshooting
    println!("DEBUG: Extracted {} Ruby ranges from ERB:", ruby_ranges.len());
    for (i, range) in ruby_ranges.iter().enumerate() {
      let text = &content[range.start_byte..range.end_byte];
      println!("  Range {}: bytes[{}..{}] -> '{}'", i, range.start_byte, range.end_byte, text);
    }

    ruby_ranges
  }

  /// Extract Ruby code ranges from ERB tree, ensuring proper boundary handling
  fn traverse_erb_node_for_ranges(node: &tree_sitter::Node, ranges: &mut Vec<tree_sitter::Range>) {
    let node_type = node.kind();

    match node_type {
      "directive" => {
        // For directive nodes, we need to find the actual Ruby code content
        // and exclude the ERB markers (<% %>)
        if let Some(code_node) = node.named_child(0) {
          if code_node.kind() == "code" {
            // The code node contains the actual Ruby code without ERB markers
            let range = tree_sitter::Range {
              start_byte: code_node.start_byte(),
              end_byte: code_node.end_byte(),
              start_point: code_node.start_position(),
              end_point: code_node.end_position(),
            };
            ranges.push(range);
          }
        }
      }
      "output_directive" => {
        // For output directives (<%=), handle similarly but preserve the structure
        if let Some(code_node) = node.named_child(0) {
          if code_node.kind() == "code" {
            let range = tree_sitter::Range {
              start_byte: code_node.start_byte(),
              end_byte: code_node.end_byte(),
              start_point: code_node.start_position(),
              end_point: code_node.end_position(),
            };
            ranges.push(range);
          }
        }
      }
      _ => {
        // Recursively traverse other nodes
        for i in 0..node.child_count() {
          if let Some(child) = node.child(i) {
            Self::traverse_erb_node_for_ranges(&child, ranges);
          }
        }
      }
    }
  }

  pub(crate) fn root_node(&self) -> Node<'_> {
    self.ast.root_node()
  }

  /// Will apply the `rule` to all of its occurrences in the source code unit.
  fn apply_rule(
    &mut self, rule: InstantiatedRule, rules_store: &mut RuleStore, parser: &mut Parser,
    scope_query: &Option<CGPattern>,
  ) {
    loop {
      if !self._apply_rule(rule.clone(), rules_store, parser, scope_query) {
        break;
      }
    }
  }

  /// Applies the rule to the first match in the source code
  /// This is implements the main algorithm of piranha.
  /// Parameters:
  /// * `rule` : the rule to be applied
  /// * `rule_store`: contains the input rule graph.
  ///
  /// Algorithm:
  /// * check if the rule is match only
  /// ** IF not (i.e. it is a rewrite):
  /// *** Get the first match of the rule for the file
  ///  (We only get the first match because the idea is that we will apply this change, and keep calling this method `_apply_rule` until all
  /// matches have been exhaustively updated.
  /// *** Apply the rewrite
  /// *** Update the substitution table
  /// *** Propagate the change
  /// ** Else (i.e. it is a match only rule):
  /// *** Get all the matches, and for each match
  /// *** Update the substitution table
  /// *** Propagate the change
  fn _apply_rule(
    &mut self, rule: InstantiatedRule, rule_store: &mut RuleStore, parser: &mut Parser,
    scope_query: &Option<CGPattern>,
  ) -> bool {
    let scope_node = self.get_scope_node(scope_query, rule_store);
    println!("scope query: {:?}", scope_query);
    println!("Scope node text: {:?}", scope_node.utf8_text(self.code().as_bytes()).unwrap());
    println!("root node text: {:?}", self.root_node().utf8_text(self.code().as_bytes()).unwrap());
    let mut query_again = false;

    // When rule is a "rewrite" rule :
    // Update the first match of the rewrite rule
    // Add mappings to the substitution
    // Propagate each applied edit. The next rule will be applied relative to the application of this edit.
    println!("Applying rule: {:?}", rule.name());
    if !rule.rule().is_match_only_rule() {
      if let Some(edit) = self.get_edit(&rule, rule_store, scope_node, true) {
        println!("Found edit from source code unit {:?}", edit);  
        self.rewrites_mut().push(edit.clone());
        query_again = true;

        // Add all the (code_snippet, tag) mapping to the substitution table.
        self.substitutions.extend(edit.p_match().matches().clone());

        // Apply edit_1
        let applied_ts_edit = self.apply_edit(&edit, parser);

        self.propagate(get_replace_range(applied_ts_edit), rule, rule_store, parser);
      }
    }
    // When rule is a "match-only" rule :
    // Get all the matches
    // Add mappings to the substitution
    // Propagate each match. Note that,  we pass a identity edit (where old range == new range) in to the propagate logic.
    // The next edit will be applied relative to the identity edit.
    else {
      for m in self.get_matches(&rule, rule_store, scope_node, true) {
        self.matches_mut().push((rule.name(), m.clone()));

        // In this scenario we pass the match and replace range as the range of the match `m`
        // This is equivalent to propagating an identity rule
        //  i.e. a rule that replaces the matched code with itself
        // Note that, here we DO NOT invoke the `_apply_edit` method and only update the `substitutions`
        // By NOT invoking this we simulate the application of an identity rule
        //
        self.substitutions.extend(m.matches().clone());

        self.propagate(*m.range(), rule.clone(), rule_store, parser);
      }
    }
    query_again
  }

  /// This is the propagation logic of the Piranha's main algorithm.
  /// Parameters:
  ///  * `applied_ts_edit` -  it's(`rule`'s) application site (in terms of replacement range)
  ///  * `rule` - The `rule` that was just applied
  ///  * `rule_store` - contains the input "rule graph"
  ///  * `parser` - parser for the language
  /// Algorithm:
  ///
  /// (i) Lookup the `rule_store` and get all the (next) rules that could be after applying the current rule (`rule`).
  ///   * We will receive the rules grouped by scope:  `GLOBAL` and `PARENT` are applicable to each language. However, other scopes are determined
  ///     based on the `<language>/scope_config.toml`.
  /// (ii) Add the `GLOBAL` rule to the global rule list in the `rule_store` (This will be performed in the next iteration)
  /// (iii) Apply the local cleanup i.e. `PARENT` scoped rules
  ///  (iv) Go to step 1 (and repeat this for the applicable parent scoped rule. Do this until, no parent scoped rule is applicable.) (recursive)
  ///  (iv) Apply the rules based on custom language specific scopes (as defined in `<language>/scope_config.toml`) (recursive)
  ///
  fn propagate(
    &mut self, replace_range: Range, rule: InstantiatedRule, rules_store: &mut RuleStore,
    parser: &mut Parser,
  ) {
    let mut current_replace_range = replace_range;

    let mut current_rule = rule.name();
    let mut next_rules_stack: VecDeque<(CGPattern, InstantiatedRule)> = VecDeque::new();
    // Perform the parent edits, while queueing the Method and Class level edits.
    // let file_level_scope_names = [METHOD, CLASS];
    loop {
      debug!("Current Rule: {current_rule}");
      // Get all the (next) rules that could be after applying the current rule (`rule`).
      let next_rules_by_scope = self
        .piranha_arguments
        .rule_graph()
        .get_next(&current_rule, self.substitutions());

      debug!(
        "\n{}",
        &next_rules_by_scope
          .iter()
          .map(|(k, v)| {
            let rules = v.iter().map(|f| f.name()).join(", ");
            format!("Next Rules:\nScope {k} \nRules {rules}").blue()
          })
          .join("\n")
      );

      // Adds rules of scope != ["Parent", "Global"] to the stack
      self.add_rules_to_stack(
        &next_rules_by_scope,
        current_replace_range,
        rules_store,
        &mut next_rules_stack,
      );

      // Add Global rules as seed rules
      for r in &next_rules_by_scope[GLOBAL] {
        rules_store.add_to_global_rules(r);
      }

      // Process the parent
      // Find the rules to be applied in the "Parent" scope that match any parent (context) of the changed node in the previous edit
      if let Some(edit) =
        self.get_edit_for_ancestors(&current_replace_range, rules_store, &next_rules_by_scope)
      {
        println!("Found edit from propagate {:?}", edit);
        self.rewrites_mut().push(edit.clone());
        // Apply the matched rule to the parent
        let applied_edit = self.apply_edit(&edit, parser);
        current_replace_range = get_replace_range(applied_edit);
        current_rule = edit.matched_rule().to_string();
        // Add the (tag, code_snippet) mapping to substitution table.
        self.substitutions.extend(edit.p_match().matches().clone());
      } else {
        break;
      }
    }
    // Apply the next rules from the stack
    for (sq, rle) in &next_rules_stack {
      self.apply_rule(rle.clone(), rules_store, parser, &Some(sq.clone()));
    }
  }

  /// Adds the "Method" and "Class" scoped next rules to the queue.
  fn add_rules_to_stack(
    &mut self, next_rules_by_scope: &HashMap<String, Vec<InstantiatedRule>>,
    current_match_range: Range, rules_store: &mut RuleStore,
    stack: &mut VecDeque<(CGPattern, InstantiatedRule)>,
  ) {
    for (scope_level, rules) in next_rules_by_scope {
      // Scope level is not "Parent", "ParentIterative" or "Global"
      if ![PARENT, PARENT_ITERATIVE, GLOBAL].contains(&scope_level.as_str()) {
        for rule in rules {
          let scope_query = self.get_scope_query(
            scope_level,
            *current_match_range.start_byte(),
            *current_match_range.end_byte(),
            rules_store,
          );
          // Add Method and Class scoped rules to the queue
          stack.push_front((scope_query, rule.clone()));
        }
      }
    }
  }

  fn get_scope_node(&self, scope_query: &Option<CGPattern>, rules_store: &mut RuleStore) -> Node {
    // Get scope node
    // let mut scope_node = self.root_node();
    if let Some(query_str) = scope_query {
      // Apply the scope query in the source code and get the appropriate node
      let scope_pattern = rules_store.query(query_str);
      println!("Scope pattern: {:?}", scope_pattern);
      println!("query_str: {:?}", query_str);
      if let Some(p_match) = scope_pattern.get_match(&self.root_node(), self.code(), true) {
        return get_node_for_range(
          self.root_node(),
          *p_match.range().start_byte(),
          *p_match.range().end_byte(),
        );
      }
    }
    self.root_node()
  }

  /// Apply all `rules` sequentially.
  pub(crate) fn apply_rules(
    &mut self, rules_store: &mut RuleStore, rules: &[InstantiatedRule], parser: &mut Parser,
    scope_query: Option<CGPattern>,
  ) {
    for rule in rules {
      self.apply_rule(rule.to_owned(), rules_store, parser, &scope_query)
    }
    self.perform_delete_consecutive_new_lines();
  }

  /// Applies an edit to the source code unit
  /// # Arguments
  /// * `replace_range` - the range of code to be replaced
  /// * `replacement_str` - the replacement string
  /// * `parser`
  ///
  /// # Returns
  /// The `edit:InputEdit` performed.
  ///
  /// Note - Causes side effect. - Updates `self.ast` and `self.code`
  pub(crate) fn apply_edit(&mut self, edit: &Edit, parser: &mut Parser) -> InputEdit {
    // Log the source code before applying the edit
    debug!("Source code before edit:\n{}", self.code);
    debug!("Applying edit: {:?}", edit);

    // Enhanced handling for ERB files with mixed HTML/Ruby content
    let (new_source_code, ts_edit) = if Self::is_erb_file(&self.path) {
      // Handle all ERB-specific cleanup rules with proper mixed content support
      self.handle_erb_mixed_content_edit(edit)
    } else {
      get_tree_sitter_edit(self.code.clone(), edit)
    };

    // Apply edit to the tree
    let number_of_errors = self._number_of_errors();
    self.ast.edit(&ts_edit);
    self._replace_file_contents_and_re_parse(&new_source_code, parser, true);

    // Panic if the number of errors increased after the edit
    if self._number_of_errors() > number_of_errors {
      self._panic_for_syntax_error();
    }
    ts_edit
  }

  fn _panic_for_syntax_error(&self) {
    let msg = format!(
      "Produced syntactically incorrect source code {}",
      self.code()
    );
    panic!("{}", msg);
  }

  /// Returns the number of errors in this source code unit
  fn _number_of_errors(&self) -> usize {
    number_of_errors(&self.root_node())
  }

  // Replaces the content of the current file with the new content and re-parses the AST
  /// # Arguments
  /// * `replacement_content` - new content of file
  /// * `parser`
  /// * `is_current_ast_edited` : have you invoked `edit` on the current AST ?
  /// Note - Causes side effect. - Updates `self.ast` and `self.code`
  pub(crate) fn _replace_file_contents_and_re_parse(
    &mut self, replacement_content: &str, parser: &mut Parser, is_current_ast_edited: bool,
  ) {
    let prev_tree = if is_current_ast_edited {
      Some(&self.ast)
    } else {
      None
    };

    // Parse based on file type
    let new_tree = if Self::is_erb_file(&self.path) {
      Self::parse_erb_with_ranges(parser, replacement_content)
    } else {
      parser
        .parse(replacement_content, prev_tree)
        .expect("Could not generate new tree!")
    };
  
    self.ast = new_tree;
    self.code = replacement_content.to_string();
  }

  /// Enhanced ERB mixed content handler for all ERB cleanup scenarios
  /// This replaces the single-case handle_erb_if_true_edit with comprehensive mixed content support
  fn handle_erb_mixed_content_edit(&self, edit: &Edit) -> (String, tree_sitter::InputEdit) {
    use crate::utilities::tree_sitter_utilities::{get_tree_sitter_edit, position_for_offset};

    println!("Handling ERB mixed content edit for file: {:?}", self.path);
    println!("Edit rule: {}", edit.matched_rule());
    println!("Edit: {:?}", edit);

    let source_content = &self.code;
    let rule_name = edit.matched_rule();

    // Handle different ERB cleanup scenarios
    match rule_name.as_str() {
      "replace_if_false" | "replace_if_true" | "replace_empty_if_true" => {
        self.handle_erb_conditional_cleanup(edit, source_content)
      }
      "replace_flag_with_boolean_literal" => {
        // For flag replacement, use standard tree-sitter but be aware of ERB context
        self.handle_erb_flag_replacement(edit, source_content)
      }
      _ => {
        // For other rules, try ERB-aware processing first, fallback to standard
        self.handle_erb_general_cleanup(edit, source_content)
      }
    }
  }

  /// Handle ERB conditional cleanup (if/else/end blocks with mixed content)
  fn handle_erb_conditional_cleanup(
    &self, edit: &Edit, source_content: &str,
  ) -> (String, tree_sitter::InputEdit) {
    use crate::utilities::tree_sitter_utilities::get_tree_sitter_edit;

    // Parse the ERB file to extract structure
    let mut parser = tree_sitter::Parser::new();
    parser
      .set_language(tree_sitter_embedded_template::language())
      .unwrap();

    if let Some(erb_tree) = parser.parse(source_content, None) {
      let erb_root = erb_tree.root_node();
      let ruby_ranges = Self::extract_ruby_ranges_from_erb(&erb_root, source_content);

      if ruby_ranges.len() >= 2 {
        if let Some(result) =
          self.process_erb_conditional_structure(&ruby_ranges, source_content, edit)
        {
          return result;
        }
      }
    }

    // Fallback to standard tree-sitter edit
    get_tree_sitter_edit(source_content.to_string(), edit)
  }

  /// Process ERB conditional structure (if-else-end) with proper content extraction
  fn process_erb_conditional_structure(
    &self, ruby_ranges: &[tree_sitter::Range], source_content: &str, edit: &Edit,
  ) -> Option<(String, tree_sitter::InputEdit)> {
    use crate::utilities::tree_sitter_utilities::position_for_offset;

    // Analyze the Ruby ranges to identify if-else-end structure
    if ruby_ranges.is_empty() {
      return None;
    }

    let first_ruby = &source_content[ruby_ranges[0].start_byte..ruby_ranges[0].end_byte].trim();

    // Check for if condition
    let (is_if_true, is_if_false) = if first_ruby.contains("if false") {
      (false, true)
    } else if first_ruby.contains("if true") {
      (true, false)
    } else {
      return None;
    };

    // Find else and end positions
    let mut else_index: Option<usize> = None;
    let mut end_index: Option<usize> = None;

    for (i, range) in ruby_ranges.iter().enumerate().skip(1) {
      let ruby_content = &source_content[range.start_byte..range.end_byte].trim();
      if ruby_content == &"else" && else_index.is_none() {
        else_index = Some(i);
      } else if ruby_content == &"end" {
        end_index = Some(i);
        break;
      }
    }

    let end_idx = end_index?; // Must have end

    // Calculate content boundaries
    let if_block_start = ruby_ranges[0].start_byte - 2; // Include <%
    let if_block_end = ruby_ranges[end_idx].end_byte + 2; // Include %>

    // Determine what content to keep based on the condition
    let kept_content = if is_if_false {
      // For if false, keep the else branch content (if it exists)
      if let Some(else_idx) = else_index {
        let else_content_start = ruby_ranges[else_idx].end_byte + 2; // After %> of else
        let else_content_end = ruby_ranges[end_idx].start_byte - 2; // Before <% of end
        &source_content[else_content_start..else_content_end]
      } else {
        // No else branch, remove everything
        ""
      }
    } else if is_if_true {
      // For if true, keep the if branch content
      let then_content_start = ruby_ranges[0].end_byte + 2; // After %> of if
      let then_content_end = if let Some(else_idx) = else_index {
        ruby_ranges[else_idx].start_byte - 2 // Before <% of else
      } else {
        ruby_ranges[end_idx].start_byte - 2 // Before <% of end
      };
      &source_content[then_content_start..then_content_end]
    } else {
      return None;
    };

    println!("ERB conditional cleanup:");
    println!(
      "  Condition: if {} (keeping {} branch)",
      if is_if_true { "true" } else { "false" },
      if is_if_false { "else" } else { "then" }
    );
    println!("  Kept content: '{}'", kept_content);

    // Build new source code
    let new_source = [
      &source_content[..if_block_start],
      kept_content,
      &source_content[if_block_end..],
    ]
    .concat();

    // Calculate InputEdit
    let old_source_bytes = source_content.as_bytes();
    let new_source_bytes = new_source.as_bytes();
    let start_byte = if_block_start;
    let old_end_byte = if_block_end;
    let new_end_byte = start_byte + kept_content.as_bytes().len();

    let input_edit = tree_sitter::InputEdit {
      start_byte,
      old_end_byte,
      new_end_byte,
      start_position: position_for_offset(old_source_bytes, start_byte),
      old_end_position: position_for_offset(old_source_bytes, old_end_byte),
      new_end_position: position_for_offset(new_source_bytes, new_end_byte),
    };

    Some((new_source, input_edit))
  }

  /// Handle ERB flag replacement while preserving ERB structure
  fn handle_erb_flag_replacement(
    &self, _edit: &Edit, source_content: &str,
  ) -> (String, tree_sitter::InputEdit) {
    use crate::utilities::tree_sitter_utilities::get_tree_sitter_edit;

    // For flag replacement, we can use the standard tree-sitter approach
    // because it only replaces the flag expression, not structural elements
    println!(
      "Handling ERB flag replacement for: {}",
      _edit.matched_rule()
    );
    get_tree_sitter_edit(source_content.to_string(), _edit)
  }

  /// Handle general ERB cleanup rules
  fn handle_erb_general_cleanup(
    &self, edit: &Edit, source_content: &str,
  ) -> (String, tree_sitter::InputEdit) {
    use crate::utilities::tree_sitter_utilities::get_tree_sitter_edit;

    println!(
      "Handling general ERB cleanup for rule: {}",
      edit.matched_rule()
    );

    // Try to intelligently handle the edit based on the matched content
    let matched_string = &edit.p_match().matched_string;

    // If the matched string spans across ERB boundaries (contains <% or %>),
    // we need special handling
    if matched_string.contains("<%") || matched_string.contains("%>") {
      println!("Matched string spans ERB boundaries, using ERB-aware processing");

      // Extract the replacement from the edit
      let replacement = &edit.replacement_string();

      // Find the exact location in the original source
      let range = edit.p_match().range();
      let start_byte = range.start_byte;
      let end_byte = range.end_byte;

      // Replace the matched content directly
      let new_source = [
        &source_content[..start_byte],
        replacement,
        &source_content[end_byte..],
      ]
      .concat();

      // Calculate InputEdit
      use crate::utilities::tree_sitter_utilities::position_for_offset;
      let old_source_bytes = source_content.as_bytes();
      let new_source_bytes = new_source.as_bytes();
      let new_end_byte = start_byte + replacement.as_bytes().len();

      let input_edit = tree_sitter::InputEdit {
        start_byte,
        old_end_byte: end_byte,
        new_end_byte,
        start_position: position_for_offset(old_source_bytes, start_byte),
        old_end_position: position_for_offset(old_source_bytes, end_byte),
        new_end_position: position_for_offset(new_source_bytes, new_end_byte),
      };

      (new_source, input_edit)
    } else {
      // Use standard tree-sitter approach
      get_tree_sitter_edit(source_content.to_string(), edit)
    }
  }

  pub(crate) fn global_substitutions(&self) -> HashMap<String, String> {
    self
      .substitutions()
      .iter()
      .filter(|e| e.0.starts_with(self.piranha_arguments.global_tag_prefix()))
      .map(|(a, b)| (a.to_string(), b.to_string()))
      .collect()
  }

  // pub(crate) fn extract_ruby_code_from_erb(&self, erb_content: &str) -> Option<String> {
  //   // use crate::models::erb_processor::ErbProcessor;
  //   let erb_processor = ErbProcessor::new();
  //   // Extract Ruby ranges from ERB
  //   if let Ok(ruby_ranges) = erb_processor.extract_ruby_blocks_with_tree_sitter(erb_content) {
  //     let mut ruby_code = String::new();
  //     for range in &ruby_ranges {
  //       ruby_code.push_str(&erb_content[range.start_byte..range.end_byte]);
  //       ruby_code.push('\n');
  //     }
  //     Some(ruby_code)
  //   } else {
  //     None
  //   }
  // }
}

#[cfg(test)]
#[path = "unit_tests/source_code_unit_test.rs"]
mod source_code_unit_test;