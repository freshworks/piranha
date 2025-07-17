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

use regex::Regex;
use std::collections::HashMap;
use tree_sitter::{Parser, Node, Tree};
// use tree_sitter_embedded_template;

/// ERB processor that handles the 3-step process:
/// 1. Parse ERB structure to identify Ruby code blocks
/// 2. Replace feature flag patterns (flag_name?) with true
/// 3. Apply Ruby cleanup rules to the modified code
pub struct ErbProcessor {
    /// Regex to match ERB code blocks (<% %> and <%= %>)
    erb_block_regex: Regex,
    /// Regex to match feature flag patterns (method_name?)
    feature_flag_regex: Regex,
}

#[derive(Debug, Clone)]
pub struct ErbBlock {
    /// The full matched text including ERB delimiters
    pub full_match: String,
    /// The Ruby code inside the ERB block (without delimiters)
    pub ruby_code: String,
    /// Whether this is an output block (<%= %>) or code block (<% %>)
    pub is_output_block: bool,
    /// Start position in the original string
    pub start_pos: usize,
    /// End position in the original string
    pub end_pos: usize,
    /// Whether this block contains control flow that affects HTML structure
    pub affects_html_structure: bool,
    /// The nesting level of this block (for proper reconstruction)
    pub nesting_level: usize,
    /// The type of Ruby block (if, unless, loop, etc.)
    pub block_type: ErbBlockType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ErbBlockType {
    /// Simple expression: <%= ... %>
    Expression,
    /// Control flow start: <% if ... %>
    ControlFlowStart,
    /// Control flow middle: <% else %>, <% elsif ... %>
    ControlFlowMiddle,
    /// Control flow end: <% end %>
    ControlFlowEnd,
    /// Loop: <% array.each do |item| %>
    Loop,
    /// Assignment: <% var = value %>
    Assignment,
    /// Other Ruby code
    Other,
}

impl ErbProcessor {
    pub fn new() -> Self {
        // Regex to match ERB blocks: <%...%> and <%=...%>
        // This captures both the output blocks (<%=) and regular code blocks (<%)
        let erb_block_regex = Regex::new(r"<%=?\s*(.*?)\s*%>").unwrap();
        
        // Regex to match feature flag patterns: word_characters followed by ?
        let feature_flag_regex = Regex::new(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\?").unwrap();
        
        Self {
            erb_block_regex,
            feature_flag_regex,
        }
    }

    /// Parse ERB using tree-sitter-embedded-template for proper multi-language support
    pub fn parse_erb_with_tree_sitter(&self, _content: &str) -> Result<Tree, String> {
        let _parser = Parser::new();
        // parser
        //     .set_language(tree_sitter_embedded_template::language())
        //     .map_err(|e| format!("Failed to set embedded template language: {:?}", e))?;
        
        // parser
        //     .parse(content, None)
        //     .ok_or_else(|| "Failed to parse ERB content with tree-sitter-embedded-template".to_string())
        Err("Tree-sitter embedded template temporarily disabled".to_string())
    }

    /// Extract Ruby code blocks using tree-sitter parsing
    pub fn extract_ruby_blocks_with_tree_sitter(&self, content: &str) -> Result<Vec<ErbBlock>, String> {
        let _tree = self.parse_erb_with_tree_sitter(content)?;
        let blocks = Vec::new();
        
        // Tree-sitter implementation temporarily disabled
        /*
        // Query for ERB code blocks in the tree-sitter AST
        let ruby_query = Query::new(
            tree_sitter_embedded_template::language(),
            r#"
            (code_block) @code
            (output_block) @output
            "#,
        ).map_err(|e| format!("Failed to create query: {:?}", e))?;
        
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&ruby_query, tree.root_node(), content.as_bytes());
        
        for query_match in matches {
            for capture in query_match.captures {
                let node = capture.node;
                let start_pos = node.start_byte();
                let end_pos = node.end_byte();
                let full_match = &content[start_pos..end_pos];
                
                // Extract the Ruby code inside the ERB delimiters
                let ruby_code = self.extract_ruby_code_from_node(node, content);
                let is_output_block = capture.index == 1; // output blocks have index 1
                
                blocks.push(ErbBlock {
                    full_match: full_match.to_string(),
                    ruby_code,
                    is_output_block,
                    start_pos,
                    end_pos,
                    affects_html_structure: false,
                    nesting_level: 0,
                    block_type: ErbBlockType::Other,
                });
            }
        }
        */
        
        Ok(blocks)
    }
    
    /// Extract Ruby code from a tree-sitter node
    fn extract_ruby_code_from_node(&self, node: Node, content: &str) -> String {
        // For ERB blocks, we need to extract the content between the delimiters
        let full_text = node.utf8_text(content.as_bytes()).unwrap_or("");
        
        // Remove ERB delimiters: <% %> or <%= %>
        if full_text.starts_with("<%=") {
            full_text.strip_prefix("<%=").unwrap_or(full_text)
                .strip_suffix("%>").unwrap_or(full_text)
                .trim().to_string()
        } else if full_text.starts_with("<%") {
            full_text.strip_prefix("<%").unwrap_or(full_text)
                .strip_suffix("%>").unwrap_or(full_text)
                .trim().to_string()
        } else {
            full_text.trim().to_string()
        }
    }

    /// Enhanced ERB processing using tree-sitter for better accuracy
    pub fn process_erb_content_with_tree_sitter(&self, content: &str, flag_names: &[String]) -> Result<String, String> {
        let blocks = self.extract_ruby_blocks_with_tree_sitter(content)?;
        let mut result = content.to_string();
        
        // Process blocks in reverse order to maintain correct positions
        for block in blocks.iter().rev() {
            let processed_ruby = self.replace_feature_flags(&block.ruby_code, flag_names);
            
            // Reconstruct the ERB block with processed Ruby code
            let new_block = if block.is_output_block {
                format!("<%= {} %>", processed_ruby)
            } else {
                format!("<% {} %>", processed_ruby)
            };
            
            // Replace the original block with the processed one
            result.replace_range(block.start_pos..block.end_pos, &new_block);
        }
        
        Ok(result)
    }

    /// Step 1: Parse ERB content and extract Ruby code blocks (regex fallback method)
    pub fn extract_erb_blocks(&self, content: &str) -> Vec<ErbBlock> {
        let mut blocks = Vec::new();
        
        for captures in self.erb_block_regex.captures_iter(content) {
            if let (Some(full_match), Some(ruby_code)) = (captures.get(0), captures.get(1)) {
                let full_text = full_match.as_str();
                let is_output_block = full_text.starts_with("<%=");
                
                blocks.push(ErbBlock {
                    full_match: full_text.to_string(),
                    ruby_code: ruby_code.as_str().trim().to_string(),
                    is_output_block,
                    start_pos: full_match.start(),
                    end_pos: full_match.end(),
                    affects_html_structure: false,
                    nesting_level: 0,
                    block_type: ErbBlockType::Other,
                });
            }
        }
        
        blocks
    }

    /// Process ERB content by applying rules.toml rules to Ruby code blocks
    /// This preserves ERB structure while allowing rules to transform Ruby code
    pub fn process_erb_with_rules(&self, content: &str, substitutions: &HashMap<String, String>) -> String {
        let blocks = self.extract_erb_blocks(content);
        let mut result = content.to_string();
        
        // Process blocks in reverse order to maintain correct positions
        for block in blocks.iter().rev() {
            // Apply rules-based transformation to the Ruby code
            let processed_ruby = self.apply_rules_to_ruby_code(&block.ruby_code, substitutions);
            
            // Only update if the Ruby code changed
            if processed_ruby != block.ruby_code {
                // Reconstruct the ERB block with processed Ruby code
                let new_block = if block.is_output_block {
                    format!("<%= {} %>", processed_ruby)
                } else {
                    format!("<% {} %>", processed_ruby)
                };
                
                // Replace the original block with the processed one
                result.replace_range(block.start_pos..block.end_pos, &new_block);
            }
        }
        
        result
    }
    
    /// Reconstruct ERB file from original content and transformed Ruby code
    /// This preserves the ERB structure while applying transformations from rules
    pub fn reconstruct_erb_from_transformed_ruby(&self, original_erb_content: &str, transformed_ruby_code: &str) -> String {
        let original_blocks = self.extract_erb_blocks(original_erb_content);
        
        // Split the transformed Ruby code into individual statements/expressions
        // Each line in the transformed Ruby corresponds to a Ruby block from the original ERB
        let ruby_lines: Vec<&str> = transformed_ruby_code.lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect();
        
        let mut result = original_erb_content.to_string();
        
        // Process blocks in reverse order to maintain correct positions
        // Match each original block with its corresponding transformed Ruby line
        for (index, block) in original_blocks.iter().enumerate().rev() {
            if index < ruby_lines.len() {
                let transformed_ruby = ruby_lines[index];
                let original_ruby = block.ruby_code.trim();
                
                // Only update if the transformed Ruby code is different from original
                if transformed_ruby != original_ruby {
                    let new_block_content = if block.is_output_block {
                        format!("<%= {} %>", transformed_ruby)
                    } else {
                        format!("<% {} %>", transformed_ruby)
                    };
                    
                    // Replace the original block with the processed one
                    result.replace_range(block.start_pos..block.end_pos, &new_block_content);
                }
            }
        }
        
        result
    }

    /// Apply rules.toml-based transformations to Ruby code
    /// This should integrate with Piranha's rule system, not do hard-coded replacements
    fn apply_rules_to_ruby_code(&self, ruby_code: &str, _substitutions: &HashMap<String, String>) -> String {
        // TODO: This should use actual rules.toml rules via Piranha's Ruby parser
        // For now, we return the ruby_code unchanged since rules.toml should handle transformations
        // When we integrate with Piranha's rule engine, this will apply actual rules
        ruby_code.to_string()
    }

    /// Preprocess ERB content for Ruby parser compatibility
    /// This extracts Ruby code blocks but doesn't do flag replacement
    /// The flag replacement will be handled by rules.toml rules
    pub fn preprocess_for_ruby_parser(&self, content: &str) -> String {
        let blocks = self.extract_erb_blocks(content);
        println!("DEBUG: ERB preprocessing - extracted {} blocks:", blocks.len());
        
        let mut result = String::new();
        
        // Extract all Ruby code and combine it
        for (i, block) in blocks.iter().enumerate() {
            println!("DEBUG: Block {}: '{}' (output: {})", i, block.ruby_code, block.is_output_block);
            result.push_str(&block.ruby_code);
            result.push('\n');
        }
        
        println!("DEBUG: Final Ruby code to be parsed:\n{}", result);
        
        // If no Ruby blocks found, return the original content
        if result.trim().is_empty() {
            content.to_string()
        } else {
            result
        }
    }

    /// Step 2: Replace feature flag patterns with 'true' in Ruby code
    pub fn replace_feature_flags(&self, ruby_code: &str, flag_names: &[String]) -> String {
        let mut result = ruby_code.to_string();
        
        // Replace each specified flag with 'true'
        for flag_name in flag_names {
            let pattern = format!(r"\b{}\?", regex::escape(flag_name));
            if let Ok(flag_regex) = Regex::new(&pattern) {
                result = flag_regex.replace_all(&result, "true").to_string();
            }
        }
        
        result
    }

    /// Process an entire ERB file: extract blocks, replace flags, and reconstruct (regex fallback)
    pub fn process_erb_content(&self, content: &str, flag_names: &[String]) -> String {
        let blocks = self.extract_erb_blocks(content);
        let mut result = content.to_string();
        
        // Process blocks in reverse order to maintain correct positions
        for block in blocks.iter().rev() {
            let processed_ruby = self.replace_feature_flags(&block.ruby_code, flag_names);
            
            // Reconstruct the ERB block with processed Ruby code
            let new_block = if block.is_output_block {
                format!("<%= {} %>", processed_ruby)
            } else {
                format!("<% {} %>", processed_ruby)
            };
            
            // Replace the original block with the processed one
            result.replace_range(block.start_pos..block.end_pos, &new_block);
        }
        
        result
    }

    /// Extract all potential feature flag names from Ruby code blocks
    pub fn find_potential_flags(&self, content: &str) -> Vec<String> {
        let blocks = self.extract_erb_blocks(content);
        let mut flags = Vec::new();
        
        for block in blocks {
            for captures in self.feature_flag_regex.captures_iter(&block.ruby_code) {
                if let Some(flag_match) = captures.get(1) {
                    let flag_name = flag_match.as_str().to_string();
                    if !flags.contains(&flag_name) {
                        flags.push(flag_name);
                    }
                }
            }
        }
        
        flags
    }

    /// Main processing method that tries tree-sitter first, falls back to regex
    pub fn process(&self, content: &str, flag_names: &[String]) -> String {
        // Try tree-sitter-embedded-template first for better accuracy
        match self.process_erb_content_with_tree_sitter(content, flag_names) {
            Ok(result) => result,
            Err(_) => {
                // Fall back to regex-based processing if tree-sitter fails
                self.process_erb_content(content, flag_names)
            }
        }
    }

    /// Enhanced processing that preserves HTML/JS structure while cleaning Ruby
    pub fn process_with_structure_preservation(&self, content: &str, flag_names: &[String]) -> String {
        // Step 1: Extract blocks with enhanced metadata
        let blocks = self.extract_enhanced_erb_blocks(content);
        
        // Step 2: Replace feature flags in each block
        let mut processed_blocks = Vec::new();
        for block in &blocks {
            let processed_ruby = self.replace_feature_flags(&block.ruby_code, flag_names);
            let mut processed_block = block.clone();
            processed_block.ruby_code = processed_ruby;
            processed_blocks.push(processed_block);
        }
        
        // Step 3: Apply Ruby cleanup rules to individual blocks
        let cleaned_blocks = self.apply_ruby_cleanup_to_blocks(processed_blocks);
        
        // Step 4: Reconstruct ERB with cleaned Ruby code
        self.reconstruct_erb_with_structure(content, &cleaned_blocks)
    }
    
    /// Extract ERB blocks with enhanced structural information
    fn extract_enhanced_erb_blocks(&self, content: &str) -> Vec<ErbBlock> {
        let mut blocks = self.extract_erb_blocks(content);
        
        // Enhance blocks with structural information
        for block in &mut blocks {
            block.block_type = self.determine_block_type(&block.ruby_code);
            block.affects_html_structure = self.affects_html_structure(&block.ruby_code);
            block.nesting_level = self.calculate_nesting_level(content, block.start_pos);
        }
        
        blocks
    }
    
    /// Determine the type of Ruby block
    fn determine_block_type(&self, ruby_code: &str) -> ErbBlockType {
        let trimmed = ruby_code.trim();
        
        if trimmed.starts_with("if ") || trimmed.starts_with("unless ") {
            ErbBlockType::ControlFlowStart
        } else if trimmed == "else" || trimmed.starts_with("elsif ") {
            ErbBlockType::ControlFlowMiddle
        } else if trimmed == "end" {
            ErbBlockType::ControlFlowEnd
        } else if trimmed.contains(".each do") || trimmed.contains(".times do") {
            ErbBlockType::Loop
        } else if trimmed.contains(" = ") && !trimmed.contains("==") {
            ErbBlockType::Assignment
        } else {
            ErbBlockType::Other
        }
    }
    
    /// Check if this Ruby code affects HTML structure (controls rendering)
    fn affects_html_structure(&self, ruby_code: &str) -> bool {
        let control_keywords = ["if", "unless", "else", "elsif", "end", "each", "times", "while"];
        let trimmed = ruby_code.trim();
        
        control_keywords.iter().any(|keyword| {
            trimmed.starts_with(keyword) || trimmed == *keyword
        })
    }
    
    /// Calculate nesting level by counting unclosed control blocks before this position
    fn calculate_nesting_level(&self, content: &str, position: usize) -> usize {
        let content_before = &content[..position];
        let blocks_before = self.extract_erb_blocks(content_before);
        
        let mut nesting: usize = 0;
        for block in blocks_before {
            match self.determine_block_type(&block.ruby_code) {
                ErbBlockType::ControlFlowStart | ErbBlockType::Loop => nesting += 1,
                ErbBlockType::ControlFlowEnd => nesting = nesting.saturating_sub(1),
                _ => {}
            }
        }
        
        nesting
    }
    
    /// Apply Ruby cleanup rules to individual Ruby blocks
    fn apply_ruby_cleanup_to_blocks(&self, blocks: Vec<ErbBlock>) -> Vec<ErbBlock> {
        let mut cleaned_blocks = Vec::new();
        
        for block in blocks {
            // For now, we'll focus on flag replacement and simple cleanup
            // Later, this can integrate with Piranha's Ruby cleanup rules
            let cleaned_ruby = self.apply_simple_ruby_cleanup(&block.ruby_code);
            
            let mut cleaned_block = block;
            cleaned_block.ruby_code = cleaned_ruby;
            cleaned_blocks.push(cleaned_block);
        }
        
        cleaned_blocks
    }
    
    /// Apply simple Ruby cleanup (dead code elimination after flag replacement)
    fn apply_simple_ruby_cleanup(&self, ruby_code: &str) -> String {
        let mut result = ruby_code.to_string();
        
        // Clean up patterns like "if true" -> remove condition
        result = result.replace("if true", "");
        result = result.replace("unless false", "");
        
        // Clean up ternary with true condition: "true ? a : b" -> "a"
        let ternary_regex = Regex::new(r"true\s*\?\s*([^:]+)\s*:\s*[^}>\n]+").unwrap();
        result = ternary_regex.replace_all(&result, "$1").to_string();
        
        // Clean up unless true (always false): "unless true" -> remove entire block
        if result.trim() == "unless true" {
            result = "".to_string();
        }
        
        result.trim().to_string()
    }
    
    /// Reconstruct ERB file preserving HTML/JS structure
    fn reconstruct_erb_with_structure(&self, original_content: &str, cleaned_blocks: &[ErbBlock]) -> String {
        let mut result = original_content.to_string();
        
        // Process blocks in reverse order to maintain correct positions
        for block in cleaned_blocks.iter().rev() {
            let new_block_content = if block.ruby_code.is_empty() {
                // If Ruby code was completely removed, remove the entire ERB block
                "".to_string()
            } else if block.is_output_block {
                format!("<%= {} %>", block.ruby_code)
            } else {
                format!("<% {} %>", block.ruby_code)
            };
            
            // Handle structural changes carefully
            if block.affects_html_structure && block.ruby_code.is_empty() {
                // For structural blocks that were completely removed,
                // we need to also remove any orphaned HTML content
                result = self.handle_orphaned_html_content(&result, block);
            } else {
                // Simple replacement for non-structural or preserved blocks
                result.replace_range(block.start_pos..block.end_pos, &new_block_content);
            }
        }
        
        result
    }
    
    /// Handle HTML content that becomes orphaned when Ruby control blocks are removed
    fn handle_orphaned_html_content(&self, content: &str, removed_block: &ErbBlock) -> String {
        // This is a complex algorithm that would need to:
        // 1. Identify HTML content controlled by the removed Ruby block
        // 2. Determine if that HTML should also be removed
        // 3. Preserve HTML that's not conditionally rendered
        
        // For now, we'll implement a simple version
        if removed_block.block_type == ErbBlockType::ControlFlowStart {
            // Look for the matching end block and remove content between them
            self.remove_conditional_html_block(content, removed_block)
        } else {
            // For non-control blocks, just remove the ERB block itself
            let mut result = content.to_string();
            result.replace_range(removed_block.start_pos..removed_block.end_pos, "");
            result
        }
    }
    
    /// Remove HTML content between conditional Ruby blocks that were eliminated
    fn remove_conditional_html_block(&self, content: &str, start_block: &ErbBlock) -> String {
        // Find the matching end block
        let blocks = self.extract_enhanced_erb_blocks(content);
        let mut nesting = 0;
        let mut end_position = None;
        
        for block in blocks.iter().skip_while(|b| b.start_pos <= start_block.start_pos) {
            match block.block_type {
                ErbBlockType::ControlFlowStart | ErbBlockType::Loop => nesting += 1,
                ErbBlockType::ControlFlowEnd => {
                    if nesting == 0 {
                        end_position = Some(block.end_pos);
                        break;
                    }
                    nesting -= 1;
                }
                _ => {}
            }
        }
        
        if let Some(end_pos) = end_position {
            // Remove the entire conditional block including HTML content
            let mut result = content.to_string();
            result.replace_range(start_block.start_pos..end_pos, "");
            result
        } else {
            // Fallback: just remove the start block
            let mut result = content.to_string();
            result.replace_range(start_block.start_pos..start_block.end_pos, "");
            result
        }
    }

    /// Extract Ruby code ranges from an ERB file using tree-sitter
    pub fn extract_ruby_ranges_with_tree_sitter(&self, erb_content: &str) -> Result<Vec<tree_sitter::Range>, String> {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_embedded_template::language())
            .map_err(|e| format!("Failed to set ERB language: {:?}", e))?;
        let erb_tree = parser.parse(erb_content, None)
            .ok_or_else(|| "Failed to parse ERB content".to_string())?;
        let erb_root = erb_tree.root_node();
        let mut ruby_ranges = Vec::new();
        // Traverse the ERB AST to find Ruby code ranges
        for i in 0..erb_root.child_count() {
            if let Some(node) = erb_root.child(i) {
                if node.kind() == "directive" {
                    if let Some(code_child) = node.named_child(0) {
                        ruby_ranges.push(tree_sitter::Range {
                            start_byte: code_child.start_byte(),
                            end_byte: code_child.end_byte(),
                            start_point: code_child.start_position(),
                            end_point: code_child.end_position(),
                        });
                    }
                }
            }
        }
        Ok(ruby_ranges)
    }

    /// Parse only the Ruby ranges from an ERB file using tree-sitter
    pub fn parse_ruby_ranges(&self, erb_content: &str, ruby_ranges: &[tree_sitter::Range]) -> Result<tree_sitter::Tree, String> {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_ruby::language())
            .map_err(|e| format!("Failed to set Ruby language: {:?}", e))?;
        parser.set_included_ranges(ruby_ranges)
            .map_err(|e| format!("Failed to set included ranges: {:?}", e))?;
        parser.parse(erb_content, None)
            .ok_or_else(|| "Failed to parse Ruby code".to_string())
    }
}

impl Default for ErbProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "unit_tests/erb_processor_test.rs"]
mod erb_processor_test;
