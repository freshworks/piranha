// /*
//  Copyright (c) 2023 Uber Technologies, Inc.

//  <p>Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//  <p>http://www.apache.org/licenses/LICENSE-2.0

//  <p>Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
//  express or implied. See the License for the specific language governing permissions and
//  limitations under the License.
// */

// // Update the import path to the correct location of Range
// use crate::models::matches::Range;
// use tree_sitter::Parser;
// // use tree_sitter_embedded_template;

// /// ERB processor that handles the 3-step process:
// /// 1. Parse ERB structure to identify Ruby code blocks
// /// 2. Replace feature flag patterns (flag_name?) with true
// /// 3. Apply Ruby cleanup rules to the modified code
// pub struct ErbProcessor {
//     /// Path to the original ERB file
//     pub filepath: String,
//     /// Contents of the original ERB file
//     pub file_contents: String,
// }

// impl ErbProcessor {
//     /// Create a new ErbProcessor with file path and contents
//     pub fn new(filepath: String, file_contents: String) -> Self {
//         Self {
//             filepath,
//             file_contents,
//         }
//     }

//     pub fn process_erb_content(erb_content_ref: &str) {
//         let mut parser = Parser::new();
//         parser
//             .set_language(tree_sitter_embedded_template::language().into()).unwrap();
//         let erb_tree = parser.parse(erb_content_ref, None).unwrap();
//         let erb_root = erb_tree.root_node();

//         println!("ERB AST:");
//         println!("{}", erb_root.to_sexp());
//         println!();

//         // Step 2: Extract ranges for HTML content and Ruby code
//         let mut html_ranges = Vec::new();
//         let mut ruby_ranges = Vec::new();
//         Self::extract_ranges(erb_root, erb_content_ref, &mut html_ranges, &mut ruby_ranges);
//     }

//     // Extract HTML and Ruby ranges from the ERB AST
//     fn extract_ranges(node: tree_sitter::Node, source: &str, html_ranges: &mut Vec<Range>, ruby_ranges: &mut Vec<Range>) {
//         let node_type = node.kind();
//         // Check if this is a content node (HTML) or code node (Ruby)
//         if node_type == "content" {
//             html_ranges.push(Range {
//             start_byte: node.start_byte(),
//             end_byte: node.end_byte(),
//             start_point: node.start_position().into(),
//             end_point: node.end_position().into(),
//             });
//         } else if node_type == "directive" {
//             // For code nodes, we want the actual Ruby code inside
//             if let Some(code_child) = node.named_child(0) {
//             ruby_ranges.push(Range {
//                 start_byte: code_child.start_byte(),
//                 end_byte: code_child.end_byte(),
//                 start_point: code_child.start_position().into(),
//                 end_point: code_child.end_position().into(),
//             });
//             }
//         }

//         // Recursively process children
//         for i in 0..node.child_count() {
//             if let Some(child) = node.child(i) {
//             Self::extract_ranges(child, source, html_ranges, ruby_ranges);
//             }
//         }
//     }
// }

// // Conversion from tree_sitter::Point to models::matches::Point
// impl From<tree_sitter::Point> for Point {
//     fn from(ts_point: tree_sitter::Point) -> Self {
//         Point {
//             row: ts_point.row,
//             column: ts_point.column,
//         }
//     }
// }


// #[cfg(test)]
// #[path = "unit_tests/erb_processor_test.rs"]
// mod erb_processor_test;
