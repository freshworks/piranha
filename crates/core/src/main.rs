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

//! Defines the entry-point for Piranha.
use std::{fs, process, time::Instant};
use log::{debug, info};
use polyglot_piranha::{
  execute_piranha, models::{
    language::PiranhaLanguage, 
    piranha_arguments::{PiranhaArguments, PiranhaArgumentsBuilder}, piranha_output::PiranhaOutputSummary},
};
use serde::de;
use tree_sitter::{Parser, Range};

/// Demo function showing proper tree-sitter multi-language parsing for ERB
fn demo_erb_parsing() {
  println!("=== Tree-sitter ERB Multi-language Parsing Demo ===");
  
  // Read ERB content from file
  let erb_content = std::fs::read_to_string("/Users/bsunder/uber/piranha/erb_test/sample.html.erb")
    .expect("Failed to read ERB file");
  let erb_content_ref = &erb_content;

  println!("ERB Content:");
  println!("{}", erb_content_ref);
  println!();

  // Step 1: Parse the entire document as ERB using embedded-template parser
  let mut parser = Parser::new();
  parser
    .set_language(tree_sitter_embedded_template::language().into()).unwrap();
  let erb_tree = parser.parse(erb_content_ref, None).unwrap();
  let erb_root = erb_tree.root_node();

  println!("ERB AST:");
  println!("{}", erb_root.to_sexp());
  println!();

  // Step 2: Extract ranges for HTML content and Ruby code
  let mut content_ranges = Vec::new();
  let mut ruby_ranges = Vec::new();
  extract_ranges(erb_root, erb_content_ref, &mut content_ranges, &mut ruby_ranges);

  println!("Extracted ranges:");
  println!("Ruby ranges: {} found", ruby_ranges.len());
  let mut ruby_snippet: String = String::new();
  for (i, range) in ruby_ranges.iter().enumerate() {
    let text = &erb_content_ref[range.start_byte..range.end_byte];
    ruby_snippet.push_str(text);  
    println!("  Ruby {}: {:?} -> {:?}", i, range, text);
  }
  println!();

  println!("Extracted content ranges:");
  println!("content ranges: {} found", content_ranges.len());
  for (i, range) in content_ranges.iter().enumerate() {
    let text = &erb_content_ref[range.start_byte..range.end_byte];
    println!("  content {}: {:?} -> {:?}", i, range, text);
  }
  println!();

  // Step 4: Parse Ruby using only the code ranges  
  if !ruby_ranges.is_empty() {

    let args = PiranhaArguments::from_cli();
    parser.set_language(tree_sitter_ruby::language()).unwrap();
    parser.set_included_ranges(&ruby_ranges).unwrap();
    if let Some(ruby_tree) = parser.parse(erb_content_ref, None) {
      println!("Ruby AST (parsed from ranges):");
      println!("{}", ruby_snippet);
      println!();
      // let  node_text = ruby_tree.root_node().utf8_text(erb_content_ref.as_bytes()).unwrap();
      println!("Ruby Code snippet for cleanup \n{}", ruby_snippet);
      let piranha_args = PiranhaArgumentsBuilder::default()
        .path_to_configurations("/Users/bsunder/uber/piranha/erb_test/rules.toml".to_string())
        .code_snippet(ruby_snippet.to_owned())
        .substitutions(args.substitutions().clone())
        .language(PiranhaLanguage::from("ruby"))
        .allow_dirty_ast(true)
        .build();

      let cleaned = execute_piranha(&piranha_args);
      println!("Piranha cleaned output:");
      for summary in cleaned {
        println!("{}", summary.content());
      }
    }
  }

  // Step 5: Run Piranha cleanup on each Ruby code range
  // println!("\n=== Piranha Cleanup on Ruby Ranges ===");
  // for (i, range) in ruby_ranges.iter().enumerate() {
  //   let ruby_code = &erb_content_ref[range.start_byte..range.end_byte];
  //   println!("\nRuby Range {}: {:?}", i, range);
  //   println!("Original Ruby code:\n{}", ruby_code);

  //   // Prepare minimal arguments for Piranha using the builder pattern
  //   let piranha_args = PiranhaArgumentsBuilder::default()
  //       .paths_to_codebase(vec!["/Users/bsunder/uber/piranha/erb_test".to_string()])
  //       .path_to_configurations("/Users/bsunder/uber/piranha/erb_test/rules.toml".to_string())
  //       .language(PiranhaLanguage::from("erb"))
  //       .dry_run(true)
  //       .allow_dirty_ast(true)
  //       .build();

  //   // Run Piranha cleanup on the extracted Ruby code
  //   let cleaned = execute_piranha(&piranha_args);
  //   println!("Piranha cleaned output:");
  //   for summary in cleaned {
  //     println!("{}", summary.content());
  //   }
  // }

  // Step 5: Run piranha cleanups for ruby code string
  println!("=== End ERB Demo ===");
  println!();
}

/// Extract HTML and Ruby ranges from the ERB AST
fn extract_ranges(node: tree_sitter::Node, source: &str, content_ranges: &mut Vec<Range>, ruby_ranges: &mut Vec<Range>) {
  let node_type = node.kind();
  // Check if this is a content node (HTML) or code node (Ruby)
  if node_type == "content" {
    content_ranges.push(Range {
      start_byte: node.start_byte(),
      end_byte: node.end_byte(),
      start_point: node.start_position(),
      end_point: node.end_position(),
    });
  } else if node_type == "directive" {
    // For code nodes, we want the actual Ruby code inside
    if let Some(code_child) = node.named_child(0) {
      ruby_ranges.push(Range {
        start_byte: code_child.start_byte(),
        end_byte: code_child.end_byte(),
        start_point: code_child.start_position(),
        end_point: code_child.end_position(),
      });
    }
  }
  
  // Recursively process children
  for i in 0..node.child_count() {
    if let Some(child) = node.child(i) {
      extract_ranges(child, source, content_ranges, ruby_ranges);
    }
  }
}


fn demo_rb_piranha_cleanups() {
  let args = PiranhaArguments::from_cli();

  let piranha_output_summaries = execute_piranha(&args);

  if let Some(path) = args.path_to_output_summary() {
    write_output_summary(piranha_output_summaries, path);
  }

}
fn main() {
  // Set up the Ctrl+C handler
  ctrlc::set_handler(move || {
    println!("Received Ctrl+C! Exiting...");
    process::exit(130);
  })
  .expect("Error setting Ctrl+C handler");

  // Add ERB parsing demo
  // demo_erb_parsing();

  demo_rb_parsing();
  return;

  let now = Instant::now();
  env_logger::init();
  // return;
  info!("Executing Polyglot Piranha");

  let args = PiranhaArguments::from_cli();

  let piranha_output_summaries = execute_piranha(&args);

  if let Some(path) = args.path_to_output_summary() {
    write_output_summary(piranha_output_summaries, path);
  }

  info!("Time elapsed - {:?}", now.elapsed().as_secs());
}

/// Writes the output summaries to a Json file named `path_to_output_summaries` .
fn write_output_summary(
  piranha_output_summaries: Vec<PiranhaOutputSummary>, path_to_json: &String,
) {
  if let Ok(contents) = serde_json::to_string_pretty(&piranha_output_summaries) {
    if fs::write(path_to_json, contents).is_ok() {
      return;
    }
  }
  panic!("Could not write the output summary to the file - {path_to_json}");
}
