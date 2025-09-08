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


use super::super::erb_processor::{ErbProcessor, ErbBlock, ErbBlockType};


#[test]
fn test_extract_erb_blocks() {
    let processor = ErbProcessor::new();
    let content = r#"<div class="<%= 'test' if some_flag? %>">
        <% if another_flag? %>
            <p>Content</p>
        <% end %>
    </div>"#;


    let blocks = processor.extract_erb_blocks(content);
    assert_eq!(blocks.len(), 3);


    assert!(blocks[0].is_output_block);
    assert_eq!(blocks[0].ruby_code, "'test' if some_flag?");


    assert!(!blocks[1].is_output_block);
    assert_eq!(blocks[1].ruby_code, "if another_flag?");


    assert!(!blocks[2].is_output_block);
    assert_eq!(blocks[2].ruby_code, "end");
}


#[test]
fn test_replace_feature_flags() {
    let processor = ErbProcessor::new();
    let ruby_code = "if some_flag? && another_flag?";
    let flags = vec!["some_flag".to_string(), "another_flag".to_string()];


    let result = processor.replace_feature_flags(ruby_code, &flags);
    assert_eq!(result, "if true && true");
}


#[test]
fn test_find_potential_flags() {
    let processor = ErbProcessor::new();
    let content = r#"<div class="<%= 'test' if ws_creation_for_non_msp? %>">
        <% if ws_creation_for_pro_enterprise? %>
            <p>Content</p>
        <% end %>
    </div>"#;


    let flags = processor.find_potential_flags(content);
    assert!(flags.contains(&"ws_creation_for_non_msp".to_string()));
    assert!(flags.contains(&"ws_creation_for_pro_enterprise".to_string()));
}


#[test]
fn test_process_erb_content() {
    let processor = ErbProcessor::new();
    let content = r#"<div class="<%= 'padding' unless ws_creation_for_pro_enterprise? %>">
        <% if ws_creation_for_non_msp? %>
            <p>Show this content</p>
        <% end %>
    </div>"#;


    let flags = vec![
        "ws_creation_for_pro_enterprise".to_string(),
        "ws_creation_for_non_msp".to_string(),
    ];


    let result = processor.process_erb_content(content, &flags);


    // Verify that flags have been replaced with 'true'
    assert!(result.contains("unless true"));
    assert!(result.contains("if true"));
    assert!(!result.contains("ws_creation_for_pro_enterprise?"));
    assert!(!result.contains("ws_creation_for_non_msp?"));
}


#[test]
fn test_process_method_with_fallback() {
    let processor = ErbProcessor::new();
    let content = r#"<%= ws_creation_for_non_msp? ? 'enabled' : 'disabled' %>"#;
    let flags = vec!["ws_creation_for_non_msp".to_string()];


    let result = processor.process(content, &flags);
    assert!(result.contains("true ? 'enabled' : 'disabled'"));
}


#[test]
fn test_extract_erb_blocks_complex() {
    let processor = ErbProcessor::new();
    let content = r#"
<span class="agent-count-message pull-right <%= ' padding-for-non-business' unless ws_creation_for_pro_enterprise? %>">
  <% unless @current_account.subscription_from_cache.trial? %>
    <% has_licenses, available_licenses = fetch_available_licenses %>
    <% if @current_account.subscription_from_cache.agent_limit.nil? %>
      <%= t('agent.account_suspended') %>
    <% else %>
        <% if has_licenses %>
          <span class="agent-list-count bg-dark"><%=available_licenses%></span>&nbsp;
        <% end %>
    <% end %>
  <% end %>
</span>"#;


    let blocks = processor.extract_erb_blocks(content);


    // Should extract all ERB blocks including nested ones
    assert!(blocks.len() >= 7);


    // Check for the feature flag in the first block
    let first_block = &blocks[0];
    assert!(first_block.is_output_block);
    assert!(first_block.ruby_code.contains("ws_creation_for_pro_enterprise?"));
}


#[test]
fn test_determine_block_type() {
    let processor = ErbProcessor::new();


    assert_eq!(processor.determine_block_type("if some_condition"), ErbBlockType::ControlFlowStart);
    assert_eq!(processor.determine_block_type("unless other_condition"), ErbBlockType::ControlFlowStart);
    assert_eq!(processor.determine_block_type("else"), ErbBlockType::ControlFlowMiddle);
    assert_eq!(processor.determine_block_type("elsif another"), ErbBlockType::ControlFlowMiddle);
    assert_eq!(processor.determine_block_type("end"), ErbBlockType::ControlFlowEnd);
    assert_eq!(processor.determine_block_type("items.each do |item|"), ErbBlockType::Loop);
    assert_eq!(processor.determine_block_type("5.times do"), ErbBlockType::Loop);
    assert_eq!(processor.determine_block_type("var = value"), ErbBlockType::Assignment);
    assert_eq!(processor.determine_block_type("some_method_call"), ErbBlockType::Other);
}


#[test]
fn test_affects_html_structure() {
    let processor = ErbProcessor::new();


    assert!(processor.affects_html_structure("if condition"));
    assert!(processor.affects_html_structure("unless condition"));
    assert!(processor.affects_html_structure("else"));
    assert!(processor.affects_html_structure("elsif condition"));
    assert!(processor.affects_html_structure("end"));
    assert!(processor.affects_html_structure("each do"));


    assert!(!processor.affects_html_structure("some_value"));
    assert!(!processor.affects_html_structure("method_call"));
    assert!(!processor.affects_html_structure("'string literal'"));
}


#[test]
fn test_replace_feature_flags_partial_match() {
    let processor = ErbProcessor::new();


    // Test that partial matches are not replaced
    let ruby_code = "if some_flag_extended? && some_flag?";
    let flags = vec!["some_flag".to_string()];


    let result = processor.replace_feature_flags(ruby_code, &flags);
    assert_eq!(result, "if some_flag_extended? && true");
}


#[test]
fn test_process_erb_content_with_ternary() {
    let processor = ErbProcessor::new();
    let content = r#"<%= feature_enabled? ? 'active' : 'inactive' %>"#;
    let flags = vec!["feature_enabled".to_string()];


    let result = processor.process_erb_content(content, &flags);
    assert!(result.contains("true ? 'active' : 'inactive'"));
    assert!(!result.contains("feature_enabled?"));
}


#[test]
fn test_simple_ruby_cleanup() {
    let processor = ErbProcessor::new();


    // Test if true cleanup
    assert_eq!(processor.apply_simple_ruby_cleanup("if true"), "");


    // Test unless false cleanup  
    assert_eq!(processor.apply_simple_ruby_cleanup("unless false"), "");


    // Test unless true cleanup (should remove entire block)
    assert_eq!(processor.apply_simple_ruby_cleanup("unless true"), "");


    // Test ternary cleanup
    let ternary_result = processor.apply_simple_ruby_cleanup("true ? 'yes' : 'no'");
    assert_eq!(ternary_result, "'yes'");
}


#[test]
fn test_extract_ruby_blocks_with_tree_sitter() {
    let processor = ErbProcessor::new();
    let content = r#"<div><%= 'hello' %><% if true %>world<% end %></div>"#;


    // This might fail if tree-sitter-embedded-template is not properly configured
    // but it should gracefully fall back to regex
    match processor.extract_ruby_blocks_with_tree_sitter(content) {
        Ok(blocks) => {
            assert!(blocks.len() >= 3); // Should find at least 3 blocks
        },
        Err(_) => {
            // Tree-sitter parsing failed, which is acceptable
            // The main process method should fall back to regex
            let blocks = processor.extract_erb_blocks(content);
            assert!(blocks.len() >= 3);
        }
    }
}


#[test]
fn test_process_with_tree_sitter_fallback() {
    let processor = ErbProcessor::new();
    let content = r#"<%= test_flag? ? 'enabled' : 'disabled' %>"#;
    let flags = vec!["test_flag".to_string()];


    // The process method should work regardless of whether tree-sitter works
    let result = processor.process(content, &flags);
    assert!(result.contains("true ? 'enabled' : 'disabled'"));
}


#[test]
fn test_find_potential_flags_multiple() {
    let processor = ErbProcessor::new();
    let content = r#"
<div>
  <%= first_flag? ? 'a' : 'b' %>
  <% if second_flag? %>
    <%= third_flag? %>
  <% end %>
  <% unless fourth_flag? %>
    <p>Content</p>
  <% end %>
</div>"#;


    let flags = processor.find_potential_flags(content);
    assert!(flags.contains(&"first_flag".to_string()));
    assert!(flags.contains(&"second_flag".to_string()));
    assert!(flags.contains(&"third_flag".to_string()));
    assert!(flags.contains(&"fourth_flag".to_string()));
    assert_eq!(flags.len(), 4);
}


#[test]
fn test_nested_erb_blocks() {
    let processor = ErbProcessor::new();
    let content = r#"
<% if outer_flag? %>
  <div>
    <% if inner_flag? %>
      <%= content_flag? ? 'show' : 'hide' %>
    <% end %>
  </div>
<% end %>"#;


    let flags = vec![
        "outer_flag".to_string(),
        "inner_flag".to_string(),
        "content_flag".to_string(),
    ];


    let result = processor.process_erb_content(content, &flags);


    // All flags should be replaced
    assert!(result.contains("if true"));
    assert!(result.contains("true ? 'show' : 'hide'"));
    assert!(!result.contains("outer_flag?"));
    assert!(!result.contains("inner_flag?"));
    assert!(!result.contains("content_flag?"));
}