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

use std::path::PathBuf;

use crate::{
  execute_piranha,
  models::{
    default_configs::RUBY, language::PiranhaLanguage,
    piranha_arguments::PiranhaArgumentsBuilder,
  },
  tests::initialize,
  utilities::eq_without_whitespace,
};

use super::create_rewrite_tests;

create_rewrite_tests! {
  RUBY,
  test_replace_empty_if_unless_statement: "replace_empty_if_or_unless_statement", 1;
  test_replace_ternary_operator: "replace_ternary_operator", 1;
  test_replace_if_statement: "replace_if_statement",  3;
  test_replace_unless_statement: "replace_unless_statement", 3;
  test_boolean_cleanup: "simplify_boolean_expressions", 1;
  test_simplify_rspec_block_expressions: "simplify_rspec_block_expressions", 1;
  test_simplify_if_lambda_conditional_statements: "simplify_if_lambda_conditional_statements", 1;
  test_simplify_unless_lambda_conditional_statements: "simplify_unless_lambda_conditional_statements", 1;
  test_simplify_if_proc_conditional_statements: "simplify_if_proc_conditional_statements", 1;
  test_simplify_unless_proc_conditional_statements: "simplify_if_proc_conditional_statements", 1;
  test_delete_lines_after_return: "delete_lines_after_return", 1;
  simplify_variable_assigned_flag_check: "simplify_variable_assigned_flag_check", 1;
  test_replace_empty_if_true_block: "replace_empty_if_true_block", 1;
}
#[test]
fn test_simple_ruby_cleanup_code_snippet() {
  initialize();
  let path_to_scenario = PathBuf::from("erb_test");
  let code_snippet = r#"
      if true
          security_desk_url = "https://#{@portal_url}/admin/security"
      end
  "#;
  let expected = r#"
      security_desk_url = "https://#{@portal_url}/admin/security"
  "#;
  let piranha_arguments = PiranhaArgumentsBuilder::default()
    .language(PiranhaLanguage::from(RUBY))
    .code_snippet(code_snippet.to_string())
    .build();

  let output_summaries = execute_piranha(&piranha_arguments);
    println!("output summaries {:?}", output_summaries);
}