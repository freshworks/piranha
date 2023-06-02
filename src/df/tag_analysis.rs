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

use crate::df::df::{Direction, Sigma};
use crate::df::utils::get_tags_from_matcher;
use crate::models::filter::Filter;
use crate::models::rule::Rule;
use crate::models::rule_graph::RuleGraph;
use crate::models::source_code_unit::SourceCodeUnit;
use crate::utilities::tree_sitter_utilities::{get_all_matches_for_query, TSQuery};
use clap::builder::Str;
use getset::Getters;
use std::collections::{HashMap, HashSet};
use std::string::String;
use tree_sitter::{Parser, Query};
use tree_sitter_tsq;

// This file implements a data flow analysis similar to the "Definite Assignment Analysis" problem
// in compilers. Instead of tracking variable definitions, it tracks "tags" as they propagate
// through a query, modeled as a directed graph of rules (`RuleGraph`).
// The goal of the analysis is to find, for each point in the query,
// the set of tags that could reach that point without any redefinitions.
// The result can then be used to check if the query contains any tag that was not reached.

#[derive(Debug, Clone)]
pub struct DefiniteAssignmentSigma {
  variables: HashSet<String>,
  is_top: bool, // hack to prevent initializing variables with all elements for top
}

impl Sigma for DefiniteAssignmentSigma {
  type Node = Rule;

  // The `merge` function computes the intersection of two sets of reaching tags.
  // This is a conservative approach that ensures that a tag is considered "reaching"
  // only if it can reach a point along all paths leading to that point.
  fn merge(&self, _other: &Self) -> Self {
    if self.is_top {
      return _other.clone();
    }
    if _other.is_top {
      return self.clone();
    }
    let new_variables: HashSet<String> = self
      .variables
      .iter()
      .cloned()
      .filter(|var| _other.variables.contains(var))
      .collect();
    DefiniteAssignmentSigma {
      variables: new_variables,
      is_top: false,
    }
  }

  fn is_equal(&self, _other: &Self) -> bool {
    self.variables == _other.variables && self.is_top == _other.is_top
  }
}

pub struct ForwardDefiniteAssignment {
  graph: RuleGraph,
}

impl Direction for ForwardDefiniteAssignment {
  type Node = Rule;
  type Sigma = DefiniteAssignmentSigma;

  fn successors(&self, _rule: &Rule) -> Vec<Rule> {
    // Get the rules and discard the edge type from the tuple
    // (we don't care if it's a Parent, File, etc)
    let child_rules: Vec<String> = self
      .graph
      .get_neighbors(_rule.name())
      .iter()
      .map(|(_, v)| v.clone())
      .collect();

    // Get the actual rule objects that we are going to use in the analysis.
    self
      .graph
      .rules()
      .iter()
      .filter(|r| child_rules.contains(r.name()))
      .cloned()
      .collect()
  }

  // Since the join operator or this analysis is intersection, the initial value
  // needs to be the set of all tags.
  // It feels weird separating to have the neet function (merge) outside this class
  fn initial_value() -> DefiniteAssignmentSigma {
    DefiniteAssignmentSigma {
      variables: HashSet::new(),
      is_top: true,
    }
  }

  // Substitutions provided by the user are the entry point of all seed rules
  // FIXME this needs to be updated
  fn entry_value() -> DefiniteAssignmentSigma {
    DefiniteAssignmentSigma {
      variables: HashSet::new(),
      is_top: false,
    }
  }

  // The `transfer` function takes a rule and the current set of reaching tags
  // (represented by `DefiniteAssignmentSigma`). It then computes the new set of reaching tags
  // after the rule is applied. This is done by inserting into the set all the tags
  // that are defined in the rule.
  fn transfer(_node: &Rule, _input: &DefiniteAssignmentSigma) -> DefiniteAssignmentSigma {
    let mut result = _input.clone();
    let res = get_tags_from_matcher(&_node);
    // insert res to result.variables
    result.variables.extend(res.iter().cloned());
    result
  }
}

#[cfg(test)]
#[path = "unit_tests/tag_analysis_test.rs"]
mod tag_analysis_test;