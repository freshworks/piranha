# Test cases for replace_empty_if_true_block rule
# This rule removes if statements with empty true blocks and only else clauses

# Basic case - simple condition with empty true block
def test_basic_empty_if_true
  if some_condition?
  else
    puts "This should remain"
  end
end

# Test with different condition types
def test_with_boolean_condition
  if true
  else
    puts "This should remain"
  end
end

def test_with_false_condition
  if false
  else
    puts "This should remain"
  end
end

def test_with_method_call_condition
  if Account.current.feature_enabled?
  else
    puts "This should remain"
  end
end

def test_with_variable_condition
  enabled = true
  if enabled
  else
    puts "This should remain"
  end
end

def test_with_complex_condition
  if user_signed_in? && feature_enabled? && !admin_disabled?
  else
    puts "This should remain"
  end
end

# Test with different else block content
def test_else_with_single_statement
  if condition?
  else
    do_something
  end
end

def test_else_with_multiple_statements
  if condition?
  else
    puts "First statement"
    puts "Second statement"
    do_something
  end
end

def test_else_with_control_flow
  if condition?
  else
    if nested_condition?
      puts "Nested if"
    end
    return false
  end
end

# Test edge cases
def test_with_whitespace_in_true_block
  if condition?
    
  else
    puts "This should remain"
  end
end

def test_with_comment_in_true_block
  if condition?
    # This is a comment
  else
    puts "This should remain"
  end
end

# Test cases that should NOT be affected
def test_with_content_in_true_block
  if condition?
    puts "This should remain"
  else
    puts "This should also remain"
  end
end

def test_without_else_clause
  if condition?
  end
end

def test_with_elsif_clause
  if condition?
  elsif other_condition?
    puts "This should remain"
  else
    puts "This should also remain"
  end
end

# Test nested cases
def test_nested_empty_if_true
  if outer_condition?
    if inner_condition?
    else
      puts "Inner else should remain"
    end
  else
    puts "Outer else should remain"
  end
end

# Test in different contexts
class TestClass
  def method_with_empty_if_true
    if condition?
    else
      puts "This should remain"
    end
  end
  
  def self.class_method_with_empty_if_true
    if condition?
    else
      puts "This should remain"
    end
  end
end

module TestModule
  def module_method_with_empty_if_true
    if condition?
    else
      puts "This should remain"
    end
  end
end
