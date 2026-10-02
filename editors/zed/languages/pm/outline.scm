(comment) @annotation

(function_definition
  name: (identifier) @name) @item

((call
  function: (identifier) @_fn
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @_name_key
      value: (string
        (string_content) @name))))
 (#any-of? @_fn "package" "step")
 (#eq? @_name_key "name")) @item

((call
  function: (identifier) @_fn
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @_stage_key
      value: (identifier) @context.extra)))
 (#eq? @_fn "step")
 (#eq? @_stage_key "stage"))
