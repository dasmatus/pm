((call
  function: (identifier) @function.builtin)
 (#any-of? @function.builtin "package" "step"))

((identifier) @constant.builtin
 (#any-of? @constant.builtin "Prepare" "Build" "Install" "Test"))

((keyword_argument
  name: (identifier) @property)
 (#any-of? @property "name" "stage" "run" "dl_urls" "version" "dependencies" "steps"))
