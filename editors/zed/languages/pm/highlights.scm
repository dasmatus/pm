;; Adapted from tree-sitter-starlark (MIT) plus pm-specific captures.

; Variables
(identifier) @variable

; Reset highlighting in f-string interpolations
(interpolation) @none

;; Identifier naming conventions
((identifier) @type
 (#match? @type "^[A-Z].*[a-z]"))
((identifier) @constant
 (#match? @constant "^[A-Z][A-Z_0-9]*$"))

((identifier) @constant.builtin
 (#match? @constant.builtin "^__[a-zA-Z0-9_]*__$"))

((identifier) @constant.builtin
 (#any-of? @constant.builtin
           "NotImplemented"
           "Ellipsis"
           "quit"
           "exit"
           "copyright"
           "credits"
           "license"))

((attribute
    attribute: (identifier) @property)
 (#match? @property "^([A-Z])@!.*$"))

((identifier) @type.builtin
 (#any-of? @type.builtin
              "ArithmeticError" "BufferError" "LookupError" "AssertionError" "AttributeError"
              "EOFError" "FloatingPointError" "ModuleNotFoundError" "IndexError" "KeyError"
              "KeyboardInterrupt" "MemoryError" "NameError" "NotImplementedError" "OSError" "OverflowError" "RecursionError"
              "ReferenceError" "RuntimeError" "StopIteration" "StopAsyncIteration" "SyntaxError" "IndentationError" "TabError"
              "SystemError" "SystemExit" "TypeError" "UnboundLocalError" "UnicodeError" "UnicodeEncodeError" "UnicodeDecodeError"
              "UnicodeTranslateError" "ValueError" "ZeroDivisionError" "EnvironmentError" "IOError" "WindowsError"
              "BlockingIOError" "ChildProcessError" "ConnectionError" "BrokenPipeError" "ConnectionAbortedError"
              "ConnectionRefusedError" "ConnectionResetError" "FileExistsError" "FileNotFoundError" "InterruptedError"
              "IsADirectoryError" "NotADirectoryError" "PermissionError" "ProcessLookupError" "TimeoutError" "Warning"
              "UserWarning" "DeprecationWarning" "PendingDeprecationWarning" "SyntaxWarning" "RuntimeWarning"
              "FutureWarning" "UnicodeWarning" "BytesWarning" "ResourceWarning"
              "bool" "int" "float" "complex" "list" "tuple" "range" "str"
              "bytes" "bytearray" "memoryview" "set" "frozenset" "dict" "type"))

(function_definition
  name: (identifier) @function)

(parameters
  (identifier) @variable.parameter)
(lambda_parameters
  (identifier) @variable.parameter)
(lambda_parameters
  (tuple_pattern
    (identifier) @variable.parameter))
(keyword_argument
  name: (identifier) @variable.parameter)
(default_parameter
  name: (identifier) @variable.parameter)
(typed_parameter
  (identifier) @variable.parameter)
(typed_default_parameter
  (identifier) @variable.parameter)
(parameters
  (list_splat_pattern
    (identifier) @variable.parameter))
(parameters
  (dictionary_splat_pattern
    (identifier) @variable.parameter))

(none) @constant.builtin
[(true) (false)] @boolean
((identifier) @variable.special
 (#eq? @variable.special "self"))
((identifier) @variable.special
 (#eq? @variable.special "cls"))

(integer) @number
(float) @number

(comment) @comment
((module . (comment) @preproc)
  (#match? @preproc "^#!/"))

(string) @string
[
  (escape_sequence)
  (escape_interpolation)
] @string.escape

(expression_statement (string) @comment.doc)

[
  "-" "-=" ":=" "!=" "*" "**" "**=" "*=" "/" "//" "//=" "/=" "&" "&=" "%" "%="
  "^" "^=" "+" "+=" "<" "<<" "<<=" "<=" "<>" "=" "==" ">" ">=" ">>" ">>=" "@" "@="
  "|" "|=" "~" "->"
] @operator

["and" "in" "not" "or" "del"] @keyword.operator
["def" "lambda"] @keyword.function
["async" "exec" "pass" "print" "with" "as"] @keyword
["return"] @keyword
["if" "elif" "else" "match" "case"] @keyword
["for" "while" "break" "continue"] @keyword

["(" ")" "[" "]" "{" "}"] @punctuation.bracket
(interpolation "{" @punctuation.special "}" @punctuation.special)
["," "." ":" ";" (ellipsis)] @punctuation.delimiter

(ERROR) @hint

(assert_keyword) @keyword
(assert_builtin) @function.builtin

((call
  function: (identifier) @_func
  arguments: (argument_list
    (keyword_argument
      name: (identifier) @property)))
 (#eq? @_func "struct"))

(call
  function: (identifier) @function)

(call
  function: (attribute
              attribute: (identifier) @function))

((call
  function: (identifier) @constructor)
 (#match? @constructor "^[A-Z]"))

((call
  function: (attribute
              attribute: (identifier) @constructor))
 (#match? @constructor "^[A-Z]"))

((call
  function: (identifier) @function.builtin)
 (#any-of? @function.builtin "package" "step")
 (#set! "priority" 110))

((identifier) @constant.builtin
 (#any-of? @constant.builtin "Prepare" "Build" "Install" "Test")
 (#set! "priority" 110))

((keyword_argument
  name: (identifier) @property)
 (#any-of? @property "name" "stage" "run" "dl_urls" "version" "dependencies" "steps")
 (#set! "priority" 110))
