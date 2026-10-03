;; From tree-sitter-rhai (MIT, https://github.com/elkowar/tree-sitter-rhai) plus pm-specific captures.

(str_template_expr ["${" "}"] @punctuation.bracket)
(SwitchArm (Expr) "=>" @punctuation.delimiter (Expr))

";" @punctuation
"," @punctuation.delimiter

[ "(" ")" "{" "}" "[" "]" "#{" ] @punctuation.bracket



[
  "as"
  "break"
  "catch"
  "const"
  "do"
  "else"
  "export"
  "fn"
  "for"
  "if"
  "import"
  "in"
  "let"
  "loop"
  "private"
  "return"
  "switch"
  "throw"
  "try"
  "until"
  "while"
] @keyword

(ExprContinue) @keyword

(lit_bool) @boolean
(lit_str) @string
(lit_char) @character
(lit_int) @number
(lit_float) @number
[(comment_line_doc) (comment_block_doc)] @comment.doc
[(comment_line) (comment_block)] @comment

((binop) @keyword
  (#eq? @keyword "in"))

((binop) @operator
  (#not-eq? @operator "in"))

(ObjectField
  key: [(ident) (lit_str)] @property
  value: (Expr))


(ident) @variable

(ExprCall fn_name: (Expr) @function.name)
(ExprFn fn_name: (FnDeclName) @function)

;; pm builtins
((ExprCall
  fn_name: (Expr (ExprPath (Path (ident) @function.builtin))))
 (#any-of? @function.builtin "package" "step" "kernel"))

((ident) @constant.builtin
 (#any-of? @constant.builtin "Prepare" "Build" "Install" "Test"))
