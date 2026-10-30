#!/usr/bin/env python3
"""
generate-wrappers.py — Generates programmatic Python & TypeScript typed wrappers
for Hermes built-in tools and deferred MCP tools, enabling single-turn code mode execution.
Inspired by @cloudflare/codemode & Connorbelez/codeMode.
"""
import os, sys, json

HERMES_BUILTINS = [
    {
        "name": "web_search",
        "description": "Search the web for information.",
        "params": [("query", "str"), ("limit", "int = 5")],
        "returns": "dict"
    },
    {
        "name": "web_extract",
        "description": "Extract content from web page URLs.",
        "params": [("urls", "list[str]"), ("char_limit", "int = None")],
        "returns": "dict"
    },
    {
        "name": "read_file",
        "description": "Read text file with line numbers and pagination.",
        "params": [("path", "str"), ("offset", "int = 1"), ("limit", "int = 2000")],
        "returns": "dict"
    },
    {
        "name": "write_file",
        "description": "Write content to a file, completely replacing existing content.",
        "params": [("path", "str"), ("content", "str")],
        "returns": "dict"
    },
    {
        "name": "search_files",
        "description": "Search file contents or find files by name.",
        "params": [("pattern", "str"), ("target", "str = 'content'"), ("path", "str = '.'"), ("file_glob", "str = None"), ("limit", "int = 50")],
        "returns": "dict"
    },
    {
        "name": "patch",
        "description": "Targeted find-and-replace edits in files.",
        "params": [("path", "str"), ("old_string", "str"), ("new_string", "str"), ("replace_all", "bool = False")],
        "returns": "dict"
    },
    {
        "name": "terminal",
        "description": "Execute shell commands on the OS.",
        "params": [("command", "str"), ("timeout", "int = None"), ("workdir", "str = None")],
        "returns": "dict"
    }
]

def generate_python_wrapper(out_dir):
    py_path = os.path.join(out_dir, "hermes_codemode.py")
    lines = [
        '"""',
        'Auto-generated Code Mode Python client wrappers for Hermes & MCP Tools.',
        'Enables multi-tool execution in a single block without round-trip token overhead.',
        '"""',
        'from hermes_tools import (',
        '    web_search as _ws,',
        '    web_extract as _we,',
        '    read_file as _rf,',
        '    write_file as _wf,',
        '    search_files as _sf,',
        '    patch as _pt,',
        '    terminal as _tm,',
        '    json_parse, retry, shell_quote',
        ')',
        '',
        'class HermesCodeMode:',
        '    """Programmatic API interface for Hermes Code Mode execution."""'
    ]

    for tool in HERMES_BUILTINS:
        p_decl = ", ".join( [f"{p[0]}: {p[1]}" for p in tool["params"]])
        p_call = ", ".join([f"{p[0]}={p[0]}" for p in tool["params"]])
        builtin_map = {
            "web_search": "_ws",
            "web_extract": "_we",
            "read_file": "_rf",
            "write_file": "_wf",
            "search_files": "_sf",
            "patch": "_pt",
            "terminal": "_tm"
        }
        target_fn = builtin_map.get(tool["name"])
        lines.append(f'    @staticmethod')
        lines.append(f'    def {tool["name"]}({p_decl}) -> {tool["returns"]}:')
        lines.append(f'        """{tool["description"]}"""')
        lines.append(f'        return {target_fn}({p_call})')
        lines.append('')

    with open(py_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Generated Python wrappers: {py_path}")

def generate_typescript_wrapper(out_dir):
    ts_path = os.path.join(out_dir, "hermes-codemode.d.ts")
    lines = [
        '/**',
        ' * Auto-generated Code Mode TypeScript interface definitions for Hermes & MCP Tools.',
        ' * Inspired by @cloudflare/codemode.',
        ' */',
        'export interface HermesTools {',
    ]

    type_map = {
        "str": "string",
        "int = 5": "number",
        "int = 1": "number",
        "int = 2000": "number",
        "int = 50": "number",
        "int = None": "number | null",
        "list[str]": "string[]",
        "str = None": "string | null",
        "str = 'content'": "string",
        "str = '.'": "string",
        "bool = False": "boolean",
        "dict": "Record<string, any>"
    }

    for tool in HERMES_BUILTINS:
        p_items = []
        for p in tool["params"]:
            t_type = type_map.get(p[1], "any")
            is_optional = "=" in p[1]
            p_items.append(f"{p[0]}{'?' if is_optional else ''}: {t_type}")
        p_sig = ", ".join(p_items)
        lines.append(f'  /** {tool["description"]} */')
        lines.append(f'  {tool["name"]}({p_sig}): Promise<Record<string, any>>;')

    lines.append('}')
    lines.append('')
    lines.append('export declare const hermes: HermesTools;')

    with open(ts_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Generated TypeScript definitions: {ts_path}")

if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "references")
    os.makedirs(target_dir, exist_ok=True)
    generate_python_wrapper(target_dir)
    generate_typescript_wrapper(target_dir)
