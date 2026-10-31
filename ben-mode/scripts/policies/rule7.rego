# Rego Rule 7 — tool-invocation policy (P26-1, MCP inline-policy style).
package hardgate.tool

import future.keywords.and
import future.keywords.every

default allow := false

allow if {
    some tool in input.allowed_tools
    tool.name == input.invocation.tool
    count(input.invocation.params) <= tool.max_params
    every k, v in input.invocation.params {
        type_ok(tool.param_types[k], v)
    }
}

type_ok("str", v) if { is_string(v) }
type_ok("int", v) if { is_number(v) }
type_ok("bool", v) if { is_boolean(v) }
