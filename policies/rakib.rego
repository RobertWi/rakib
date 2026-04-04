# Rakib — Data Flow Policy for AI Agent Tool Calls
#
# Evaluated by OPA for every tool call. Prevents untrusted data
# (web scrapes, external APIs) from controlling agent actions
# (message routing, code commits, task delegation).
#
# Portable: tool names, sensitive params, and untrusted sources
# are loaded from data.json, not hardcoded here.

package rakib

import rego.v1

default allow := true

# Check if a source string is untrusted
is_untrusted(source) if {
    startswith(source, "tool:")
    tool_name := substring(source, 5, -1)
    tool_name in data.untrusted_tools
}

# Deny if sensitive parameter has untrusted data in its sources
deny contains msg if {
    some param in data.sensitive_params[input.tool]
    some source in input.data_sources[param]
    is_untrusted(source)
    not input.args[param] in input.safe_values
    msg := sprintf(
        "BLOCKED: %s.%s value '%s' has untrusted source '%s' and is not in safe values",
        [input.tool, param, input.args[param], source]
    )
}

# Final decision
allow if {
    count(deny) == 0
}
