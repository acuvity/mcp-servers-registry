package main

import rego.v1

# Pattern definitions
_covert_patterns := [
	"(?i)do not (tell|inform|alert|notify|mention)(?!\\s+(to\\s+)?use)",
	"(?i)hide this",
	"(?i)not visible",
	"(?i)user (should not|must not|cannot) see",
	"(?i)do(n't| not) (show|display|reveal|share)",
	"(?i)no need to mention this",
	"(?i)n</?instructions>",
	"(?i)</?important>",
	"(?i)</?secret>",
	"(?i)</?system>",
	"(?i)ignore (previous|all|other) instructions",
	"(?i)instead (of|do|provide|you should)",
	"(?i)never (disclose|tell|show|reveal|leak)",
	"(?i)very important",
	`(?i)(\\xF3\\xA0[\\x80-\\x81][\\x80-\\xBF]){15,}`,
]

_schema_keys := {
	"note", "notes", "feedback", "details", "extra", "additional",
	"metadata", "debug", "sidenote", "context", "annotation",
	"reasoning", "remark",
}

_redaction_patterns := [
	`(gh[usop]_[A-Za-z0-9]{36})`,
	`(github_pat_\w{82})`,
	`(dckr_pat_[A-Za-z0-9_-]{27})`,
	`(AIza[\w-]{35})`,
	`((?:A3T|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})`,
	`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9+/=]{40})['"]?`,
	`(ey[0-9A-Za-z_-]{17,}\.ey[0-9A-Za-z\\/\\_-]{17,}\.[0-9A-Za-z\\/\\_-]{10,}={0,2})`,
	`(hf_[a-z]{34})`,
	`(xapp-\d-[A-Za-z0-9]+-\d+-[a-z0-9]+)`,
	`(xox[abrp]-\d{10,13}-\d{10,13}[A-Za-z0-9-]*)`,
	`https://hooks\.slack\.com/(?:services|workflows)/([A-Z0-9]+/[A-Z0-9]+/[0-9A-Za-z]{17,25})`,
	`(?i)(?:\\["']|['"])?[A-Za-z0-9_]*(?:TOKEN|KEY|SECRET|PASS|USERNAME)[A-Za-z0-9_]*(?:\\["']|['"])?(?:\\n|\s)*[:=](?:\\n|\s)*(?:\\["']|['"])?([A-Za-z0-9_/\-]{8,})(?:\\["']|['"])?`,
]

_sensitive_patterns := [
	"\\.env\\b",
	"config\\.json\\b",
	"/etc/passwd\\b",
	"/var/log\\b",
	"\\.ssh(/|$)",
	"id_(rsa|ecdsa)\\b",
	"\\.\\./",
	`(\\xF3\\xA0[\\x80-\\x81][\\x80-\\xBF]){15,}`,
]

_shadowing_patterns := [
	"(?i)instead of using",
	"(?i)before using",
	"(?i)after using",
]

_cross_tool_patterns := [
	`(?i)(?:use|using|with)(?:\s+(?:the|this))?\s+tool\s+(?:["']([^"']+)["']|([A-Za-z0-9_]{4,}))`,
	`(?i)(?:use|using|with)(?:\s+(?:the|this))?\s+(?:["']([^"']+)["']|([A-Za-z0-9_]{4,}))\s+tool`,
]

_our_tools := [
	#
	"maps_geocode",
	#
	"maps_reverse_geocode",
	#
	"maps_search_places",
	#
	"maps_place_details",
	#
	"maps_distance_matrix",
	#
	"maps_elevation",
	#
	"maps_directions",
	#
	# The last item so to avoid regal formater to mess up
	# the templating
	"__placeholder_template",
]

# Deny rules for tools/list
reasons contains msg if {
	input.mcp.method == "tools/list"
	some tool in input.mcp.result.tools
	some pattern in _covert_patterns
	regex.match(pattern, tool.description)
	msg = sprintf("covert instruction in tool %v: %v", [tool.name, pattern])
}

reasons contains msg if {
	input.mcp.method == "tools/list"
	some tool in input.mcp.result.tools
	some prop in tool.inputSchema.properties
	lower(prop) in _schema_keys
	msg = sprintf("schema parameter misuse in tool %v: %v", [tool.name, prop])
}

reasons contains msg if {
	input.mcp.method == "tools/list"
	some tool in input.mcp.result.tools
	some pattern in _sensitive_patterns
	regex.match(pattern, tool.description)
	msg = sprintf("sensitive resource in tool %v: %v", [tool.name, pattern])
}

reasons contains msg if {
	input.mcp.method == "tools/list"
	some tool in input.mcp.result.tools
	some pattern in _shadowing_patterns
	regex.match(pattern, tool.description)
	msg = sprintf("tool-shadowing in tool %v: %v", [tool.name, pattern])
}

# capture cross origin in tool description
reasons contains msg if {
	some tool in input.mcp.result.tools
	some pattern in _cross_tool_patterns
	some tool_match in regex.find_all_string_submatch_n(pattern, tool.description, -1)
	extracted_tool := tool_match[count(tool_match) - 1]
	not extracted_tool in _our_tools
	msg := sprintf("untrusted tool use detected in tool description %v: %v", [tool.name, extracted_tool])
}

# Deny rules for tools/call
reasons contains msg if {
	input.mcp.method == "tools/call"
	some pattern in _covert_patterns
	regex.match(pattern, sprintf("%v", [input.mcp.params.arguments]))
	msg = sprintf("covert content in call args: %v", [pattern])
}

reasons contains msg if {
	input.mcp.method == "tools/call"
	some arg_name in input.mcp.params.arguments
	lower(arg_name) in _schema_keys
	msg = sprintf("schema parameter misuse in call args: %v", [arg_name])
}

reasons contains msg if {
	input.mcp.method == "tools/call"
	some pattern in _sensitive_patterns
	regex.match(pattern, sprintf("%v", [input.mcp.params.arguments]))
	msg = sprintf("sensitive content in call args: %v", [pattern])
}

reasons contains msg if {
	input.mcp.method == "tools/call"
	some pattern in _shadowing_patterns
	regex.match(pattern, sprintf("%v", [input.mcp.params.arguments]))
	msg = sprintf("tool-shadowing in call args: %v", [pattern])
}

# capture cross origin in tool calls
reasons contains msg if {
	some idx, element in input.mcp.result.content
	element.type == "text"
	text := element.text
	some pattern in _cross_tool_patterns
	some tool_match in regex.find_all_string_submatch_n(pattern, text, -1)
	extracted_tool := tool_match[count(tool_match) - 1]
	not extracted_tool in _our_tools
	msg := sprintf("untrusted tool detected in call response: %v", [extracted_tool])
}

# Mutation: redact sensitive text in responses
# Only the matched fragment is replaced with "[REDACTED]", preserving the rest of the text.
mcp := patched if {
	patches := [patch |
		some idx, element in input.mcp.result.content
		element.type == "text"
		redactions := {m[count(m) - 1] |
			some pat in _redaction_patterns
			some m in regex.find_all_string_submatch_n(pat, element.text, -1)
		}
		repl_map := {c: "[REDACTED]" | c := redactions[_]}
		new_text := strings.replace_n(repl_map, element.text)
		new_text != element.text
		patch := {
			"op": "replace",
			"path": sprintf("/result/content/%d/text", [idx]),
			"value": new_text,
		}
	]
	count(patches) > 0
	patched := json.patch(input.mcp, patches)
}

# Allow only if no violations
allow if {
	count(reasons) == 0
}
