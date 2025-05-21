# This policy exposes the several guardrails that can be enbled with
# REGO_POLICY_RUNTIME_GUARDRAILS="covert-instruction-detection schema-misuse-prevention secrets-redaction cross-origin-tool-access sensitive-pattern-detection shadowing-pattern-detection"
#
# This also exposes a simple way to do authentication using a shared secrets
# by settting the following. it would expext a header Authorization header
# with a token/password set to the same thing.
# REGO_POLICY_RUNTIME_BASIC_AUTH_SECRET
#
# The are exposed in rego without the REGO_POLICY_RUNTIME_ prefix

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
	"(?i)never (disclose|tell|show|reveal|leak)",
	"(?i)n</?instructions>",
	"(?i)</?important>",
	"(?i)</?secret>",
	"(?i)</?system>",
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
	`(?i)(?:\\["']|['"])?[A-Za-z0-9_]*(?:TOKEN|API_KEY|SECRET|PASS)[A-Za-z0-9_]*(?:\\["']|['"])?(?:\\n|\s)*(?::=|:|=)(?:\\n|\s)*(?:\\["']|['"])?([\x20-\x21\x23-\x26\x28-\x7E]{8,})(?:\\["']|['"])?`,
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
	`http:\/\/169\.254\.169\.254\/latest\/meta-data\/iam\/security-credentials(?:\/[\w\-]+)?`,
	`http:\/\/169\.254\.169\.254\/computeMetadata\/v1\/instance\/service-accounts\/(?:default|[\w\-]+)\/token`,
	`http:\/\/169\.254\.169\.254\/metadata\/identity\/oauth2\/token\?[^ ]*`,
	`http:\/\/100\.100\.100\.200\/latest\/meta-data\/ram\/security-credentials(?:\/[\w\-]+)?`,
	`http:\/\/169\.254\.169\.254\/instance_identity\/v1\/token`,
	`http:\/\/169\.254\.169\.254\/opc\/v1\/instance\/`,
]

_shadowing_patterns := [
	"(?i)instead of using",
	"(?i)before using",
	"(?i)after using",
	"(?i)ignore (previous|all|other) (instructions|directives)",
	"(?i)instead (of|do|provide|you should)",
]

_cross_tool_patterns := [
	`(?i)\b(?:use|run|launch|execute|start|invoke|trigger|initiate)\s+(?:the\s+)?(?:tool\s+)?([A-Za-z][A-Za-z0-9_-]{5,})\b`,
	`(?i)\b(?:use|run|launch|execute|start|invoke|trigger|initiate)\s+(?:the\s+)?([A-Za-z][A-Za-z0-9_-]{5,})\b(?:tool)?`,
	`(?i)\b(?:when|after|before|upon)\s+(?:calling|running|invoking|executing)\s+([A-Za-z][A-Za-z0-9_-]{5,})\b`,
	`(?i)\b(?:when|after|before|upon)\s+\(?([A-Za-z][A-Za-z0-9_-]{5,})\)?[\s.:_-]*(?i)(?:[A-Za-z][A-Za-z0-9_]*\s+)?(?:is\s+)?(?:invoked|called|run|started|executed|triggered)\b`,
	`(?i)\b([A-Za-z][A-Za-z0-9_-]{5,})\.([A-Za-z][A-Za-z0-9_-]*)\s+should\s+(?:use|run|launch|execute|start|invoke|trigger|initiate)\b`,
]

_cross_tool_exclude := [
	# add our tools to exclude list
	#
	"create_customer",
	#
	"list_customers",
	#
	"create_product",
	#
	"list_products",
	#
	"create_price",
	#
	"list_prices",
	#
	"create_payment_link",
	#
	"create_invoice",
	#
	"create_invoice_item",
	#
	"finalize_invoice",
	#
	"retrieve_balance",
	#
	"create_refund",
	#
	"list_payment_intents",
	#
	"list_subscriptions",
	#
	"cancel_subscription",
	#
	"update_subscription",
	#
	"list_coupons",
	#
	"create_coupon",
	#
	"update_dispute",
	#
	"list_disputes",
	#
	# exclude word that might be misdetected
	"to",
	"this",
	"that",
	"it",
	"something",
	"anything",
	"tool",
	"script",
	"function",
	"i",
	"you",
	"me",
	"we",
	"he",
	"she",
	"they",
	"them",
	"our",
	"us",
	"please",
	"today",
	"tomorrow",
	"yesterday",
	"warning",
	"discussion",
	"order",
	"case",
]

## Retrieve the env set by the runtime
#

env := opa.runtime().env

## Get activated guardrails
active_guardrails contains norm if {
	some raw in split(env.GUARDRAILS, " ")
	norm = lower(raw)
}

## Generic authentication block
#

reasons contains "invalid credentials" if {
	env.BASIC_AUTH_SECRET != ""
	input.agent.password != env.BASIC_AUTH_SECRET
}

## Deny rules for tools/list response
#

reasons contains msg if {
	"covert-instruction-detection" in active_guardrails
	some tool in input.mcp.result.tools
	some pattern in _covert_patterns
	regex.match(pattern, tool.description)
	msg = sprintf("covert instruction in tool %v: %v", [tool.name, pattern])
}

reasons contains msg if {
	"schema-misuse-prevention" in active_guardrails
	some tool in input.mcp.result.tools
	some prop, _ in tool.inputSchema.properties
	lower(prop) in _schema_keys
	msg = sprintf("schema parameter misuse in tool %v: %v", [tool.name, prop])
}

reasons contains msg if {
	"sensitive-pattern-detection" in active_guardrails
	some tool in input.mcp.result.tools
	some pattern in _sensitive_patterns
	regex.match(pattern, tool.description)
	msg = sprintf("sensitive resource in tool %v: %v", [tool.name, pattern])
}

reasons contains msg if {
	"shadowing-pattern-detection" in active_guardrails
	some tool in input.mcp.result.tools
	some pattern in _shadowing_patterns
	regex.match(pattern, tool.description)
	msg = sprintf("tool-shadowing in tool %v: %v", [tool.name, pattern])
}

reasons contains msg if {
	"cross-origin-tool-access" in active_guardrails
	some tool in input.mcp.result.tools
	some pattern in _cross_tool_patterns
	some tool_match in regex.find_all_string_submatch_n(pattern, tool.description, -1)
	extracted_tool := tool_match[count(tool_match) - 1]
	not extracted_tool in _cross_tool_exclude
	msg := sprintf("untrusted tool use detected in tool description %v: %v", [tool.name, extracted_tool])
}

## Deny rules for tools/call request
#
#
reasons contains msg if {
	"schema-misuse-prevention" in active_guardrails
	input.mcp.method == "tools/call"
	some arg_name, _ in input.mcp.params.arguments
	lower(arg_name) in _schema_keys
	msg = sprintf("schema parameter misuse in call args: %v", [arg_name])
}

reasons contains msg if {
	"sensitive-pattern-detection" in active_guardrails
	input.mcp.method == "tools/call"
	some pattern in _sensitive_patterns
	regex.match(pattern, sprintf("%v", [input.mcp.params.arguments]))
	msg = sprintf("sensitive content in call args: %v", [pattern])
}

## Deny rules for tools/call response
#

reasons contains msg if {
	"covert-instruction-detection" in active_guardrails
	some element in input.mcp.result.content
	element.type == "text"
	some pattern in _covert_patterns
	regex.match(pattern, sprintf("%v", [element.text]))
	msg = sprintf("covert content in call response: %v", [pattern])
}

reasons contains msg if {
	"shadowing-pattern-detection" in active_guardrails
	some element in input.mcp.result.content
	element.type == "text"
	some pattern in _shadowing_patterns
	regex.match(pattern, sprintf("%v", [element.text]))
	msg = sprintf("tool-shadowing in call response: %v", [pattern])
}

reasons contains msg if {
	"cross-origin-tool-access" in active_guardrails
	some element in input.mcp.result.content
	element.type == "text"
	text := element.text
	some pattern in _cross_tool_patterns
	some tool_match in regex.find_all_string_submatch_n(pattern, text, -1)
	extracted_tool := tool_match[count(tool_match) - 1]
	not extracted_tool in _cross_tool_exclude
	msg := sprintf("untrusted tool detected in call response: %v", [extracted_tool])
}

mcp := patched if {
	"secrets-redaction" in active_guardrails
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

## Allow only if no violations
#
allow if {
	count(reasons) == 0
}
