# Claude research fixtures (#19)

`research-output.json` is the real stdout of one run of Claude Code 2.1.314 on 2026-10-30:
`claude -p <prompt> --output-format json --json-schema <schema> --safe-mode --tools WebSearch,WebFetch
--allowedTools WebSearch WebFetch --permission-mode dontAsk --strict-mcp-config --mcp-config '{"mcpServers":{}}'
--no-session-persistence --disable-slash-commands`, from an empty folder, with only PATH, HOME, USER, LOGNAME,
TMPDIR and LANG in the environment. The prompt named only the public topics GitHub, Google Gmail and Apple.
Exit code 0 after 134 s, 25 turns, `permission_denials` empty. The output holds no owner data.
It has 5 claims in `structured_output` (and the same JSON as text in `result`). One claim has a vendor link.
