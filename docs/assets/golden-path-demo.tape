# Golden-path demo GIF -- real `vinctor` commands, run step by step.
# The same action is allowed or denied by context (grant + resource +
# environment), not by a denylist.
#
# Prereq: `vinctor` on PATH (e.g. `pipx install vinctor-core`).
# Render:  vhs golden-path-demo.tape   ->   golden-path-demo.gif
# Spec:    docs/superpowers/specs/2026-06-25-golden-path-demo-design.md

Output golden-path-demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 760
Set Padding 22
Set Theme "Dracula"
Set TypingSpeed 35ms

# run in a scratch dir so demo.sqlite / vinctor.env don't litter the cwd
Hide
Type "cd $(mktemp -d); clear"
Enter
Sleep 600ms
Show

Type "# start a local Vinctor service -- this agent's grant is staging-scoped"
Enter
Type "vinctor local start --db demo.sqlite --port 0 --scope 'send:net/internal/*' --scope 'deploy:staging/*' --boundary-name claude-code-local > vinctor.env &"
Enter
Sleep 1800ms
Type "source vinctor.env"
Enter
Sleep 800ms
Enter

Type "# agent fetches an internal API  ->  within grant"
Enter
Type "vinctor agent enforce --action send --resource net/internal/orders-api"
Enter
Sleep 1900ms
Enter

Type "# same fetch, EXTERNAL destination (exfil)  ->  out of scope"
Enter
Type "vinctor agent enforce --action send --resource net/external/pastebin.com"
Enter
Sleep 1900ms
Enter

Type "# deploy to PRODUCTION, but granted staging only  ->  'I thought I was in staging'"
Enter
Type "vinctor agent enforce --action deploy --resource production/web"
Enter
Sleep 3200ms
