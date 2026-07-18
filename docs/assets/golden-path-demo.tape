# Golden-path demo GIF -- real `vinctor` commands. The GIF opens already showing a
# live ALLOW, then animates two out-of-scope attempts being denied. The same action
# is allowed or denied by context (grant + resource + environment), not a denylist.
#
# Prereq: `vinctor` on PATH (e.g. `pipx install vinctor-core`).
# Render:  vhs golden-path-demo.tape   ->   golden-path-demo.gif
# Spec:    docs/superpowers/specs/2026-06-25-golden-path-demo-design.md

Output golden-path-demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 430
Set Padding 26
Set Theme "Dracula"
Set TypingSpeed 32ms

# Off-camera: boot a local service (grant scoped to staging + internal net) and run
# the first, in-scope call -- so the GIF opens on a real ALLOW, not a blank prompt.
Hide
Type "cd $(mktemp -d)"
Enter
Type "vinctor local start --db demo.sqlite --port 0 --scope 'send:net/internal/*' --scope 'deploy:env/staging/*' --boundary-name claude-code-local > vinctor.env 2>&1 &"
Enter
Sleep 2s
Type "source vinctor.env && clear"
Enter
Type "vinctor agent enforce --action send --resource net/internal/orders-api"
Enter
Sleep 1500ms
Show

# On-camera: two out-of-scope attempts, denied before they run.
Sleep 900ms
Type "vinctor agent enforce --action send --resource net/external/pastebin.com"
Sleep 500ms
Enter
Sleep 1900ms
Type "vinctor agent enforce --action deploy --resource production/web"
Sleep 500ms
Enter
Sleep 2600ms
