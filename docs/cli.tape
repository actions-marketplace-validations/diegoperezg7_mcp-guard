# Records docs/assets/cli.gif. Run from the repository root after `npm run build`: vhs docs/cli.tape
Output docs/assets/cli.gif
Set Shell zsh
Set FontSize 13
Set Width 1280
Set Height 820
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type "alias mcp-guard='node dist/cli/index.js' && export PS1='$ ' && node dist/examples/ops-toolbox.js 2>/dev/null & sleep 1; clear"
Enter
Sleep 1500ms
Show

Type `mcp-guard scan --stdio "node dist/examples/poisoned-notes.js" --http http://127.0.0.1:3401/mcp --json examples/exports/mail-server.json --probe; echo "exit=$?"`
Sleep 400ms
Enter
Sleep 9s

Type "clear"
Enter
Type `mcp-guard scan --stdio "node dist/examples/weather-safe.js" --probe; echo "exit=$?"`
Sleep 400ms
Enter
Sleep 4s

Hide
Type "kill %1"
Enter
