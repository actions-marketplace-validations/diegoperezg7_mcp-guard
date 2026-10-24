# Records docs/assets/cli.gif. Run from the repository root after `npm run build`: vhs docs/cli.tape
Output docs/assets/cli.gif
Set Shell zsh
Set FontSize 13
Set Width 1240
Set Height 800
Set Padding 18
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type "alias mcp-guard='node dist/cli/index.js' && export PS1='$ ' && clear"
Enter
Sleep 500ms
Show

Type `mcp-guard scan --stdio "node dist/examples/poisoned-notes.js" --probe -r report.html; echo "exit=$?"`
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
Type "rm -f report.html"
Enter
