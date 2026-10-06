# Regenerates the README screenshots. Run from the repo root:
#
#   vhs docs/screenshots/screenshots.tape
#
# Needs vhs (https://github.com/charmbracelet/vhs) and network access: the
# search hits crt.sh and the live feed reads the real CT logs, so the data
# differs between runs. demo.tape makes the GIF.
#
# Two vhs 0.12 quirks shape this file. A search takes 1 to 3 minutes, so the
# tape waits for the result on screen instead of sleeping a fixed time. And a
# Screenshot can capture a frame drawn after the next keystroke, so every
# Screenshot is followed by a pause.

Output "/tmp/ctq-screenshots.gif"

Require go

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 860
Set Padding 20
Set WindowBar Colorful
Set TypingSpeed 60ms

Type "go build -o /tmp/ctq-demo/ctq . && export PATH=/tmp/ctq-demo:$PATH && clear"
Enter
Wait@90s

Type "ctq tui example.com"
Enter
Sleep 5s
Screenshot docs/screenshots/searching.png
Sleep 2s

Wait+Screen@5m /history: \d+ certs in/
Sleep 3s

Type "1"
Sleep 2s
Screenshot docs/screenshots/history.png
Sleep 2s

Type "2"
Sleep 2s
Screenshot docs/screenshots/live.png
Sleep 2s

Type "3"
Sleep 2s
Screenshot docs/screenshots/names.png
Sleep 2s

# The newest event is on top: the search result. Enter opens its details.
Type "5"
Sleep 2s
Enter
Sleep 2s
Screenshot docs/screenshots/sources.png
Sleep 2s

Type "q"
Sleep 1s
