# Regenerates the README demo GIF. Run from the repo root:
#
#   vhs docs/screenshots/demo.tape
#
# Needs vhs (https://github.com/charmbracelet/vhs) and network access: the
# search hits crt.sh and the live feed reads the real CT logs, so the data
# differs between runs. The wait for crt.sh's database (1 to 3 minutes) is
# hidden, and ends when the result is on screen. Screenshots come from
# screenshots.tape.

Output docs/screenshots/demo.gif

Require go

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 860
Set Padding 20
Set WindowBar Colorful
Set TypingSpeed 60ms

Hide
Type "go build -o /tmp/ctq-demo/ctq . && export PATH=/tmp/ctq-demo:$PATH && clear"
Enter
Wait@90s
Show

Type "ctq tui example.com"
Sleep 500ms
Enter
Sleep 4s

# Watch the search from the Sources tab while the query waits in crt.sh's queue.
Type "5"
Sleep 5s

Hide
Wait+Screen@5m /history: \d+ certs in/
Show

Sleep 2s
Type "1"
Sleep 3s
Type "3"
Sleep 3s
Type "2"
Sleep 3s
Type "5"
Sleep 3s
Type "q"
Sleep 1s
