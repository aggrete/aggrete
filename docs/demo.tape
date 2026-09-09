# Regenerate the README demo GIF. Run from the repo root:
#   PATH="$PWD/.venv/bin:$PATH" vhs docs/demo.tape
# Produces docs/demo.gif. Needs a .venv with the package installed (pip install -e .).
Output docs/demo.gif

Set FontSize 13
Set Width 900
Set Height 700
Set Padding 20
Set TypingSpeed 50ms

Type "python examples/attacks/lethal_trifecta.py"
Sleep 600ms
Enter
Sleep 7s
Sleep 2s
