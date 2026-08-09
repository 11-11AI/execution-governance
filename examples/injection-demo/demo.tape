# Regenerate the README GIF:
#
#   vhs examples/injection-demo/demo.tape      (run from the repository root)
#
# The GIF is generated from this file rather than screen-recorded by hand, so it
# can be regenerated whenever the demo changes and can never drift into showing
# output the demo no longer produces. Same rule as every other claim here: if it
# cannot be re-run, it does not go in the README.
#
# A build is run off-camera first so the recording is not dominated by a cold
# tsc. `npm run demo` still runs its own build, so a short `tsc -b` line does
# appear -- that is the real script, unedited. Nothing is faked: the deny, the
# reason, the receipt id and the chain verification are the program's real
# output on the day the GIF was made.
#
# Width is set to fit the longest line the demo emits (149 characters, the
# ephemeral-key warning) so nothing wraps.

Output docs/img/demo.gif

Require npm

Set Shell bash
Set FontSize 14
Set Width 1500
Set Height 700
Set Padding 20
Set TypingSpeed 55ms

Hide
Type "npm run build >/dev/null 2>&1 && clear"
Enter
Sleep 8s
Show

Type "npm run demo"
Sleep 400ms
Enter

# Long enough to read the DENY and the verified chain, short enough that the
# GIF stays under the 15s target.
Sleep 7s
