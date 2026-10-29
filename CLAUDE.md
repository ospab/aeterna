# Rules for AI agents working in this repository

## Editing files
- Change files with the built-in Edit/Write tools. Do not write Python, sed, awk or PowerShell
  scripts to modify source files, and do not leave helper scripts behind.
- If Edit does not match, find out why instead of switching to a script: read the exact lines
  again (whitespace, CRLF line endings, tabs, control characters such as a literal 0x18), then
  use a smaller unique `old_string` around the change. For the same change in several places use
  several Edit calls or `replace_all`.
- A script is acceptable only for generated data (images, test fixtures) and only in the
  scratchpad, never in the repository.

## Work split
- Agents never `git commit` or `git push`; the lead does.
- Stay inside the files your brief gives you; other agents may be editing the rest.
- Never read, print or copy `%USERPROFILE%\.ospab\tmt.key`.
- ROMs, disc images and other third-party binaries (`*.rom`, `*.ssd`) never go into the repository.
- Do not consume ISO numbers in `isos/`: test builds set `ISO_PATH` outside it.
- Never kill all QEMU processes, only the PID you started.

## Documentation
- English in `docs/en` is primary, `docs/ru` is the translation. Plain technical style: short
  sentences, no marketing, no emoji.
