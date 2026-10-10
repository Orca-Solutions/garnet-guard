# Garnet Guard terminal colours

| Element | ANSI | Hex (for docs, GIFs and asciinema themes) |
|---|---|---|
| Header line, package names | bold (1) | #FFFFFF on dark, ink on light |
| Finding, WARN verdict | yellow (33), bold for the verdict | #F0B429 (amber, lifted for dark terminals) |
| pass verdict | green (32) | #5DBB7A |
| Rule IDs, versions, paths | default, never coloured | |
| Secondary notes, "couldn't check" | bright black (90) | #8A9099 |
| BLOCK verdict | bold yellow, never red | |

Rules: respect `NO_COLOR` and `--no-color`; detect a non-TTY and print plain text; never use red (31), it is the brand, not the alarm; never print "safe".
Asciinema theme: background #1B1F24, foreground #E6E1DA, palette above.
