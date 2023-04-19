# XWorm packet tool

You can use this tool to quickly craft XWorm packets.

`generate.py` builds packets from a description file.

## File format

- If a line begins with `#`, it is considered a comment.
- `@INCLUDE otherfile.pck` includes `otherfile.pck` (as if the packets inside it were written into the current file).
- `@EVALL code` evaluates Python code and expects the result to be a list. The packets in the list are added to the output.
- `@EVAL code` evaluates Python code and expects the result to be one single packet which is added to the output.

Otherwise, a semicolon-separated packet is created. In the fields, gzipped files can be included like `gz:somefile.txt`.

See example.pck for an example.