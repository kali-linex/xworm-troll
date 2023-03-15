# XWorm packet tool

You can use this tool to quickly craft XWorm packets.

Usage given with `--help`.

Example: `python main.py -e out.bin INFO somefilename gz:somefile.exe` will put the following in `out.bin` (encrypted in XWorm's networking format, with the default key `<123456789>`): `INFO<XWormmm>somefilename<XWormmm>(the gzipped contents of somefile.exe)`.

Interesting packet types:

- `INFO <ID> <Username> <OS> <Version> <Date> <USB> <UAC> <Webcam> <Antivirus>`: Client handshake packet. All of the parameters are displayed character-for-character in the clients window. If a client sends multiple INFO packets, "ghost entries" will appear which don't vanish, even after the client has disconnected. Prime trolling opportunity.
- `FileM <ID>`: Begins a file manager session and pops up a file manager window on the C2. The ID is displayed in the title and can be any string.
- `downloadedfile <ID> <gzipped file contents> <file name>`: Originally the response for file download requests, but the C2 is stateless and vulnerable to path traversal. A `downloadedfile anything gz:evil.vbs ..\..\evil.vbs` will drop evil.vbs into the XWorm folder, no questions asked.
