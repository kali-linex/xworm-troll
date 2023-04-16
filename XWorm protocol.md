The XWorm protocol is mostly stateless and encrypted with a pre-shared key. Packets are usually plaintext when decrypted, but occassionally contain gzipped files.
This information was figured out from Wireshark network dumps and with the invaluable [dnSpy](https://github.com/dnSpyEx/dnSpy).
Note that since I reverse engineered it, XWorm 4.0 was released which has some updates, including probably changing the workings of some packets and adding or removing security holes. I was too lazy to find a crack for it yet and start breaking it apart, but the inner workings mostly seem to be the same based on information from the owner's Telegram group.
## A single packet
One encrypted packet consists of two parts: the length marker, and the encrypted data itself. The length marker is the length of the encrypted data, literally as an ASCII string, followed by a zero byte. Let's look at the hexdump of a captured INFO packet:
```
00000000: 3230 3800 0d2f e1b3 98fd e0a6 72cd a7fd  208../......r...  
00000010: 0856 a190 ce49 cce3 8a5f cccb 79d9 e43c  .V...I..._..y..<  
00000020: 861d 3a42 d1a6 e0c4 0a6c 6813 4af9 e48c  ..:B.....lh.J...  
00000030: e0d5 c7b6 58ff 541a cbee 7fdb 06a1 d311  ....X.T.........  
00000040: 1fc1 50de 8498 da76 cff1 c091 5620 351c  ..P....v....V 5.  
00000050: f5ac 5f1a 0ee6 ea4e 0199 812d a419 fba9  .._....N...-....  
00000060: 7265 65f7 ad29 29dd 9739 52cd 7c19 76b0  ree..))..9R.|.v.  
00000070: 2ee5 68d7 cf99 5b48 313b 60f3 88c3 67af  ..h...[H1;`...g.  
00000080: 812f 96a4 f5e2 138c adfa 2a95 b011 1c4e  ./........*....N  
00000090: 78bf 16d8 78c7 93b3 b228 b9d7 f6d9 b167  x...x....(.....g  
000000a0: 6ac6 8151 6640 6328 dcbd c7e5 a24b 4860  j..Qf@c(.....KH`  
000000b0: ab6c 404e c8aa 3e94 7203 6488 b22c 3a74  .l@N..>.r.d..,:t  
000000c0: e490 dc64 daba 6e4f 5899 f905 7208 73af  ...d..nOX...r.s.  
000000d0: 69bc 5062 3936 00fc fcde 5d8d 9eaa 733b  i.Pb
```
We can see that it begins with the number 208 in plain text, then a zero byte and encrypted data follows.
Encryption is performed with a preshared key. This key is hashed with MD5 and the resulting 16 bytes are used as the key for an AES-128 cipher (in ECB mode). XWorm's default key is `<123456789>`, and from experience, people don't really tend to change that. (If they did for some reason, it can be easily read with a .NET debugger after the first four statements of the XWorm stub.)
If you put the relevant parts of the above captured packet into a program like [CyberChef](https://gchq.github.io/CyberChef/), and decrypt AES-128 ECB with the MD5 hash of `<123456789>` (`dadefdfd3df5ba731438e7569f826962`), we can see the output:
```
INFO<Xwormmm>BC666AABAFC76AEBF101<Xwormmm>nignog<Xwormmm> Windows 10 Home 64bit<Xwormmm>XWorm V3.0<Xwormmm>19/02/2023<Xwormmm>False<Xwormmm>False<Xwormmm>Tr  
ue<Xwormmm>Malwarebytes,Windows Defender
```
Voilà!
Just from this packet, it can be inferred that these are primarily arrays of strings separated by `<XWormmm>`. In order to not repeat myself, I'm going to use semicolons to separate packet arguments in this document; these are to be implicitly replaced with `<Xwormmm>`. Note that the program in this repo does it for you automatically.
## Basic connection flow
The client begins by sending an INFO packet. This is formatted as `INFO;Client ID;Username;OS version;XWorm version;Date;Whether XWorm has USB access;Whether UAC is on;Whether the computer has a web camera;Installed antiviruses`. This is the same kind of packet that was decrypted in the previous section. Note that even fields which *should* have a fixed data type are transmitted as strings and displayed in the RAT's main window. Therefore, if one were to synthetise an `INFO` packet where the webcam field was set to `Hello World`, that would be displayed in the table. Additionally, if one client sends multiple info packets, the extra ones appear as "ghost entries" which can't be meaningfully interacted with and aren't removed when the client disconnects.
Afterwards, multiple messages are sent periodically that only say `PING!`. A client is nevertheless not disconnected if it doesn't respond to a `PING!` nor marked as inactive.
## Plugins
Plugins are DLLs which are saved to the registry and dynamically loaded and executed by the client. Upon startup, they get the IP, port and encryption key of the server from the running client. They usually make a new connection afterwards and possibly can also be given arguments (haven't explored them too much at this point). They communicate in the same packet format, but have different handshakes.
Plugins provide functionality such as the file manager, remote desktop and webcam access.
### The file manager plugin
This is the one that I found the important vulnerabilities in, specifically the ability to drop files on the server.
When the file manager plugin is activated it sends a handshake in the format of `FileM;Client ID`. The server then unconditionally (!) begins a file manager session (popping up a window), even if that client ID isn't connected anyway.
I haven't documented much of the protocol, but that should be possible to read from additional packet dumps and decryption.
The notable packet is `downloadedfile`. Originally, this is the client's response to a request from the RAT to download a file. However, as the RAT's connection is mostly stateless, this can be abused to upload files to the server at any point, and, combined with a path traversal, to almost any directory.
The packet looks like `downloadedfile;Client ID;gzipped file contents;file name`. The client ID **must** be the same as one of the existing file manager sessions on the RAT (so in the trivial case, the ID that was sent with the `FileM` packet). File contents are then saved to `ClientsFolder/Client ID/file name`. We have path traversal at two points: first, the server accepts a `..` in the client ID. Additionally, because it is `Path.Combine`d to the ClientsFolder path, an absolute path would also be accepted without hesitation. (This allows one to overwrite any system file if the RAT is running with admin privileges!)
The file name entry is also path traversable, but this might be fixed in the new update (the Client ID still seems to be vulnerable).
A note about the gzipped file contents: it's just the contents of the downloaded file, but gzipped and the length of **the original file** is prepended to it in 4 little-endian bytes (for preallocating a properly sized buffer). The program also handles gzipping automatically, if an argument is given in the format of `gz:/path/to/some/file`.
Some other interesting packets are:
- `FileManagerMSG;Client ID;message` - displays a green message in the bottom of the file manager window belonging to the session of the specified client ID
- `FileManagerErr;Client ID;message` - same thing, but the message is red
- `viewimage;Client ID;gzipped PNG file` - used to display a thumbnail of selected images. Interestingly, it looks like it can't be (easily) abused to display anything, needs more research.
- `txtttt;Client ID;file contents;file name` - response to a text file editing request. I didn't try it out yet, but sending it without asking can probably pop up an editor window with arbitrary text.
Fun fact: adding a file or folder named `FileManagerSplit` to any directory and then navigating there seems to partially break the file manager. A file/folder named `<Xwormmm>` would probably do the same thing.
## Miscallenous interesting packets
- `Msg;message` - displays a log message in the Log tab of the main RAT window

## Actually using the program
After getting the server IP, port and encryption key, faking packets is fairly trivial. The program takes input from its command line arguments and puts the `<Xwormmm>` separator between them. Files can be gzipped and included with the previously described `gz:` syntax. The `-e` switch is used for starting the encryption. First argument is the output file, then the packet follows. Some examples:
- `python main.py -e packet.bin INFO ID User OS Version Date USB UAC Webcam Antivirus` - makes a fake INFO packet and writes it to `packet.bin`. **Note that `packet.bin` is overridden**. Use `-ae` in the beginning to append to the file instead of overwriting.
- `python main.py -e packet.bin FileM ..\..` - crafts a packet that begins a file manager session with the ID `..\..`, preparing it for a path traversal attack.
- `python main.py -ae packet.bin downloadedfile ..\.. gz:evil.bat Fixer.bat` - Continues the previous packet (note the `-ae`!) with one that overwrites `Fixer.bat` in the XWorm folder with our nicely crafted `evil.bat` (`evil.bat` must be obviously in the same directory as `main.py` or you need to give the full absolute/relative path to it).
When all of this is done and you have one or more packet files to go, just send them over to the server with any socket connection program. For example, with netcat: `netcat IP PORT < packet.bin`.