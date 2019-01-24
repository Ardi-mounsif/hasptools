# HASP

Client / Server / Proxy Emulation Work for HASP HL PRO/MAX/RTC Dongles.


## Core Components
- Dongles: Necessary metadata about the dongle to emulate.
- APIs: Necessary data to emulate a particular hasp API (generally paired by vendor ID).
- Server: Consumes both APIs and Dongles to serve hasp functionality to client processes.
- Client: Consumes API to act like a client process and talk to a real service/dongle.
- Proxy : Sits between a real client and server to record transactions.




### TODO
- Test fake client against fake server.
- Test real software against server.

