# packet_macro_cookie_001

The rejected pointer operation is hidden inside an inline helper rather than in
the XDP entry function. The helper establishes packet bounds, then destroys the
UDP-header pointer by treating it as an integer cookie before reading the
destination port.

The oracle checks DNS drop/pass behavior and guards against repairs that ignore
the packet parser.
