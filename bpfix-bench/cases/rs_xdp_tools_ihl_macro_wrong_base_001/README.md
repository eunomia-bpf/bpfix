# rs_xdp_tools_ihl_macro_wrong_base_001

Source: real project seed from `xdp-tools` commit `e946950`,
`xdp-filter/xdpfilt_prog.h`, license `GPL-2.0`.

The xdp-tools filter program is generated from a shared header with parser
helpers, inline verdict functions, and macro-wrapped checks. This minimized
candidate keeps the source/object correlation shape: a macro proves bounds for
one L4 pointer while the rejected read happens in an inline helper using a
different pointer derived from the IPv4 IHL field.

A correct repair must validate the variable IHL-derived UDP header pointer and
preserve UDP destination filtering, including IPv4 packets with options.
Checking only `iph + 1` is not enough.
