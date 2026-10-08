# Third-party components

- `engine/tpws`: official `bol-van/zapret` tpws sources based on commit `c4d0b1990129dce2b28095277173ee0d7702d304`, with the local compatibility patch described below. Source: https://github.com/bol-van/zapret/tree/c4d0b1990129dce2b28095277173ee0d7702d304/tpws. License: `licenses/zapret-MIT.txt`; individual headers retain their own notices, including uthash, OpenBSD tree/PF definitions and epoll-shim.
- `lists/*.txt` (excluding newly created `*-user.txt`) and `targets.txt`: Flowseal `zapret-discord-youtube` tag `1.10.3`, commit `865da4f` as shown by the release. Source: https://github.com/Flowseal/zapret-discord-youtube/tree/1.10.3. License: `licenses/Flowseal-LICENSE.txt`.
- `payloads/discord-fake.bin`: unchanged `bin/ACTIVE_DISCORD_UDP.bin` from that same Flowseal release; attribution and license are retained. Only used by the experimental local UDP relay.
- epoll-shim is bundled in upstream tpws. Its MIT notice from the original project is included at `licenses/epoll-shim-LICENSE`. Source: https://github.com/jiixyj/epoll-shim/blob/master/LICENSE.

This package does not ship WinDivert, Windows executables, or Flowseal's batch files. The retained Flowseal license file describes those components in its original distribution.

The local Python controller, UDP relay, launchers, documentation and tests are supplied under the root `LICENSE`. The NAT lookup wire layout follows the small PF compatibility header already bundled in upstream tpws; no XNU kernel implementation is bundled. Neither Flowseal nor bol-van is presented as the author or maintainer of this macOS controller.

The UDP NAT lookup uses Apple's `PF_EXTFILTER_APD = 1` state-key discriminator, documented in the public [XNU PF definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h) and [UDP state lookup](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pf.c). This is an interface constant; Apple kernel code is not bundled.

Local tpws patch: `engine/tpws/helpers.c` copies IPv4/IPv6 addresses directly into `sockaddr_in46` members in `sa46copy`. The upstream cast to `sockaddr_storage *` imposes stronger alignment than the small union guarantees on Darwin. A transparent TCP test on macOS 15 triggered UndefinedBehaviorSanitizer at that copy. The patch preserves address bytes and removes the invalid alignment assumption; `native/address_copy_check.c` provides a sanitizer regression. It does not change SOCKS local-address restrictions or PF destination lookup.
