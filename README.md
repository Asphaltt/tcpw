<!--
 Copyright 2024 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# tcpw: An eBPF enhanced tool to capture tcp tuple info of curl,telnet,socat tools

```bash
$ ./tcpw -h
Usage: tcpw [options] <command args...>
Options:
  --udp, -U       Trace UDP sockets
  --unix, -X      Trace Unix domain sockets
  --help, -h      Print this help message
```

By default, `tcpw` only traces TCP *socket*, if you want to trace UDP *socket*, you can use `--udp`/`-U` option; if you want to trace Unix domain *socket*, you can use `--unix`/`-X` option.

Example of tracing TCP *socket*:

```bash
$ ./tcpw curl https://google.com
2024/12/21 14:42:15 tcpw: pid=97849 comm=curl af=AF_INET proto=TCP 192.168.241.133:46182 -> 142.251.10.101:443
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="https://www.google.com/">here</A>.
</BODY></HTML>
```

Example of tracing UDP *socket*:

```bash
$ ./tcpw -U nslookup google.com
2024/12/21 14:44:36 tcpw: pid=98464 comm=isc-net-0000 af=AF_INET proto=UDP 127.0.0.1:37324 -- 127.0.0.53:53
Server:     127.0.0.53
Address:    127.0.0.53#53

Non-authoritative answer:
...
```

Example of tracing Unix domain *socket*:

```bash
$ ./tcpw -X ../sockdump/sockdump-example
2024/12/21 14:45:24 serving
2024/12/21 14:45:24 tcpw: pid=98505 comm=sockdump-exampl af=AF_UNIX proto=UNIX-STREAM path=/tmp/uskdump.sock
2024/12/21 14:45:24 got response
...
```
