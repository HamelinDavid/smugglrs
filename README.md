Smugglrs
-------------------

A simple reverse TCP tunnel.

## Why would I want to use this ?

Consider the following diagram:

```
                       ┌─────┐
            Clients───►│ ┌─┐ │
                       │ │C│ │
┌────────────────────┐ │ └─┘ │
│┌─┐  ┌────────┐  ┌─┐│ │ ┌─┐ │
││A├──┤Firewall│  │B││ │ │D│ │
│└─┘  └────────┘  └─┘│ │ └─┘ │
└──▲─────────────────┘ │ ┌─┐ │
   │                   │ │E│ │
   │Your machines      │ └─┘ │
   │                   └─────┘
```

In this example, you can control machines `A` and `B`,
And you'd like to host a server for some clients, `C` `D` and `E`.

Ideally, you would host your server on machine `A`, which is
way more powerful than machine `B`. However, `A` is behind a firewall
not under your control, so you cannot open any ports.

`smugglrs` can solve this problem by running both on machine `B` (the _gateway_)
and machine `A` (the _server_). It establishes a reverse TCP tunnel routing traffic as follows:

```
      Smugglrs             
 ┌────────────────┐     ┌─┐
 │                │ ┌───┼C│
 │                │ │   └─┘
┌▼┐  ┌────────┐  ┌▼┐│   ┌─┐
│A│──┤Firewall│  │B◄┼───┼D│
└─┘  └────────┘  └─┘│   └─┘
                    │   ┌─┐
                    └───┼E│
                        └─┘
```

## How to install

- [Install rust if you haven't already](https://www.rust-lang.org/tools/install)
- Compile the project using `cargo build --release`
- The compiled binary is located in `./target/releases/smugglrs`
  Copy it to a new directory on your gateway and on your server.

## Gateway installation
In the directory you just created on the gateway, 
create a new file `config.toml` with the following content:
```
mode = "gateway"
port = 14531
```
You can change the port if you want, just don't forget to
open the port on your router if you have one.

Execute the `smugglrs` binary in the directory.
A new file `aeskey.bin` should be generated.
This is the symmetric key used to authentificate the server.

## Server installation
On your server, go to the directory you created before that contains
the `smugglrs` binary. First, copy the `aeskey.bin` that was generated
before, then create a new file `config.toml` with the following content:

```
mode = "server"
port = 14531
gateway_address = "<youriphere>"
redirects = [[25565, "TCP"]]
```

You will need to change the `gateway_address` field to the public IP
of your gateway server.

`redirects` contains the list of ports that should be redirected.
In the example `config.toml` above, all connection to port `25565`
on the gateway will be tunnelled to the port `25565` on the server.

You can add more than one redirect if needed. However,
UDP is not yet supported.

Once this is done, execute the `smugglrs` binary on the server;
it should connect to the gateway.

## HTTP/HTTPS proxy

If the server fails to connect, it may be because traffic has to go
through an http/https proxy. You can test this by checking the
`http_proxy` (or sometime `https_proxy`) environment variable.
If it is set, then you need to tweak the `config.toml` on the server.
Add the following line:
```
http_proxy = "<proxyip>:<proxyport>"
```
Replacing `<proxyip>` with the IP of the proxy (**without** the leading `http://`),
and `<proxyport>` with the port of the proxy (usually `3128`).

Restart the server, this time it should connect. If it still doesn't,
you can try changing the port of the gateway to `443`. 
If it still doesn't work after this, you're out of luck : the firewall
is smart enough to figure out that you're not really connecting to
a website using `https`.

