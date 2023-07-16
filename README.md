# Wasp Malware Controller

This is an implementation of a controller for the [HiddenWasp malware](https://intezer.com/blog/malware-analysis/hiddenwasp-malware-targeting-linux-systems/).
This repo is an example to accompany my stream series on [Twitch](https://twitch.tv/cyberkaida) on reverse engineering malware and writing controller software.

> What is a controller?

A malware controller is an implementation of the server side command and control (C2) software for a malware. In this case we reverse engineered HiddenWasp
on stream to understand its functionality and then implement the server side of the malware using the client side as a guide.

We had to understand a few things to do this:
- How to start a Wasp malware running, what does it expect when it is deployed?
- How does Wasp determine the server to communicate with? How do we patch it to talk to us instead?
- The communications flow, how does a Wasp choose to communicate? What protocol does it use?
- The encryption and decryption for the communications protocol and any key material. Do we need to alter key material?

> Why build this?

Building a controller can be useful for dynamic analysis of a malware or shutting down a malware campaign.
In this case this was to demonstrate how to build a controller. It is also a great way to prove your analysis
correct and test your understanding.

> What can this controller do?

This controller allows you to configure a Wasp executable to communicate to a new C2 server. We've also implemented the
following commands.

- Downloading a file from the infected machine
- Uploading a file to the infected machine
- Listing a directory
- Running a shell command
- Establishing a reverse proxy

## Using the controller

Build and run the container (note no-network flag)

```sh
docker build -t wasp . ; docker run --rm -t -i --net none --name wasp wasp
```

Log into the container in another shell and start the Wasp beaconing.

```sh
docker exec -t -i wasp /tmp/libse1inux.emptycipher.localhost.patched
```

You should see communications from the Wasp in your main shell.

To interact with the Wasp, log in to the container and start the UI.

```sh
docker exec -t -i wasp python3 /wasp-server/wasp_ui.py
```

## Using the Wasp UI

The UI is a simple shell that allows you to control Wasps.
You can run `help` in the shell to see the implemented commands.

First you must run `list` to see available Wasps that have contacted the C2.
Then run  `select <wasp id>` to control that particular Wasp instance. Otherwise
your commands will not go anywhere.

# Architecture notes

The server and communications protocol is implmented in [wasp/server.py](wasp/server.py)
Abstract command serialisation logic is in the base `WaspCommand` class and `WaspResponse` class.
Each command is registered with the framework using the `@WaspCommandClass` decorator. This hooks
the command class into the command map, which lets the abstract type find the concrete type during
serialization.

In general the logic for moving things around on disk lives in the `WaspMalware` class.

Configuration logic is implemented in [wasp/wasp\_builder.py](wasp/wasp_builder.py).

## Commands left to implement

These can be found in `0fe1248ecab199bee383cef69f2de77d33b269ad1664127b366a4e745b1199c8` at offset `0x41a91c` (`Worker::HandleRequest`).

- `copy`
- `remove`
- `move`
- `connect`
- `script`

