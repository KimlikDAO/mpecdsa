# MPECDSA

This repository contains an implementation of the 2-of-n threshold ECDSA protocol described in
_Threshold ECDSA from ECDSA assumptions_ by Jack Dorner, Yashvanth Kondi, Eysa Lee, and abhi shelat

## How to compile on Linux

The protocol is implemented in Rust, and requires features in rust nightly (as of early 2018).  We have found the easiest way to install this is to use [rustup](https://rustup.rs/).
```
$ rustup default nightly
``` 
This repository also depends on the ```curves``` crate which implements the secp256k1 elliptic curve used to instantiate ECDSA with a 256-bit security parameter. Thus, to set up this repository,
```
$ git clone --recurse-submodules https://gitlab.com/neucrypt/mpecdsa.git
```
And to compile,
```
$ cargo build --release
```
Finally, the included test cases can be run via
```
$ cargo test
```
### How to compile on MacOS

Our protocol requires the [```openmp```](https://www.openmp.org/) compiler feature, which is provided by ```gcc```, but not by ```clang```. The easiest way to compile on MacOS is to install ```gcc``` via either [MacPorts](https://www.macports.org/) or [Brew](https://brew.sh/) and then to make the following changes:

1. Replace ```gcc``` with the full path to your new gcc binary in line 13 of ```build.rs```. For example,
	
	```
	Command::new("/usr/local/bin/gcc-7").args(&["src/sha256_octa.c", "-c", "-mavx2", "-O3", "-fPIC", "-fopenmp", "-Wa,-q", "-o"])
	```

2. Prepend ```CC=<gcc path>``` to your cargo commands. For example,
	
	```
	$ CC=/usr/local/bin/gcc-7 cargo build --release
	```
	
  
## Benchmarking
This repository includes three benchmark applications, which were used to generate the experimental results reported in the paper. They are:

+ ```bench_sign``` - benchmarks the 2-of-2 signing protocol, or the 2-of-2 setup protol if the ```--bench_setup``` flag is used. This program plays the role of Alice, unless it is given the ```--bob``` flag.
+ ```bench_thres_sign``` - benchmarks the 2-of-n signing protocol. This program plays the role of Alice, unless it is given the ```--bob``` flag.
+ ```bench_thres_setup``` - benchmarks the 2-of-n setup protocol. Note that the number of parties must be specified via the ```-N``` flag, and the (zero indexed) party number must be specified via the ```-P``` flag.

All of these programs represent one party, and expect to connect to other parties via the network. All of them also accept the ```--help``` flag, which lists their arguments. As an example, to benchmark 2-of-2 signing, one must first start the server on one machine:
```
$ ./target/release/bench_sign 
args: ["./target/release/bench_sign"]
Waiting for client to connect on 0.0.0.0:12345
```
Next, one must start the client in another terminal or on another machine, using the ```-c <address>``` option to specify a server:
```
$ ./target/release/bench_sign -c localhost --bob
args: ["./target/release/bench_sign", "-c", "localhost", "--bob"]
Connecting to server "localhost:12345"...
Connected. Performing 1000 Iteration Benchmark...
PT3.519420S ms avg
```

In addition, this repository comes with a number of local-machine benchmarks that do not make use of the network. These may be accessed via

```
$ cargo bench
```

# How to use the protocol
This software is provided under the Three-clause BSD License. We make serious efforts to check this code for errors and vulnerabilities, but this is an *academic project* and we caution against using this implementation in any production scenario.