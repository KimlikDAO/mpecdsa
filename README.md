# MPECDSA

This repository contains the following implementations: 
* The 2-of-n threshold ECDSA protocol described in
[_Secure Two-party Threshold ECDSA from ECDSA assumptions_](https://eprint.iacr.org/2018/499) by Jack Doerner, Yashvanth Kondi, Eysa Lee, and abhi shelat.
* The t-of-n threshold ECDSA protocol described in [_Threshold ECDSA from ECDSA Assumptions: the Multiparty Case_](https://eprint.iacr.org/2019/523) by Jack Doerner, Yashvanth Kondi, Eysa Lee, and abhi shelat.
* The threshold signature proactivization protocols described in [_Refresh When You Wake Up:Proactive Threshold Wallets with Offline Devices_](https://eprint.iacr.org/2019/1328) by Yashvanth Kondi, Bernardo Magri, Claudio Orlandi, and Omer Shlomovits

## Compilation

### How to compile on Linux

The protocols contained in this repo are implemented in Rust, and requires features in rust nightly (as of early 2018).  We have found the easiest way to install this is to use [rustup](https://rustup.rs/).
```
$ rustup default nightly
``` 
This repository also depends on the ```curves``` crate which implements the secp256k1 elliptic curve used to instantiate ECDSA with a 256-bit security parameter. Thus, when cloning this repository, be sure to initialize submodules.
```
$ git clone --recurse-submodules https://gitlab.com/neucrypt/mpecdsa.git
```
Alternatively, submodules may be initialized after cloning via
```
$ git submodule init; git submodule update
```
To compile, run
```
$ cargo build --release
```
Finally, the included test cases can be run via
```
$ cargo test
```

### How to compile on MacOS

Some parts of this project are written in C and require the [```openmp```](https://www.openmp.org/) compiler feature, which is provided by ```gcc```, but not by ```clang```. The easiest way to compile on MacOS is to install ```gcc``` via either [MacPorts](https://www.macports.org/) or [Brew](https://brew.sh/) and then prepend ```CC=<gcc path>``` to your cargo commands. For example,
	
```
$ CC=/usr/local/bin/gcc-7 cargo build --release
```
	
  
### How to cross-compile for Linux on MacOS
This allows you to produce a statically-linked executable for Linux from  MacOS.

```
$ brew install FiloSottile/musl-cross/musl-cross
$ brew install isl
$ install_name_tool -change '@@HOMEBREW_PREFIX@@/opt/isl/lib/libisl.15.dylib' /usr/local/opt/isl/lib/libisl.dylib /usr/local/opt/musl-cross/libexec/libexec/gcc/x86_64-linux-musl/6.3.0/cc1
$ install_name_tool -change '@@HOMEBREW_PREFIX@@/opt/isl/lib/libisl.15.dylib' /usr/local/opt/isl/lib/libisl.dylib /usr/local/opt/musl-cross/libexec/libexec/gcc/x86_64-linux-musl/6.3.0/cc1plus
$ install_name_tool -change '@@HOMEBREW_PREFIX@@/opt/isl/lib/libisl.15.dylib' /usr/local/opt/isl/lib/libisl.dylib /usr/local/opt/musl-cross/libexec/libexec/gcc/x86_64-linux-musl/6.3.0/lto1
```
Finally, you can run
```
$ CC=/usr/local/bin/x86_64-linux-musl-gcc CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/usr/local/bin/x86_64-linux-musl-gcc cargo build --release --target=x86_64-unknown-linux-musl
``` 


### Feature flags
* ```blake2``` - causes the resulting code to use the blake2 hash instead of SHA256. If an optimized version of blake2 is available for the target architecture, it will be used.
* ```openmp``` - enables automatic openmp parallelization of either SHA256 or blake2 hashing. Use this feature with caution; it is not guaranteed to improve performance, and it does not take the main rayon-based parallelization strategy into account in any way.
* ```rpi3``` - triggers optimizations specific to the Raspberry Pi 3 (and implies the ```blake2``` feature).


### Runtime environment variables
* ```RAYON_NUM_THREADS``` - sets the exact number of threads used by rayon for parallelism. Leaving this variable unset allows rayon to choose automatically.
* ```OMP_NUM_THREADS``` - sets the exact number of threads used by openmp for parallelism (if openmp is enabled). Leaving this variable unset allows openmp to choose automatically.


## Benchmarking
This repository includes three benchmark applications, which were used to generate the experimental results reported in the papers. They are:

+ ```bench_sign``` - benchmarks the 2-of-2 signing protocol, or the 2-of-2 setup protol if the ```--bench_setup``` flag is used. This program plays the role of Alice, unless it is given the ```--bob``` flag.
+ ```bench_thres_sign``` - benchmarks the t-of-n signing protocol. This program plays the role of Alice, unless it is given the ```--bob``` flag. The ```--bench_proactive``` will cause the proactivization protocols to be included in the benchmark.
+ ```bench_thres_setup``` - benchmarks the 2-of-n setup protocol. Note that the number of parties must be specified via the ```-N``` flag, and the (zero indexed) party number that this program plays must be specified via the ```-P``` flag.

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

# Building on this work
This software is provided under the Three-clause BSD License. We make serious efforts to check this code for errors and vulnerabilities, but this is an *academic project* and we caution against using this implementation in any production scenario.