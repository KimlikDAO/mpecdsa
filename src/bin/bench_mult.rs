use ::mpecdsa::mpmul::*;
use ::mpecdsa::mul::*;
use ::mpecdsa::ro::*;
use ::mpecdsa::*;
use rand::Rng;
use rayon::prelude::*;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::sleep;
use std::time::Duration;

extern crate curves;
use curves::{Ford, SecpOrd};

extern crate getopts;
use self::getopts::{Matches, Options};

// options from bench_sign; update for n party
pub fn process_options() -> Option<Matches> {
    let args: Vec<String> = env::args().collect();

    println!("args: {:?}", args);

    let mut opts = Options::new();
    opts.optopt("o", "", "set output file name", "NAME");
    opts.optopt(
        "p",
        "port",
        "lowest port (the required number will be allocated above)",
        "PORT",
    );
    opts.optopt("n", "iterations", "number of iterations", "ITERS");
    opts.optopt(
        "a",
        "addresses",
        "comma-delimited list of IP Addresses",
        "IP",
    );

    opts.optflag("h", "help", "print this help menu");

    // threshold flags
    //opts.optopt("T", "threshold", "size of threshold", "THRES");
    opts.optopt("N", "size", "number of parties", "SIZE");
    opts.optopt("P", "party", "party number", "PARTY");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };

    if matches.opt_present("h") {
        let program = args[0].clone();
        let brief = format!("Usage: {} [options]", program);
        print!("{}", opts.usage(&brief));
        return Option::None;
    }

    return Option::Some(matches);
}

fn main() {
    let matches = process_options();
    if let None = matches {
        ::std::process::exit(1);
    }
    let matches = matches.unwrap();

    // number of parties
    let parties = matches
        .opt_str("N")
        .unwrap_or("2".to_owned())
        .parse::<usize>()
        .unwrap();
    //let thres = matches.opt_str("T").unwrap_or("2".to_owned()).parse::<usize>().unwrap();
    // If party index isn't specified, assume 2P
    let index = matches.opt_str("P").unwrap().parse::<usize>().unwrap();
    let mut sendvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(parties);
    let mut recvvec: Vec<Option<std::net::TcpStream>> = Vec::with_capacity(parties);

    if !matches.opt_present("p") && parties != 2 {
        println!("Please add ports");
        ::std::process::exit(1);
    }

    // ports should be separated by commas
    let addrs = matches.opt_str("a").unwrap_or("0.0.0.0".to_owned());
    let addrs: Vec<&str> = addrs.split(",").collect();
    let port: usize = matches
        .opt_str("p")
        .unwrap_or("12345".to_owned())
        .parse()
        .unwrap();
    //let min_ports = parties*(parties)/2;
    //let mut ports = Vec::with_capacity(min_ports);
    //for ii in port..(port+min_ports) {
    //    ports.push(format!("{}", ii));
    //}

    for jj in 0..parties {
        // first n-1 are party 0's ports, next n-2 party 1, ...
        // given a high and a low, offset into list of ports is
        //      sum i =1...low (n-i) => n*low - low*(low+1)/2
        // corresponding port for high is given as the difference between high and low -1
        //      high - low - 1
        // port_index for pair high, low becomes
        //      (n * low) - low * (low + 1) / 2 + high - low - 1

        if jj < index {
            //let port_index = (jj*parties)-(jj*(jj+1))/2 + (index-jj) - 1;
            //let port = format!("0.0.0.0:{}", &ports[port_index]);
            let port = format!("0.0.0.0:{}", &(port + jj));
            println!("{} waiting for {} to connect on {}", index, jj, port);
            let listener = TcpListener::bind(port).unwrap_or_else(|e| panic!("{}", e));
            let (recv, _) = listener.accept().unwrap_or_else(|e| panic!("{}", e));
            let send = recv.try_clone().unwrap();
            recv.set_nodelay(true).expect("Could not set nodelay");
            send.set_nodelay(true).expect("Could not set nodelay");
            sendvec.push(Some(send));
            recvvec.push(Some(recv));
        } else if jj > index {
            //let port_index = (index*parties)-(index*(index+1))/2 + (jj-index) - 1;
            //let port = format!("{}:{}", addrs[jj], &ports[port_index]);
            let port = format!("{}:{}", addrs[jj], &(port + index));
            println!("{} connecting to {} server {:?}...", index, jj, port);
            let mut send = TcpStream::connect(&port);
            let connection_wait_time = 10 * 60;
            let poll_interval = 100;
            for _ in 0..(connection_wait_time * 1000 / poll_interval) {
                if send.is_err() {
                    sleep(Duration::from_millis(poll_interval));
                    send = TcpStream::connect(&port);
                }
            }
            let send = send.unwrap();
            let recv = send.try_clone().unwrap();
            recv.set_nodelay(true).expect("Could not set nodelay");
            send.set_nodelay(true).expect("Could not set nodelay");
            sendvec.push(Some(send));
            recvvec.push(Some(recv));
        } else {
            // pause here so the lower numbers can start their listeners?
            //sleep(Duration::from_millis(500));
            sendvec.push(None);
            recvvec.push(None);
        }
    }

    let iters = matches
        .opt_str("n")
        .unwrap_or("1000".to_owned())
        .parse::<i32>()
        .unwrap();
    let mut seeder = rand::os::OsRng::new().unwrap();
    let mut rng = rand::ChaChaRng::new_unseeded();
    rng.set_counter(seeder.gen::<u64>(), seeder.gen::<u64>());

    if index == parties - 1 {
        for ii in 0..parties - 1 {
            sendvec[ii]
                .as_mut()
                .unwrap()
                .write(&[0])
                .expect(&format!("Party {} failed to send ready signal.", index));
            sendvec[ii]
                .as_mut()
                .unwrap()
                .flush()
                .expect(&format!("Party {} failed to flush.", index));
        }
    } else {
        let mut sigread = [1u8; 1];
        recvvec[parties - 1]
            .as_mut()
            .unwrap()
            .read_exact(&mut sigread)
            .expect(&format!("Party {} failed to read ready signal.", index));
    }

    println!("{} connected. Initializing...", index);

    let mut ro = {
        let mut prunedrecv: Vec<Option<&mut _>> =
            recvvec.iter_mut().map(|val| val.as_mut()).collect();
        let mut prunedsend: Vec<Option<&mut _>> =
            sendvec.iter_mut().map(|val| val.as_mut()).collect();
        GroupROTagger::from_network_unverified(
            index,
            &mut rng,
            &mut prunedrecv[..],
            &mut prunedsend[..],
        )
        .unwrap()
    };

    let mut rngs = Vec::with_capacity(parties);
    for _ in 0..parties {
        let mut newrng = rand::ChaChaRng::new_unseeded();
        newrng.set_counter(rng.next_u64(), rng.next_u64());
        rngs.push(newrng);
    }

    let threadcount = match std::env::var_os("RAYON_NUM_THREADS") {
        Some(val) => {
            let val = val.into_string().unwrap().parse().unwrap();
            if val > 0 {
                val
            } else {
                parties
            }
        }
        None => parties,
    };

    let rayonpool = rayon::ThreadPoolBuilder::new()
        .num_threads(threadcount)
        .build()
        .unwrap();
    let multipliervec = rayonpool.install(|| {
        sendvec
            .par_iter_mut()
            .zip(recvvec.par_iter_mut())
            .zip(rngs.par_iter_mut())
            .enumerate()
            .map(|(ii, ((sendi, recvi), rngi))| {
                if ii > index {
                    MulPlayer::Sender(
                        mul::MulSender::new(
                            &ro.get_dyadic_tagger(ii).unwrap(),
                            rngi,
                            recvi.as_mut().unwrap(),
                            sendi.as_mut().unwrap(),
                        )
                        .unwrap(),
                    )
                } else if ii < index {
                    MulPlayer::Recver(
                        mul::MulRecver::new(
                            &ro.get_dyadic_tagger(ii).unwrap(),
                            rngi,
                            recvi.as_mut().unwrap(),
                            sendi.as_mut().unwrap(),
                        )
                        .unwrap(),
                    )
                } else {
                    MulPlayer::Null
                }
            })
            .collect::<Vec<_>>()
    });

    let counterparties = (0..parties).collect::<Vec<usize>>();
    ro.apply_subgroup_list(&counterparties).unwrap();

    if index == parties - 1 {
        let mut sigread = [1u8; 1];
        for ii in 0..parties - 1 {
            recvvec[ii]
                .as_mut()
                .unwrap()
                .read_exact(&mut sigread)
                .expect(&format!("Party {} failed to send ready signal.", ii));
        }
        for ii in 0..parties - 1 {
            sendvec[ii]
                .as_mut()
                .unwrap()
                .write(&[0])
                .expect(&format!("Party {} failed to send ready signal.", index));
            sendvec[ii]
                .as_mut()
                .unwrap()
                .flush()
                .expect(&format!("Party {} failed to flush.", index));
        }
    } else {
        let mut sigread = [1u8; 1];
        sendvec[parties - 1]
            .as_mut()
            .unwrap()
            .write(&[0])
            .expect(&format!("Party {} failed to send ready signal.", index));
        sendvec[parties - 1]
            .as_mut()
            .unwrap()
            .flush()
            .expect(&format!("Party {} failed to flush.", index));
        recvvec[parties - 1]
            .as_mut()
            .unwrap()
            .read_exact(&mut sigread)
            .expect(&format!(
                "Party {} failed to send ready signal.",
                parties - 1
            ));
    }

    println!("Performing {} Iteration Benchmark...", iters);

    let mut prunedrecv: Vec<&mut Option<_>> = recvvec
        .iter_mut()
        .enumerate()
        .filter_map(|(index, val)| {
            if counterparties.contains(&index) {
                Some(val)
            } else {
                None
            }
        })
        .collect();
    let mut prunedsend: Vec<&mut Option<_>> = sendvec
        .iter_mut()
        .enumerate()
        .filter_map(|(index, val)| {
            if counterparties.contains(&index) {
                Some(val)
            } else {
                None
            }
        })
        .collect();
    let mut prunedmultiplier: Vec<&mul::MulPlayer> = multipliervec
        .iter()
        .enumerate()
        .filter_map(|(index, val)| {
            if counterparties.contains(&index) {
                Some(val)
            } else {
                None
            }
        })
        .collect();

    let setupstart = std::time::Instant::now();
    for _ in 0..iters {
        let shares = mprmul(
            1,
            index,
            &mut prunedmultiplier[..],
            &mut ro,
            &mut rng,
            &mut prunedrecv[..],
            &mut prunedsend[..],
            &rayonpool,
        )
        .unwrap();
        let mut shares1 = Vec::with_capacity(shares.len());
        for kk in 0..shares.len() {
            shares1.push(&shares[kk][..]);
        }
        mpmul(
            &[SecpOrd::rand(&mut rng)],
            index,
            &shares1.as_slice(),
            &mut prunedrecv.as_mut_slice(),
            &mut prunedsend.as_mut_slice(),
        )
        .unwrap();
    }
    let duration = setupstart.elapsed();
    println!(
        "{:.3} ms avg",
        (duration.as_millis() as f64) / (iters as f64)
    );
}
