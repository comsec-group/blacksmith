# Blacksmith Rowhammer Fuzzer

[![Academic Code](https://img.shields.io/badge/Origin-Academic%20Code-C1ACA0.svg?style=flat)]() [![Language Badge](https://img.shields.io/badge/Made%20with-C/C++-blue.svg)](https://isocpp.org/std/the-standard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![contributions welcome](https://img.shields.io/badge/Contributions-welcome-lightgray.svg?style=flat)]()


[![DOI](https://img.shields.io/badge/DOI-20.500.11850/525008-yellow.svg)](https://www.research-collection.ethz.ch/handle/20.500.11850/525013) [![Preprint](https://img.shields.io/badge/Preprint-ETH%20Research%20Collection-orange.svg)](https://www.research-collection.ethz.ch/handle/20.500.11850/525008) [![Paper](https://img.shields.io/badge/To%20appear%20in-IEEE%20S&P%20'22-brightgreen.svg)](https://www.ieee-security.org/TC/SP2022/program-papers.html) [![Funding](https://img.shields.io/badge/Grant-NCCR%20Automation%20(51NF40180545)-red.svg)](https://nccr-automation.ch/)

This repository provides the code accompanying the paper _[Blacksmith: Scalable Rowhammering in the Frequency Domain](https://comsec.ethz.ch/wp-content/files/blacksmith_sp22.pdf)_ that is to appear in the IEEE conference Security & Privacy (S&P) 2022.

This is the implementation of our Blacksmith Rowhammer fuzzer. This fuzzer crafts novel non-uniform Rowhammer access patterns based on the concepts of frequency, phase, and amplitude. Our evaluation on 40 DIMMs showed that it is able to bypass recent Target Row Refresh (TRR) in-DRAM mitigations effectively and as such can could trigger bit flips on all 40 tested DIMMs.

## Getting Started

Following, we quickly describe how to build and run Blacksmith.

### Prerequisites

Blacksmith has been tested on Ubuntu 18.04 LTS with Linux kernel 4.15.0. As the CMakeLists we ship with Blacksmith downloads all required dependencies at compile time, there is no need to install any package other than g++ (>= 8) and cmake (>= 3.14).

**NOTE**: The DRAM address functions that are hard-coded in [DRAMAddr.cpp](https://github.com/comsec-group/blacksmith/blob/public/src/Memory/DRAMAddr.cpp) assume an Intel Core i7-8700K. For any other microarchitecture, you will need to first reverse-engineer these functions (e.g., using [DRAMA](https://github.com/IAIK/drama) or [TRResspass' DRAMA](https://github.com/vusec/trrespass/tree/master/drama)) and then update the matrices in this class accordingly.

To facilitate the development, we also provide a Docker container (see [Dockerfile](docker/Dockerfile)) where all required tools and libraries are installed. This container can be configured, for example, as remote host in the CLion IDE, which automatically transfers the files via SSH to the Docker container (i.e., no manual mapping required).

### Building Blacksmith

You can build Blacksmith with its supplied `CMakeLists.txt` in a new `build` directory:

```bash
mkdir build \ 
  && cd build \
  && cmake .. \
  && make -j$(nproc)
```

Now we can run Blacksmith. For example, we can run Blacksmith in fuzzing mode by passing a random DIMM ID (e.g., `--dimm-id 1`; only used internally for logging into `stdout.log`), we limit the fuzzing to 6 hours (`--runtime-limit 21600`), pass the number of ranks of our current DIMM (`--ranks 1`) to select the proper bank/rank functions, and tell Blacksmith to do a sweep with the best found pattern after fuzzing finished (`--sweeping`): 

```bash
sudo ./blacksmith --dimm-id 1 --runtime-limit 21600 --ranks 1 --sweeping  
```

While Blacksmith is running, you can use `tail -f stdout.log` to keep track of the current progress (e.g., patterns, found bit flips). You will see a line like 
```
[!] Flip 0x2030486dcc, row 3090, page offset: 3532, from 8f to 8b, detected after 0 hours 6 minutes 6 seconds.
```
in case that a bit flip was found. After finishing the Blacksmith run, you can find a `fuzz-summary.json` that contains the information found in the stdout.log in a machine-processable format. In case you passed the `--sweeping` flag, you can additionally find a `sweep-summary-*.json` file that contains the information of the sweeping pass.

## Supported Parameters

Blacksmith supports the command-line arguments listed in the following.
Except for the parameters `--dimm-id` and `--ranks` all other parameters are optional.

```
    -h, --help
        shows this help message

==== Mandatory Parameters ==================================

    -d, --dimm-id
        internal identifier of the currently inserted DIMM (default: 0)
    -r, --ranks
        number of ranks on the DIMM, used to determine bank/rank/row functions, assumes Intel Coffe Lake CPU (default: None)
    
==== Execution Modes ==============================================

    -f, --fuzzing
        perform a fuzzing run (default program mode)        
    -g, --generate-patterns
        generates N patterns, but does not perform hammering; used by ARM port
    -y, --replay-patterns <csv-list>
        replays patterns given as comma-separated list of pattern IDs

==== Replaying-Specific Configuration =============================

    -j, --load-json
        loads the specified JSON file generated in a previous fuzzer run, required for --replay-patterns
        
==== Fuzzing-Specific Configuration =============================

    -s, --sync
        synchronize with REFRESH while hammering (default: 1)
    -w, --sweeping
        sweep the best pattern over a contig. memory area after fuzzing (default: 0)
    -t, --runtime-limit
        number of seconds to run the fuzzer before sweeping/terminating (default: 120)
    -a, --acts-per-ref
        number of activations in a tREF interval, i.e., 7.8us (default: None)
    -p, --probes
        number of different DRAM locations to try each pattern on (default: NUM_BANKS/4)

```

The default values of the parameters can be found in the [`struct ProgramArguments`](include/Blacksmith.hpp#L8).

Configuration parameters of Blacksmith that we did not need to modify frequently, and thus are not runtime parameters, can be found in the [`GlobalDefines.hpp`](include/GlobalDefines.hpp) file.

## Citing our Work

To cite the Blacksmith **paper** in other academic papers, please use the following BibTeX entry:

```
@inproceedings{20.500.11850/525008,
  title = {{{BLACKSMITH}}: Rowhammering in the {{Frequency Domain}}},
  shorttitle = {Blacksmith},
  booktitle = {{{IEEE S}}\&{{P}} '22},
  author = {Jattke, Patrick and {van der Veen}, Victor and Frigo, Pietro and Gunter, Stijn and Razavi, Kaveh},
  year = {2022-05},
  note = {\url{https://comsec.ethz.ch/wp-content/files/blacksmith_sp22.pdf}}
  doi = {20.500.11850/525008},
}
```

To cite the Blacksmith **software** in academic papers, please use the following BibTeX entry:

```
@MISC{20.500.11850/525013,
    title = {{{BLACKSMITH}}: Rowhammering in the {{Frequency Domain}}},
	copyright = {MIT License},
	year = {2022-05},
	author = {Jattke, Patrick and van der Veen, Victor and Frigo, Pietro and Gunter, Stijn and Razavi, Kaveh},
	language = {en},
    note = {\url{https://github.com/comsec-group/blacksmith}}
    doi = {20.500.11850/525013}
}
```
