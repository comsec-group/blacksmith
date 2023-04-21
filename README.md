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

Now we can run Blacksmith. For example, we can run Blacksmith in fuzzing mode by passing a config file (see
[JSON configuration](#json-configuration)) and tell Blacksmith to do a sweep with the best found pattern after fuzzing 
finished (`--sweeping`): 

```bash
sudo ./blacksmith --runtime-limit 21600 --config config/esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS.json --sweeping --logfile stdout.log  
```

While Blacksmith is running, you can use `tail -f stdout.log` to keep track of the current progress (e.g., patterns, found bit flips). You will see a line like 
```
[!] Flip 0x2030486dcc, row 3090, page offset: 3532, from 8f to 8b, detected after 0 hours 6 minutes 6 seconds.
```
in case that a bit flip was found. After finishing the Blacksmith run, you can find a `fuzz-summary.json` that contains the information found in the `stdout.log` in a machine-processable format. In case you passed the `--sweeping` flag, you can additionally find a `sweep-summary-*.json` file that contains the information of the sweeping pass.

## Supported Parameters

Blacksmith supports the command-line arguments listed in the following.
Except for the `--config` parameter all other parameters are optional.

```
    -h, --help
        shows this help message

==== Mandatory Parameters ==================================

    -c, --config
        path to JSON file containing the memory configuration to use. See below for sample configuration 
    
==== Execution Modes ==============================================

    -f, --fuzzing
        perform a fuzzing run (default program mode)        
    -g, --generate-patterns
        generates N patterns, but does not perform hammering; used by ARM port
    -y, --replay-patterns <csv-list>
        replays patterns given as comma-separated list of pattern IDs
    -l, --logfile
        log to specified file

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

## JSON Configuration

### Overview

Blacksmith uses a JSON config file for configuration. To provide a path to the config file, use the `--config` flag. 
All keys in the config file are required for the `blacksmith` binary. For pre-made config files, please refer to the 
[config directory](config/).

### Keys

| Key            | Type                 | Description                                                                                                                                                            | Example                                           |
|----------------|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| name           | string               | A user-defined name identifying this config                                                                                                                            | "esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS"    |
| channels       | uint                 | Number of active channels in the system                                                                                                                                | 1                                                 |
| dimms          | uint                 | Number of active DIMMs in the system                                                                                                                                   | 1                                                 |
| ranks          | uint                 | Number of ranks on the DIMM                                                                                                                                            | 2                                                 |
| total_banks    | uint                 | Number of *total* banks in the system, i.e., #banks * #ranks                                                                                                           | 32                                                |
| max_rows       | uint                 | Maximum number of aggressor rows                                                                                                                                       | 30                                                |
| threshold      | uint                 | Threshold to distinguish between row buffer miss (t > `threshold`) and row buffer hit (t < `threshhold`).                                                              | 400                                               |
| hammer_rounds  | uint                 | Number of rounds to hammer                                                                                                                                             | 1000000                                           |
| drama_rounds   | uint                 | Number of rounds to measure cache hit/miss latency                                                                                                                     | 1000                                              |
| acts_per_trefi | uint                 | Number of measured activations per REFRESH interval (optional, set to zero to make blacksmith determine acts-per-ref on the fly)                                       | 76                                                |
| row_bits       | [uint &#124; [uint]] | Row Bits of a given address. For multi-bit schemes, e.g. bank functions, you can pass a list of bits. Each entry in the list determines a row in the address matrix    | [29,28,27,26,25,24,23,22,21,20,19,18]             |
| col_bits       | [uint &#124; [uint]] | Column bits of a given address. For multi-bit schemes, e.g. bank functions, you can pass a list of bits. Each entry in the list determines a row in the address matrix | [12,11,10,9,8,7,6,5,4,3,2,1,0]                    |
| bank_bits      | [uint &#124; [uint]] | Bank bits of a given address. For multi-bit schemes, e.g. bank functions, you can pass a list of bits. Each entry in the list determines a row in the address matrix   | [[6, 13], [14, 18], [15, 19], [16, 20], [17, 21]] |

The values for keys `row_bits`, `col_bits`, and `bank_bits` can be reversed-engineered by using a tool such as DRAMA.
The values for `channels`, `dimms`, `ranks`, `total_banks`, `threshold`, and `acts_per_trefi` depend on the memory 
configuration and the CPU in use.
The values for `max_rows`, `hammer_rounds`, and `drama_rounds` are parameters in blacksmith experiments. 

### Sample JSON Configuration

The following configuration contains reasonable default values for `hammer_rounds` and `drama_rounds` as well as reverse-engineered address mappings for a Intel i5-6400 CPU with a single G.SKILL F4-2133C15-16GIS DIMM.

```json
{
  "name": "esprimo-d757_i5-6400_gskill-F4-2133C15-16GIS",
  "channels": 1,
  "dimms": 1,
  "ranks": 2,
  "total_banks": 32,
  "max_rows": 30,
  "threshold": 300,
  "hammer_rounds": 1000000,
  "drama_rounds": 1000,
  "acts_per_trefi": 76,
  "row_bits": [29,28,27,26,25,24,23,22,21,20,19,18],
  "col_bits": [12,11,10,9,8,7,6,5,4,3,2,1,0],
  "bank_bits": [[6, 13], [14, 18], [15, 19], [16, 20], [17, 21]]
}
```
If you have reverse-engineered the DRAM address mappings for your system, please consider 
[submitting a pull request](https://github.com/comsec-group/blacksmith/pulls) with your configuration file. This 
will enable other members of the research community to benefit from your findings and use them for their own experiments.

## Additional Tools

### determineConflictThreshold
The `determineConflictThreshold` tool helps experimentally determine the value for `threshold`. Pass a JSON config file 
using the `--config` parameter. Set `threshold` to 0 in the JSON config file. The tool repeatedly measures access timings
between same-bank same-row addresses (low latency) and same-bank differing-row addresses (high latency) and logs those
timings to a CSV file (`--output` argument). After analysis of conflict threshold data, e.g., by using 
`tools/visualize_access_timings.py`, update the `threshold` value in the config file.

### determineActsPerRef
The `determineActsPerRef` tool helps in determining the number of row activations between two TRR refresh instructions.
It repeatedly measures the timing between two random addresses which share the same bank with different rows and logs
those timings to a CSV file. After some number of row activations, a REFRESH command will be issued by the memory controller.
This REFRESH command results in a longer access time for the subsequent row activation and can be observed by analyzing
the resulting CSV file. Since two row activations happen per measurement, the expected activations per refresh interval 
can be approximated by the average of twice the number of measurements between timing peaks. The python script in 
`tools/visualize_acts_per_ref.py` can be used to determine the correct number of activations per REFRESH interval.
The number of activations is required for fuzzing using `blacksmith`. You can pass it using the `acts_per_trefi` key in 
the config file. If `acts_per_trefi` is set to zero, `blacksmith` periodically determines the activations per refresh 
cycle while fuzzing.

### checkAddrFunction
The `checkAddrFunction` tool can be used to verify the correctness of reverse-engineered memory mapping. It measures
the average access timing between all rows on all banks for a given JSON configuration passed with the --config parameter. 
If the configuration is correct, all accesses should take at least `threshold` cycles. If the tool measures less than 
`threshold` cycles between addresses accesses, an error is logged. All measurements are logged to the output file 
specified by `--output` for further analysis.

### tools/visualize_acts_per_ref.py
The `visualize_acts_per_ref tool` enables users to visualize data collected using `determineActsPerRef`. By analyzing 
the mean distance between timing peaks in the visualization, one can determine the activations per REFRESH interval. 
It's important to note that since two address accesses are performed for each measurement, one needs to **multiply the 
observed distance by two** to obtain the correct value for `acts_per_trefi`.

### tools/visualize_access_timings.py
This tool can be used to visualize the data collected with `determineConflictThreshold`. The visualization should 
show two piles, one around the average row buffer hit timing, the other around the average row buffer miss timing. The 
conflict `threshold` can be choosen somewhere between those two piles.

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
