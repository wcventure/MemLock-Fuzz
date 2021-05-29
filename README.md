# MemLock: Memory Usage Guided Fuzzing

[![MIT License](https://img.shields.io/github/license/xiaocong/uiautomator.svg)](http://opensource.org/licenses/MIT)

This repository provides the tool and the evaluation subjects for the paper "MemLock: Memory Usage Guided Fuzzing" accepted for the technical track at ICSE'2020. A pre-print of the paper can be found at [ICSE2020_MemLock.pdf](https://wcventure.github.io/pdf/ICSE2020_MemLock.pdf).

The repository contains three folders: [*tool*](#tool), [*tests*](#tests) and [*evaluation*](#evaluation).


## Tool

MemLock is built on top of the fuzzer AFL. Check out [AFL's website](http://lcamtuf.coredump.cx/afl/) for more information details. We provide here a snapshot of MemLock. For simplicity, we provide shell script for the whole installation.


### Requirements

- Operating System: Ubuntu 16.04 LTS (*We have tested the artifact on the Ubuntu 16.04*)
- Run the following command to install Docker (*Docker version 18.09.7*):
  ```sh
  $ sudo apt-get install docker.io
  ```
  (If you have any question on docker, you can see [Docker's Documentation](https://docs.docker.com/install/linux/docker-ce/ubuntu/)).
- Run the following command to install required packages
    ```sh
    $ sudo apt-get install git build-essential python3 cmake tmux libtool automake autoconf autotools-dev m4 autopoint help2man bison flex texinfo zlib1g-dev libexpat1-dev libfreetype6 libfreetype6-dev
    ```


### Clone the Repository

```sh
$ git clone https://github.com/wcventure/MemLock-Fuzz.git MemLock --depth=1
$ cd MemLock
```


### Build and Run the Docker Image

Firstly, system core dumps must be disabled as with AFL.

```sh
$ echo core|sudo tee /proc/sys/kernel/core_pattern
$ echo performance|sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

Run the following command to automatically build the docker image and configure the environment.

```sh
# build docker image
$ sudo docker build -t memlock --no-cache ./

# run docker image
$ sudo docker run --cap-add=SYS_PTRACE -it memlock /bin/bash
```


### Usage

The running command line is similar to AFL.

To perform stack memory usage guided fuzzing, run following command line after use `memlock-stack-clang` to compile the program, as an example shown in `tests/run_test1_MemLock.sh`
```
tool/MemLock/build/bin/memlock-stack-fuzz -i testcase_dir -o findings_dir -d -- /path/to/program @@
```

To perform heap memory usage guided fuzzing, run following command line after use `memlock-heap-clang` to compile the program, as an example shown in `tests/run_test2_MemLock.sh`. 
```
tool/MemLock/build/bin/memlock-heap-fuzz -i testcase_dir -o findings_dir -d -- /path/to/program @@
```


## Tests

Before you use MemLock fuzzer, we suggest that you first use two simple examples provided by us to determine whether the Memlock fuzzer can work normally. We show two simple examples to shows how MemLock can detect excessive memory consumption and why AFL cannot detect these bugs easily. Example 1 demonstrates an uncontrolled-recursion bug and Example 2 demonstrates an uncontrolled-memory-allocation bug.


### Run for testing example 1

Example 1 demonstrates an uncontrolled-recursion bug. The function `fact()` in `example1.c` is a recursive function. With a sufficiently large recursive depth, the execution would run out of stack memory, causing stack-overflow. You can perform fuzzing on this example program by following commands.

```sh
# enter the tests folder
$ cd tests

# run testing example 1 with MemLock
$ ./run_test1_MemLock.sh

# run testing example 1 with AFL (Open another terminal)
$ ./run_test1_AFL.sh
```

In our experiments for testing example 1, MemLock can find crashes in a few minutes while AFL can not find any crashes.


### Run for testing example 2

Example 2 demonstrates an uncontrolled-memory-allocation bug.  At line 25 in `example2.c`, the length of the user inputs is fed directly into `new []`. By carefully handcrafting the input, an adversary can provide arbitrarily large values, leading to program crash (i.e., `std::bad_alloc`) or running out of memory. You can perform fuzzing on this example program by following commands.

```sh
# enter the tests folder
$ cd tests

# run testing example 2 with MemLock
$ ./run_test2_MemLock.sh

# run testing example 2 with AFL (Open another terminal)
$ ./run_test2_AFL.sh
```

In our experiments for testing example 2, MemLock can find crashes in a few minutes while AFL can not find any crashes.


## Evaluation

The fold *evaluation* contains all our evaluation subjects. After having MemLock installed, you can run the script to build and instrument the subjects. After instrument the subjects you can run the script to perform fuzzing on the subjects.


### Build Target Program

In BUILD folder, You can run the script `./build_xxx.sh`. It shows how to build and instrument the subject. For example:

```sh
# build cxxfilt
$ cd BUILD
$ ./build_cxxfilt.sh
```


### Run for Fuzzing

After instrumenting the subjects, In FUZZ folder you can run the script `./run_MemLock_cxxfilt.sh` to run a MemLock fuzzer instance on program *cxxfilt*. If you want to compare its performance with AFL, you can open another terminal and run the script `./run_AFL_cxxfilt.sh`.

```sh
# build cxxfilt
$ cd FUZZ
$ ./run_MemLock_cxxfilt.sh
```


## Publications
```
@inproceedings{wen2020memlock,
Author = {Wen, Cheng and Wang, Haijun and Li, Yuekang and Qin, Shengchao and Liu, Yang, and Xu, Zhiwu and Chen, Hongxu and Xie, Xiaofei and Pu, Geguang and Liu, Ting},
Title = {MemLock: Memory Usage Guided Fuzzing},
Booktitle= {2020 IEEE/ACM 42nd International Conference on Software Engineering},
Year ={2020},
Address = {Seoul, South Korea},
}
```

## Practical Security Impact

### CVE ID Assigned By This Work (26 CVEs)

Our tools have found several security-critical vulnerabilities in widely used open-source projects and libraries, such as Binutils, Elfutils, Libtiff, Mjs.

| Vulnerability | Package | Program | Vulnerability Type |
| - | - | - | - |
| [**CVE-2020-36375**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36375) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36374**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36374) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36373**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36373) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36372**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36372) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36371**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36371) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36370**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36370) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36369**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36369) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36368**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36368) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36367**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36367) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-36366**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36366) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2020-18392**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-18392) | MJS 1.20.1  | mjs  | CWE-674: Uncontrolled Recursion |
| [**CVE-2019-6293**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6293) | Flex 2.6.4  | flex  | CWE-674: Uncontrolled Recursion |
| [**CVE-2019-6292**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6292) | Yaml-cpp v0.6.2  | prase  | CWE-674: Uncontrolled Recursion |
| [**CVE-2019-6291**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6291) | NASM 2.14.03rc1  | nasm  | CWE-674: Uncontrolled Recursion |
| [**CVE-2019-6290**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-6290) | NASM 2.14.03rc1  | nasm  | CWE-674: Uncontrolled Recursion |
| [**CVE-2018-18701**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18701) | Binutils 2.31  | nm       | CWE-674: Uncontrolled Recursion |
| [**CVE-2018-18700**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18700) | Binutils 2.31  | nm       | CWE-674: Uncontrolled Recursion |
| [**CVE-2018-18484**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18484) | Binutils 2.31  | c++filt | CWE-674: Uncontrolled Recursion |
| [**CVE-2018-17985**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17985) | Binutils 2.31  | c++filt | CWE-674: Uncontrolled Recursion |
| [**CVE-2019-7704**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7704) | Binaryen 1.38.22  | wasm-opt | CWE-789: Uncontrolled Memory Allocation |
| [**CVE-2019-7698**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7698) | Bento4 v1.5.1-627  | mp4dump  | CWE-789: Uncontrolled Memory Allocation |
| [**CVE-2019-7148**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-7148) | Elfutils 0.175  | eu-ar  | CWE-789: Uncontrolled Memory Allocation |
| [**CVE-2018-20652**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20652) | Tinyexr v0.9.5  | tinyexr | CWE-789: Uncontrolled Memory Allocation |
| [**CVE-2018-18483**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-18483) | Binutils 2.31  | c++filt | CWE-789: Uncontrolled Memory Allocation |
| [**CVE-2018-20657**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20657) | Binutils 2.31  | c++filt    | CWE-401: Memory Leak |
| [**CVE-2018-20002**](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20002) | Binutils 2.31  | nm       | CWE-401: Memory Leak |


## Video

- [https://www.youtube.com/embed/fXxx46Oj-_s](https://www.youtube.com/embed/fXxx46Oj-_s)


## Links

- **Website**: https://wcventure.github.io/MemLock

- **GitHub**: https://github.com/wcventure/MemLock-Fuzz

- **Benchmark**: https://github.com/ICSE2020-MemLock/MemLock_Benchmark
