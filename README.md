# A Prototype for Protocol Reverse Engineering

## Overview

**ProtocolTaint** is a protocol-reverse-tool designed for industrial binary protocol analysis. It is based on a Dynamic Taint Analysis Framework, which is build with Pin from Intel. We have tested the tool with 5 different open source Industrial protocol implementation (*libmodbus*, *freemodbus*, *gec-dnp3*, *automatak-dnp3* and *snap7*) and so far, it does offer some results (listed in  `/result`). The tool is written with C++ and Python2 and designed for Linux x86-64 platform. This is the very first try and we hope to produce a practical analysis tool eventually.

## Installation

### Set up Pin

This prototype has been tested on **Ubuntu 16.04** and we recommend not to try other Linux OS in case of unnecessary  problems. Docker is also a good choice to hold and isolate the whole environment. The guide is completed in docker, if you want to try outside, run in **root**.

You need to install Pin first , the tool was build with pin-3.2 and the latest version is 3.11. But you may have to modify the source code and the Configure file to continue the compilation with Pin-3.11, so it's better to chose 3.2 :).

```
# download Pin
wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.2-81205-gcc-linux.tar.gz
tar -xzf pin-3.2-81205-gcc-linux.tar.gz
cd pin-3.2-81205-gcc-linux

# configuration
ln -s ${PWD}/pin /usr/local/bin
echo export PIN_ROOT=${PWD} >> /.bashrc
source ~/.bashrc

# test Pin
cd source/tools/ManualExamples/ && make all
pin -t obj-intel64/inscount0.so -- /bin/ls
cat inscount.out
```

There may be some error at the step `pin -t obj-intel64/inscount0.so -- /bin/ls` because pin-3.2 is designed for Kernel 3.X and Ubuntu 16.04 's Kernel is 4.15. To bypass the kernel check, the command should be modified to `pin -t obj-intel64/inscount0.so -- /bin/ls`. If the pin is successfully set up, you will see the count number in terminal. 

```
git clone https://github.com/nesclab/ProtocolTaint.git
mv /ProtocolTaint/src ${PIN_ROOT}/source/tools/ProtocolTaint
cd ${PIN_ROOT}/source/tools/ProtocolTaint
```

The compilation and run processes are integrated in `run`. Remember to add `-ifeellucky` in line 9 if you have encountered the VEX error when test pin. 

```
# compile
./run compile taint

# run
./run run taint {target_file}
```



### Set up Test Object

#### libmodbus

libmodbus is a popular open source library for Modbus protocol.

```
git clone https://github.com/stephane/libmodbus
cd libmodbus
./autogen.sh
./configure && make install
cd ..
# test
./libmodbus/tests/unit-test-server
# experiment
./run run taint ./libmodbus/tests/.libs/unit-test-server
```

if `autogen.sh` fail to run, try:
```
apt-get install automake autoconf libtool
```

to perform the experiment, we need to modify the `tests/unit-test.h` first.

```
const uint16_t UT_BITS_ADDRESS = 0x0;
const uint16_t UT_REGISTERS_ADDRESS = 0x0;
```



#### freemodbus

Also a popular Modbus tool.

```
git clone https://github.com/cwalter-at/freemodbus
cd freemodbus
cd demo/LINUXTCP && make
cd ../../../
# test
./freemodbus/demo/LINUXTCP/tcpmodbus
# experiment
./run run taint ./freemodbus/demo/LINUXTCP/tcpmodbus
```

Some files need to be modified before `make`:

`freemodbus/modbus/include/mbconfig.h`:

```
/*! \brief If Modbus ASCII support is enabled. */
#define MB_ASCII_ENABLED ( 1 )
/*! \brief If Modbus RTU support is enabled. */
#define MB_RTU_ENABLED ( 1 )
/*! \brief If Modbus TCP support is enabled. */
#define MB_TCP_ENABLED ( 0 )
/*! \brief The character timeout value for Modbus ASCII.
```

`freemodbus/demo/LINUXTCP/demo.c`:

```
#define REG_HOLDING_START 0
```

if the make returns: `undefined reference to ‘pthread_create’`, the `Makefile` need to be modified too.

`freemodbus/demo/LINUXTCP/Makefile`:

```
$(BIN): $(OBJS) $(NOLINK_OBJS) $(CC) $(LDFLAGS) $(OBJS) $(LDLIBS) -o $@
# modified to:
$(BIN): $(OBJS) $(NOLINK_OBJS) $(CC) $(OBJS) $(LDLIBS) -o $@ $(LDFLAGS)
```



#### gec-dnp3

A DNP3 protocol implementation using boost. Before make, we need to install the boost library, the source code of which    can be downloaded on its official website. After many try, we confirmed that **boost_1_55** is the best choice.

```
git clone https://github.com/gec/dnp3
mv dnp3 gec && cd gec
autoreconf -f -i
mkdir build && cd build
../configure && make install
cd ../../
./gec/build/.libs/demo-slave-cpp
```

During the `make` process, terminal may tell you that there are errors due to conflicting declaration of `boost::asio::io_service`. If so, you need to modify the corresponding head files:

```
#include <boost/asio.hpp>	// import the extern boost library

// delete the following code
namespace boost
{
	namespace asio
	{
		class io_service;
	}
}
```

There may still be some problems：

```
./demo-slave-cpp: error while loading shared libraries: libboost_system.so.1.55.0: cannot open shared object file: No such file or directory
```

You can apt install `libboost-all-dev` and add soft link

```
sudo ln -s /usr/lib/x86_64-linux-gnu/libboost_system.so.1.58.0  /usr/lib/x86_64-linux-gnu/libboost_system.so.1.55.0
```



#### automatak-dnp3

```
git clone --recursive https://github.com/automatak/dnp3.git
mv dnp3 automatak && cd automatak
mkdir build && cd build
cmake .. && make install
cd ../cpp/examples/outstation && cmake .
make
cd ../../
./automatak/cpp/examples/outstation/outstation-demo
```



#### snap7

snap7 is a famous S7Comm protocol implement, which can be used to imitate a real Siemens PLC.

```
wget http://sourceforge.net/projects/snap7/files/1.2.1/snap7-full-1.2.1.tar.gz/download
tar -zxvf snap7-full-1.2.1.tar.gz && cd snap7-full-1.2.1
cd build/unix && make -f x86_64_linux.mk all
cp ../bin/x86_64-linux/libsnap7.so /usr/lib/libsnap7.so
cd ../../examples/cpp/x86_64-linux/ && make
cd ../../../../
./snap7/examples/cpp/x86_64-linux/server
```

