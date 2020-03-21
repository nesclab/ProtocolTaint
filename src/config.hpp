#ifndef _CONFIG_H
#define _CONFIG_H

#include <string>

namespace config {

const bool thread_flag = false;
const int threadId = 2;

// run mode
const bool debugMode = true;

const bool traceLog = false;

// entry function name for filter out irrelavant functions
const std::string start_entry = "main";
// const std::string start_entry = "init_codecs"; // for python
// use IMG_Entry instead in future

// flag for print miss assembly
const bool missFlag = true;

// flush immediately after print
const bool isFlush = true;
// logger print to console
const bool print = true;

// debug, info, verbose filenames
const char *filenames[3] = {"debug.txt", "info.txt", "verbose.txt"};
const bool flags[3] = {true, true, true};

// use syscall
const bool syscall = true;

const bool use_interactive = false;

// read size control
const bool read_size_flag = false;
// const bool read_size_flag = true;
const int read_size_max = 0x30;
const int read_size_min = 0x5;

// read fd control
// const bool read_fd_flag = true;
const bool read_fd_flag = false;
const int read_fd_max = 4;
const int read_fd_min = 4;

// max taint size
const size_t maxsize = 1024;

const bool demangle = true;
// const bool demangle = false;

const char *tetfuncs[] = {
};

const char *blackfuncs[] = {
    "PyDict_GetItem", "PyDict_SetItem", "PyObject_Hash",
    "PyObject_Free",  "PyFunction_New", "PyCode_New",
    "PyList_New",     "PyTuple_New",    "PyDict_New",
};

const char *libs[] = {
    // "libstdc++",
    // "libc"
    // "libboost_system",
    "libopendnp3",
    "libsnap7",
    "libmodbus",
    "libtest",
};

}  // namespace config

#endif