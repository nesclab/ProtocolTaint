#ifndef _TAINTLOGIC_H
#define _TAINTLOGIC_H

#include "pin.H"
#include "taintengine.hpp"
#include "util.hpp"
#include "pinobject.hpp"

// IARG_MEMORYWRITE_SIZE
// IARG_FUNCARG_ENTRYPOINT_VALUE, 0 函数参数


std::vector<std::vector<std::string> > functraces;
std::vector<int> threadIds;

void printTrace(int index) {
    std::vector<std::string>::iterator it;
    for (it = functraces[index].begin(); it != functraces[index].end(); ++it) {
        logger::debug("%s -> ", (*it).c_str());
    }
    logger::debug("\n");
}


void enterTrace(int threadId, const std::string* name) {
    if (!config::traceLog) return;
    const int size = threadIds.size();
    int index;
    for (int i = 0; i < size; ++i) {
        if (threadIds[i] == threadId) {
            index = i;
            break;
        }
    }
    if (index == size) {
        threadIds.push_back(threadId);
        functraces.push_back(std::vector<std::string>());
    }
    functraces[index].push_back(*name);
}

void exitTrace(int threadId, const std::string* name) {
    if (!config::traceLog) return;
    const int size = threadIds.size();
    int index;
    for (int i = 0; i < size; ++i) {
        if (threadIds[i] == threadId) {
            index = i;
            break;
        }
    }
    if (index == size) { 
        logger::print("trace exit error\n"); 
        return;
    }
    // while (!functraces[index].empty() && functraces[index].back() != *name) {
    //     functraces[index].pop_back();    
    // }
    util::myassert(functraces[index].back() == *name);
    functraces[index].pop_back();
}

void function_entry(int threadId, const std::string* name, uint64_t begin, uint64_t end, uint64_t ret) {
    if (*name == config::start_entry) monitor::start();
    if (monitor::invalid(threadId)) return;
    enterTrace(threadId, name);
    logger::debug("thread id: %d, enter function: %s\n", threadId, util::demangle(name->c_str()));
    logger::info("Function\t%d\tenter\t%s\t(%lx,%lx,%lx)\n", threadId, util::demangle(name->c_str()), begin, end, ret);
}


void function_exit(int threadId, const std::string* name) {
    if (monitor::invalid(threadId)) return;
    exitTrace(threadId, name);
    logger::debug("thread id: %d, exit  function: %s\n", threadId, util::demangle(name->c_str()));
    logger::info("Function\t%d\texit \t%s\n", threadId, util::demangle(name->c_str()));
    if (*name == config::start_entry) monitor::end();
}

void print_functions(const std::string *name, uint64_t para1, uint64_t para2, uint64_t para3, uint64_t para4) {
    logger::verbose("%s: %lx %lx %lx %lx\t%s\n", util::demangle(name->c_str()), para1, para2, para3, para4, name->c_str());
}

void print_instructions0(const std::string *name, uint64_t address) {
    logger::verbose("%p: %s\n", address, name->c_str());
}

void print_instructions1(const std::string *name, uint64_t address, const CONTEXT *ctxt, REG r1, REG r2, uint64_t m1, uint64_t m2) {
    static char buf[64];
    int n = 0;
    if (util::valiReg(r1)) {
        n += sprintf(buf + n, " reg(%d, %lx) ", r1, PIN_GetContextReg(ctxt, util::rawReg(r1)));
    }
    if (util::valiReg(r2)) {
        n += sprintf(buf + n, " reg(%d, %lx) ", r2, PIN_GetContextReg(ctxt, util::rawReg(r2)));
    }
    if (m1 > 0) {
        n += sprintf(buf + n, " mem(%lx, %lx) ", m1, util::Value(m1, 8));
    }
    if (m2 > 0) {
        n += sprintf(buf + n, " mem(%lx, %lx) ", m2, util::Value(m2, 8));
    }
    buf[n] = 0;
    logger::verbose("%p: %s %s\n", address, name->c_str(), buf);
}


void Syscall_point(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v) {
    if (!monitor::valid()) return;
    const char *point = (const char *)v;
    ADDRINT number = PIN_GetSyscallNumber(ctx, std);
    logger::print("system number: %p in %s\n", number, point);
    if (number == __NR_read) {
        int fd          = static_cast<int>((PIN_GetSyscallArgument(ctx, std, 0)));
        uint64_t start  = static_cast<uint64_t>((PIN_GetSyscallArgument(ctx, std, 1)));
        size_t size     = static_cast<size_t>((PIN_GetSyscallArgument(ctx, std, 2)));
        if (filter::read(fd, start, size)) return;
        logger::print("%s read: fd: %d, start: %p, size: %p\n", point, fd, start, size);
        if (!filter::taint_start()) return;
        logger::debug("[TAINT]\t %p bytes tainted from %p to %p (via read %s fd: %d)\n", size, start, start+size, point, fd);
        TaintEngine::Init(start, size);
    }
}


static int cur_sock = -1;


void read_point(const char *point, int fd, uint64_t buffer, size_t length, ssize_t ret) {
    static int _fd;
    static uint64_t _buffer;
    static size_t _length;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _fd = fd;
        _buffer = buffer;
        _length = length;
    }

    if (filter::read(_fd, _buffer, _length)) return;

    if (point == filter::exit) {
        logger::print("read(fd: %d, buffer: %p, length: %p) => %zd\n", _fd, _buffer, _length, ret);
        logger::debug("[TAINT]\t %p bytes tainted from %p to %p (via recv socket: %d)\n", _length, _buffer, _buffer+_length, _fd);
        TaintEngine::Init(_buffer, ret);
    }
}


void write_point(const char *point, int fd, uint64_t buffer, size_t length, ssize_t ret) {
    static int _fd;
    static uint64_t _buffer;
    static size_t _length;
    if (monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _fd = fd;
        _buffer = buffer;
        _length = length;
    }
    if (_fd != cur_sock) return;

    if (point == filter::exit) {
        logger::info("Trace Address (write) :\t%lx\t%d\t%d\n", _buffer, _length, ret);
    }
}


void send_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, ssize_t ret) {
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _buffer = buffer;
        _length = length;
    }

    if (_socket != cur_sock) return;
    
    if (point == filter::exit) {
        logger::info("Trace Address (send) :\t%lx\t%d\t%d\n", _buffer, _length, ret);
    }
}


void sendto_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, struct sockaddr *address, socklen_t address_len, ssize_t ret){
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _buffer = buffer;
        _length = length;
    }

    if (_socket != cur_sock) return;

    if (point == filter::exit) {
        logger::info("Trace Address (sendto) :\t%lx\t%d\t%d\n", _buffer, _length, ret);
    }
}


void sendmsg_point(const char *point, int socket, struct msghdr* mhdr, int flags, ssize_t ret) {
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    if (!monitor::valid() || !filter::taint_start()) return;
    if (point == filter::entry) {
        _socket = socket;
        _buffer = (uint64_t) mhdr->msg_iov[0].iov_base;
        _length = mhdr->msg_iov->iov_len;
    }

    if (_socket != cur_sock) return;

    if (point == filter::exit) {
        logger::info("Trace Address (sendmsg) :\t%lx\t%d\t%d\n", _buffer, _length, ret);
    }
}


void recv_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, ssize_t ret) {
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    static int _flags;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _buffer = buffer;
        _length = length;
    }
    if (filter::read(_socket, _buffer, _length)) return;
    
    if (point == filter::exit) {
        cur_sock = _socket;
        logger::print("recv(socket: %d, buffer: %p, length: %p, flags: %d) => %zd\n", _socket, _buffer, _length, _flags, ret);
        logger::debug("[TAINT]\t %p bytes tainted from %p to %p (via recv socket: %d)\n", _length, _buffer, _buffer+_length, _socket);
        if (TaintEngine::isTainted(REG_RDX)) { // log if size is tainted
            logger::info("LENGTH\t%s\n", TaintEngine::offsets(REG_RDX));
        }
        TaintEngine::Init(_buffer, ret);
    }
}


void recvfrom_point(const char *point, int socket, uint64_t buffer, size_t length, int flags, struct sockaddr *address, socklen_t *address_len, ssize_t ret){
    static int _socket;
    static uint64_t _buffer;
    static size_t _length;
    static int _flags;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _buffer = buffer;
        _length = length;
    }

    if (filter::read(_socket, _buffer, _length)) return;
    
    if (point == filter::exit) {
        cur_sock = _socket;
        logger::print("recvfrom(socket: %d, buffer: %p, length: %p, flags: %d) => %zd\n", _socket, _buffer, _length, _flags, ret);
        logger::debug("[TAINT]\t %p bytes tainted from %p to %p (via recvfrom socket: %d)\n", _length, _buffer, _buffer+_length, _socket);
        if (TaintEngine::isTainted(REG_RDX)) { // log if size is tainted
            logger::info("LENGTH\t%s\n", TaintEngine::offsets(REG_RDX));
        }
        TaintEngine::Init(_buffer, ret);
    }
}


void recvmsg_point(const char *point, int socket, struct msghdr* mhdr, int flags, ssize_t ret) {
    static int _socket;
    static struct msghdr* _mhdr;
    static int _flags;
    static uint64_t _buffer;
    if (!monitor::valid() || !filter::taint_start()) return;

    if (point == filter::entry) {
        _socket = socket;
        _mhdr = mhdr;
        _flags = flags;
        _buffer = (uint64_t) mhdr->msg_iov[0].iov_base;
        // size_t len = message->msg_iovlen;
    }

    if (point == filter::exit) {
        ssize_t _length = ret;
        if (filter::read(_socket, _buffer, _length)) return;
        cur_sock = _socket;
        if (_length > 0) {
            logger::print("recvmsg(socket: %d, mhdr: %p, flags: %d) => %zd\n", _socket, _mhdr, _flags, _length);
            logger::debug("[TAINT]\t %p bytes tainted from %p to %p (via recvmsg socket: %d)\n", _length, _buffer, _buffer+_length, _socket);
            TaintEngine::Init(_buffer, _length);
        }
    }
}


void memcpy_point(const char *point, uint64_t dst, uint64_t src, size_t size) {
    if (!monitor::valid()) return;
    logger::info("Trace Copy:\t%lx\t%lx\t%d\n", dst, src, size);
    for (size_t i = 0; i < size;) {
        if (TaintEngine::isTainted(src + i)) {
            size_t s = i;
            while (i < size && TaintEngine::isTainted(src + i)) ++i;
            logger::print("memcpy(dst: %p, src: %p, size: %p)\n", dst + s, src + s, i - s);
            logger::debug("[COPY]\t %p bytes from %p to %p (via memcpy)\n", i - s, src + s, dst + s);
            TaintEngine::Init(dst + s, i - s);
        } else {
            ++i;
        }
    }
}


void memmove_point(const char *point, uint64_t dst, uint64_t src, size_t size) {
    if (!monitor::valid()) return;
    logger::info("Trace Copy:\t%lx\t%lx\t%d\n", dst, src, size);
    for (size_t i = 0; i < size;) {
        if (TaintEngine::isTainted(src + i)) {
            size_t s = i;
            while (i < size && TaintEngine::isTainted(src + i)) ++i;
            logger::print("memmove(dst: %p, src: %p, size: %p)\n", dst + s, src + s, i - s);
            logger::debug("[COPY]\t %p bytes from %p to %p (via memcpy)\n", i - s, src + s, dst + s);
            TaintEngine::Init(dst + s, i - s);
        } else {
            ++i;
        }
    }
}


// reg <- mem
void ReadMem(int threadId, const std::string* assembly, unsigned long address, REG reg, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg);
    bool taint_r = TaintEngine::isTainted(mem);
    ADDRINT value = util::Value(mem, size);
    if (!taint_w && !taint_r) {
        logger::debug("Not Taint %p: %s\t mem: %p\tvalue: %p\n", address, assembly->c_str(), mem, value);
        return;
    }
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    if (taint_r) { // retaint
        TaintEngine::move(reg, mem, size);
        logger::debug("thread: %d [+ Reg <- Mem]\t%p: %s\t addr: %p value: (%p, %p)\n%s%s\n", 
            threadId,
            address, assembly->c_str(), mem, TaintEngine::src(mem), value,
            TaintEngine::debug(mem),
            TaintEngine::debug(reg)
        );

        logger::info("Instruction %p: %s\t%d\t%s\t%p\t%p\n", 
            address, assembly->c_str(), threadId, 
            TaintEngine::offsets(mem), TaintEngine::src(mem), value);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("thread: %d [- Reg <- Mem]\t%p: %s\t addr: %p\n%s\n", 
            threadId,
            address, assembly->c_str(), mem,
            TaintEngine::debug(reg)
        );
        TaintEngine::remove(reg);
    }
}

// mem <- reg
void WriteMem(int threadId, const std::string* assembly, unsigned long address, UINT64 mem, REG reg, ADDRINT value, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(mem);
    bool taint_r = TaintEngine::isTainted(reg);
    
    int offset = taint_r ? TaintEngine::offset(reg) : -1;
    logger::info("Trace %p: %s\t%lx\t%d\t%lx\t%d\n", address, assembly->c_str(), mem, size, value, offset);
    
    if (!taint_w && !taint_r) {
        logger::debug("Not Taint %p: %s\tmem: %p\tvalue: %p\n", address, assembly->c_str(), mem, value);
        return;
    }

    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    if (taint_r) { // retaint
        TaintEngine::move(mem, reg, size); // change src
        logger::debug("thread: %d [+ Mem <- Reg]\t%p: %s\t addr: %p value: (%p, %p)\n%s%s\n", 
            threadId,
            address, assembly->c_str(), mem, TaintEngine::src(reg), value,
            TaintEngine::debug(reg),
            TaintEngine::debug(mem)
        );
        logger::info("Instruction %p: %s\t%d\t%s\t%p\t%p\n", 
            address, assembly->c_str(), threadId,  
            TaintEngine::offsets(reg), TaintEngine::src(reg), value);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("thread: %d [- Mem <- Reg]\t%p: %s\t addr: %p\n%s\n", 
            threadId,
            address, assembly->c_str(), mem,
            TaintEngine::debug(mem)
        );
        TaintEngine::remove(mem);
    }
}

// reg <- reg
void spreadReg(int threadId, const std::string* assembly, unsigned long address, REG reg_w, REG reg_r, ADDRINT value) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg_w);
    bool taint_r = TaintEngine::isTainted(reg_r);
    if (!taint_w && !taint_r) {
        logger::debug("Not Taint %p: %s\tvalue: %p\n", address, assembly->c_str(), value);
        return;
    }
    
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    if (taint_r) { // retaint
        TaintEngine::move(reg_w, reg_r);
        logger::debug("thread: %d [+ Reg <- Reg]\t%p: %s value: (%p, %p)\n%s%s\n", 
            threadId,
            address, assembly->c_str(), TaintEngine::src(reg_r), value,
            TaintEngine::debug(reg_r),
            TaintEngine::debug(reg_w)
        );

        logger::info("Instruction %p: %s\t%d\t%s\t%p\t%p\n", 
            address, assembly->c_str(), threadId, 
            TaintEngine::offsets(reg_r), TaintEngine::src(reg_r), value);
    } else if (taint_w && !taint_r) { // untaint
        logger::debug("thread: %d [- Reg <- Reg]\t%p: %s\n%s\n", 
            threadId,
            address, assembly->c_str(),
            TaintEngine::debug(reg_w)
        );
        TaintEngine::remove(reg_w);
    }
}

// mem <- mem
void spreadMem(int threadId, const std::string* assembly, unsigned long address, UINT64 mem_w, UINT64 mem_r, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(mem_w);
    bool taint_r = TaintEngine::isTainted(mem_r);
    ADDRINT value = util::Value(mem_r, size);
    
    int offset = taint_r ? TaintEngine::offset(mem_r) : -1;
    logger::info("Trace %p: %s\t%lx\t%d\t%lx\t%d\n", 
        address, assembly->c_str(), mem_w, size, value, offset);
    
    if (!taint_w && !taint_r) {
        logger::debug("Not Taint %p: %s\t mem: %p <- %p\tvalue: %p\n", address, assembly->c_str(), mem_w, mem_r, value);
        return;
    }

    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    if (taint_r) { // retaint
        TaintEngine::move(mem_w, mem_r, size);

        logger::debug("thread: %d [+ Mem <- Mem]\t%p: %s\t mem_w: %p mem_r: %p value: (%p, %p)\n%s%s\n",
            threadId, 
            address, assembly->c_str(), mem_w, mem_r, TaintEngine::src(mem_r), value,
            TaintEngine::debug(mem_r),
             TaintEngine::debug(mem_w)
        );

        logger::info("Instruction %p: %s\t%d\t%s\t%p\t%p\n", 
            address, assembly->c_str(), threadId, 
            TaintEngine::offsets(mem_r), TaintEngine::src(mem_r), value);
    } else if (taint_w && !taint_r) { // untaint
        TaintEngine::remove(mem_w);

        logger::debug("thread: %d [- Mem <- Mem]\t%p: %s\t mem_w: %p mem_r: %p\n%s\n", 
            threadId, 
            address, assembly->c_str(), mem_w, mem_r,
            TaintEngine::debug(mem_w)
        );
    }
}

// reg <- imm
void deleteReg(int threadId, const std::string* assembly, unsigned long address, REG reg) {
    if (monitor::invalid(threadId)) return;
    if (TaintEngine::isTainted(reg)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);
        logger::debug("thread: %d [DELETE Reg]\t%p : %s\n%s\n", 
            threadId, 
            address, assembly->c_str(),
            TaintEngine::debug(reg)
        );
        TaintEngine::remove(reg);
    }
}

// mem <- imm
void deleteMem(int threadId, const std::string* assembly, unsigned long address, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    logger::info("Trace %p: %s\t%lx\t%d\t%d\n", address, assembly->c_str(), mem, size, -2);
    if (TaintEngine::isTainted(mem)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);
        ADDRINT value = util::Value(mem, size);

        logger::debug("thread: %d [DELETE Mem]\t\t%p: %s value: %p\n%s\n", 
            threadId,
            address, assembly->c_str(), value,
            TaintEngine::debug(mem)
        );

        TaintEngine::remove(mem);
    }
}


//Insert Logic

// ReadMem
void InsertCall(Ins ins, REG reg, int mem) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ReadMem, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, reg,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

// WriteMem
void InsertCall(Ins ins, int mem, REG reg) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMem, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

// spreadMem
void InsertCall(Ins ins, int mem_w, int mem_r) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadMem,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem_w,
        IARG_MEMORYOP_EA, mem_r,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}

// spreadReg
void InsertCall(Ins ins, REG reg_w, REG reg_r) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)spreadReg,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR, 
        IARG_ADDRINT, reg_w,
        IARG_ADDRINT, reg_r,
        IARG_REG_VALUE, reg_r,
    IARG_END);
}

// delete mem
void InsertCall(Ins ins, int mem) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)deleteMem,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

// delete reg
void InsertCall(Ins ins, REG reg) {
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)deleteReg, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, reg,
    IARG_END);
}


// 3 Ops

// reg <- reg
void Op3RegReg(int threadId, const std::string* assembly, unsigned long address, int opcode, REG reg_w, REG reg_r, ADDRINT value_w, ADDRINT value_r) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg_w);
    bool taint_r = TaintEngine::isTainted(reg_r);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    
    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(reg_w));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(reg_r));
    }
    buf[n] = 0;

    logger::info("Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);


    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR) && reg_w != reg_r) {
        if (TaintEngine::merge(reg_w, reg_r)) {
            logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), 
                threadId,
                TaintEngine::offsets(reg_w), value_w);
        }
    } else if ((opcode == XED_ICLASS_XOR || opcode == XED_ICLASS_SUB) && reg_w == reg_r) {
        TaintEngine::remove(reg_w);
    }

    logger::debug("[USE RegReg]\t\t%p: %s value: %p, opcode: %d\n%s%s\n", 
        address, assembly->c_str(), value_w, opcode,
        taint_w ? TaintEngine::debug(reg_w) : "",
        taint_r ? TaintEngine::debug(reg_r) : ""
    );
}

void InsertCallExtra(Ins ins, REG reg_w, REG reg_r) { // Reg Reg
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegReg, 
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR, 
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg_w,
        IARG_ADDRINT, reg_r,
        IARG_REG_VALUE, reg_w,
        IARG_REG_VALUE, reg_r,
    IARG_END);
}

void Op3RegImm(int threadId, const std::string* assembly, unsigned long address, int opcode, REG reg, ADDRINT value, int imm) {
    if (monitor::invalid(threadId)) return;
    if (TaintEngine::isTainted(reg)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);
        if (opcode == XED_ICLASS_SHL) {
            TaintEngine::shift(reg, imm);
        } else if (opcode == XED_ICLASS_SHR || opcode == XED_ICLASS_SAR || opcode == XED_ICLASS_ROR) {
            TaintEngine::shift(reg, -imm); 
            // ror uncheck
            // add ROL switch: rol ax
        } else if (opcode == XED_ICLASS_AND) { // and uncheck
            TaintEngine::and_(reg, imm);
        }
        logger::debug("[USE RegImm]\t\t%p: %s value: %p, opcode: %d, imm: %d\n%s\n", 
            address, assembly->c_str(), value, opcode, imm,
            TaintEngine::debug(reg)
        );
        logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
            address, assembly->c_str(), threadId,
            TaintEngine::offsets(reg), value);
    }   
}

void InsertCallExtra(Ins ins, REG reg) { // Reg Imm
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegImm,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.valueImm(1),
    IARG_END);
}

void Op3RegMem(int threadId, const std::string* assembly, unsigned long address, int opcode, REG reg, ADDRINT value_w, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(reg);
    bool taint_r = TaintEngine::isTainted(mem);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    ADDRINT value_r = util::Value(mem, size);
    
    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(reg));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(mem));
    }
    buf[n] = 0;

    logger::info("Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);

    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR)) {
        if (TaintEngine::merge(reg, mem)) {
            logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), threadId,
                TaintEngine::offsets(reg), value_w);
        }
    }
    logger::debug("[USE RegMem]\t\t%p: %s value: %p, opcode: %d\n%s%s\n", 
        address, assembly->c_str(), value_w, opcode,
        taint_w ? TaintEngine::debug(reg) : "",
        taint_r ? TaintEngine::debug(mem) : ""
    ); // TODO
}

void InsertCallExtra(Ins ins, REG reg, int mem) { // Reg Mem
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3RegMem,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemRSize(),
    IARG_END);
}


void Op3MemReg(int threadId, const std::string* assembly, unsigned long address, int opcode, UINT64 mem, REG reg, ADDRINT value_r, USIZE size) {
    if (monitor::invalid(threadId)) return;
    bool taint_w = TaintEngine::isTainted(mem);
    bool taint_r = TaintEngine::isTainted(reg);
    if (!taint_w && !taint_r) return;
    debug::log(address, assembly->c_str());
    util::LockGuard lock(threadId);
    ADDRINT value_w = util::Value(mem, size);
    
    char buf[32];
    int n = 0;
    if (taint_w) {
        n += sprintf(buf + n, "%s", TaintEngine::offsets(mem));
    } 
    if (taint_r) {
        n += sprintf(buf + n, ";%s", TaintEngine::offsets(reg));
    }
    buf[n] = 0;

    logger::info("Instruction %p: %s\t%d\t%s\t%p;%p\n", 
        address, assembly->c_str(), threadId,
        buf, value_w, value_r);

    if (taint_w && taint_r && (opcode == XED_ICLASS_ADD || opcode == XED_ICLASS_OR)) {
        if (TaintEngine::merge(mem, reg)) {
            logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
                address, assembly->c_str(), threadId,
                TaintEngine::offsets(mem), value_w);
        }
    }
    logger::debug("[USE RegMem]\t\t%p: %s value: %p, opcode: %d\n%s%s\n", 
        address, assembly->c_str(), value_w, opcode,
        taint_w ? TaintEngine::debug(mem) : "",
        taint_r ? TaintEngine::debug(reg) : ""
    ); // TODO
}

void InsertCallExtra(Ins ins, int mem, REG reg) { // Mem Reg
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3MemReg,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, reg,
        IARG_REG_VALUE, reg,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

void Op3MemImm(int threadId, const std::string* assembly, unsigned long address, int opcode, UINT64 mem, USIZE size) {
    if (monitor::invalid(threadId)) return;
    if (TaintEngine::isTainted(mem)) {
        debug::log(address, assembly->c_str());
        util::LockGuard lock(threadId);
        ADDRINT value = util::Value(mem, size);
        logger::debug("[USE MemImm]\t\t%p: %s value: %p, opcode: %d\n%s\n", 
            address, assembly->c_str(), value, opcode,
            TaintEngine::debug(mem)
        );
        logger::info("Instruction %p: %s\t%d\t%s\t%p\n", 
            address, assembly->c_str(), threadId,
            TaintEngine::offsets(mem), value);
    }
}


void InsertCallExtra(Ins ins, int mem) { // Mem Imm
    const std::string *insName = new std::string(ins.Name());
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Op3MemImm,
        IARG_THREAD_ID,
        IARG_PTR, insName, IARG_INST_PTR,
        IARG_ADDRINT, ins.OpCode(),
        IARG_MEMORYOP_EA, mem,
        IARG_ADDRINT, ins.MemWSize(),
    IARG_END);
}

#endif
// taint logic end
