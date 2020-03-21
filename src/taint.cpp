#include <asm/unistd.h>
#include <vector>
#include <set>
#include "config.hpp"
#include "logic.hpp"
#include "pin.H"
#include "pinobject.hpp"
#include "util.hpp"
#include "loop.cpp"

void Test(Ins ins) {
    UINT32 opcount = ins.OpCount();
    OPCODE opcode = ins.OpCode();
    INT32 ext = ins.Extention();

    if (ins.isCall() || ins.isRet() || ins.isBranch() || ins.isNop() ||
        opcount <= 1)
        return;
    
    if (ext >= 40) return;  // sse TODO
    
    if (opcount == 2 || (opcode >= 83 && opcode <= 98)) {
        if (ins.isLea()) return;
        if (ins.isOpImplicit(0) || ins.isOpImplicit(1)) return;
        if (ins.isOpReg(0) && ins.isOpReg(1)) return;
        if (ins.isOpReg(0) && ins.isOpImm(1)) return;
        if (ins.isOpReg(0) && ins.isOpMem(1)) return;
        if (ins.isOpMem(0) && ins.isOpReg(1)) return;
        logger::verbose("0 %s", ins.prettify()); return;
        // if (ins.isOpMem(0) && ins.isOpImm(1)) return;
        // if ((ins.isMemoryWrite() || ins.isMemoryRead())) return;
    } else if (opcount == 3) {
        logger::verbose("1 %s", ins.prettify()); return;
        // if (opcode != XED_ICLASS_XOR) return;
        // add sub adc(carry) sbb(borrow)
        // sar shr shl ror(rotate) or and
        // test cmp bt
    } else if (opcount == 4) {
        logger::verbose("2 %s", ins.prettify()); return;
        // push pop
        // mul div imul idiv
    } else {
        logger::verbose("3 %s", ins.prettify()); return;
    }
    // INS_OperandImmediate
    // INS_OperandRead
    // INS_OperandReadAndWritten
    // INS_OperandReg
    // INS_OperandWritten
    // INS_OperandReadOnly
    // INS_OperandWrittenOnly
}

bool filter_ins(Ins ins) {
    // filter rules
    // if (opcount == 2 && (ins.isOpImplicit(0) || ins.isOpImplicit(1))) return;
    // TODO neg inc, dec cgo setx
    UINT32 opcount = ins.OpCount();
    bool ret = ins.isCall() || ins.isRet() || ins.isBranch() || ins.isNop() || opcount <= 1 || opcount >= 5
        || ins.Extention() >= 40  // TODO sse instructions
        // || (ins.isOpReg(0) && (ins.OpReg(0) == REG_RBP || ins.OpReg(0) == REG_RSP || ins.OpReg(0) == REG_RIP))
        // || (ins.isOpReg(0) && (ins.OpReg(0) == REG_EBP || ins.OpReg(0) == REG_ESP || ins.OpReg(0) == REG_EIP))
        ;
    static std::vector<OPCODE> cache;
    if (ret) {
        OPCODE opcode = ins.OpCode();
        if (std::find(cache.begin(), cache.end(), opcode) == cache.end()) {
            cache.push_back(opcode);
            logger::debug("assembly not taint included : %s\n",
                          ins.Name().c_str());
        }
    }
    return ret;
}

void LogInst(Ins ins) {
    if (!config::debugMode) return;
    if ( filter_ins(ins) ) {
        INS_InsertPredicatedCall(
        ins, IPOINT_BEFORE, (AFUNPTR)print_instructions0,
        IARG_PTR, new std::string(ins.Name()), IARG_INST_PTR,
        IARG_END);
        return;
    }
    if (ins.isOpMem(0)) {
        if (ins.isOpMem(1)) {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)print_instructions1,
                IARG_PTR, new std::string(ins.Name()), IARG_INST_PTR,
                IARG_CONST_CONTEXT,

                IARG_ADDRINT, ins.OpReg(0),
                IARG_ADDRINT, ins.OpReg(1),
                
                IARG_MEMORYOP_EA, 0,

                IARG_MEMORYOP_EA, 1,

                IARG_END);
        } else {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)print_instructions1,
                IARG_PTR, new std::string(ins.Name()), IARG_INST_PTR,
                IARG_CONST_CONTEXT,

                IARG_ADDRINT, ins.OpReg(0),
                IARG_ADDRINT, ins.OpReg(1),

                IARG_MEMORYOP_EA, 0,

                IARG_ADDRINT, 0,

                IARG_END);
        }
    } else {
        INS_InsertPredicatedCall(
            ins, IPOINT_BEFORE, (AFUNPTR)print_instructions1,
            IARG_PTR, new std::string(ins.Name()), IARG_INST_PTR,
            IARG_CONST_CONTEXT,

            IARG_ADDRINT, ins.OpReg(0),
            IARG_ADDRINT, ins.OpReg(1),
            
            IARG_ADDRINT, 0,

            IARG_ADDRINT, 0,

            IARG_END);
    }
}


void Instruction(Ins ins) {
    
    UINT32 opcount = ins.OpCount();

    if ( filter_ins(ins) ) {
        return;
    }

    bool miss = false;

    OPCODE opcode = ins.OpCode();

    REG reg_w = ins.OpReg(0);
    REG reg_r = ins.OpReg(1);

    if (opcount == 2) {  // condition mov
        if (ins.isLea()) {                               // reg calculation
            InsertCall(ins, reg_w);                      // deleteReg #TODO
        } else if (ins.isOpReg(0) && ins.isOpMem(1)) {
            InsertCall(ins, reg_w, 0);  // ReadMem
        } else if (ins.isOpMem(0) && ins.isOpReg(1)) {
            InsertCall(ins, 0, reg_r);  // WriteMem
        } else if (ins.isOpMem(0) && ins.isOpImm(1)) {
            InsertCall(ins, 0);  // deleteMem
        } else if (ins.isOpReg(0) && ins.isOpReg(1)) {
            InsertCall(ins, reg_w, reg_r);  // spreadReg
        } else if (ins.isOpReg(0) && ins.isOpImm(1)) {
            InsertCall(ins, reg_w);  // deleteReg
        } else {
            miss = true;
        }
    } else if (opcount == 3) {
        if (ins.isOpReg(0) && ins.isOpReg(1)) {
            InsertCallExtra(ins, reg_w, reg_r); 
        } else if (ins.isOpReg(0) && ins.isOpMem(1)) {
            InsertCallExtra(ins, reg_w, 0); 
        } else if (ins.isOpReg(0) && ins.isOpImm(1)) {
            InsertCallExtra(ins, reg_w); 
        } else if (ins.isOpMem(0) && ins.isOpImm(1)) {
            InsertCallExtra(ins, 0); 
        } else if (ins.isOpMem(0) && ins.isOpReg(1)) {
            InsertCallExtra(ins, 0, reg_r);
        } else {
            miss = true;
        }
        // add sub adc(carry) sbb(borrow)
        // sar shr shl ror(rotate) or and
        // test cmp bt
    } else if (opcount == 4) {
        if (opcode == XED_ICLASS_PUSH) {  // push
            if (ins.isOpReg(0)) {
                InsertCall(ins, 0, reg_w);  // WriteMem // note reg_w is the
                                            // first reg op in push
            } else if (ins.isOpMem(0)) {
                InsertCall(ins, 0, 1);  // spreadMem
            } else if (ins.isOpImm(0)) {
                InsertCall(ins, 0);  // deleteMem
            } else {
                miss = true;
            }
        } else if (opcode == XED_ICLASS_POP) {  // pop
            if (ins.isOpReg(0)) {
                InsertCall(ins, reg_w, 0);  // ReadMem
            } else {
                miss = true;
            }
        } else {
            miss = true;
        }
        // mul div imul idiv
    }
    if (config::missFlag && miss) {
        static std::vector<OPCODE> cache;
        if (std::find(cache.begin(), cache.end(), opcode) == cache.end()) {
            cache.push_back(opcode);
            logger::debug("assembly not taint included : %s %d %d\n",
                          ins.Name().c_str(), reg_w, reg_r);
        }
    }
}

void Image(IMG img, VOID *v) {
    std::string imgName = IMG_Name(img);

    logger::verbose("image: %s\n", imgName.c_str());
    const bool isMain = IMG_IsMainExecutable(img);
    const bool isWrapper = (imgName.find("libx.so") != std::string::npos);
    const bool isLib = filter::libs(imgName);
    if (!(isMain || isWrapper || isLib)) return;
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        logger::verbose("sec: %s\n", SEC_Name(sec).c_str());
        for (Rtn rtn = SEC_RtnHead(sec); rtn.Valid(); rtn = rtn.Next()) {
            if (rtn.isArtificial()) continue;
            std::string *rtnName = new std::string(rtn.Name());
            if (filter::blackfunc(*rtnName)) continue;
            logger::verbose("function %s\t%s\n", rtnName->c_str(), util::demangle(rtnName->c_str()));

            rtn.Open();

            if (config::debugMode) {
                RTN_InsertCall(
                    rtn, IPOINT_BEFORE, (AFUNPTR)print_functions,
                    IARG_PTR, rtnName,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                    IARG_END);
            }

            if (isMain || isLib) {
                RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)function_entry,
                                IARG_THREAD_ID, IARG_PTR, rtnName, 
                                IARG_ADDRINT, rtn.InsHead().Address(),
                                IARG_ADDRINT, rtn.InsTail().Address(),
                                IARG_RETURN_IP,
                                IARG_END);

                RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)function_exit,
                                IARG_THREAD_ID, IARG_PTR, rtnName, 
                                IARG_END);
                for (Ins ins = rtn.InsHead(); ins.Valid();
                        ins = ins.Next()) {
                    LogInst(ins);
                    Instruction(ins);
                }
            } else if (isWrapper) {
                if (*rtnName == "read") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)read_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // fd
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)read_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // fd
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "recv") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)recv_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)recv_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "recvfrom") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)recvfrom_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 4,  // address
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 5,  // address_len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)recvfrom_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 4,  // address
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 5,  // address_len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "recvmsg") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)recvmsg_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // msghdr
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)recvmsg_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // msghdr
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "write") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)write_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // fd
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)read_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // fd
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "send") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)send_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)send_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "sendto") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)sendto_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 4,  // address
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 5,  // address_len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)sendto_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // buf
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 3,  // flags
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 4,  // address
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 5,  // address_len
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "sendmsg") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)sendmsg_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // msghdr
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                    RTN_InsertCall(
                        rtn, IPOINT_AFTER, (AFUNPTR)sendmsg_point,
                        IARG_ADDRINT, filter::exit,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // socket
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // msghdr
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // flags
                        IARG_REG_VALUE, REG_RAX,           // ret
                        IARG_END);
                } else if (*rtnName == "memcpy") {  // memcpy use xmm registers to copy
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)memcpy_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // dest
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // src
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_END);
                } else if (*rtnName == "memmove") {
                    RTN_InsertCall(
                        rtn, IPOINT_BEFORE, (AFUNPTR)memmove_point,
                        IARG_ADDRINT, filter::entry,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // dest
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // src
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 2,  // len
                        IARG_END);
                }
            }
            rtn.Close();
        }
    }
}

FILE *files[3];

void Init() {
    // PIN_InitLock(&util::lock);
    files[0] = fopen(config::filenames[0], "w");
    files[1] = fopen(config::filenames[1], "w");
    files[2] = fopen(config::filenames[2], "w");
    logger::setDebug(config::flags[0], files[0]);
    logger::setInfo(config::flags[1], files[1]);
    logger::setVerbose(config::flags[2], files[2]);
}

void Fini(INT32 code, VOID *v) {
    printf("program end\n");
    fprintf(files[0], "#eof\n");
    fclose(files[0]);
    fprintf(files[1], "#eof\n");
    fclose(files[1]);
    fprintf(files[2], "#eof\n");
    fclose(files[2]);
}

INT32 Usage() {
    printf("error\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) return Usage();
    Init();
    // Initialize symbol table code, needed for rtn instrumentation
    PIN_InitSymbols();
    PIN_InitLock(&util::lock);
    // PIN_SetSyntaxIntel();
    IMG_AddInstrumentFunction(Image, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    // if (config::syscall) {
    //     if (config::use_entry) PIN_AddSyscallEntryFunction(Syscall_point,
    //     (void*)filter::entry); if (config::use_exit)
    //     PIN_AddSyscallExitFunction(Syscall_point , (void*)filter::exit);
    // }

    PIN_StartProgram();
    // PIN_StartProgramProbed();
    PIN_AddFiniFunction(Fini, 0);

    return 0;
}
