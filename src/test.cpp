#include <asm/unistd.h>
#include <vector>
#include <set>
#include "pin.H"
#include "pinobject.hpp"
#include <stdio.h>
#include <queue>

class Block {
public:

    Block() {}

    Block(uint64_t rsp, int id): _rsp(rsp), _id(id) {}

    void push(uint64_t head, size_t size) {
        blocks.push_back(std::make_pair(head, head + size));
    }

    bool valid(uint64_t head, int n) {
        int size = blocks.size();
        if (n > size) n = size;
        for (int i = 0; i < n; ++i) {
            if (head >= blocks[size - 1 - i].first &&  head < blocks[size - 1 - i].second) return true;
        }
        return false;
    }

    bool exist(uint64_t head) {
        return valid(head, blocks.size());
    }

    uint64_t rsp() { return _rsp;}
    int id() {return _id;}

private:
    std::vector<std::pair<uint64_t, uint64_t> > blocks;
    uint64_t _rsp;
    int _id;
};

class BlockTrace {
public:
    BlockTrace() {}
    void push(uint64_t head, size_t size, uint64_t rsp, int id) {
        if (trace.count(id) == 0) {
            trace[id] = Block(rsp, id);
            functions.push_back(std::make_pair(rsp, id));
        }
        while (!functions.empty()) {
            if (functions.back().first >= rsp) break;
            trace.erase(functions.back().second);
            functions.pop_back();
        }
        trace[id].push(head, size);
    }

    bool exist(uint64_t head, int id) {
        if (trace.count(id) == 0) return false;
        return trace[id].exist(head);
    }

private: 
    std::map<int, Block> trace;
    std::vector<std::pair<uint64_t, int> > functions;
};

BlockTrace blocktrace;
std::set<uint64_t> loops;

void LogBlock(uint64_t head, size_t size, uint64_t rsp, int id) {
    if (blocktrace.exist(head, id)) {
        if (loops.count(head) == 0) {
            printf("LOOP\t%lx\t%lx\n", head, size);
            loops.insert(head);
        }
    }
    blocktrace.push(head, size, rsp, id);
}

VOID Trace(TRACE trace, VOID *v) {
    RTN rtn = TRACE_Rtn(trace);
    if (!RTN_Valid(rtn)) return;
    bool plt = (RTN_Name(rtn).find("plt") != std::string::npos);
    if (plt) return;
    SEC sec = RTN_Sec(rtn);
    if (!SEC_Valid(sec)) return;
    IMG img = SEC_Img(sec);
    if (!IMG_IsMainExecutable(img)) return;
    std::string imgName = IMG_Name(img);
    int id = RTN_Id(rtn);
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl=BBL_Next(bbl)) {
        uint64_t addr = BBL_Address(bbl);
        size_t size = BBL_Size(bbl);
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)LogBlock, 
                        IARG_ADDRINT, addr,
                        IARG_ADDRINT, size,
                        IARG_REG_VALUE, REG_RSP,
                        IARG_ADDRINT, id,
                        IARG_END);
    }
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
    PIN_InitSymbols();

    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_StartProgram();

    return 0;
}