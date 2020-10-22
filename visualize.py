#coding:utf8
import pydot
from collections import OrderedDict
import sys

file = "info.txt"
threadId = 0
if len(sys.argv) > 1:
    case = sys.argv[1]
    file = "results/{}/info.txt".format(case)
if len(sys.argv) > 2:
    threadId = int(sys.argv[2])


with open(file, "r") as f:
    lines = f.readlines()

loops = []

def findInLoop(addr):
    for head, size in loops:
        if addr >= head and addr < head + size:
            return True
    return False

def mystrip(s):
    # return str(hash(s))
    temp = []
    count = 0
    for c in s:
        if c == '<':
            count += 1
        elif c == '>':
            count -= 1
        elif count == 0:
            temp.append(c)
    s = "".join(temp)
    s = s.split('(')[0]
    s = "-".join(s.split("::")[-2:])
    return s


def fold(s, n, maxline=3):
    ret = []
    size = len(s)
    if size <= n: return s
    line = min(maxline, (size - 1)// n + 1)
    n = (size - 1) // line + 1
    for i in range(line):
        ret.append(s[n * i : n * (i+1)])
        ret.append("\n")
    ret.pop()
    return "".join(ret)
    

class Node(object):
    _id = 0

    def __init__(self):
        self._id = Node._id
        Node._id += 1
        self.parent = None
        self.children = []
    
    def name(self):
        return ""

    def id(self):
        return "{}-{}".format(self.name(), self._id)

    def __getitem__(self, s):
        return self.children[s]

    def __len__(self):
        return len(self.children)
    
    def construct(self, graph):    
        for child in self.children:
            # print child.name()
            graph.add_node(pydot.Node(child.id(), label=child.name()))
            edge = pydot.Edge(self.id(), child.id())
            graph.add_edge(edge)
            child.construct(graph)


class FuncNode(Node):

    def __init__(self, name):
        super(FuncNode, self).__init__()
        self.name_ = name
    
    def name(self):
        return fold(self.name_, 12)

    def add(self, c):
        c.parent = self
        self.children.append(c)

    def trim(self):
        self.children = [c for c in self.children if c.trim()]
        return len(self.children) > 0
    
    def collect(self, container):
        for c in self.children:
            c.collect(container)


class DataNode(Node):

    def __init__(self):
        super(DataNode, self).__init__()
        self.data = []

    def name(self):
        return fold(str(self.data)[1:-1], 12)

    def empty(self):
        return not self.data

    def trim(self):
        return len(self.data) > 0

    def add(self, c):
        size = len(c)
        if not size: return
        if size == 1: c = c[0]
        if c not in self.data:
            self.data.append(c)

    def collect(self, container):
        container.append(self.data)


class MemoryBlock:

    def __init__(self):
        self.container = OrderedDict()
        self.max = None
        self.min = None
        self.thres = 0x40
    
    def valid(self, addr):
        return addr >= self.min - self.thres and addr <= self.max + self.thres
    
    def add(self, addr, offset, size):
        if not self.max or addr + size - 1 > self.max:
            self.max = addr + size -1
        if not self.min or addr < self.min:
            self.min = addr        
        while size > 0:
            self.container[addr] = offset
            addr += 1
            offset += 1
            size -= 1
    
    def remove(self, addr, size):
        while size > 0:
            del self.container[addr]
            addr += 1
            size -= 1
    
    def snapshot(self):
        for k, v in self.container.items():
            print(k, v)


class Memory:

    def __init__(self):
        self.container = []

    def index(self, addr):
        for c in self.container:
            if c.valid(addr): return c
        self.container.append(MemoryBlock())
        return self.container[-1]

    def add(self, addr, offset, size):
        self.index(addr).add(addr, offset, size)

    def remove(self, addr, size):
        self.index(addr).remove(addr, size)

    def snapshot(self):
        for c in self.container:
            c.snapshot()


root = FuncNode("")
cur_f = root
cur_d = DataNode()
memory = Memory()

trace = []
ips = []


def index(ret):
    i = 0
    while i < len(ips):
        begin, end, _ = ips[-i]
        if ret > begin  and ret < end: break
        i += 1
    return i

num = 0

looplog = dict()
cmplog = dict()
xorlog = []
xortemp = []
lengthlog = []


for line in lines:
    content = line.strip().split('\t')
    size = len(content)
    if size <= 1: continue
    tag = content[0]
    if tag == "LENGTH":
        lengthlog.append(content[1])
    if tag == "Function":
        thread = int(content[1])
        if thread != threadId: continue
        state = content[2].strip()
        name = content[3]
        if "@plt" in name: continue
        name = mystrip(name)
        if state == "enter":
            if xortemp:
                xorlog.append(xortemp)
                xortemp = []
            ip = [int(c, 16) for c in content[4].strip('()').split(',')]
            k = index(ip[2])
            if k > 1 and k < 3:
                while k > 1 and len(ips) > 0:
                    cur_f = cur_f.parent
                    trace.pop()
                    ips.pop()
                    k -= 1
            trace.append(name)
            ips.append(ip)
            extra = ""
            if k > 1:
                extra = "\n" + str(k)
            node = FuncNode(name + extra)            
            if not cur_d.empty():
                cur_f.add(cur_d)
                cur_d = DataNode()
            cur_f.add(node)
            cur_f = node
        elif content[2].strip() == "exit":
            if not cur_d.empty():
                cur_f.add(cur_d)
                cur_d = DataNode()
            try:
                cur_f = cur_f.parent
                trace.pop()
                ips.pop()
            except:
                print "error"
    elif tag.startswith("Instruction"):
        thread = int(content[1])
        if thread != threadId: continue
        head = content[0].strip("Instruction ").split(",")
        addr, inst0 = head[0].split(':')
        addr = int(addr, 16)
        assembly = inst0.strip().split()[0]
        write = inst0.strip().split()[1]
        if len(head) == 1:
            read = None
            isnum = False
        else:
            read = head[1].strip()
            isnum = read.startswith("0x")
        data = content[2]
        iswrite, isread = True, True
        if data.count(';') == 0:
            isread = False
        elif data.startswith(';'):
            iswrite = False
        if isnum:
            writev = content[3]
            readv = read
        elif content[3].count(';') > 0:
            writev, readv = content[3].split(';')
        else:
            readv = content[3]
        if assembly.startswith("cmp"):
            data = data.strip(';')
            if data not in cmplog:
                cmplog[data] = set()
            if isread:
                cmpobj = "[{}]".format(writev)
            if iswrite:
                cmpobj = readv
                if not isnum:
                    cmpobj = "[{}]".format(readv)
            cmplog[data].add(cmpobj)
            print "compare: ", data, cmpobj
        if assembly.startswith("xor"):
            data = data.strip(';')
            xortemp.append(data)
        if findInLoop(addr) and\
            (((assembly.startswith("add") or assembly.startswith("sub")) and readv == "0x1") or\
            (assembly.startswith("cmp") and not (readv.startswith("0x") and readv != "0x0")) ):
            key = " ".join(head) + " " + data.strip(';')
            print key
            if key not in looplog:
                looplog[key] = 0
            looplog[key] += 1
            print "Loop: ", head, data, readv
        for d in data.split(';'):
            if not d: continue
            cur_d.add([int(c) for c in d.split(",")])
    elif tag == "LOOP":
        loops.append((int(content[1], 16), int(content[2], 16)))


graph = pydot.Dot(graph_type='graph')
root.trim()
while len(root) == 1:
    root = root[0]
graph.add_node(pydot.Node(root.id(), label=root.name()))
root.construct(graph)
graph.write_svg('output.svg')
graph.write_png('output.png')
memory.snapshot()
container = []
root.collect(container)

print "\nresult:"
for d in container:
    print "\t", d

print "\nlength:"
for d in lengthlog:
    print "\t长度字段:\t", d

print "\ncmp instructions:"
for k, v in cmplog.items():
    print "\t字段: {:6s}\t比较值: {}".format(k, " ".join(v))

print "\nloops:"
for k, v in looplog.items():
    d = k.split(" ")
    print "\t指令: {:40s}\t字段: {:10s}次数: {}".format(" ".join(d[:-1]), d[-1], v)

print "\nxor instructions:"
for d in xorlog:
    print "\txor 字节序列:\t", " ".join(d)

