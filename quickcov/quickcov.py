#!/usr/bin/python3

import argparse
import os
import subprocess
import json
import signal
import resource
import ctypes
import sys
import random
import copy
import ptrace
import subprocess
import pickle
import re
import time
import builtins
import numpy as np

from multiprocessing import Process, Queue, Pipe
from enum import Enum, auto
from threading import Lock

import ptrace.debugger
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.child import createChild
from ptrace.ctypes_tools import (truncateWord, formatWordHex, formatAddress, formatAddressRange, word2bytes)
from ptrace.debugger.memory_mapping import readProcessMappings
from ptrace.debugger import ProcessExit, ProcessSignal
from ptrace.cpu_info import CPU_POWERPC

from icecream import ic

PTRACE_TRACEME = 0
PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_PEEKUSR = 3
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_POKEUSR = 6
PTRACE_CONT = 7
PTRACE_KILL = 8
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_GETFPREGS = 14
PTRACE_SETFPREGS = 15
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_GETWMMXREGS = 18
PTRACE_SETWMMXREGS = 19
PTRACE_OLDSETOPTIONS = 21
PTRACE_GET_THREAD_AREA = 22
PTRACE_SET_SYSCALL = 23
PTRACE_SYSCALL = 24
PTRACE_GETCRUNCHREGS = 25
PTRACE_SETCRUNCHREGS = 26
PTRACE_GETVFPREGS = 27
PTRACE_SETVFPREGS = 28
PTRACE_GETHBPREGS = 29
PTRACE_SETHBPREGS = 30
PTRACE_SETOPTIONS = 0x4200
PTRACE_GETEVENTMSG = 0x4201
PTRACE_GETSIGINFO = 0x4202
PTRACE_SETSIGINFO = 0x4203

MAX_MEMORY = 500 << 20
FILTER_AFL_FILES = set(["fuzz_bitmap", "min-branch-fuzzing.log", "fuzzer_stats", ".cur_input", "plot_data", "cmdline"])

# python-ptrace code
def fastReadProcessMappings(pid):
  maps = []
  #print(open("/proc/%d/maps" % pid, "r").read())
  try:
    mapsfile = open("/proc/%d/maps" % pid, "r")
  except:
    raise Exception("Unable to read process maps")
  for line in mapsfile:
    line = line.rstrip()
    start = end = permissions = None
    line_split = line.split(' ')
    start_end = line_split[0].split('-')
    start = int(start_end[0], 16)
    end = int(start_end[1], 16)
    permissions = line_split[1]
    path_name = line.rsplit(' ')[-1]
    maps.append((start, end, permissions, path_name))
  mapsfile.close()
  return maps

# https://windelbouwman.wordpress.com/2016/02/26/a-linux-debugger-in-python/
class UserRegsStruct(ctypes.Structure):
  _fields_ = [
      ("r15", ctypes.c_ulonglong),
      ("r14", ctypes.c_ulonglong),
      ("r13", ctypes.c_ulonglong),
      ("r12", ctypes.c_ulonglong),
      ("rbp", ctypes.c_ulonglong),
      ("rbx", ctypes.c_ulonglong),
      ("r11", ctypes.c_ulonglong),
      ("r10", ctypes.c_ulonglong),
      ("r9", ctypes.c_ulonglong),
      ("r8", ctypes.c_ulonglong),
      ("rax", ctypes.c_ulonglong),
      ("rcx", ctypes.c_ulonglong),
      ("rdx", ctypes.c_ulonglong),
      ("rsi", ctypes.c_ulonglong),
      ("rdi", ctypes.c_ulonglong),
      ("orig_rax", ctypes.c_ulonglong),
      ("rip", ctypes.c_ulonglong),
      ("cs", ctypes.c_ulonglong),
      ("eflags", ctypes.c_ulonglong),
      ("rsp", ctypes.c_ulonglong),
      ("ss", ctypes.c_ulonglong),
      ("fs_base", ctypes.c_ulonglong),
      ("gs_base", ctypes.c_ulonglong),
      ("ds", ctypes.c_ulonglong),
      ("es", ctypes.c_ulonglong),
      ("fs", ctypes.c_ulonglong),
      ("gs", ctypes.c_ulonglong),
  ]

class ExecuterMode(Enum):
  AFL = auto()
  AFL_QEMU = auto()
  AFL_QEMU_BB = auto()
  PTRACE = auto()

def get_queue_files(folder):
  files = []
  for d in os.listdir(folder):
    p = os.path.abspath(os.path.join(folder, d))
    if os.path.isdir(p):
      files.extend(get_queue_files(p))
    else:
      files.append(p)
  return files

def print_usage():
    print("Usage: python quickcov.py [options] -- [binary] [binary_options] @@")

def check_afl():
  f = open('/proc/sys/kernel/core_pattern', "r")
  core_pattern = f.read().strip()
  ready = (core_pattern == "core")
  f.close()
  return ready

def check_if_binary_instrumented(binary):
  instrumented = True
  with open(binary, "rb") as f:
    instrumented = (b"__AFL_SHM_ID" in f.read())
  return instrumented

class AFLBitmap:

  def __init__(self, bitmap=None):
    self.bitmap = np.array(bytearray())
    if bitmap is not None:
      if isinstance(bitmap, np.ndarray):
        # bitmap is already a converted np.array, leave it as it is
        assert(np.sum(np.where(bitmap > 1, 1, 0)) == 0) # check if it looks like a converted array
        self.bitmap = np.array(bitmap, copy=True)
      else:
        # bitmap was delivered as an actual AFL bitmap, convert to np.array
        self.bitmap = np.array(bytearray(bitmap), dtype='uint8')
        self.normalize_bitmap()

  def normalize_bitmap(self):
    # it could be an AFL virgin_bits or an AFL trace_bits
    # virgin_bits uses 0xff to say "this edge was not touched"
    # trace_bits uses 0x00 to say the same
    # so only count an edge as visited if it's neither 0xff nor 0x00
    # more reliant than trying to detect if it's coming from virgin_bits or trace_bits
    self.bitmap = np.array(np.where((self.bitmap != 0xff) & (self.bitmap != 0x00), 1, 0), dtype='uint8')

  def is_new(self, data):
    if len(self.bitmap) == 0:
      return True
    else:
      return data.delta(self.bitmap) > 0

  def initialize_bitmap_if_necessary(self, size):
    if len(self.bitmap) == 0 and size > 0:
      b = bytearray([0])*size
      self.bitmap = np.array(b)
      del b

  # counts visited edges in bitmap
  def count(self):
    return np.sum(self.bitmap)

  # use other bitmap as baseline, what are the new branches in our bitmap?
  def delta(self, other):
    if len(other.bitmap) > 0:
      self.initialize_bitmap_if_necessary(len(other.bitmap))
    elif len(self.bitmap) > 0:
      other.initialize_bitmap_if_necessary(len(self.bitmap))
    assert(len(self.bitmap) == len(other.bitmap))
    delta = (self.bitmap | other.bitmap) - other.bitmap
    return AFLBitmap(delta)

  def reset(self):
    self.bitmap = np.array(bytearray())

  # use other bitmap as baseline,, how many new branches are in our bitmap?
  def delta_count(self, other):
    return np.sum(self.delta(other).bitmap)
  
  # update bitmap
  def update(self, other):
    if len(other.bitmap) == 0:
      return
    self.initialize_bitmap_if_necessary(len(other.bitmap))
    assert(len(self.bitmap) == len(other.bitmap))
    u = self.bitmap | other.bitmap
    self.bitmap = u

  def __repr__(self):
    return str(self.bitmap)

class AFLBBTrace:

  def __init__(self, other=None):
    if other is None:
      self.trace = []
    else:
      if isinstance(other, AFLBBTrace):
        self.trace = list(other.trace)
      elif isinstance(other, list) or isinstance(other, set):
        self.trace = list(other)
      else:
        self.trace = []

  def is_new(self, other):
    return len(set(other.trace) - set(self.trace)) > 0

  # counts visited BBs in trace (unique BBs)
  def count(self):
    return len(set(self.trace))

  # use other trace as baseline, what are the new BBs in our trace?
  def delta(self, other):
    return AFLBBTrace(list(set(self.trace) - set(other.trace)))

  # use other trace as baseline, how many new BBs are in our trace?
  def delta_count(self, other):
    return len(set(self.trace) - set(other.trace))
  
  # update bitmap
  def update(self, other):
    self.trace.extend(other.trace)

  def _make_unique(self):
    self.trace = list(set(self.trace))

  def reset(self):
    self.trace = []

  def __repr__(self):
    return str(self.trace)

class AFLForkserverExecuter:

  def __init__(self, binary, arguments, qemu_mode=False, dump_basic_blocks=False):
    script_path = os.path.dirname(os.path.realpath(__file__))
    
    if not check_afl():
      raise Exception("AFL is not configured, please execute:\n"
                      "sudo bash -c 'echo core >/proc/sys/kernel/core_pattern; cd /sys/devices/system/cpu; echo performance | tee cpu*/cpufreq/scaling_governor'")

    self.qemu_mode = qemu_mode
    self.dump_basic_blocks = dump_basic_blocks
    if self.qemu_mode:
      if os.path.isfile(os.path.join(script_path, "afl-qemu-trace")):
        os.environ["QEMU_LOG"] = "nochain"
      else:
        raise Exception("QEMU mode is activated but couldn't find afl-qemu-trace. Did you install it properly?")
    
    self.fuzzed_binary = binary
    self.binary = self.fuzzed_binary
    self.arguments = arguments

    self.script_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))
    
    self.input_file_path = None
    while self.input_file_path == None or os.path.isfile(self.input_file_path):
        self.randID = random.randint(1111111111, 9999999999)
        self.input_file_path = "/dev/shm/quickcov_input_%d" % (self.randID)
    self.input_file_path = self.input_file_path
    self.f = open(self.input_file_path, "wb+")

    if '@@' in self.arguments:
      self.arguments[self.arguments.index('@@')] = self.input_file_path
    self.arguments.insert(0, os.path.abspath(self.binary))
    # in QEMU mode, we need to do some special stuff
    if self.qemu_mode:
      afl_qemu_trace = os.path.join(script_path, "afl-qemu-trace")
      # we don't actually call the binary anymore, but "afl-qemu-trace -- ./program --flags @@"
      # and QEMU returns the bitmap after execution
      self.arguments.insert(0, afl_qemu_trace)
      self.arguments.insert(1, "--")
      self.binary = afl_qemu_trace
      # in dump_basic_blocks mode, we have to tell QEMU where to dump everything
      if dump_basic_blocks:
        os.environ["DUMP_BB"] = "1"
        self.dump_basic_blocks_path = "/dev/shm/quickcov_bb_output_%d" % (self.randID)
        os.environ["DUMP_BB_FILE"] = self.dump_basic_blocks_path
        self.coverage = AFLBBTrace()
      else:
        self.coverage = AFLBitmap()
    else:
      self.coverage = AFLBitmap()
    

    # https://github.com/albertz/playground/blob/master/shared_mem.py
    self.aflforkserverlib = ctypes.cdll.LoadLibrary(os.path.abspath(os.path.join(self.script_path, "aflforkserver.so")))

    LP_c_char = ctypes.POINTER(ctypes.c_char)
    LP_LP_c_char = ctypes.POINTER(LP_c_char)

    # int shmget(key_t key, size_t size, int shmflg);

    # void setup(char* out_file_path)
    self.setup = self.aflforkserverlib.setup
    self.setup.restype = None
    self.setup.argtypes = (ctypes.c_char_p, ctypes.c_int)

    # void init_target(char *argv[], char* target)
    self.init_target = self.aflforkserverlib.init_target
    self.init_target.restype = ctypes.c_int
    self.init_target.argtypes = (ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char))

    # int run_target(char **argv)
    # returns non-zero if error happened
    self.run_target = self.aflforkserverlib.run_target
    self.run_target.restype = ctypes.c_int
    self.run_target.argtypes = (ctypes.POINTER(ctypes.c_char_p), )

    # int check_new_coverage()
    self.check_new_coverage = self.aflforkserverlib.check_new_coverage
    self.check_new_coverage.restype = ctypes.c_int
    self.check_new_coverage.argtypes = None

    # static void write_to_testcase(void* mem, u32 len)
    self.write_to_testcase = self.aflforkserverlib.write_to_testcase
    self.write_to_testcase.restype = None
    self.write_to_testcase.argtypes = (ctypes.POINTER(ctypes.c_char), ctypes.c_int)

    # int get_map_size()
    self.get_map_size = self.aflforkserverlib.get_map_size
    self.get_map_size.restype = ctypes.c_int
    self.get_map_size.argtypes = None
    self.MAP_SIZE = self.get_map_size()

    # uint8_t* get_bitmap()
    self.get_bitmap = self.aflforkserverlib.get_bitmap
    self.get_bitmap.restype = ctypes.POINTER(ctypes.c_uint8 * self.MAP_SIZE)
    self.get_bitmap.argtypes = None

    # int has_exec_failed()
    self.has_exec_failed = self.aflforkserverlib.has_exec_failed
    self.has_exec_failed.restype = ctypes.c_int
    self.has_exec_failed.argtypes = None

    # int cleanup()
    self.afl_cleanup = self.aflforkserverlib.cleanup
    self.afl_cleanup.restype = None
    self.afl_cleanup.argtypes = None

    # void reset_bitmap()
    self._reset = self.aflforkserverlib.reset_bitmap
    self._reset.restype = None
    self._reset.argtypes = None

    # set up aflforkserver
    #(ctypes.c_char * len(self.input_file_path.encode('ascii')))(*self.input_file_path.encode('ascii'))
    self.input_file_path_c = (self.input_file_path+"\x00").encode('ascii')
    self.setup(self.input_file_path_c, int(self.qemu_mode))
    execve_arguments = [s.encode('ascii') for s in self.arguments] + [None] # execve needs this format [param1, param2, NULL]
    self.arguments_c = (ctypes.c_char_p * len(execve_arguments))(*execve_arguments)
    binary = (self.binary+"\x00").encode('ascii') # I'm sure there is some ctypes-proper way to do this ... @TODO
    self.binary_c = (ctypes.c_char * len(binary))(*binary)
    exec_failed = self.init_target(self.arguments_c, self.binary_c)
    if exec_failed > 0:
        print("forkserver error")
        raise Exception("AFL Forkserver error")

    self.has_get_coverage = True
    self.new_input = False

  def execute(self, inp):
    self.f.truncate()
    self.f.seek(0)
    self.f.write(bytearray(inp))
    self.f.seek(0)
    self.f.flush()
    if self.dump_basic_blocks:
      with open(self.dump_basic_blocks_path, "w+") as f:
        f.truncate()
        f.seek(0)
        f.flush()

    hasCrashed = False
    hasExited = False

    hasCrashed = (self.run_target(self.arguments_c) == 2)
    self.new_input = (self.check_new_coverage() > 0)
    return hasCrashed

  def get_coverage(self):
    cov = None
    if self.dump_basic_blocks:
      with open(self.dump_basic_blocks_path, "r") as f:
        file_content = f.read()
        try:
          trace = list(map(int, [x for x in file_content.split(';') if x != '']))
        except Exception as e:
          print("!!!! quickcov QEMU returned broken basic block dump: %s" % e)
          trace = []
        if len(trace) == 0:
          print("!!! quickcov couldn't extract trace data (file_content size: %d)" % len(file_content))
      cov = AFLBBTrace(trace)
    else:
      cov = AFLBitmap(self.get_bitmap().contents)
    self.coverage.update(cov)
    return self.coverage

  def reset(self):
    self._reset()
    self.coverage.reset()

  def cleanup(self):
    self.f.close()
    try:
        os.remove(self.input_file_path)
    except:
        pass
    try:
      os.remove(self.dump_basic_blocks_path)
    except:
      pass
    self.afl_cleanup()
    self.coverage.reset()

  def __del__(self):
    self.cleanup()

class AFLForkserverTask(Enum):
  SET_CORE = 1
  EXECUTE = 2
  GET_COVERAGE = 3
  RESET = 4
  CLEANUP = 5

class AFLForkserverProcess():
  def __init__(self, binary, binary_arguments, qemu_mode=False, dump_basic_blocks=False):
    self.binary = binary
    self.binary_arguments = binary_arguments
    self.qemu_mode = qemu_mode
    self.dump_basic_blocks = dump_basic_blocks
    self.running = True
    self.queue = Queue()
    self.parent, self.child = Pipe()
    self.p = Process(target=self.process_loop)
    self.p.start()

  def process_loop(self):
    self.afl = AFLForkserverExecuter(self.binary, self.binary_arguments, 
                                     qemu_mode=self.qemu_mode, 
                                     dump_basic_blocks=self.dump_basic_blocks)
    while self.running:
      if self.child.poll(timeout=1):
        (task, args) = self.child.recv()
      else:
        continue
        
      if task == AFLForkserverTask.EXECUTE:
        self.child.send(self.afl.execute(*args))
      elif task == AFLForkserverTask.GET_COVERAGE:
        self.child.send(self.afl.get_coverage(*args))
      elif task == AFLForkserverTask.RESET:
        self.child.send(self.afl.reset())
      elif task == AFLForkserverTask.SET_CORE:
        assert(args[0] < os.cpu_count())
        os.system("taskset -p -c %d %d" % (args[0], self.p.pid))
      elif task == AFLForkserverTask.CLEANUP:
        ret = self.afl.cleanup()
        self.running = False
        self.child.send(ret)
        self.child.close()
      else:
        assert(False) # should never reach this

  def execute(self, inp):
    self.parent.send((AFLForkserverTask.EXECUTE, [inp]))
    return self._parent_recv()

  def get_coverage(self):
    self.parent.send((AFLForkserverTask.GET_COVERAGE, []))
    return self._parent_recv()

  def reset(self):
    self.parent.send((AFLForkserverTask.RESET, []))
    return self._parent_recv()

  def set_core(self, core):
    self.parent.send((AFLForkserverTask.SET_CORE, [core]))

  def cleanup(self):
    try:
      self.parent.send((AFLForkserverTask.CLEANUP, []))
      self._parent_recv()
      self.parent.close()
    except (EOFError, OSError):
      pass
    return

  def restart_forkserver(self):
    self.running = False
    self.p = Process(target=self.process_loop)
    self.p.start()

  # recv with timeout
  def _parent_recv(self):
    if self.parent.poll(timeout=10):
        return self.parent.recv()
    else:
        self.restart_forkserver()
        raise Exception("Forkserver crashed, restart initiated.")


  def __del__(self):
    self.cleanup()

class PTraceExecuter():

  def __init__(self, binary, binary_arguments, skip_visited_bbs=False):

    self.binary = binary
    self.arguments = binary_arguments
    self.script_path = os.path.abspath(os.path.dirname(os.path.realpath(__file__)))

    if not os.path.isfile("%s.bb" % self.binary):
      raise Exception("*.bb file is needed, please run IDA to collect the data")

    self.coverage = AFLBBTrace()
    
    self.input_file_path = None
    while self.input_file_path == None or os.path.isfile(self.input_file_path):
        self.rand_id = random.randint(1111111111, 9999999999)
        self.input_file_path = "/dev/shm/quickcov_input_%d" % (self.rand_id)
    self.input_file_path = self.input_file_path
   
    if '@@' in self.arguments:
      self.arguments[self.arguments.index('@@')] = self.input_file_path
    self.arguments.insert(0, os.path.abspath(self.binary))

    with open("%s.bb" % self.binary, "rb") as pf:
      ida_data = pickle.load(pf)
      self.all_bbs = list(ida_data["bb"].keys())
      self.main_address = ida_data['meta']['main']
      self.main_code = bytes.fromhex(ida_data['meta']['main_code'])

    self.f = open(self.input_file_path, "wb+")
    self.visited_bbs = set([])
    self.libc = ctypes.CDLL('libc.so.6')
    self.skip_visited_bbs = skip_visited_bbs

  def execute(self, inp):
    self.old_code = {}
    self.visited_bbs = set([])

    self.f.truncate()
    self.f.seek(0)
    self.f.write(bytearray(inp))
    self.f.seek(0)
    self.f.flush()

    has_crashed = False

    pid = os.fork()
    if pid > 0:
      # parent

      # wait for execv to be called, waitpid returns if it was
      os.waitpid(pid, 0)

      self.base = 0
      executable_mappings = []
      basename = os.path.basename(self.binary)
      for m in fastReadProcessMappings(pid):
        (start, end, permissions, pathname) = m
        if pathname and basename in pathname and "x" in permissions:
          executable_mappings.append(m)

      #print "%s" % executable_mappings
      if not executable_mappings:
        raise Exception("Could not find mapping with executable flag")

      if len(executable_mappings) > 1:
        #raise Exception
        print("Note: there are more than one executable mappings, don't know which one to use. @TODO add support")
        print(executable_mappings)

      # select the executable mapping with the lowest starting address (@TODO)
      self.selected_map = min(executable_mappings, key=lambda m: m[0])
      self.base = self.selected_map[0] #selected_map.start

      # sometimes IDA has found the complete address already
      # in which case, just use the BB addresses from IDA (set base=0)
      self.mem = open('/proc/%d/mem' % pid, "rb+", 0)
      try:
        self.mem.seek(self.main_address)
        # does this code on this address look like the main-function?
        if self.mem.read(8) == self.main_code:
          # yeah, set base = 0
          self.base = 0
      except:
        pass
      # go through all BBs that were not visited yet (no breakpoint necessary for BBs that were already visited)
      if self.skip_visited_bbs:
        iterate_bbs = self.all_bbs - self.visited_bbs
      else:
        iterate_bbs = self.all_bbs
      error_while_reading = 0
      for bb in iterate_bbs:
        #self.log.info("Set breakpoint for %x" % bb) 
        bb = self.base + bb
        self.mem.seek(bb)
        try:
          self.old_code[bb] = self.mem.read(1)
        except:
          error_while_reading += 1
          continue
        self.mem.seek(bb)
        self.mem.write(b"\xCC")
        #self.libc.ptrace(PTRACE_POKETEXT, pid, bb, "\xCC")
      #if error_while_reading > 0:
      #  print("Attention: got errors while reading %d BBs (out of %d), ignoring those." % (error_while_reading, len(iterate_bbs)))
      if error_while_reading == len(iterate_bbs):
        raise Exception("Couldn't add a single breakpoint, maybe issue with calculating correct base address?")
      #self.log.info("cont'ing ptraced process")
      self.libc.ptrace(PTRACE_CONT, pid, 0, 0)
      regs = UserRegsStruct()
      while True:
        try:
          (p, status) = os.waitpid(pid, 0)
        except:
          #self.log.info("process %d does not exist anymore" % pid)
          break
        if os.WIFEXITED(status):
          #self.log.info("process %d exited with %d (%d)" % (pid, status, os.WIFEXITED(status)))
          break
        elif os.WIFSIGNALED(status):
          #self.log.info("process %d crashed with %d (%d)" % (pid, status, os.WIFSIGNALED(status)))
          has_crashed = True
          break
        elif os.WIFSTOPPED(status):
          #self.log.info("received WIFSTOPPED with %d (%d), signal %d" % (status, os.WIFSTOPPED(status), os.WSTOPSIG(status)))
          signalNum = os.WSTOPSIG(status)
          if signalNum == signal.SIGTRAP:
            self.libc.ptrace(PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
            regs.rip -= 1
            self.visited_bbs.add(regs.rip - self.base)
            #self.log.info("SIGTRAP received at %x" % regs.rip)
            self.mem.seek(regs.rip)
            self.mem.write(self.old_code[regs.rip])
            self.libc.ptrace(PTRACE_SETREGS, pid, 0, ctypes.byref(regs))
            self.libc.ptrace(PTRACE_CONT, pid, 0, 0)
          else:
            #self.log.info("got unknown signal %d, probably crash" % signalNum)
            has_crashed = True
            break
        else:
          #self.log.info("got unknown status %d" % pid)
          pass
      try:
        os.kill(pid, 9)
      except:
        pass
    
    else:
      # child
      resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY, MAX_MEMORY)) # 50 MB process memory limit
      resource.setrlimit(resource.RLIMIT_CORE, (0, 0)) # Maximum size of core file
      
      nulf = os.open(os.devnull, os.O_WRONLY)
      os.dup2(nulf, sys.stdout.fileno())
      os.dup2(nulf, sys.stderr.fileno())
      os.close(nulf)
      
      self.libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
      os.execv(self.binary, self.arguments)
      os._exit(0)
    return has_crashed

  def get_coverage(self):
    self.coverage.update(AFLBBTrace(self.visited_bbs))
    return self.coverage

  def reset(self):
    self.coverage.reset()

  def cleanup(self):
    self.f.close()
    self.coverage.reset()
    try:
        os.remove(self.input_file_path)
    except:
        pass

class QuickCov:
    # binary = path to afl-instrumented binary (e.g. /home/bla/binutils/objdump)
    # binary_arguments = list of paramters for calling the binary, use @@ for filename (e.g. ["-d", "-x", "@@"])
    def __init__(self, binary, binary_arguments, mode=ExecuterMode.AFL):
        self.binary = binary
        if isinstance(binary_arguments, str):
            self.binary_arguments = binary_arguments.split(' ')
        else:
            self.binary_arguments = copy.deepcopy(binary_arguments)
        if self.binary_arguments[-1] == '':
          self.binary_arguments[-1] = '@@'
        if '@@' not in self.binary_arguments:
          self.binary_arguments.append('@@')

        # use the given mode except when 
        # the given mode is AFL, but the binary is not instrumented
        # in which case, use AFL-QEMU mode
        self.mode = mode
        if self.mode == ExecuterMode.AFL and not check_if_binary_instrumented(binary):
            self.mode = ExecuterMode.AFL_QEMU
        
        if self.mode in [ExecuterMode.AFL, ExecuterMode.AFL_QEMU, ExecuterMode.AFL_QEMU_BB]:
          qemu_mode = (self.mode in [ExecuterMode.AFL_QEMU, ExecuterMode.AFL_QEMU_BB])
          dump_basic_blocks = (self.mode == ExecuterMode.AFL_QEMU_BB)
          self.executer = AFLForkserverProcess(self.binary, self.binary_arguments, 
                                               qemu_mode=qemu_mode, 
                                               dump_basic_blocks=dump_basic_blocks)
        elif self.mode == ExecuterMode.PTRACE:
          self.executer = PTraceExecuter(self.binary, self.binary_arguments)

    # corpus = if string: directory where to find input files, if list: list of corpus files (absolute paths)
    # plot = True if a plot over a time period should be generated
    # time_dict = dictionary with key=file,value=timestamp to determine file creation times 
    #             (or None if filesystem modification times should be used)
    #             if time_dict is not specified, the filesystem 
    #             modification time will be used instead
    # time_dict_lock = if time_dict is still updated, lock file to prevent race conditions
    # limit = only get coverage for these files (list of absolute paths)
    # relative_time = for plot output, set key values to relative timings 
    #                 (i.e. start with 0 instead of the actual timestamp 
    #                  of the first file)
    # ignore_missing_files = do not throw exception when file in corpus is missing
    # use_afl_file_filter = remove non-corpus files introduced by AFL 
    #                       (e.g. if corpus is /afl_output/ instead of /afl_output/queue/)
    # minimum_time = some files have old modification dates (prior to starting fuzzing), 
    #                in which case set their date to this value
    # returns (plot, bitmap, final_coverage):
    # plot = dictionary where key = timestamp and value = accumulated number of branches at that time
    # bitmap = bytearray of bitmap or list of BBs
    # final_coverage = number of visited branches/BBs after all queue files were executed
    def get_coverage(self, corpus, plot=False, \
                     time_dict=None, time_dict_lock=None, limit=None, \
                     relative_time=False, ignore_missing_files=True,
                     use_afl_file_filter=True, minimum_time=0):
        self.executer.reset()
        if isinstance(corpus, str):
            # treat corpus argument as file path
            files = get_queue_files(corpus)
        else:
            # treat corpus argument as list of files
            files = corpus
        if use_afl_file_filter:
            files = list(set(files) - FILTER_AFL_FILES)
        plot_dict = {}
        # check if all files exist and apply limit filter if necessary
        existing_files = []
        for f in files:
            if os.path.isfile(f):
                if limit is None or f in limit:
                    existing_files.append(f)
            else:
                if ignore_missing_files:
                    continue
                else:
                    raise Exception("Missing file: %s" % f)
                
        files = existing_files
        if len(files) == 0:
            print("No files, returning empty handed")
            return ({}, AFLBitmap(), 0)
        
        if time_dict_lock is None:
            time_dict_lock = Lock()
        # make sure that all files exist as keys in time_dict to avoid errors
        if time_dict is None:
            time_dict = {}
            for f in files:
                try:
                    time_dict[f] = max(os.path.getmtime(f), minimum_time)
                except:
                    if ignore_missing_files:
                        pass
                    else:
                        raise Exception("Missing file: %s" % f)
        
        with time_dict_lock:
            files = list(set(time_dict.keys()) & set(files))
            time_sorted_files = sorted(files, key=lambda f: max(time_dict[f], minimum_time))
            basetime = 0
            if relative_time:
                basetime = max(time_dict[time_sorted_files[0]], minimum_time)
        
        for f in time_sorted_files:
            try:
                inpf = open(f, "rb")
            except:
                if ignore_missing_files:
                    continue
                else:
                    raise Exception("Missing file: %s" % f)
            inp = bytearray(inpf.read())
            inpf.close()
            self.executer.execute(inp)
            if plot:
                with time_dict_lock:
                    t = max(time_dict[f], minimum_time)
                time_as_key = int(t - basetime)
                if time_as_key in plot_dict:
                    plot_dict[time_as_key] = max(plot_dict[time_as_key], self.executer.get_coverage().count())
                else:
                    plot_dict[time_as_key] = self.executer.get_coverage().count()
        
        ret = (plot_dict, self.executer.get_coverage(), self.executer.get_coverage().count())
        
        return ret

    def _get_coverage(self, corpus, plot_file, dump_bitmap_path, time_file):
        set_plot = True if plot_file else False
        set_dump_bitmap = True if dump_bitmap_path else False
        # time file
        time_dict = None
        if time_file:
            tf = open(time_file, "r")
            time_dict = json.loads(tf.read()) #@TODO replace with pickle
            tf.close()
        (plot, bitmap, final_coverage) = self.get_coverage(corpus, plot=set_plot, time_dict=time_dict, limit=None)
        if set_dump_bitmap:
            bf = open(dump_bitmap_path, "wb+")
            bf.write(bytearray(bitmap.bitmap))
            bf.close()
        if set_plot:
            pf = open(plot_file, "w+")
            pf.write(json.dumps({k: int(v) for k,v in plot.items()}, indent=4))
            pf.close()
        
        return (plot, bitmap, final_coverage)

    def reset(self):
        self.executer.reset()

    def cleanup(self):
        self.executer.cleanup()

    def __del__(self):
      self.cleanup()

    def __enter__(self):
      return self

    def __exit__(self, type, value, traceback):
      self.cleanup()

if __name__ == '__main__':
    if '--' not in sys.argv:
        print_usage()
        sys.exit(-1)

    full_command = sys.argv[sys.argv.index('--')+1:]
    binary = full_command[0]
    binary_arguments = full_command[1:]

    sys.argv = sys.argv[:sys.argv.index('--')]

    parser = argparse.ArgumentParser(description="Get code coverage by executing binary with given input", prog="quickcov.py")
    parser.add_argument('--corpus', '-c', dest='corpus', help='Corpus directory', nargs=1, required=True)
    parser.add_argument('--plot', '-p', dest="plot", help="Output plot for branch-coverage-over-time to this path", nargs=1)
    parser.add_argument('--dump-bitmap', '-d', dest="dump_bitmap", help="If set, bitmap will be dumped to specified path (e.g. --dump-bitmap /dev/shm/bla.bitmap)", nargs=1)
    parser.add_argument('--time-file', '-t', dest="time_file", help="Use the given json dict file to determine creation dates of files instead of filesystem modification times", nargs=1)
    args = parser.parse_args()

    corpus = args.corpus[0]
    if not os.path.isdir(corpus):
        print("%s is not a valid dir")
        sys.exit(-1)
    if args.plot:
        plot = args.plot[0]
    else:
        plot = None
    if args.dump_bitmap:
        dump_bitmap = args.dump_bitmap[0]
    else:
        dump_bitmap = None
    if args.time_file:
        time_file = args.time_file[0]
    else:
        time_file = None
    q = QuickCov(binary, binary_arguments)
    (plot, bitmap, final_coverage) = q._get_coverage(corpus, plot, dump_bitmap, time_file)
    q.cleanup()
    print(final_coverage)
