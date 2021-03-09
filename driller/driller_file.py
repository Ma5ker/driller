import os
import time
import signal
import hashlib
import resource
import pickle
import logging
import binascii

import angr
import tracer
from . import config


l = logging.getLogger("driller.driller")
l.setLevel(logging.DEBUG)

class DrillerFile(object):
    """
    DrillerFile is a simple patch to handle a special case that Driller can't handle properly(program with filepath as its argv) 

    Ignore the redis and cgc code for simple, just the basic code to handle linux x86 or x86_64 binary :)
    """
    def __init__(self,binary,input_str=None,fuzz_bitmap=None,hooks=None,argv=None):
        """
        :param binary     : The binary to be traced.
        :param input_str  : Input string to feed to the binary.
        :param fuzz_bitmap: AFL's bitmap of state transitions (defaults to empty).
        :param hooks      : Dictionary of addresses to simprocedures.
        :param argv       : Optionally specify argv params (i,e,: ['./calc', 'parm1']),
                            defaults to binary name with no params.
                            Note:if argv is a filepath,prefix it with @,
                            i.e,:['./objdump','-d','@./bin'] 
        """
        self.binary      = binary
        self.input       = input_str
        self.fuzz_bitmap = fuzz_bitmap
        self.fileargv=[]
        
        # parse file argv
        self.argv=list()
        if argv:
            for arg in argv:
                if arg.startswith('@'):
                    self.argv.append(arg[1:])
                    self.fileargv.append(arg[1:])
                else:
                    self.argv.append(arg)
        else:
            self.argv = [binary]
        
        # at least one input mode is needed
        if self.input==None:
            if len(self.fileargv)==0:
                raise Exception("No input")
            else:
                # input is needed in QEMURunner
                self.input = b"\x00"

        #The following init code same to Driller

        self.base = os.path.join(os.path.dirname(__file__), "..")

        # The simprocedures.
        self._hooks = {} if hooks is None else hooks

        # The driller core, which is now an exploration technique in angr.
        self._core = None

        # Start time, set by drill method.
        self.start_time = time.time()

        # Set of all the generated inputs.
        # self._generated = set()
        self._generated = list()

        # Set the memory limit specified in the config.
        if config.MEM_LIMIT is not None:
            resource.setrlimit(resource.RLIMIT_AS, (config.MEM_LIMIT, config.MEM_LIMIT))
    
    def drill(self):
        """
        perform the drilling
        """
        
        list(self._drill_input())
        return self._generated

    def _drill_input(self):
        """
        symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        """

        # rebuild the path with qemu
        r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv)
        p = angr.Project(self.binary)

        # handle hooks
        for addr, proc in self._hooks.items():
            p.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)

        # try to get an init simstate
        # check the argv 
        s = p.factory.full_init_state(stdin=angr.SimFileStream, args=self.argv)
        
        # preconstrain
        s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, True)

        simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

        # use_technique
        t = angr.exploration_techniques.Tracer(trace=r.trace, crash_addr=r.crash_addr, copy_states=True)
        self._core = angr.exploration_techniques.DrillerCore(trace=r.trace, fuzz_bitmap=self.fuzz_bitmap)

        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self._core)

        self._set_concretizations(simgr.one_active)

        while simgr.active and simgr.one_active.globals['trace_idx'] < len(r.trace) - 1:
            simgr.step()

            # if something in diverted
            if 'diverted' not in simgr.stashes:
                continue
            
            while simgr.diverted:
                state = simgr.diverted.pop(0)
                l.debug("Found a diverted state, exploring to some extent.")
                w = self._writeout(state.history.bbl_addrs[-1], state)
                if w is not None:
                    yield w
                # symbolic explore
                for i in self._symbolic_explorer_stub(state):
                    yield i


    def _writeout(self, prev_addr, state):
        """

        writeout all inputs to a dict
        {
            "stdin":xxxxxxx,
            "filename":(length ,content),
            "block":(prev_addr, cur_addr)
        }

        """
        
        info = dict()

        # first the stdin 
        generated = state.posix.stdin.load(0, state.posix.stdin.pos)
        generated = state.solver.eval(generated, cast_to=bytes)
        info["stdin"] = generated

        # file argv
        for fd in self.fileargv:
            try:
                content = state.fs.get(fd).concretize()
                info[fd] = (len(content),content)
            #maybe the file is not needed
            except AttributeError:
                info[fd] = (0,b"\x00")

        info["block"] = (prev_addr, state.addr)

        # self._generated.add()
        self._generated.append(info)

        return info


    def _symbolic_explorer_stub(self, state):
        
        """
        Create a new simulation manager and step it forward up to 1024
        accumulated active states or steps.
        """
        steps = 0
        accumulated = 1

        p = state.project
        state = state.copy()

        try:
            state.options.remove(angr.options.LAZY_SOLVES)
        except KeyError:
            pass
        simgr = p.factory.simulation_manager(state, hierarchy=False)

        l.debug("[%s] started symbolic exploration at %s.", self.binary, time.ctime())

        # try to explore
        while len(simgr.active) and accumulated < 1024:
            simgr.step()
            steps += 1

            # Dump all inputs.
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))#？？  步数乘以状态数来设置符号执行器探索的上限约束

        l.debug("[%s] stopped symbolic exploration at %s.", self.binary, time.ctime())

        # DO NOT think this is the same as using only the deadended stashes. this merges deadended and active
        simgr.stash(from_stash='deadended', to_stash='active')

        for dumpable in simgr.active:
            try:
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
                    if w is not None:
                        yield w

            # If the state we're trying to dump wasn't actually satisfiable.
            except IndexError:
                pass


    @staticmethod
    def _set_concretizations(state):
        # Let's put conservative thresholds for now.
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000