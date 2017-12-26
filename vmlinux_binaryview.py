# BinaryNinja Plugin Support
# @Author  : NWMonster@hotmail.com

from binaryninja import *
from vmlinux import *

import traceback

class RunInBackground(BackgroundTaskThread):
    def __init__(self, bv, msg, func):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv
        self.func = func

    def run(self):
        bv = self.bv
        bv.begin_undo_actions()
        self.func()
        bv.commit_undo_actions()
        bv.update_analysis()

class VMLinuxView(BinaryView):

    name = "VMLinux"
    long_name = "VMLinux"
    entry_point = 0

    def __init__(self, data):
        BinaryView.__init__(self, file_metadata = data.file, parent_view = data)
        self.raw = data

    @classmethod
    def is_valid_for_data(self, data):
        magic = data.read(0x38, 4)
        if magic != 'ARMd':
            return False 
        return True

    def init_vmlinux(self):
        try:
            print self.file.filename
            with open(self.file.filename, 'rb') as f:
                vmlinux_context = f.read()
            vmlinux_size = len(vmlinux_context)

            do_get_arch(kallsyms, vmlinux_context)
            do_kallsyms(kallsyms, vmlinux_context)

            if kallsyms['numsyms'] == 0:
                print '[!]get kallsyms error...'
                return False

            if kallsyms['arch'] == 64:
                self.arch = binaryninja.Architecture['aarch64']
                self.platform = binaryninja.Platform['linux-aarch64']
            else:
                print '[!]get arch error...'
                return False

            flags = 0
            flags |= SegmentFlag.SegmentContainsData
            flags |= SegmentFlag.SegmentContainsCode
            flags |= SegmentFlag.SegmentReadable
            flags |= SegmentFlag.SegmentExecutable

            self.entry_point = kallsyms["_start"]
            self.add_auto_segment(self.entry_point, vmlinux_size, 0, vmlinux_size, flags)
            self.add_auto_section('.text', self.entry_point, vmlinux_size)

            for i in xrange(kallsyms['numsyms']):
                if kallsyms["address"][i] == 0:
                    continue
                if kallsyms['type'][i] in ['t','T']:
                    sym = Symbol(binaryninja.enums.SymbolType.FunctionSymbol, kallsyms["address"][i], kallsyms["name"][i])
                    self.define_auto_symbol(sym)
                    self.create_user_function(kallsyms["address"][i], self.platform)
                else:
                    sym = Symbol(binaryninja.enums.SymbolType.DataSymbol, kallsyms["address"][i], kallsyms["name"][i])
                    self.define_auto_symbol(sym)

            f.close()
        except:
            log_error(traceback.format_exc())
            return False
        
        return True

    def init(self):
        s = RunInBackground(self, "VMLinux Loading...", self.init_vmlinux)
        s.start()

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.entry_point

#VMLinuxView.register()
