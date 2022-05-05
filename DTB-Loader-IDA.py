'''
IDAPython plugin

Useful for reversing linux/android kernels.
Author:
    (c) Mathieu Renard <dark@gotohack.io>

License: GPLv3
'''
import logging
from collections import namedtuple
import idc
import idaapi
import idautils
from idaapi import simplecustviewer_t
from idaapi import Choose2
from idaapi import PluginForm


import sys
sys.path.insert(0, ".")

from DTB_Parser import *
#from __future__ import print_function

logger = logging.getLogger(__name__)

from PyQt5.QtWidgets import (QWidget, QPushButton, QLabel,
    QHBoxLayout, QVBoxLayout, QApplication, QTreeWidget, QTreeWidgetItem, QTreeWidgetItem)



def get_seg_list(type='DATA'):
    seg_list = []
    for seg in Segments():
        print('%x-%x'%(SegStart(seg),SegEnd(seg)))
        seg_list.append({'start':SegStart(seg),'end':SegEnd(seg)})
    return seg_list


def get_xref_to_seg(seg):
    start = SegStart(seg)
    end = SegEnd(seg)
    for ea in idautils.Heads(start, end):
        gen_xrefs = XrefsTo(ea, 0)
        for xx in gen_xrefs:
            print hex(ea), hex(xx.frm),


def addPrefixToFunctionName(prefix, functionAddr):
    name = GetFunctionName(functionAddr)
    print("addPrefixToFunctionName:%s-%08x" % (prefix, functionAddr))
    name = ""
    if (name and not name.startswith(prefix)):
        name = prefix + name
        print("Function 0x%x => Name: " % (functionAddr, name))
        #idc.MakeNameEx(int(curr_addr), name, idc.SN_NOWARN)
        idc.set_name(functionAddr, name, anyway=True)

class NameSpaceForm(PluginForm):

    def __init__(self, peripherals=None):
        idaapi.PluginForm.__init__(self)
        self.peripherals = peripherals
        self.__name = "Namespaces"
        self.peripherals = peripherals
        return

    def OnCreate(self, form):
        self.myform = form
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        return

    def PopulateForm(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel(self.__name))
        self.tree = QTreeWidget()
        layout.addWidget(self.tree)
        self.tree.setHeaderLabels(("Peripherals",))
        self.tree.setColumnCount(4)
        self.tree.setColumnWidth(0, 100)
        self.tree.setColumnWidth(0, 300)
        self.tree.setColumnWidth(0, 300)
        self.tree.setSortingEnabled(True)
        self.tree.itemClicked.connect(self.OnClick)
        self.PopulateTree()
        self.parent.setLayout(layout)
        return

    def Show(self):
        idaapi.PluginForm.Show(self, self.__name)
        return


    def PopulateTree(self):
        self.tree.clear()
        root = QTreeWidgetItem(self.tree)
        root.setText(0, "Peripherals")
        root.setText(1, "Function Name")
        root.setText(2, "Address")
        root.setText(3, "Instruction")
        for p in self.peripherals:
            p_item = QTreeWidgetItem(root)
            p_item.setText(0, p.name)
            xrefs = XrefsTo(p.base_address, 0)
            last_func = None
            last_p_func = None
            for x in xrefs:
                func_name = GetFunctionName(x.frm)
                print("isCode: %d" % isCode(GetFlags(x.frm)))
                if not isCode(GetFlags(x.frm)):
                    MakeCode(x.frm)
                    MakeFunction(x.frm)
                    t = idaapi.generate_disasm_line(x.frm)
                    if t:
                        line = idaapi.tag_remove(t)
                    else:
                        line = ""
                    print("New Func @%08x => %s"% (x.frm,func_name))

                addPrefixToFunctionName("Auto_%s_%08x" % (p.name, x.frm),x.frm)

                if last_func != func_name:
                    last_func = GetFunctionName(x.frm)
                    p_func = QTreeWidgetItem(p_item)
                    p_func.setText(1, "%s" % GetFunctionName(x.frm))
                    print("Rename Func @%08x => %s"% (x.frm,func_name))
                    last_p_func = p_func
                p_addr = QTreeWidgetItem(last_p_func)
                p_addr.setText(2, "0x%08x" % x.frm)
                p_inst = QTreeWidgetItem(last_p_func)
                p_inst.setText(3,GetDisasm(x.frm))

    def OnClose(self, form):
        pass

    def OnClick(self, it, col):
        print(it, col, it.text(col))
        if col == 2:
            idc.Jump(int(it.text(col),16))


class BadInputError(Exception):
    pass


class SelectDTBFile(idaapi.Form):
    def __init__(self):
        idaapi.Form.__init__(self, """STARTITEM 0
DTB File
<##DTB File path:{path}>
""",
                             {
                                 'path': idaapi.Form.FileInput(open=True),
                             })
    def OnFormChange(self, fid):
        return 1


def prompt_for_dtb():
    ''' :returns: DTB file path, or raises BadInputError '''
    f = SelectDTBFile()
    f.Compile()
    f.path.value = ""
    ok = f.Execute()
    if ok != 1:
        raise BadInputError('user cancelled')
    path = f.path.value
    if path == "" or path is None:
        raise BadInputError('bad path provided')

    if not os.path.exists(path):
        raise BadInputError('file doesn\'t exist')

    f.Free()
    return path


def add_segment(addr, seglen, name,seg_type='Peripheral', perms=(4 | 2)):  # READ | WRITE
    print("[+] creating seg: 0x%08X: %d" % (addr, 4))
    if not idc.AddSeg(addr, addr + seglen, 0, 1, 0, idaapi.scPub):
        logger.error('[!] failed to add segment: 0x%x', addr)
        return -1
    if not idc.RenameSeg(addr, name):
        logger.warning('[!] failed to rename segment: %s' % (seg_type, name))

    if not idc.SetSegClass(addr, seg_type):
        logger.warning('[!] failed to set segment class %s : %s', name)

    if not idc.SegAlign(addr, idc.saRelPara):
        logger.warning('[!] failed to align segment: %s', name)
    if not idc.SetSegmentAttr(addr, idc.SEGATTR_PERM, perms ):
        logger.warning('[!] failed to set permitions for segment class: %s', name)
    return 1


def main(argv=None):
    DTBLoaderPlugin.header()

    if argv is None:
        argv = sys.argv[:]
    try:
        dtb_path = prompt_for_dtb()
    except BadInputError:
        logger.error('[!] bad input, exiting...')
        return -1

    print("[+] Loading DTB file...")
    print("[+] Geting peripherals...")

    peripherals = dtb_parser(dtb_path)

    print("[+] Creating segments...")
    for p in peripherals:
        addr = p.get("addr")
        size = p.get("size")
        name = p.get("name").encode('utf-8')
        print(type(name), addr, size)
        add_segment(addr, size, name)

        print("[+] Creating %s:\t0x%08x" % (name, addr))

        peripheral_name = "struct_"+name

        # Generate structure for the peripheral
        p_sid = GetStrucIdByName(peripheral_name)
        if p_sid != -1:
            DelStruc(p_sid)

        p_sid = AddStrucEx(-1, peripheral_name, 0)

        peripheral_end = addr + size

        MakeStructEx(addr, GetStrucSize(p_sid), peripheral_name)
        MakeNameEx(addr,name, SN_AUTO | SN_NOCHECK)

    try:
        # created already?
        print "Already created, will close it..."
        nvw.Close()
        del nvw
    except:
        pass
    nvw = NameSpaceForm(peripherals)
    nvw.Show()


class DTBLoaderPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Add a segment to an IDA .dtb from a file."
    help = "Add a segment to an IDA .dtb from a file."
    wanted_name = "DTBLoader"
    wanted_hotkey = "Alt-F9"

    @staticmethod
    def header():
        """
            help!
        """
        print("-*" * 40)
        print("")
        print("         DTB Loader ")
        print("             (c) Mathieu Renard <dark@gotohack.org>")
        print("")
        print("-" * 80)
        print("\t License: GPLv3")
        print("Help:")
        print("see   https://www.github.com/gotohack/DTBLoader/docs/")
        print("-*" * 40)
        return

    def init(self):
        self.icon_id = 0
        return idaapi.PLUGIN_OK

    def run(self, arg):
        main()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return DTBLoaderPlugin()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
