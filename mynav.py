# coding=utf8
#!/usr/bin/python

"""
MyNav, a tool 'similar' to BinNavi
Copyright (C) 2010 Joxean Koret

Itsaslapurraren izenean, beti gogoan izango zaitugu.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
"""

import imp
import sys
import time
import random
import idaapi

# debugger event codes
NOTASK         = -2         # process does not exist
DBG_ERROR      = -1         # error (e.g. network problems)
DBG_TIMEOUT    = 0          # timeout
PROCESS_START  = 0x00000001 # New process started
PROCESS_EXIT   = 0x00000002 # Process stopped
THREAD_START   = 0x00000004 # New thread started
THREAD_EXIT    = 0x00000008 # Thread stopped
BREAKPOINT     = 0x00000010 # Breakpoint reached
STEP           = 0x00000020 # One instruction executed
EXCEPTION      = 0x00000040 # Exception
LIBRARY_LOAD   = 0x00000080 # New library loaded
LIBRARY_UNLOAD = 0x00000100 # Library unloaded
INFORMATION    = 0x00000200 # User-defined information
SYSCALL        = 0x00000400 # Syscall (not used yet)
WINMESSAGE     = 0x00000800 # Window message (not used yet)
PROCESS_ATTACH = 0x00001000 # Attached to running process
PROCESS_DETACH = 0x00002000 # Detached from process
PROCESS_SUSPEND = 0x00004000 # Process has been suspended

try:
    import sqlite3
    hasSqlite = True
except ImportError:
    hasSqlite = False
    print ("Warning! Your python version lacks SQLite support!")

from idc import (get_bpt_qty, get_bpt_ea, get_reg_value, find_text, next_addr, generate_disasm_line, print_insn_mnem, set_bpt_attr, get_event_ea, get_segm_start, get_segm_end, create_insn, get_event_exc_code,
                 get_func_name, add_func, get_item_size, get_bpt_attr, exit_process, get_func_attr, get_screen_ea, add_bpt, get_strlit_contents, set_color, plan_and_wait)
from idaapi import (get_func, info, get_dbg_byte, get_idp_name,
                    DBG_Hooks, run_requests, request_run_to, find_not_func,
                    get_func, msg)

from ida_kernwin import (Choose, ask_file, ask_long, ask_yn, ask_str, jumpto)

from ida_auto import (show_auto)

from ida_dbg import (del_bpt, enable_bpt, start_process, wait_for_next_event, get_process_state, dbg_can_query)

from ida_nalt import (get_input_file_path)

from ida_ida import (inf_get_min_ea, inf_get_max_ea)

try:
    #from idaapi import GraphViewer
    from ida_graph import GraphViewer
    #GraphViewer = False
    import mybrowser
    mybrowser.PLUGIN_ENTRY
    hasGraphViewer = True
except ImportError:
    hasGraphViewer = False

import myexport

APPLICATION_NAME = "MyNav"
VERSION = 0x01020200

COLORS = [0xfff000, 0x95AFCD, 0x4FFF4F, 0xc0ffff,
          0xffffc0, 0xc0cfff, 0xc0ffcf, 0x95AFFD]

imp.reload(sys)
#sys.setdefaultencoding('utf8')


def mynav_print(amsg):
    msg("[%s] %s\n" % (APPLICATION_NAME, amsg))


class FunctionsGraph(GraphViewer):
    def __init__(self, title, session):
        GraphViewer.__init__(self, title)
        self.result = session
        self.nodes = {}

    def OnRefresh(self):
        try:
            self.Clear()
            dones = []

            for hit in self.result:
                if not hit in dones:
                    ea = int(hit[0])
                    name = get_func_name(ea)
                    self.nodes[ea] = self.AddNode((ea, name))

            for n1 in self.nodes:
                l1 = map(get_func_name, list(CodeRefsTo(n1, 1)))
                l2 = map(get_func_name, list(DataRefsTo(n1)))

                for n2 in self.nodes:
                    if n1 != n2:
                        name = get_func_name(n2)
                        if name in l1 or name in l2:
                            self.AddEdge(self.nodes[n2], self.nodes[n1])

            return True
        except:
            print ("***Error", sys.exc_info()[1])

    def OnGetText(self, node_id):
        ea, label = self[node_id]
        return label

    def OnDblClick(self, node_id):
        ea, label = self[node_id]
        jumpto(ea)

        return True


class MyChoose(Choose):

    def __init__(self, title, items):
        Choose.__init__(
            self,
            title=title,
            cols=[["", Choose.CHCOL_PLAIN | 50]],
            flags=Choose.CH_MULTI)
        # self.items是必要的,表示显示的每行的内容
        self.items = items

    def OnGetSize(self):
        # OnGetSize函数返回的值相当于表示对话框的列长
        return len(self.items)

    def OnGetLine(self, n):
        # OnGetLine函数用来显示对话框中的内容,必需有这个函数
        return [self.items[n]]

    def OnSelectLine(self, n):
        # OnSelectLine函数用来获得用户选择的内容,Show(True)时:
        # 1.只有双击具体的item时才会运行这个函数,
        # 2.选择item后单击ok按钮不会运行这个函数
        self.deflt = n  # save current selection
        #print "OnSelectLine self.deflt is:"
        #print self.deflt
        return (Choose.NOTHING_CHANGED, )

    def OnSelectionChange(self,n):
        # OnSelectionChange函数可用来在用户选择item后运行,可用于弥补上面的OnSelectLine函数的第2个缺陷
        self.deflt = n
        #print "OnSelectionChange self.deflt is:"
        #print self.deflt

        


    def show(self):
        # Show(True)表示单独弹出对话框窗口,Show()表示显示为内联(像functions那种)窗口
        self.Show(True)
        #print self.deflt
        #pdb.set_trace()
        chioce_index=self.deflt[0]
        return chioce_index


class Mn_Menu_Context(idaapi.action_handler_t):

    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()
        return idaapi.register_action(idaapi.action_desc_t(
            self.get_name(),  # Name. Acts as an ID. Must be unique.
            instance.get_label(),  # Label. That's what users see.
            instance  # Handler. Called when activated, and for updating
        ))

    @classmethod
    def unregister(self):
        """Unregister the action.
        After unregistering the class cannot be used.
        """
        idaapi.unregister_action(self.get_name())

    @classmethod
    def activate(self, ctx):
        # dummy method
        return 1

    @classmethod
    def update(self, ctx):
        try:
            if ctx.widget_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_FORM
            else:
                return idaapi.AST_DISABLE_FOR_FORM
        except:
            # Add exception for main menu on >= IDA 7.0
            return idaapi.AST_ENABLE_ALWAYS


class DeleteALLSessions(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.clearSessions()
        return 1


class DeleteASession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.deleteSession()
        return 1


class AdvancedDeselectionOptions(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.deselectAdvanced()
        return 1


class AdvancedSelectionOptions(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.selectAdvanced()
        return 1


class DeselectHitsFromSession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.loadBreakpointsFromSessionInverse()
        return 1


class SelectHitsFromSession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.loadBreakpointsFromSession()
        return 1


class ClearAllBreakpoints(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.clearBreakpoints()
        return 1


class SetAllBreakpoints(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.setBreakpoints()
        return 1


class AddRemoveTargetPoint(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.addRemoveTargetPoint()
        return 1


class AddRemoveEntryPoint(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.addRemoveEntryPoint()
        return 1


class ClearTraceSession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.clearTraceSession()
        return 1


class SessionsFunctionsList(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.showSessionsFunctions()
        return 1


class ShowSessionsManager(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.showSessionsManager()
        return 1


class ShowAdvancedOptions(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.showAdvanced()
        return 1


class ShowTraceSession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.showTraceSession()
        return 1


class ShowSession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.showSessionsGraph()
        return 1


class ShowBrowser(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.showBrowser()
        return 1


class ConfigureCPURecording(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.configureSaveCPU()
        return 1


class Configuretimeout(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.configureTimeout()
        return 1


class NewAdvancedSession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.newAdvancedSession()
        return 1


class TraceThisFunction(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.traceInFunction()
        return 1


class TraceInSession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.traceInSession()
        return 1


class NewSession(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.newSession()
        return 1


class OpenGraph(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.openSavedGraph()
        return 1


class RunAPythonScript(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.runScript()
        return 1


class AdvancedUtilities(Mn_Menu_Context):
    def activate(self, ctx):
        self.plugin.searchAdvanced()
        return 1


class CMyNav():
    def __init__(self):
        # Initialize basic properties
        self.db = None
        self.filename = None
        self.debugMode = False
        self.sessions = {}
        self.records = {}
        self.timeout = 0
        self.step_mode = False
        self.step_functions = []
        random.seed(time.time())
        self.current_color = random.choice(COLORS)
        self.current_name = None
        self.default_name = "Session1"
        self.current_session = []
        self.current_session_cpu = []
        self.save_cpu = False
        self.endpoints = []
        self.temporary_breakpoints = []

        self.dbg_path = ""
        self.dbg_arguments = ""
        self.dbg_directory = ""
        self.on_exception = None

        if hasSqlite:
            self._loadDatabase()

    def __del__(self):
        if self.db is not None:
            self.db.close()

    def _createSchema(self):
        """ Try to create the schema or silently exit if some error ocurred. """
        try:
            sql = """CREATE TABLE NODES (
                            NODE_ID INTEGER PRIMARY KEY,
                            FUNC_ADDR VARCHAR(50),
                            STATUS INTEGER)"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass

        try:
            sql = """CREATE TABLE GRAPHS (
                            GRAPH_ID INTEGER PRIMARY KEY,
                            NAME VARCHAR(50),
                            SHOW_STRINGS INTEGER,
                            SHOW_APIS INTEGER,
                            RECURSION_LEVEL INTEGER,
                            FATHER VARCHAR(50))"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass

        try:
            sql = """CREATE TABLE GRAPH_NODES (
                            GRAPH_NODES_ID INTEGER PRIMARY KEY,
                            GRAPH_ID INTEGER,
                            NODE_ID INTEGER)"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass

        try:
            sql = """CREATE TABLE POINTS (
                            POINT_ID INTEGER PRIMARY KEY,
                            FUNC_ADDR VARCHAR(50),
                            TYPE VARCHAR(50))"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass

        try:
            sql = """CREATE TABLE SETTINGS (
                            SETTING_ID INTEGER PRIMARY KEY,
                            NAME VARCHAR(50),
                            VALUE VARCHAR(50))"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass

        try:
            sql = """CREATE TABLE RECORDS (
                            RECORD_ID INTEGER PRIMARY KEY,
                            NAME VARCHAR(50),
                            DESCRIPTION VARCHAR(255),
                            TIMESTAMP DATETIME,
                            TYPE VARCHAR(50))"""
            cur = self.db.cursor()
            cur.execute(sql)
        except:
            pass

        try:
            sql = """CREATE TABLE RECORD_DATA (
                            RECORD_DATA_ID INTEGER PRIMARY KEY,
                            RECORD_ID INTEGER,
                            LINE_ID INTEGER,
                            FUNC_ADDR VARCHAR(50),
                            TIMESTAMP DATETIME)"""
            cur.execute(sql)
        except:
            pass

        try:
            sql = """CREATE TABLE CPU_STATE (
                            CPU_STATE_ID INTEGER PRIMARY KEY,
                            RECORD_DATA_ID INTEGER,
                            LINE_ID INTEGER,
                            REG_NAME VARCHAR(50),
                            REG_VALUE VARCHAR(255),
                            MEMORY VARCHAR(255),
                            TEXT VARCHAR(255))"""
            cur.execute(sql)
        except:
            pass

        try:
            sql = """CREATE VIEW SESSIONS_STRINGS
                    AS
                    SELECT rec.name session,
                           data.func_addr address,
                           cpu.text text, 
                           cpu.reg_name register, 
                           cpu.reg_value value,
                           rec.record_id id
                      FROM CPU_STATE cpu,
                           RECORDS rec,
                           RECORD_DATA data
                     WHERE CPU.TEXT IS NOT NULL 
                       AND LENGTH(CPU.TEXT) > 6
                       AND DATA.record_id = REC.record_id
                       AND CPU.record_data_id = DATA.record_data_id """
            cur.execute(sql)
        except:
            pass

        cur.close()
        self.db.commit()

    def _loadDatabase(self):
        """ Connect to the SQLite database and create the schema if needed """

        try:
            self.filename = "%s.sqlite" % get_input_file_path()
            self.db = sqlite3.connect(
                self.filename, check_same_thread=False, isolation_level=None)
        except:
            self.filename = ask_file(
                1, "*.sqlite", "Select an existing or new SQLite database")

            if self.filename is not None:
                self.db = sqlite3.connect(
                    self.filename, check_same_thread=False, isolation_level=None)

        self.db.text_factory = str
        self._createSchema()

    def _debug(self, msg):
        """ Print a message if debugMode is enabled """
        if self.debugMode:
            mynav_print(msg)

    def saveSession(self, name, session, cpu):
        """ Save a session """
        if self.step_mode:
            mtype = 1
        else:
            mtype = 0

        cur = self.db.cursor()
        sql = "insert into records (name, description, timestamp, type) values (?, ?, ?, ?)"
        cur.execute(sql, (name, "", time.time(), mtype))

        i = 0
        id = cur.lastrowid
        total = len(session)

        for event in session:
            pct = i * 100 / total
            temp = "Saved " + str(pct) + "%"

            sql = """insert into record_data (record_id, line_id, func_addr, timestamp)
                                      values (?, ?, ?, ?)"""
            cur.execute(sql, (id, i, event[0], event[1]))
            m_id = cur.lastrowid

            if self.save_cpu:
                j = 0
                for name, val, mem, txt in cpu[i]:
                    sql = """insert into cpu_state (record_data_id, line_id, reg_name, reg_value,
                                                    memory, text)
                                              values (?, ?, ?, ?, ?, ?) """
                    cur.execute(sql, (m_id, j, name, "0x%08x" % val, mem, txt))
                    j += 1
            i += 1

        self.db.commit()

        return id

    def readSetting(self, setting):
        """ Read some configuration setting """
        cur = self.db.cursor()
        sql = "select value from settings where name = ?"
        cur.execute(sql, (setting,))
        val = None
        for row in cur.fetchall():
            val = row[0]
        cur.close()
        return val

    def saveSetting(self, setting, value):
        """ Save a configuration setting """
        old_value = self.readSetting(setting)
        if not old_value:
            sql = """ insert into settings (value, name) values (?, ?)"""
        else:
            sql = """ update settings set value = ? where name = ?"""

        cur = self.db.cursor()
        cur.execute(sql, (value, setting))
        self.db.commit()
        return True

    def addPoint(self, ea, STRTYPE_C):
        """ Add the function ea as point. STRTYPE_C can be either 'E' for entry point or 'T' for target point """
        new_ea = get_func_attr(ea, FUNCATTR_START)
        if not new_ea:
            new_ea = ea

        cur = self.db.cursor()
        sql = """ insert into points (func_addr, type) values (?, ?) """
        cur.execute(sql, (new_ea, STRTYPE_C))
        self.db.commit()
        cur.close()

        return True

    def removePoint(self, ea, STRTYPE_C):
        """ Remove the function ea as point. STRTYPE_C can be either 'E' for entry point or 'T' for target point """
        new_ea = get_func_attr(ea, FUNCATTR_START)
        if not new_ea:
            new_ea = ea
        cur = self.db.cursor()
        sql = """ delete from points where func_addr = ? and type = ? """
        cur.execute(sql, (new_ea, STRTYPE_C))
        self.db.commit()
        cur.close()

        return True

    def removeDataEntryPoint(self, ea):
        """ Remove data entry point ea """
        self.removePoint(ea, "E")

    def removeTargetPoint(self, ea):
        """ Remove target point ea """
        self.removePoint(ea, "T")

    def addDataEntryPoint(self, ea):
        """ Add a data entry point """
        self.addPoint(ea, "E")

    def addTargetPoint(self, ea):
        """ Add a target point """
        self.addPoint(ea, "T")

    def addCurrentAsDataEntryPoint(self):
        """ Add current function as entry point """
        self.addDataEntryPoint(get_screen_ea())

    def addCurrentAsTargetPoint(self):
        """ Add current function as target point """
        self.addTargetPoint(get_screen_ea())

    def removeCurrentDataEntryPoint(self):
        """ Remove current entry point """
        self.removeDataEntryPoint(get_screen_ea())

    def removeCurrentTargetPoint(self):
        """ Remove current target point """
        self.removeTargetPoint(get_screen_ea())

    def getAllPointsList(self):
        """ Return a list with all entry and target points """
        cur = self.db.cursor()
        sql = """ select func_addr from points """
        cur.execute(sql, (STRTYPE_C, ))

        l = []
        for row in cur.fetchall():
            l.append(row[0])
        cur.close()

        return l

    def getPointsList(self, STRTYPE_C):
        """ Return a list with all either entry or target points. STRTYPE_C can be either 'E' or 'T' """
        cur = self.db.cursor()
        sql = """ select func_addr from points where type = ? """
        cur.execute(sql, (STRTYPE_C, ))

        l = []
        for row in cur.fetchall():
            l.append(int(row[0]))
        cur.close()

        return l

    def getDataEntryPointsList(self):
        l = self.getPointsList('E')
        return l

    def getTargetPointsList(self):
        l = self.getPointsList('T')
        return l

    def getPoint(self, STRTYPE_C, p):
        """ Read from database an specific point """
        cur = self.db.cursor()
        sql = """ select 1 from points where type = ? and func_addr = ?"""
        cur.execute(sql, (STRTYPE_C, p))

        l = []
        for row in cur.fetchall():
            l.append(int(row[0]))
        cur.close()

        return l

    def addRemoveTargetPoint(self):
        ea = get_func_attr(get_screen_ea(), FUNCATTR_START)
        if self.getPoint("T", ea):
            self.removeCurrentTargetPoint()
            mynav_print("Target point 0x%08x removed" % ea)
        else:
            self.addCurrentAsTargetPoint()
            mynav_print("Target point 0x%08x added" % ea)

    def addRemoveEntryPoint(self):
        ea = get_func_attr(get_screen_ea(), FUNCATTR_START)
        if self.getPoint("E", ea):
            self.removeCurrentDataEntryPoint()
            mynav_print("Data entry point 0x%08x removed" % ea)
        else:
            self.addCurrentAsDataEntryPoint()
            mynav_print("Data entry point 0x%08x added" % ea)

    def saveCurrentSession(self, name):
        return self.saveSession(name, self.current_session, self.current_session_cpu)

    def showTargetPoints(self):
        tps = self.getTargetPointsList()
        if len(tps) == 0:
            info("No target entry point selected!")
            return False

        g = mybrowser.PathsBrowser("Target points graph", tps, [], [])
        g.Show()

        return True

    def showDataEntryPoints(self):
        eps = self.getDataEntryPointsList()
        if len(eps) == 0:
            info("No entry point selected!")
            return False

        g = mybrowser.PathsBrowser("Entry points graph", eps, [], [])
        g.Show()

        return True

    def showPointsGraph(self):
        """ Show a graph with all entry and target points and the relationships between them """
        eps = self.getDataEntryPointsList()
        if len(eps) == 0:
            info("No entry point selected!")
            return False

        tps = self.getTargetPointsList()
        if len(tps) == 0:
            info("No target point selected!")
            return False

        l = eps
        l.extend(tps)

        g = mybrowser.PathsBrowser("Entry and target points graph", l, [], [])
        g.Show()

        return True

    def getCodePathsBetweenPoints(self):
        eps = self.getDataEntryPointsList()
        if len(eps) == 0:
            mynav_print("No entry point selected!")
            return None

        tps = self.getTargetPointsList()
        if len(tps) == 0:
            mynav_print("No target point selected!")
            return None

        mynav_print(
            "Searching code paths between all the points, it will take a while...")
        l = []
        for p1 in eps:
            for p2 in tps:
                tmp = mybrowser.SearchCodePath(p1, p2)
                l.extend(tmp)

        if len(l) == 0:
            info("No data to show :(")
            return None

        return l, eps, tps

    def showCodePathsBetweenPoints(self):
        ret = self.getCodePathsBetweenPoints()
        if ret:
            l, eps, tps = ret
            if l:
                g = mybrowser.PathsBrowser("Code paths graph", l, eps, tps)
                g.Show()

    def selectCodePathsBetweenPoints(self):
        l = self.getCodePathsBetweenPoints()
        if l:
            for p in l:
                for x in p:
                    self.addBreakpoint(x)

    def deselectCodePathsBetweenPoints(self):
        l = self.getCodePathsBetweenPoints()
        if l:
            for p in l:
                for x in p:
                    del_bpt(p)

    def selectDataEntryPoints(self):
        eps = self.getDataEntryPointsList()
        for p in eps:
            self.addBreakpoint(p)

    def deselectDataEntryPoints(self):
        eps = self.getDataEntryPointsList()
        for p in eps:
            del_bpt(p)

    def tracePoints(self):
        self.preserveBreakpoints()
        self.selectCodePathsBetweenPoints()
        self.newSession()
        self.restoreBreakpoints()

    def selectTargetPoints(self):
        tps = self.getTargetPointsList()
        for p in tps:
            self.addBreakpoint(p)

    def deselectTargetPoints(self):
        tps = self.getTargetPointsList()
        for p in tps:
            del_bpt(p)

    def getSessionsList(self, mtype=0, all=False):
        if not all:
            sql = "select * from records where type=?"
        else:
            sql = "select * from records"

        cur = self.db.cursor()

        if not all:
            cur.execute(sql, (mtype, ))
        else:
            cur.execute(sql)

        l = []
        for row in cur.fetchall():
            s = "%s: %s %s %s" % (
                row[0], row[1], row[2], time.asctime(time.gmtime(row[3])))
            l.append(s)
        cur.close()

        return l

    def showSessions(self, mtype=0, all=False, only_first=True):
        """ Show the session's list """

        items = self.getSessionsList(mtype)
        chooser = MyChoose(title="Active Sessions", items=items)
        c = chooser.show()
        #pdb.set_trace()
        c=c+1

        if c > 0:
            if only_first:
                c = items[c - 1].split(":")[0]
            else:
                c = [c]
        else:
            c = None

        return c

    def showSessionsGraph(self):
        id = self.showSessions()
        if id is not None:
            self.showGraph(id)

    def showSessionsFunctions(self):
        id = self.showSessions()
        if id is not None:
            if self.loadSession(id):
                results = []
                for hit in self.current_session:
                    ea = int(hit[0])
                    tmp_item = {}
                    tmp_item["func_name"] = get_func_name(ea)
                    tmp_item["xref"] = ea

                    if tmp_item not in results:
                        results.append(tmp_item)

                if results:
                    ch2 = mybrowser.UnsafeFunctionsChoose2(
                        "%s (Functions List)" % self.current_name, self)
                    for item in results:
                        ch2.add_item(
                            mybrowser.UnsafeFunctionsChoose2.Item(item))
                    r = ch2.show()

    def loadSession(self, id):
        cur = self.db.cursor()
        sql = "select name from records where record_id = ?"
        cur.execute(sql, (int(id), ))
        self.current_name = cur.fetchone()[0]
        self.default_name = "Trace: " + str(self.current_name)

        sql = "select func_addr, timestamp from record_data where record_id = ?"
        cur.execute(sql, (int(id), ))

        self.current_session = []
        for row in cur.fetchall():
            self.current_session.append([row[0], row[1]])

        return len(self.current_session) > 0

    def showGraph(self, id=None, name=None):
        """ Show a graph for one specific recorded session """
        if not hasGraphViewer:
            print ("No GraphViewer support :(")
            return

        if id is not None:
            if not self.loadSession(id):
                mynav_print("No records found for session %s" % id)
                return

        g = FunctionsGraph("%s - Session %s - %s" % (APPLICATION_NAME,
                                                     self.current_name, time.ctime()), self.current_session)
        g.Show()

    def addBreakpoint(self, f):
        val = self.readSetting("save_cpu")
        if val is None:
            val = 0

        if int(val) == 1:
            save_cpu = True
        else:
            save_cpu = False

        del_bpt(int(f))
        add_bpt(int(f))

        if not save_cpu:
            set_bpt_attr(f, BPTATTR_FLAGS, BPT_TRACE)

        enable_bpt(int(f), 1)

    def setBreakpoints(self, trace=True):
        """ Set a breakpoint in every function """
        mynav_print("Setting breakpoints. Please, wait...")
        val = self.readSetting("save_cpu")
        if val is None:
            val = True
        else:
            if int(val) == 0:
                val = True
            else:
                val = False

        for f in list(Functions()):
            self.addBreakpoint(f)

        mynav_print("Done")

    def clearBreakpoints(self):
        """ Clear all breakpoints """
        mynav_print("Removing breakpoints. Please, wait...")
        i = 0
        while 1:
            ea = get_bpt_ea(i)
            if ea == BADADDR:
                break
            del_bpt(ea)
        mynav_print("Done")

    def getRegisters(self):
        l = []

        try:
            for x in idaapi.dbg_get_registers():
                name = x[0]
                try:
                    addr = get_reg_value(name)
                except:
                    break

                bytes = None
                """try:
                    if get_dbg_byte(addr) != 0xFF:
                        for i in range(16):
                            bytes += "%02x " % get_byte(addr+i)
                        bytes = bytes.strip(" ")
                except:
                    bytes = None"""

                try:
                    strdata = get_strlit_contents(int(addr), -1, STRTYPE_C)
                except:
                    try:
                        strdata = "Unicode: " + \
                            get_strlit_contents(int(addr), -1, STRTYPE_C_16)
                    except:
                        strdata = None

                l.append([name, addr, bytes, strdata])
        except:
            print ("getRegisters()", sys.exc_info()[1])

        return l

    def recordBreakpoint(self):
        try:

            pc = self.getPC()
            t2 = time.time()
            self.current_session.append([pc, t2])
            if self.save_cpu:
                self.current_session_cpu.append(self.getRegisters())

            self._debug("Hit %s:%08x" % (get_func_name(pc), pc))
            if self.step_mode:
                set_color(pc, 1, self.current_color)

            """if not all:
                del_bpt(pc)"""
            del_bpt(pc)
            """
            if self.endRecording(pc):
                mynav_print("Session's endpoint reached")
            """
        except:
            print ("recordBreakpoint:", sys.exc_info()[1])

    def stop(self):
        exit_process()

    def startRecording(self, all=False):
        """ Start recording breakpoint hits """
        if not dbg_can_query():
            info("Select a debugger first!")
            return False

        start_process(self.dbg_path, self.dbg_arguments, self.dbg_directory)

        t = time.time()
        if self.timeout != 0:
            mtimeout = min(self.timeout, 10)
        else:
            mtimeout = 10
        last = -1

        while 1:
            # WFNE_CONT|WFNE_SUSP
            code = wait_for_next_event(WFNE_ANY | WFNE_CONT | WFNE_SUSP, mtimeout)


            if code == BREAKPOINT or code == STEP and last != BREAKPOINT:
                pc = get_event_ea()
                t2 = time.time()
                self.current_session.append([pc, t2])
                if self.save_cpu:
                    self.current_session_cpu.append(self.getRegisters())
                self._debug("Hit %s:%08x" % (get_func_name(pc), pc))
                if self.step_mode:
                    set_color(pc, 1, self.current_color)

                if not all:
                    del_bpt(pc)
                if self.endRecording(pc):
                    mynav_print("Session's endpoint reached")
                    break
            elif code == INFORMATION:
                # print "INFORMATION"
                pass
            elif get_process_state() != DSTATE_RUN:
                if get_event_exc_code() != 0 and self.on_exception is not None:
                    self.on_exception(get_event_ea(), get_event_exc_code())
                break
            elif code in [EXCEPTION, 0x40]:
                # print "**EXCEPTION", hex(get_event_ea()),
                # hex(get_event_exc_code())
                if self.on_exception is not None:
                    self.on_exception(get_event_ea(), get_event_exc_code())
            elif code not in [DBG_TIMEOUT, PROCESS_START, PROCESS_EXIT, THREAD_START,
                              THREAD_EXIT, LIBRARY_LOAD, LIBRARY_UNLOAD, PROCESS_ATTACH,
                              PROCESS_DETACH, STEP]:
                print ("DEBUGGER: Code 0x%08x" % code)

            last = code
            if time.time() - t > self.timeout and self.timeout != 0:
                mynav_print("Timeout, exiting...")
                break

    def endRecording(self, ea):
        """ End recording breakpoint hits """
        return ea in self.endpoints

    def intersectHits(self, rec1, rec2):
        """ Return the intersection of 2 recorded sessions """
        pass

    def showIntersectionGraph(self, inter):
        """ Show a graph with the given intersection """
        pass

    def showUniqueInGraph(self, rec1, rec2):
        """ Show a graph with the nodes uniques in rec1 and not in rec2 """
        pass

    def getPC(self):
        try:
            pc = get_event_ea()
            return pc
        except:
            print ("getPc", sys.exc_info()[1])

    def start(self, do_show=True, session_name=None):
        if session_name is None:
            name = ask_str(self.default_name, 0, "Enter new session name")
        else:
            name = session_name

        if name:
            if get_bpt_ea(0) == BADADDR:
                res = ask_yn(
                    1, "There is no breakpoint set. Do you want to set breakpoints in all functions?")
                if res == 1:
                    self.setBreakpoints()
                elif res == -1:
                    return

            val = self.readSetting("timeout")
            if val is not None:
                self.timeout = int(val)

            val = self.readSetting("save_cpu")
            if val is None:
                self.save_cpu = False
            elif int(val) == 1:
                self.save_cpu = True
            else:
                self.save_cpu = False

            self.current_name = name
            self.current_session = []
            self.current_session_cpu = []
            try:
                mynav_print("Starting debugger ...")
                self.startRecording()
            except :
                print (sys.exc_info()[1])
                mynav_print("Cancelled by user")

            mynav_print("Saving current session ...")
            id = None
            if len(self.current_session) > 0:
                id = self.saveCurrentSession(name)
                if not self.step_mode and do_show:
                    if len(self.current_session) > 100:
                        if ask_yn(1, "There are %d node(s), it will take a long while to show the graph. Do you want to show it?" % len(self.current_session)) == 1:
                            self.showGraph()
                    else:
                        self.showGraph()

                self.current_session = []
                self.current_session_cpu = []
            else:
                mynav_print("No data to save")

            mynav_print("OK, all done")
            return id

    def newSession(self):
        self.step_mode = False
        self.start()

    def clearSessions(self):
        if ask_yn(0, "Are you sure to delete *ALL* saved sessions?") == 1:
            cur = self.db.cursor()
            cur.execute("delete from records")
            cur.execute("delete from record_data")
            cur.execute("delete from cpu_state")
            self.db.commit()
            cur.close()
            mynav_print("Done")

    def deleteSession(self):
        l = self.showSessions(all=True, only_first=False)

        if l is not None:
            for id in l:
                cur = self.db.cursor()
                cur.execute(
                    "delete from records where record_id = ?", (str(id),))
                cur.execute(
                    "delete from record_data where record_id = ?", (str(id),))
                cur.execute(
                    "delete from cpu_state where record_data_id = ?", (str(id),))
                self.db.commit()
                cur.close()
                mynav_print("Deleted session %s" % str(id))

    def loadBreakpointsFromSession(self):
        l = self.showSessions(only_first=False)
        if l is not None:
            for c in l:
                self.loadSession(c)
                self.clearBreakpoints()
                for addr in self.current_session:
                    self.addBreakpoint(int(addr[0]))
                mynav_print("Done loading " + str(c))

    def loadBreakpointsFromSessionInverse(self):
        l = self.showSessions(only_first=False)
        if l is not None:
            for c in l:
                self.loadSession(c)
                # self.setBreakpoints()
                for addr in self.current_session:
                    del_bpt(int(addr[0]))
                mynav_print("Done unloading " + str(c))

    def preserveBreakpoints(self):
        self.temporary_breakpoints = []
        i = 0
        while 1:
            ea = get_bpt_ea(i)
            if ea == BADADDR:
                break
            self.temporary_breakpoints.append(ea)
            i += 1

    def restoreBreakpoints(self):
        for bpt in self.temporary_breakpoints:
            self.addBreakpoint(bpt)
        self.temporary_breakpoints = []

    def traceInSession(self):
        c = self.showSessions(mtype=0)
        if c is not None:
            if not self.loadSession(c):
                return

            self.preserveBreakpoints()

            self.step_mode = True
            self.current_color = random.choice(COLORS)
            self.step_functions = []
            for addr in self.current_session:
                for ea in FuncItems(int(addr[0])):
                    self.addBreakpoint(ea)

            self.start()

            self.clearBreakpoints()
            self.restoreBreakpoints()

    def clearTraceSession(self):
        l = self.showSessions(mtype=1, only_first=False)
        if l is not None:
            for c in l:
                self.loadSession(c)
                for addr in self.current_session:
                    set_color(int(addr[0]), 1, 0xFFFFFFFF)

    def showTraceSession(self):
        c = self.showSessions(mtype=1)
        if c is not None:
            self.loadSession(c)
            self.current_color = random.choice(COLORS)
            for addr in self.current_session:
                set_color(int(addr[0]), 1, self.current_color)

    def showSimplifiedTraceSession(self):
        pass

    def setBreakpointsInFunction(self, func):
        pass

    def traceInFunction(self):
        self.step_mode = True
        self.current_color = random.choice(COLORS)
        ea = get_screen_ea()
        self.step_functions = [ea]
        self.preserveBreakpoints()
        self.clearBreakpoints()
        for x in FuncItems(ea):
            self.addBreakpoint(x)

        self.start()
        self.clearBreakpoints()
        self.restoreBreakpoints()

    def doNothing(self):
        pass

    def getGraphList(self):
        cur = self.db.cursor()
        sql = """select graph_id || ':' || name from graphs"""
        cur.execute(sql)

        l = []
        for row in cur.fetchall():
            l.append(row[0])
        cur.close()

        return l

    def showSavedGraphs(self):
        items = self.getGraphList()
        chooser = MyChoose(title="Active Sessions", items=items)
        c = chooser.show()
        c=c+1

        if c > 0:
            c = items[c - 1].split(":")[0]
        else:
            c = None

        return c

    def showBrowser(self):
        mybrowser.ShowFunctionsBrowser(mynav=self)

    def loadSavedGraphNodes(self, graph_id):
        cur = self.db.cursor()
        sql = """ select func_addr, status
                    from graph_nodes gn,
                         graphs g,
                         nodes n
                   where gn.graph_nodes_id = g.graph_id
                     and gn.node_id = n.node_id
                     and g.graph_id = ?"""
        cur.execute(sql, (graph_id, ))
        n = []
        h = []
        for row in cur.fetchall():
            if int(row[1]) == 1:
                n.append(int(row[0]))
            else:
                h.append(int(row[0]))
        cur.close()

        return n, h

    def saveGraph(self, father, max_level, show_runtime_functions, show_string, hidden, result):
        pass

    def loadSavedGraphData(self, graph_id):
        cur = self.db.cursor()
        sql = """ select name, father, recursion_level, show_strings, show_apis
                    from graphs
                   where graph_id = ? """
        cur.execute(sql, (graph_id,))
        ea = level = strings = runtime = None
        for row in cur.fetchall():
            name = row[0]
            ea = int(row[1])
            level = int(row[2])
            strings = int(row[3]) == 1
            runtime = int(row[4]) == 1
        cur.close()

        return name, ea, level, strings, runtime

    def loadSavedGraph(self, graph_id):
        nodes, hidden = self.loadSavedGraphNodes(graph_id)
        name, ea, level, strings, runtime = self.loadSavedGraphData(graph_id)
        mybrowser.ShowGraph(name, ea, nodes, hidden,
                            level, strings, runtime, self)

    def openSavedGraph(self):
        g = self.showSavedGraphs()
        if g:
            self.loadSavedGraph(g)

    def showBrowser2(self):
        mybrowser.ShowFunctionsBrowser(show_runtime=True, mynav=self)

    def traceFromThisFunction(self):
        self.preserveBreakpoints()
        self.selectFunctionChilds()
        self.newSession()
        self.restoreBreakpoints()

    def deselectFunctionChilds(self):
        self.selectFunctionChilds(False)

    def selectFunctionChilds(self, badd=True):
        self.done_functions = []
        self.addChildsBpt(get_screen_ea(), badd)
        if badd:
            mynav_print("Added a total of %d breakpoints" %
                        len(self.done_functions))
        self.done_functions = []

    def addChildsBpt(self, ea, badd=True):
        if not ea in self.done_functions:
            if badd:
                mynav_print("Adding breakpoint at 0x%08x:%s" %
                            (ea, get_func_name(ea)))
            self.done_functions.append(ea)
            if badd:
                self.addBreakpoint(ea)
            else:
                del_bpt(ea)

        refs = mybrowser.GetCodeRefsFrom(ea)
        for ref in refs:
            if ref in self.done_functions:
                continue
            self.done_functions.append(ref)
            if badd:
                mynav_print("Adding breakpoint at 0x%08x:%s" %
                            (ref, get_func_name(ref)))
                self.addBreakpoint(ref)
            else:
                del_bpt(ref)

            self.addChildsBpt(ref, badd)

    def selectCodePaths(self):
        nodes = mybrowser.SearchCodePathDialog(ret_only=True)
        if nodes is not None:
            if len(nodes) > 0:
                for node in nodes:
                    mynav_print("Adding breakpoint at 0x%08x:%s" %
                                (node, get_func_name(node)))
                    self.addBreakpoint(node)
                return True
        return False

    def traceCodePaths(self):
        self.preserveBreakpoints()
        if self.selectCodePaths():
            self.newSession()
        self.restoreBreakpoints()

    def deselectCodePaths(self):
        nodes = mybrowser.mybrowser.SearchCodePathDialog(ret_only=True)
        if len(nodes) > 0:
            for node in nodes:
                del_bpt(node)

    def selectExtendedCodePaths(self):
        nodes = mybrowser.mybrowser.SearchCodePathDialog(
            ret_only=True, extended=True)
        if len(nodes) > 0:
            for node in nodes:
                mynav_print("Adding breakpoint at 0x%08x:%s" %
                            (node, get_func_name(node)))
                self.addBreakpoint(node)

    def deselectExtendedCodePaths(self):
        nodes = mybrowser.mybrowser.SearchCodePathDialog(
            ret_only=True, extended=True)
        if len(nodes) > 0:
            for node in nodes:
                del_bpt(node)

    def configureTimeout(self):
        val = self.readSetting("timeout")
        if val is None:
            val = 0

        val = ask_long(int(val), "Timeout for the session")
        if val is not None:
            self.saveSetting("timeout", val)

    def propagateBreakpointChanges(self):
        count = get_bpt_qty()
        for i in range(0, count):
            f = get_bpt_ea(i)
            del_bpt(f)
            self.addBreakpoint(f)
        mynav_print("Changes applied")

    def configureSaveCPU(self):
        changed = False
        val = self.readSetting("save_cpu")
        if val is None:
            val = 0
        else:
            val = int(val)

        if val == 1:
            val = ask_yn(1, "Do you want to *DISABLE* CPU recording?")
            if val == 1:
                self.saveSetting("save_cpu", 0)
                changed = True
        else:
            val = ask_yn(1, "Do you want to *ENABLE* CPU recording?")
            if val == 1:
                self.saveSetting("save_cpu", 1)
                changed = True

        if changed:
            if ask_yn(1, "Do you want to apply changes to the currently set breakpoints?"):
                self.propagateBreakpointChanges()

    def showSegmentsGraph(self):
        ea = get_screen_ea()
        l = list(Functions(get_segm_start(ea), get_segm_end(ea)))

        if len(l) > 0:
            g = mybrowser.PathsBrowser(
                "Current segment's function's graph", l, [], [])
            g.Show()
        else:
            info("No function in this segment!")

    def showBreakpointsGraph(self):
        l = []
        count = get_bpt_qty()
        for i in range(0, count):
            l.append(get_bpt_ea(i))

        if len(l) > 0:
            g = mybrowser.PathsBrowser("Breakpoints graph", l, [], [])
            g.Show()
        else:
            info("No breakpoint set!")

    def doDiscoverFunctions(self):
        ea = get_screen_ea()
        old_ea = ea
        start_ea = get_segm_start(ea)
        # print "Start at 0x%08x" % start_ea
        end_ea = get_segm_end(ea)
        # print "End at 0x%08x" % end_ea
        #ea2 = inf_get_max_ea()
        t = time.time()
        val = 1000

        asked = False
        while ea != BADADDR and ea < end_ea:
            tmp = ea
            val = min(1000, end_ea - ea)
            #ea = find_not_func(tmp, 0)
            # if ea == BADADDR:
            ea = find_text(tmp, SEARCH_REGEX | SEARCH_DOWN, val, 0,
                          "# End of| endp|align |END OF FUNCTION")
            show_auto(ea)
            if time.time() - t > 60 and not asked:
                val = ask_yn(
                    1, "The process is taking too long. Do you want to continue?")
                asked = True
                if val is None:
                    return False
                elif val != 1:
                    return False
                else:
                    t = time.time()

            if ea != BADADDR and ea < end_ea:
                show_auto(ea)
                ea += get_item_size(ea)

                if ea != BADADDR and ea < end_ea:
                    txt = generate_disasm_line(ea)

                    if txt.startswith("align ") or txt.startswith("db ") or txt.endswith(" endp") \
                       or txt.find("END OF FUNCTION") > -1:
                        ea = ea + get_item_size(ea)

                    if ea < end_ea:
                        if get_func_name(ea) == "":
                            mynav_print("Creating function at 0x%08x" % ea)
                            create_insn(ea)
                            add_func(ea, BADADDR)
            else:
                break
        return True

    def realDoDiscoverFunctions(self):
        ea = get_screen_ea()
        start_ea = get_segm_start(ea)
        end_ea = get_segm_end(ea)
        total = len(list(Functions(start_ea, end_ea)))
        times = 0
        while times <= 5:
            times += 1
            mynav_print("Doing pass %d" % times)
            if not self.doDiscoverFunctions():
                break

            tmp = len(list(Functions(start_ea, end_ea)))
            mynav_print("Total of %d function(s) in database" % tmp)
            total = tmp - total
            if total > 0:
                mynav_print("  Total of %d new function(s)" % total)
                total = tmp
            else:
                break

        mynav_print("Done")

    def getSessionsForString(self, txt, id=None):
        sql = "select * from sessions_strings where text like '%' || ? || '%'"
        if id is not None and False:
            sql += " and id = ?"
        cur = self.db.cursor()

        if id is None or True:
            cur.execute(sql, (txt,))
        else:
            cur.execute(sql, (txt, id))

        l = []
        for row in cur.fetchall():
            l.append([row[0], row[1], row[2]])
        cur.close()
        return l

    def searchStringInSessions(self, id=None):
        txt = ask_str("String to search", 0, "")
        if txt is not None:
            #id = self.showSessions()
            id = None
            l = self.getSessionsForString(txt, id)
            if len(l) > 0:
                mybrowser.ShowStringsGraph(l)

    def newAdvancedSession(self):
        items = ["Trace code paths between 2 functions",
                        "Trace code paths between points"]
        chooser = MyChoose(title="Advanced Session", items=items)
        c = chooser.show()
        c=c+1

        if c > 0:
            if c == 1:
                self.traceCodePaths()
            elif c == 2:
                self.tracePoints()
        else:
            c = None

        return c

    def showAdvanced(self):
        items = ["Show entry points", "Show target points", "Show code paths between points",
                 "Show code paths between 2 functions", "Show all function in this segment",
                 "Show all breakpoints graph"]
        chooser = MyChoose(title="Show Advanced Graphs", items=items)
        c = chooser.show()
        # c为选择的序号,从0开始
        c=c+1
        if c > 0:
            if c == 1:
                self.showDataEntryPoints()
            elif c == 2:
                self.showTargetPoints()
            elif c == 3:
                self.showCodePathsBetweenPoints()
            elif c == 4:
                mybrowser.SearchCodePathDialog()
            elif c == 5:
                self.showSegmentsGraph()
            elif c == 6:
                self.showBreakpointsGraph()
        else:
            c = None

        return c

    def showSessionsManager(self):
        ch2 = mybrowser.SessionsManager(
            "%s (Functions List)" % self.current_name, self)
        results = self.getSessionsList()
        for item in results:
            print ("Adding item", item)
            ch2.add_item(item)

        r = ch2.show()

    def selectFunctionsInSegment(self):
        ea = get_screen_ea()
        for f in list(Functions(get_segm_start(ea), get_segm_end(ea))):
            self.addBreakpoint(f)
        mynav_print("Done")

    def deselectFunctionsInSegment(self):
        ea = get_screen_ea()
        for f in list(Functions(get_segm_start(ea), get_segm_end(ea))):
            del_bpt(f)
        mynav_print("Done")

    def selectAdvanced(self):
        items = ["Function's child", "Code paths between points", "Code paths between 2 functions",
                        "All functions in this segment"]
        chooser = MyChoose(title="Select advanced", items=items)
        c = chooser.show()
        c=c+1

        if c > 0:
            if c == 1:
                self.selectFunctionChilds()
            elif c == 2:
                self.selectCodePathsBetweenPoints()
            elif c == 3:
                self.selectCodePaths()
            elif c == 4:
                self.selectFunctionsInSegment()
        else:
            c = None

        return c

    def deselectAdvanced(self):
        items = ["Function's child", "Code paths between points",
                        "Code paths between 2 functions", "All functions in this segment"]
        chooser = MyChoose(title="Deselect advanced", items=items)
        c = chooser.show()
        c=c+1

        if c > 0:
            if c == 1:
                self.deselectFunctionChilds()
            elif c == 2:
                self.deselectCodePathsBetweenPoints()
            elif c == 3:
                self.deselectCodePaths()
            elif c == 4:
                self.deselectFunctionsInSegment()
        else:
            c = None

        return c

    def searchAdvanced(self):
        items = ["Search string in session", "Export database's functions",
                        "Import database's functions", "Search new functions in this segment",
                        "Analyze current segment",
                        "Analyze complete program", "Analyze this segment and search new functions"]
        chooser = MyChoose(title="Advanced options", items=items)
        c = chooser.show()
        c=c+1

        if c > 0:
            if c == 1:
                self.searchStringInSessions()
            elif c == 2:
                x = myexport.CFunctionsMatcher()
                x.export()
            elif c == 3:
                msg = "WARNING! This process can discover a lot of function names but it may generate incorrect results too.\n"
                msg += "Do you want to continue?"
                if ask_yn(1, msg) == 1:
                    x = myexport.CFunctionsMatcher()
                    x.doImport()
            elif c == 4:
                msg = "WARNING! This process can discover a lot of new functions but it may generate incorrect results.\n"
                msg += "Do you want to continue?"
                if ask_yn(1, msg) == 1:
                    self.realDoDiscoverFunctions()
            elif c == 5:
                plan_and_wait(get_segm_start(here()), get_segm_end(here()))
            elif c == 6:
                plan_and_wait(inf_get_min_ea(), inf_get_max_ea())
            elif c == 7:
                plan_and_wait(get_segm_start(here()), get_segm_end(here()))
                msg = "WARNING! This process can discover a lot of new functions but it may generate incorrect results.\n"
                msg += "Do you want to continue?"
                if ask_yn(1, msg) == 1:
                    self.realDoDiscoverFunctions()
                plan_and_wait(get_segm_start(here()), get_segm_end(here()))
        else:
            c = None

        return c

    def runScript(self):
        res = ask_file(0, "*.py", "Select python script to run")
        if res is not None:
            g = globals()
            g["mynav"] = self
            g["mybrowser"] = mybrowser
            g["myexport"] = myexport
            #execfile(res, g)
            exec(open("./filename").read(), g)

    def mynav_print(self, msg):
        mynav_print(msg)

    def registerMenus(self):
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Deselect extended code paths between 2 functions", None, 0, self.deselectExtendedCodePaths, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Select extended code paths between 2 functions", None, 0, self.selectExtendedCodePaths, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show extended code paths between 2 functions", None, 0, mybrowser.mybrowser.SearchCodePathDialog, (False, True))
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show sessions union", "", 0, self.doNothing, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show sessions intersection", "", 0, self.doNothing, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Show simplified step trace session", "Ctrl+Alt+F6", 0, self.showSimplifiedTraceSession, None)
        #idaapi.add_menu_item("Edit/Plugins/", "MyNav: Trace code paths between 2 functions", None, 0, self.traceCodePaths, None)
        #idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, None)
        #idaapi.add_menu_item("Edit/Plugins/", "-", None, 0, self.doNothing, ())
        if hasSqlite:
            DeleteALLSessions.register(self, "Delete ALL sessions")
            DeleteASession.register(self, "Delete a session")
        AdvancedDeselectionOptions.register(
            self, "Advanced deselection options")
        AdvancedSelectionOptions.register(self, "Advanced selection options")
        if hasSqlite:
            DeselectHitsFromSession.register(
                self, "Deselect hits from session")
            SelectHitsFromSession.register(self, "Select hits from session")
        ClearAllBreakpoints.register(self, "Clear all breakpoints")
        SetAllBreakpoints.register(self, "Set all breakpoints")
        if hasSqlite:
            AddRemoveTargetPoint.register(self, "Add/Remove target point")
            AddRemoveEntryPoint.register(self, "Add/Remove entry point")
            ClearTraceSession.register(self, "Clear trace session")
            SessionsFunctionsList.register(self, "Session's functions List")
            ShowSessionsManager.register(self, "Show session's manager")
            ShowAdvancedOptions.register(self, "Show advanced options")
            ShowTraceSession.register(self, "Show trace session")
            ShowSession.register(self, "Show session")
        ShowBrowser.register(self, "Show browser")
        if hasSqlite:
            ConfigureCPURecording.register(self, "Configure CPU Recording")
            Configuretimeout.register(self, "Configure timeout")
            NewAdvancedSession.register(self, "New advanced session")
            TraceThisFunction.register(self, "Trace this function")
            TraceInSession.register(self, "Trace in session")
            NewSession.register(self, "New session")
            OpenGraph.register(self, "Open graph")
        RunAPythonScript.register(self, "Run a python script")
        AdvancedUtilities.register(self, "Advanced utilities")

        if hasSqlite:
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", DeleteALLSessions.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", DeleteASession.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/Plugins/MyNav/", AdvancedDeselectionOptions.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/Plugins/MyNav/", AdvancedSelectionOptions.get_name(), idaapi.SETMENU_APP)
        if hasSqlite:
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", DeselectHitsFromSession.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", SelectHitsFromSession.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/Plugins/MyNav/", ClearAllBreakpoints.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/Plugins/MyNav/", SetAllBreakpoints.get_name(), idaapi.SETMENU_APP)
        if hasSqlite:
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", AddRemoveTargetPoint.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", AddRemoveEntryPoint.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", ClearTraceSession.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", SessionsFunctionsList.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", ShowSessionsManager.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", ShowAdvancedOptions.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", ShowTraceSession.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", ShowSession.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/Plugins/MyNav/", ShowBrowser.get_name(), idaapi.SETMENU_APP)
        if hasSqlite:
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", ConfigureCPURecording.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", Configuretimeout.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", NewAdvancedSession.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", TraceThisFunction.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", TraceInSession.get_name(), idaapi.SETMENU_APP)
            idaapi.attach_action_to_menu(
                "Edit/Plugins/MyNav/", NewSession.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/Plugins/MyNav/", RunAPythonScript.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            "Edit/Plugins/MyNav/", AdvancedUtilities.get_name(), idaapi.SETMENU_APP)


def PLUGIN_ENTRY():
    idaapi.set_script_timeout(0)
    nav = CMyNav()
    """
    if ask_yn(1, "Set breakpoints?") == 1:
        nav.setBreakpoints()

    nav.start()
    nav.showSessions()
    """
    # nav.selectFunctionChilds()
    nav.registerMenus()
    # nav.doDiscoverFunctions()
    # nav.deselectFunctionChilds()
    # nav.showFunctionChilds()


if __name__ == "__main__":
    try:
        PLUGIN_ENTRY()
    except:
        print ("***Error, main", sys.exc_info()[1])
