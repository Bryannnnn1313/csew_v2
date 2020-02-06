import os
import time
import json
import admin_test
import installer
from tkinter import *
from tkinter import ttk as ttk
from tkinter import filedialog
import traceback
from tkinter import messagebox


class VerticalScrolledFrame(Frame):
    """A pure Tkinter scrollable frame that actually works!
    * Use the 'interior' attribute to place widgets inside the scrollable frame
    * Construct and pack/place/grid normally
    * This frame only allows vertical scrolling
    """

    def __init__(self, parent, *args, **kw):
        Frame.__init__(self, parent, *args, **kw)
        # create a canvas object and a vertical scrollbar for scrolling it
        vscrollbar = ttk.Scrollbar(self, orient=VERTICAL)
        vscrollbar.pack(fill=Y, side=RIGHT, expand=FALSE)
        canvas = Canvas(self, bd=0, highlightthickness=0, background='#d9d9d9', yscrollcommand=vscrollbar.set)
        canvas.pack(side=LEFT, fill=BOTH, expand=TRUE)
        vscrollbar.config(command=canvas.yview)
        # reset the view
        canvas.xview_moveto(0)
        canvas.yview_moveto(0)
        # create a frame inside the canvas which will be scrolled with it
        self.interior = interior = ttk.Frame(canvas)
        interior_id = canvas.create_window(0, 0, window=interior, anchor=NW)

        # track changes to the canvas and frame width and sync them,
        # also updating the scrollbar

        def _configure_interior(event):
            # update the scrollbars to match the size of the inner frame
            size = (interior.winfo_reqwidth(), interior.winfo_reqheight())
            canvas.config(scrollregion="0 0 %s %s" % size)
            if interior.winfo_reqwidth() != canvas.winfo_width():
                # update the canvas's width to fit the inner frame
                canvas.config(width=interior.winfo_reqwidth())

        interior.bind('<Configure>', _configure_interior)

        def _configure_canvas(event):
            if interior.winfo_reqwidth() != canvas.winfo_width():
                # update the inner frame's width to fill the canvas
                canvas.itemconfigure(interior_id, width=canvas.winfo_width())

        canvas.bind('<Configure>', _configure_canvas)


class Config(Tk):
    def __init__(self, *args, **kwargs):
        Tk.__init__(self, *args, **kwargs)

        vulnerability_settings = {"Main Menu": {"Desktop Checkbox": IntVar(), "Desktop Entry": StringVar(), "Silent Mode": IntVar(), "Server Mode": IntVar(), "Server Name": StringVar(), "Server User Name": StringVar(), "Server Password": StringVar(), "Tally Points": StringVar()},
                                 "Forensic": {"Points": [IntVar()], "Question": [StringVar()], "Answer": [StringVar()], "Location": ['']},
                                 "User Policy Account Disable": {"Disable Guest": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                                 "Disable Admin": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}}},
                                 "User Policy Account Management": {"Keep User": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                                    "Add Admin": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                                    "Remove Admin": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                                    "Add User": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                                    "Remove User": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                                    "User Change Password": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'User Name': [StringVar()]}},
                                                                    "Add  User to Group": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'User Name': [StringVar()], 'Group Name': [StringVar()]}},
                                                                    "Remove User from Group": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'User Name': [StringVar()], 'Group Name': [StringVar()]}}},
                                 "Local Policy Options": {"Require CTRL_ALT_DEL": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                          "Turn On Firewall": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                          "Don't Display Last User": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}}},
                                 "Local Policy Password": {"Minimum Password Age": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                           "Maximum Password Age": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                           "Minimum Password Length": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                           "Maximum Login Tries": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                           "Lockout Duration": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                           "Lockout Reset Duration": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                           "Password History": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                           "Password Complexity": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                           "Reversible Password Encryption": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}}},
                                 "Local Policy Audit": {"Audit Account Login": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                        "Audit Account Management": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                        "Audit Directory Settings Access": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                        "Audit Logon Events": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                        "Audit Object Access": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                        "Audit Policy Change": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                        "Audit Privilege Use": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                        "Audit Process Tracking": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                        "Audit System Events": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}}},
                                 "Program": {"Good Program": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Program Name': [StringVar()]}},
                                             "Bad Program": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Program Name': [StringVar()]}},
                                             "Good Service": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Service Name': [StringVar()]}},
                                             "Bad Service": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Service Name': [StringVar()]}}},
                                 "Files": {"Bad File": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'File Path': [StringVar()]}},
                                           "Check Hosts": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Text': [StringVar()]}},
                                           "File Contains Text": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Text to Add': [StringVar()], 'File Path': [StringVar()]}},
                                           "File No Longer Contains": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Text to Remove': [StringVar()], 'File Path': [StringVar()]}}},
                                 "Miscellaneous": {"Anti-Virus": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                   "updateCheckPeriod": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                   "updateAutoInstall": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()]}},
                                                   "taskScheduler": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Task Name': [StringVar()]}},
                                                   "checkStartup": {"Definition": 'Definition', "Enabled": IntVar(), "Categories": {'Points': [IntVar()], 'Program Name': [StringVar()]}}}}
        vulnerability_settings["Main Menu"]["Tally Points"].set("Vulnerabilities: 0 Total Points: 0")

        nb = ttk.Notebook(self)
        MainPage = ttk.Frame(nb)

        ttk.Button(MainPage, text='Save', command=lambda: (save_config(vulnerability_settings))).grid(sticky=EW)
        ttk.Checkbutton(MainPage, text="Check if this configurator is on the Desktop of the main account.", variable=vulnerability_settings["Main Menu"]["Desktop Checkbox"], command=lambda: (set_desktop(vulnerability_settings))).grid(row=0, column=1, sticky=W, columnspan=4)
        ttk.Button(MainPage, text='Commit', command=lambda: (commit_config(vulnerability_settings))).grid(row=1, sticky=EW)
        ttk.Entry(MainPage, textvariable=vulnerability_settings["Main Menu"]["Desktop Entry"]).grid(row=1, column=1, columnspan=3, sticky=EW)
        ttk.Label(MainPage, text="Enter the user name where you want the information to goto.", wraplength=200).grid(row=1, column=4, columnspan=2, sticky=W)
        ttk.Checkbutton(MainPage, text='Silent Miss', variable=vulnerability_settings["Main Menu"]["Silent Mode"]).grid(row=2, sticky=W)
        ttk.Label(MainPage, text='Check this box to hide missed items (Similar to competition)').grid(row=2, column=1, columnspan=5, sticky=W)
        ttk.Checkbutton(MainPage, text='Server Mode', variable=vulnerability_settings["Main Menu"]["Server Mode"], command=lambda: (serverL.configure(state='enable'), serverE.configure(state='enable'), userL.configure(state='enable'), userE.configure(state='enable'), passL.configure(state='enable'), passE.configure(state='enable'))).grid(row=3, sticky=W)
        ttk.Label(MainPage, text='Check this box to enable an FTP server to save the scores (Similar to competition)').grid(row=3, column=1, columnspan=5, sticky=W)
        serverL = ttk.Label(MainPage, text='Server Name/IP', state='disable')
        serverL.grid(row=4, sticky=E)
        serverE = ttk.Entry(MainPage, textvariable=vulnerability_settings["Main Menu"]["Server Name"], state='disable')
        serverE.grid(row=4, column=1, sticky=W)
        userL = ttk.Label(MainPage, text='User Name', state='disable')
        userL.grid(row=4, column=2, sticky=E)
        userE = ttk.Entry(MainPage, textvariable=vulnerability_settings["Main Menu"]["Server User Name"], state='disable')
        userE.grid(row=4, column=3, sticky=W)
        passL = ttk.Label(MainPage, text='Password', state='disable')
        passL.grid(row=4, column=4, sticky=E)
        passE = ttk.Entry(MainPage, textvariable=vulnerability_settings["Main Menu"]["Server Password"], state='disable')
        passE.grid(row=4, column=5, sticky=W)
        ttk.Label(MainPage, textvariable=vulnerability_settings["Main Menu"]["Tally Points"], font='Verdana 10 bold', wraplength=150).grid(row=5)

        ForensicsPage = VerticalScrolledFrame(nb)
        ForensicsPageIn = ForensicsPage.interior
        ForensicsPageIn.grid_columnconfigure(1, weight=1)
        ForensicsPageIn.grid_columnconfigure(2, weight=1)
        ttk.Button(ForensicsPageIn, text="Add", command=lambda: self.add_row(ForensicsPageIn, vulnerability_settings["Forensic"], widgetDict["Forensic"], 2)).grid(row=0, column=0, sticky=EW)
        ttk.Label(ForensicsPageIn, text='This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation', wraplength=int(self.winfo_screenwidth() / 2 - 100)).grid(row=0, column=1, columnspan=3)
        ttk.Label(ForensicsPageIn, text="Points", font='Verdana 10 bold').grid(row=1, column=0)
        ttk.Label(ForensicsPageIn, text="Question", font='Verdana 10 bold').grid(row=1, column=1)
        ttk.Label(ForensicsPageIn, text="Answer", font='Verdana 10 bold').grid(row=1, column=2)
        ttk.Entry(ForensicsPageIn, width=5, textvariable=vulnerability_settings["Forensic"]["Points"][0]).grid(row=2, column=0)
        ttk.Entry(ForensicsPageIn, textvariable=vulnerability_settings["Forensic"]["Question"][0]).grid(row=2, column=1, sticky=EW)
        ttk.Entry(ForensicsPageIn, textvariable=vulnerability_settings["Forensic"]["Answer"][0]).grid(row=2, column=2, sticky=EW)
        ttk.Button(ForensicsPageIn, text='X', command=lambda: remove_row(0, vulnerability_settings["Forensic"], widgetDict["Forensic"])).grid(row=2, column=3)
        widgetDict["Forensic"].update({0: ForensicsPageIn.grid_slaves(row=2)})

        UserPolicyPage = VerticalScrolledFrame(nb)
        UserPolicyPageIn = UserPolicyPage.interior
        UserPolicyPageIn.grid_columnconfigure(1, weight=1)
        ttk.Label(UserPolicyPageIn, text='This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation', padding='10 5').grid(row=0, column=0, columnspan=3)
        ttk.Label(UserPolicyPageIn, text='User Policy Account Disable', font='Verdana 10').grid(row=1, column=0, stick=W)
        ttk.Label(UserPolicyPageIn, text="Points", font='Verdana 10 bold').grid(row=1, column=2, stick=W)
        for i, t in enumerate(vulnerability_settings["User Policy Account Disable"].keys()):
            self.add_option(UserPolicyPageIn, vulnerability_settings["User Policy Account Disable"][t], t, i + 2, nb)
            l = i + 3
        ttk.Label(UserPolicyPageIn, text='User Policy Account Management', font='Verdana 10').grid(row=l, column=0, stick=W)
        ttk.Label(UserPolicyPageIn, text="Modify", font='Verdana 10 bold').grid(row=l, column=2, stick=W)
        for i, t in enumerate(vulnerability_settings["User Policy Account Management"].keys()):
            self.add_option(UserPolicyPageIn, vulnerability_settings["User Policy Account Management"][t], t, i + l + 1, nb)

        LocalPolicyPage = VerticalScrolledFrame(nb)
        LocalPolicyPageIn = LocalPolicyPage.interior
        LocalPolicyPageIn.grid_columnconfigure(1, weight=1)
        ttk.Label(LocalPolicyPageIn, text='This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation', padding='10 5').grid(row=0, column=0, columnspan=3)
        ttk.Label(LocalPolicyPageIn, text='Local Security Policy Password', font='Verdana 10').grid(row=1, column=0, stick=W)
        ttk.Label(LocalPolicyPageIn, text="Points", font='Verdana 10 bold').grid(row=1, column=2, stick=W)
        for i, t in enumerate(vulnerability_settings["Local Policy Password"].keys()):
            self.add_option(LocalPolicyPageIn, vulnerability_settings["Local Policy Password"][t], t, i + 2, nb)
            l = i + 3
        ttk.Label(LocalPolicyPageIn, text='Local Security Policy Audit', font='Verdana 10').grid(row=l, column=0, stick=W)
        ttk.Label(LocalPolicyPageIn, text="Points", font='Verdana 10 bold').grid(row=l, column=2, stick=W)
        for i, t in enumerate(vulnerability_settings["Local Policy Audit"].keys()):
            self.add_option(LocalPolicyPageIn, vulnerability_settings["Local Policy Audit"][t], t, i + l + 1, nb)
            l = i + l + 2
        ttk.Label(LocalPolicyPageIn, text='Local Security Policy Options', font='Verdana 10').grid(row=l, column=0, stick=W)
        ttk.Label(LocalPolicyPageIn, text="Points", font='Verdana 10 bold').grid(row=l, column=2, stick=W)
        for i, t in enumerate(vulnerability_settings["Local Policy Options"].keys()):
            self.add_option(LocalPolicyPageIn, vulnerability_settings["Local Policy Options"][t], t, i + l + 1, nb)

        ProgramFilePage = VerticalScrolledFrame(nb)
        ProgramFilePageIn = ProgramFilePage.interior
        ProgramFilePageIn.grid_columnconfigure(1, weight=1)
        ttk.Label(ProgramFilePageIn, text='This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation', padding='10 5').grid(row=0, column=0, columnspan=3)
        ttk.Label(ProgramFilePageIn, text='Programs', font='Verdana 10').grid(row=1, column=0, stick=W)
        ttk.Label(ProgramFilePageIn, text="Modify", font='Verdana 10 bold').grid(row=1, column=2, stick=W)
        for i, t in enumerate(vulnerability_settings["Program"].keys()):
            self.add_option(ProgramFilePageIn, vulnerability_settings["Program"][t], t, i + 2, nb)
            l = i + 3
        ttk.Label(ProgramFilePageIn, text='Files', font='Verdana 10').grid(row=l, column=0, stick=W)
        ttk.Label(ProgramFilePageIn, text="Modify", font='Verdana 10 bold').grid(row=l, column=2, stick=W)
        for i, t in enumerate(vulnerability_settings["Files"].keys()):
            self.add_option(ProgramFilePageIn, vulnerability_settings["Files"][t], t, i + l + 1, nb)

        MiscellaneousPage = VerticalScrolledFrame(nb)
        MiscellaneousPageIn = MiscellaneousPage.interior
        MiscellaneousPageIn.grid_columnconfigure(1, weight=1)
        ttk.Label(MiscellaneousPageIn, text='This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation', padding='10 5').grid(row=0, column=0, columnspan=3)
        ttk.Label(MiscellaneousPageIn, text='Miscellaneous', font='Verdana 10').grid(row=1, column=0, stick=W)
        ttk.Label(MiscellaneousPageIn, text="Points", font='Verdana 10 bold').grid(row=1, column=2, stick=W)
        for i, t in enumerate(vulnerability_settings["Miscellaneous"].keys()):
            if len(vulnerability_settings["Miscellaneous"][t]["Categories"]) == 1:
                self.add_option(MiscellaneousPageIn, vulnerability_settings["Miscellaneous"][t], t, i + 2, nb)
            else:
                self.add_option(MiscellaneousPageIn, vulnerability_settings["Miscellaneous"][t], t, i + 2, nb)

        ReportPage = VerticalScrolledFrame(nb)
        ReportPageIn = ReportPage.interior
        ttk.Button(ReportPageIn, text='Export to csv').grid(row=0, column=0, stick=EW)
        ttk.Button(ReportPageIn, text='Export to HTML').grid(row=1, column=0, stick=EW)
        ttk.Button(ReportPageIn, text='Generate', command=lambda: (self.generate_report(ReportPageIn, vulnerability_settings))).grid(row=2, column=0, stick=EW)
        ttk.Label(ReportPageIn, text='This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation', wraplength=int(self.winfo_screenwidth() / 2 - 125)).grid(row=0, column=1, rowspan=3, columnspan=4)

        nb.add(MainPage, text='Main Page')
        nb.add(ForensicsPage, text='Forensics')
        nb.add(UserPolicyPage, text='User Policy')
        nb.add(LocalPolicyPage, text='Local Policy')
        nb.add(ProgramFilePage, text='Programs and Files')
        nb.add(MiscellaneousPage, text='Miscellaneous')
        nb.add(ReportPage, text='Report')

        nb.pack(expand=1, fill="both")
        self.load_config(vulnerability_settings, ForensicsPageIn)

    def add_row(self, frame, entry, widgets, default_row):
        test = True
        rwl = 0
        while test:
            if not rwl in widgets.keys():
                test = False
            else:
                rwl += 1
        if len(widgets) > 0:
            i = 0
            for w in widgets:
                if widgets[w][0].grid_info()['row'] > i:
                    tempr = widgets[w][0].grid_info()['row'] + 1
        else:
            tempr = default_row
        if rwl == len(widgets):
            for i in entry:
                if i == "Points":
                    entry[i].append(IntVar())
                else:
                    entry[i].append(StringVar())
        else:
            for i in entry:
                if i == "Points":
                    entry[i][rwl] = IntVar()
                else:
                    entry[i][rwl] = StringVar()

        for i, t in enumerate(entry):
            if t == "Points":
                ttk.Entry(frame, width=5, textvariable=entry["Points"][rwl]).grid(row=tempr, column=i)
            elif t == "File Path":
                frame.grid_columnconfigure(i, weight=1)
                ttk.Entry(frame, textvariable=entry[t][rwl]).grid(row=tempr, column=i, sticky=EW)
                ttk.Button(frame, text='...', command=lambda: entry[t][rwl].set(filedialog.askdirectory())).grid(row=tempr, column=i + 1)
                c = i + 2
            elif t != "Location":
                ttk.Entry(frame, textvariable=entry[t][rwl]).grid(row=tempr, column=i, sticky=EW)
                c = i + 1
        ttk.Button(frame, text='X', command=lambda: remove_row(rwl, entry, widgets)).grid(row=tempr, column=c, sticky=W)
        widgets.update({rwl: frame.grid_slaves(row=tempr)})

    def add_option(self, frame, entry, name, row, return_frame):
        ttk.Checkbutton(frame, text=name, variable=entry["Enabled"]).grid(row=row, column=0, stick=W)
        ttk.Label(frame, text=entry["Definition"]).grid(row=row, column=1, stick=W)
        if len(entry["Categories"]) > 1:
            ttk.Button(frame, text='Modify', command=lambda: self.modify_settings(name, entry, return_frame)).grid(row=row, column=2)
        else:
            ttk.Entry(frame, width=5, textvariable=entry["Categories"]["Points"][0]).grid(row=row, column=2)

    def modify_settings(self, option, entry, packing):
        self.pack_slaves()[0].pack_forget()
        modifyPage = VerticalScrolledFrame(self)
        modifyPage.pack(expand=1, fill="both")
        modifyPageIn = modifyPage.interior
        if entry["Enabled"].get() != 1:
            entry["Enabled"].set(1)
        if len(widgetDict["Modify"]) > 0:
            for i in widgetDict["Modify"]:
                for t in widgetDict["Modify"][i]:
                    t.destroy()
            widgetDict["Modify"].clear()
        ttk.Button(modifyPageIn, text="Save", command=lambda: (self.pack_slaves()[0].pack_forget(), packing.pack(expand=1, fill="both"))).grid(row=0, column=0, sticky=EW)
        ttk.Label(modifyPageIn, text=option + ' Modification', font='Verdana 15').grid(row=0, column=1, columnspan=len(entry["Categories"]))
        ttk.Button(modifyPageIn, text="Add", command=lambda: (self.add_row(modifyPageIn, entry["Categories"], widgetDict["Modify"], 3))).grid(row=1, column=0, sticky=EW)
        ttk.Label(modifyPageIn, text='This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation page This will be the explanation', wraplength=int(self.winfo_screenwidth() / 2 - 100)).grid(row=1, column=1, columnspan=len(entry["Categories"]))
        for i, t in enumerate(entry["Categories"]):
            ttk.Label(modifyPageIn, text=t, font='Verdana 10 bold').grid(row=2, column=i)
        for i in range(len(entry["Categories"]["Points"])):
            if entry["Categories"]["Points"][i] != 0:
                for r, t in enumerate(entry["Categories"]):
                    if t == "Points":
                        ttk.Entry(modifyPageIn, width=5, textvariable=entry["Categories"]["Points"][i]).grid(row=i + 3, column=r)
                    elif t == "File Path":
                        modifyPageIn.grid_columnconfigure(r, weight=1)
                        ttk.Entry(modifyPageIn, textvariable=entry["Categories"][t][i]).grid(row=i + 3, column=r, sticky=EW)
                        ttk.Button(modifyPageIn, text='...', command=lambda: entry["Categories"][t][i].set(filedialog.askdirectory())).grid(row=i + 3, column=r + 1)
                        c = r + 2
                    else:
                        ttk.Entry(modifyPageIn, textvariable=entry["Categories"][t][i]).grid(row=i + 3, column=r, sticky=EW)
                        c = r + 1
                ttk.Button(modifyPageIn, text='X', command=lambda: remove_row(i, entry["Categories"], widgetDict["Modify"])).grid(row=i + 3, column=c, sticky=W)
                widgetDict["Modify"].update({i: modifyPageIn.grid_slaves(row=i + 3)})

    def load_config(self, dictionary, forensic):
        filename = 'save_data.json'
        if os.path.exists(filename):
            f = open(filename)
            save_dictionary = json.load(f)
            for s in save_dictionary.keys():
                if s == "Main Menu":
                    for m in save_dictionary[s]:
                        dictionary[s][m].set(save_dictionary[s][m])
                elif s == "Forensic":
                    for i in range(1, len(save_dictionary[s]["Points"])):
                        self.add_row(forensic, dictionary["Forensic"], widgetDict["Forensic"], 2)
                    for m in save_dictionary[s]:
                        for i, settings in enumerate(save_dictionary[s][m]):
                            if m == "Location":
                                dictionary[s][m][i] = settings
                            else:
                                dictionary[s][m][i].set(settings)
                else:
                    for m in save_dictionary[s].keys():
                        dictionary[s][m]["Enabled"].set(save_dictionary[s][m]["Enabled"])
                        for c in save_dictionary[s][m]["Categories"].keys():
                            for i, settings in enumerate(save_dictionary[s][m]["Categories"][c]):
                                if i == 0:
                                    dictionary[s][m]["Categories"][c][i].set(settings)
                                else:
                                    if c == "Points":
                                        dictionary[s][m]["Categories"][c].append(IntVar())
                                    else:
                                        dictionary[s][m]["Categories"][c].append(StringVar())
                                    dictionary[s][m]["Categories"][c][i].set(settings)
            f.close()
            tally(dictionary)

    def generate_report(self, frame, dictionary):
        for i in widgetDict["Report"]:
            i.destroy()
        widgetDict["Report"] = []
        wrap = int(self.winfo_screenwidth() / 2 / 5) - 65
        final_row = 4
        for s in dictionary.keys():
            tested = False
            if s != "Main Menu":
                ttk.Separator(frame, orient=HORIZONTAL).grid(row=final_row, column=0, columnspan=5, sticky=EW)
                final_row += 1
                if s == "Forensic":
                    set_first_row = final_row
                    row_span = 0
                    for i, c in enumerate(dictionary[s]):
                        if c != "Location":
                            for srow, settings in enumerate(dictionary[s][c]):
                                if settings != 0:
                                    tested = True
                                    ttk.Label(frame, text=settings.get()).grid(row=srow * 2 + set_first_row + 1, column=i + 2)
                                    ttk.Separator(frame, orient=HORIZONTAL).grid(row=srow * 2 + set_first_row + 2, column=2, columnspan=3, sticky=EW)
                                    row_span = srow * 2 + 2
                            if tested:
                                ttk.Label(frame, text=c).grid(row=set_first_row, column=i + 2)
                                final_row = set_first_row + row_span
                    if tested:
                        ttk.Label(frame, text=s, wraplength=wrap).grid(row=set_first_row, column=1, rowspan=row_span)
                else:
                    set_first_row = final_row
                    row_span = 0
                    for o in dictionary[s].keys():
                        if dictionary[s][o]["Enabled"].get() == 1:
                            tested = True
                            temp_row = final_row
                            temp_count = 0
                            temp_row_span = 0
                            for i, c in enumerate(dictionary[s][o]["Categories"].keys()):
                                ttk.Label(frame, text=c, wraplength=wrap).grid(row=temp_row, column=i + 2)
                                for e, settings in enumerate(dictionary[s][o]["Categories"][c]):
                                    if settings != 0:
                                        ttk.Label(frame, text=settings.get(), wraplength=wrap).grid(row=e * 2 + temp_row + 1, column=i + 2)
                                        ttk.Separator(frame, orient=HORIZONTAL).grid(row=e * 2 + temp_row + 2, column=2, columnspan=3, sticky=EW)
                                        final_row = e * 2 + temp_row + 2
                                        temp_row_span = e + 2
                                        temp_count = e
                            row_span += temp_row_span + temp_count + 1
                            ttk.Label(frame, text=o, wraplength=wrap).grid(row=temp_row, column=1, rowspan=temp_row_span * 2 - 2)
                            ttk.Separator(frame, orient=HORIZONTAL).grid(row=temp_row - 1, column=1, columnspan=4, sticky=EW)
                            final_row += 1
                    if tested:
                        ttk.Label(frame, text=s, wraplength=wrap).grid(row=set_first_row, column=0, rowspan=row_span - 1)
                        final_row -= 1
                if not tested:
                    final_row -= 1
        for i in range(4, final_row):
            for w in frame.grid_slaves(row=i):
                widgetDict["Report"].append(w)
        tally(dictionary)


def remove_row(rem, entry, widgets):
    for i in entry:
        entry[i][rem] = 0
    rem_row = widgets[rem][0].grid_info()['row']
    for w in widgets[rem]:
        w.destroy()
    for i in widgets:
        if i != rem and widgets[i][0].grid_info()['row'] > rem_row:
            tempr = widgets[i][0].grid_info()['row'] - 1
            for r in widgets[i]:
                r.grid_configure(row=tempr)
    del widgets[rem]


def create_forensic(dictionary):
    qHeader = 'This is a forensics question. Answer it below\n------------------------\n'
    qFooter = '\n\nANSWER: <TypeAnswerHere>'
    for i, q in enumerate(dictionary["Forensic"]["Question"]):
        if q != 0 and q.get() != '':
            g = open((str(dictionary["Main Menu"]["Desktop Entry"].get()) + 'Forensic Question ' + str(i + 1) + '.txt'), 'w+')
            g.write(qHeader + q.get() + qFooter)
            g.close()
            dictionary["Forensic"]["Location"][i] = (str(dictionary["Main Menu"]["Desktop Entry"].get()) + 'Forensic Question ' + str(i + 1) + '.txt')


def commit_config(dictionary):
    if not admin_test.isUserAdmin():
        switch = messagebox.askyesno('Administrative Access Required', 'You need to be Admin to Write to Config. Do you want to relaunch the confiturator as Administrator.')
        if switch:
            sys.exit(admin_test.runAsAdmin())
        return
    save_config(dictionary)
    installer.setup()
    balloonPath = os.path.abspath('balloontip.py')
    scoringPath = os.path.abspath('scoring_engine.py')
    adminPath = os.path.abspath('admin_test.py')
    iconPath = os.path.abspath('scoring_engine_logo_windows_icon_5TN_icon.ico')
    command = 'pyinstaller -y -F -w -i "' + iconPath + '" --add-data "' + balloonPath + '";"." --add-data "' + adminPath + '";"." "' + scoringPath + '"'
    installer.convert(command)
    installer.autoTasks()
    time.sleep(2)
    exit()


def save_config(dictionary):
    save_dictionary = {}
    # We wanna use those fancy variable lists
    set_desktop(dictionary)
    if "\\Desktop\\" not in dictionary["Main Menu"]["Desktop Entry"].get() and dictionary["Main Menu"]["Desktop Entry"].get() == '':
        cwd = dictionary["Main Menu"]["Desktop Entry"].get()
        cwd = "C:\\Users\\" + cwd + "\\Desktop\\"
        dictionary["Main Menu"]["Desktop Entry"].set(cwd)
    create_forensic(dictionary)
    if dictionary["Main Menu"]["Server Mode"].get() == 1:
        f = open('FTP.txt', 'w+')
        line1 = "serverName='" + dictionary["Main Menu"]["Server Name"].get() + "'\n"
        line2 = "userName='" + dictionary["Main Menu"]["Server User Name"].get() + "'\n"
        line3 = "password='" + dictionary["Main Menu"]["Server Password"].get() + "'\n"
        for line in (line1, line2, line3):
            f.write(line)
        f.close()
    for s in dictionary.keys():
        if s == "Main Menu":
            save_dictionary.update({s: {}})
            for m in dictionary[s]:
                save_dictionary[s].update({m: dictionary[s][m].get()})
        elif s == "Forensic":
            save_dictionary.update({s: {}})
            for m in dictionary[s]:
                save_dictionary[s].update({m: []})
                for settings in dictionary[s][m]:
                    if settings != 0:
                        if m == "Location":
                            save_dictionary[s][m].append(settings)
                        else:
                            save_dictionary[s][m].append(settings.get())
        else:
            save_dictionary.update({s: {}})
            for m in dictionary[s].keys():
                save_dictionary[s].update({m: {"Enabled": dictionary[s][m]["Enabled"].get(), "Categories": {}}})
                for c in dictionary[s][m]["Categories"].keys():
                    save_dictionary[s][m]["Categories"].update({c: []})
                    for settings in dictionary[s][m]["Categories"][c]:
                        if settings != 0:
                            save_dictionary[s][m]["Categories"][c].append(settings.get())
    filename = 'save_data.json'
    with open(filename, 'w+') as f:
        json.dump(save_dictionary, f)
    tally(dictionary)


def tally(dictionary):
    # Set tally scores
    tally_score = 0
    tally_settings = 0
    for s in dictionary.keys():
        if s == "Forensic":
            for i, p in enumerate(dictionary[s]["Points"]):
                if dictionary[s]["Question"][i].get() != '' and p != 0:
                    tally_settings += 1
                    tally_score += int(p.get())
        elif s != "Main Menu":
            for o in dictionary[s].keys():
                if dictionary[s][o]["Enabled"].get() == 1:
                    for settings in dictionary[s][o]["Categories"]["Points"]:
                        if settings != 0:
                            tally_settings += 1
                            tally_score += int(settings.get())
        dictionary["Main Menu"]["Tally Points"].set("Vulnerabilities: {0}\nTotal Points: {1}".format(str(tally_settings), str(tally_score)))


def set_desktop(dictionary):
    if dictionary["Main Menu"]["Desktop Checkbox"].get() == 1:
        cwd = os.getcwd()
        s = cwd.rfind('\\')
        a = len(cwd)
        s = a - s - 1
        cwd = cwd[:-s]
        dictionary["Main Menu"]["Desktop Entry"].set(cwd)


def show_error(self, *args):
    err = traceback.format_exception(*args)
    for i in err:
        if 'expected integer but got' in i:
            err = 'There is an integer error with one of the points'
    messagebox.showerror('Exception', err)


Tk.report_callback_exception = show_error

widgetDict = {"Forensic": {}, "Modify": {}, "Report": []}

root = Config()
root.title('Configurator')
root.geometry("{0}x{1}+{2}+{3}".format(int(root.winfo_screenwidth() / 2), int(root.winfo_screenheight() / 2), int(root.winfo_screenwidth() / 4), int(root.winfo_screenheight() / 4)))

style = ttk.Style()
style.theme_create("MyStyle", parent="winnative", settings={"TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0]}}, "TNotebook.Tab": {"configure": {"width": 20, "anchor": 'center'}}, "TLabel": {"configure": {"padding": '5 0', "justify": 'center', "wraplength": int(root.winfo_screenwidth() / 2 - 30)}, "map": {"foreground": [('disabled', '#8c8c8c')]}}, "TEntry": {"map": {"fieldbackground": [('disabled', '#d9d9d9')]}}, "TButton": {"configure": {"anchor": 'center'}}})
style.theme_use("MyStyle")

root.mainloop()