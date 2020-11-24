import os
import sys
import shutil
import shlex
import json
import tempfile
from tkinter import *
from tkinter import ttk as ttk
from tkinter import filedialog
from tkinter import messagebox
from ttkthemes import ThemedStyle
from PyInstaller import __main__ as pyi


def move_project(src, dst):
    """ Move the output package to the desired path (default is output/ - set in script.js) """
    # Make sure the destination exists
    if not os.path.exists(dst):
        os.makedirs(dst)

    # Move all files/folders in dist/
    for file_or_folder in os.listdir(src):
        _dst = os.path.join(dst, file_or_folder)
        # If this already exists in the destination, delete it
        if os.path.exists(_dst):
            if os.path.isfile(_dst):
                os.remove(_dst)
            else:
                shutil.rmtree(_dst)
        # Move file
        shutil.move(os.path.join(src, file_or_folder), dst)


def convert(command):
    temporary_directory = tempfile.mkdtemp()
    dist_path = os.path.join(temporary_directory, 'application')
    build_path = os.path.join(temporary_directory, 'build')
    extra_args = ['--distpath', dist_path] + ['--workpath', build_path] + ['--specpath', temporary_directory]
    sys.argv = shlex.split(command) + extra_args
    output_directory = os.path.abspath('.\\')
    pyi.run()
    move_project(dist_path, output_directory)
    shutil.rmtree(temporary_directory)


'''def build_options(frame, var_list):
    optionList = ttk.Frame(frame)
    ttk.Button(frame, text="Add File", command=lambda: (add_options(optionList, var_list, filedialog.askopenfilenames(title="Select Files to add to the builder", filetypes=[("Python Files", "*.py")])))).pack(anchor=NW)
    # ttk.Button(frame, text="Remove File", command=lambda: (build_option_removal(optionList, var_list))).pack(anchor=NW)
    optionList.pack(fill=BOTH, expand=1)
    optionList.columnconfigure((0, 1), weight=1)
    add_options(optionList, var_list, ())


def add_options(frame, var_list, option_list):
    for item in frame.grid_slaves():
        item.destroy()
    for path in option_list:
        var_list.update({path.rsplit('/', 1)[1]: {"Include": IntVar(), "Path": path}})
    for idx, file in enumerate(var_list):
        ttk.Checkbutton(frame, text=file, variable=var_list[file]["Include"]).grid(row=int(idx / 2), column=idx % 2, sticky=W)
        var_list[file]["Include"].set(1)


def build_option_removal(frame, var_list):
    removeWindow = Toplevel()
    removeWindow.wm_title('Remove Files')
    removeWindow.wm_geometry("{0}x{1}+{2}+{3}".format(int(root.winfo_screenwidth() * 2 / 6), int(root.winfo_screenheight() * 1 / 4), int(root.winfo_screenwidth() / 3), int(root.winfo_screenheight() / 6)))
    removeFrame = ttk.Frame(removeWindow)
    ttk.Label(removeWindow, text="Select the files you want to remove from the list.").pack(fill=X)
    removeFrame.pack(fill=BOTH, expand=1)
    removeFrame.columnconfigure((0, 1), weight=1)
    removeList = []
    rowidx = 0
    for idx, file in enumerate(var_list):
        removeList.append(IntVar())
        ttk.Checkbutton(removeFrame, text=file, variable=removeList[idx]).grid(row=int(idx / 2), column=idx % 2, sticky=W)
        rowidx = int(idx / 2) + 1
    ttk.Button(removeFrame, text="Remove Files").grid(row=rowidx, column=0, columnspan=2)


def del_option(frame, var_list, remove_list):
    for idx, rem in enumerate(var_list):
        if remove_list[idx].get():
            pass


def build_command(path_list, main_program):
    save_build()
    iconPath = os.path.abspath('scoring_engine_logo_windows_icon_5TN_icon.ico')
    command = 'pyinstaller -y -F -w -i "' + iconPath + '"'
    for path in path_list:
        print(path_list[path]["Include"])
        if path_list[path]["Include"]:
            command += ' --add-data "' + path_list[path]["Path"] + '";"."'
    command += ' "' + main_program + '"'
    convert(command)
    messagebox.showinfo("Build Complete", str(main_program) + " has completed building.")


def save_build():
    savePaths = filePaths.copy()
    for build in filePaths:
        for file in filePaths[build]:
            savePaths[build][file]["Include"] = filePaths[build][file]["Include"].get()
    f = open(filename, 'w+')
    json.dump(savePaths, f)
    f.close()


def load_build():
    for build in filePaths:
        for file in filePaths[build]:
            filePaths[build][file]["Include"] = IntVar()


root = Tk()
root.title('Configurator')
root.geometry("{0}x{1}+{2}+{3}".format(int(root.winfo_screenwidth() * 3 / 4), int(root.winfo_screenheight() * 2 / 3), int(root.winfo_screenwidth() / 9), int(root.winfo_screenheight() / 6)))

root.ttkStyle = ThemedStyle(root.winfo_toplevel())
root.ttkStyle.set_theme("black")
root.ttkStyle.theme_settings(themename="black", settings={"TLabel": {"configure": {"padding": '5 0', "justify": 'center', "wraplength": int(root.winfo_screenwidth() * 3 / 4 / 2)}}, "TEntry": {"map": {"fieldbackground": [('disabled', '#868583')]}}, "TButton": {"configure": {"anchor": 'center', "width": '13'}}})

filename = 'build_data.json'
if os.path.exists(filename):
    f = open(filename)
    filePaths = json.load(f)
    f.close()
    load_build()
else:
    filePaths = {"Config": {}, "Score": {}}

configPath = os.path.abspath('configurator.py')
scoringPath = os.path.abspath('scoring_engine.py')

configMain = ttk.Frame(root)
configContent = ttk.Frame(configMain)
scoreMain = ttk.Frame(root)
scoreContent = ttk.Frame(scoreMain)
configMain.pack(side=LEFT, fill=BOTH, expand=1)
ttk.Separator(root, orient=VERTICAL).pack(side=LEFT, fill=Y)
scoreMain.pack(side=LEFT, fill=BOTH, expand=1)

configMain.rowconfigure(1, weight=1)
configMain.columnconfigure(0, weight=1)
ttk.Label(configMain, text="Files to include into the configurator executable. Do not include the main file in this list it is added by default", font='15').grid(row=0, column=0)
configContent.grid(row=1, column=0, sticky=NSEW)
build_options(configContent, filePaths["Config"])
ttk.Button(configMain, text="Convert", command=lambda: (build_command(filePaths["Config"], configPath))).grid(row=2, column=0)

scoreMain.rowconfigure(1, weight=1)
scoreMain.columnconfigure(0, weight=1)
ttk.Label(scoreMain, text="Files to include into the scoring engine executable. Do not include the main file in this list it is added by default", font='15').grid(row=0, column=0)
scoreContent.grid(row=1, column=0, sticky=NSEW)
build_options(scoreContent, filePaths["Score"])
ttk.Button(scoreMain, text="Convert", command=lambda: (build_command(filePaths["Score"], scoringPath))).grid(row=2, column=0)


root.mainloop()'''


scoringPath = os.path.abspath('scoring_engine.py')
configPath = os.path.abspath('configurator.py')
dbHandlerPath = os.path.abspath('db_handler.py')
balloonPath = os.path.abspath('balloontip.py')
adminPath = os.path.abspath('admin_test.py')
iconPath = os.path.abspath('scoring_engine_logo_windows_icon_5TN_icon.ico')
cccLogoPath = os.path.abspath('CCC_logo.png')
SoCalPath = os.path.abspath('SoCalCCCC.png')
enginePath = os.path.abspath('scoring_engine.exe')
command_score = 'pyinstaller -y -F -w -i "' + iconPath + '" --add-data "' + balloonPath + '";"." --add-data "' + adminPath + '";"." --add-data "' + dbHandlerPath + '";"." "' + scoringPath + '"'
command_config = 'pyinstaller -y -F -w -i "' + iconPath + '" --add-data "' + adminPath + '";"." --add-data "' + dbHandlerPath + '";"." --add-data "' + cccLogoPath + '";".\\extras" --add-data "' + SoCalPath + '";".\\extras" --add-data "' + iconPath + '";".\\extras" --add-data "' + enginePath + '";".\\extras" "' + configPath + '"'
while True:
    ask = input("To rebuild the configurator type: config. To rebuild the scoring engine type: score. To rebuild both type: both. To exit type: exit.\n")
    if ask.lower() == 'config':
        convert(command_config)
    elif ask.lower() == 'score':
        convert(command_score)
    elif ask.lower() == 'both':
        convert(command_score)
        convert(command_config)
    elif ask.lower() == 'temp':
        temp_path = os.path.abspath('db_handler.py')
        # -c for console -w for window
        temp = 'pyinstaller -y -F -c "' + temp_path + '"'
        convert(temp)
    else:
        exit()
