import os
import sys
import subprocess
import shutil
import shlex
import tempfile
from PyInstaller import __main__ as pyi


def setup():
    output_directory = 'C:/CyberPatriot/'
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    shutil.copy('CCC_logo.png', os.path.join(output_directory, 'CCC_logo.png'))
    shutil.copy('iguana.png', os.path.join(output_directory, 'iguana.png'))
    shutil.copy('logo.png', os.path.join(output_directory, 'logo.png'))
    shutil.copy('SoCalCCCC.png', os.path.join(output_directory, 'SoCalCCCC.png'))
    shutil.copy('scoring_engine_logo_windows_icon_5TN_icon.ico', os.path.join(output_directory, 'scoring_engine_logo_windows_icon_5TN_icon.ico'))
    shutil.copy('scoring_engine.py', 'scoring_engine_temp.py')

def autoTasks():
    f = open(r'Run.bat', 'w+')
    f.write('@echo off\nschtasks /create /SC ONSTART /TN ScoringEngine /TR C:\\CyberPatriot\\RunScoring.bat /RL HIGHEST /F\nschtasks /create /SC MINUTE /MO 2 /TN RepeatScore /TR C:\\CyberPatriot\\Repeat.bat /RL HIGHEST /F')
    f.close()
    r = open(r'C:\\CyberPatriot\\RunScoring.bat', 'w+')
    r.write('@echo off\ncd C:\\CyberPatriot\n.\scoring_engine.exe')
    r.close()
    # Use for if .exe counts as process
    # q = open(r'C:\\CyberPatriot\\RepeatScoring.ps1', 'w+')
    # q.write('$score = Get-Process scoring_engine.exe -ErrorAction SilentlyContinue\nif ($score) {\n}\nelse{\n\tcd c:\CyberPatriot\n\t.\scoring_engine.exe\n}')
    # q.close()
    # s = open(r'c:\\CyberPatriot\\Repeat.bat', 'w+')
    # s.write('@echo off \npowershell.exe -ExecutionPolicy RemoteSigned -File C:\\CyberPatriot\\RepeatScoring.ps1')
    # s.close()
    # Use if .exe counts as application
    s = open(r'c:\\CyberPatriot\\Repeat.bat', 'w+')
    s.write('@echo off\ntasklist /nh /fi "imagename eq scoring_engine.exe" | find /i "scoring_engine.exe" > nul || (cd C:\CyberPatriot\nstart .\RunScoring.bat)')
    s.close()
    subprocess.Popen([r'Run.bat'])
    os.remove('scoring_engine.py')
    shutil.copy('scoring_engine_temp.py', 'scoring_engine.py')


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
    output_directory = 'C:/CyberPatriot/'
    pyi.run()
    move_project(dist_path, output_directory)
    shutil.rmtree(temporary_directory)


def replacesec(loc, search, replace):
    lines = []
    with open(loc) as file:
        for line in file:
            line = line.replace(search, replace)
            lines.append(line)
    with open(loc, 'w') as file:
        for line in lines:
            file.write(line)