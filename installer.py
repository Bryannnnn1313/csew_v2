import os
import sys
import subprocess
import time
import shutil
import shlex
import tempfile
from PyInstaller import __main__ as pyi


def setup():
    os.makedirs('C:/CyberPatriot/')


def autoTasks():
    f = open('Run.bat', 'x')
    f.write('@echo off\nschtasks /create /SC ONSTART /TN ScoringEngine /TR C:\\CyberPatriot\\RunScoring.bat /RL HIGHEST\nschtasks/create /SC MINUTE /MO 2 /TN C:\\CyberPatriot\\RepeatScoring.ps1 /RL HIGHEST')
    f.close()
    r = open(r'C:\\CyberPatriot\\RunScoring.bat', 'x')
    r.write('@echo off\ncd C:\\CyberPatriot\n.\scoring_engine.exe')
    r.close()
    q = open(r"C:\\CyberPatriot\\RepeatScoring.ps1", 'w+')
    q.write('Get-Process WinStore.app > test.txt\n$Text = Get-Content -Path C:\\Users\\CyberPatriot\\test.txt\n$Text.GetType() | Format-Table -AutoSize\n$new = $Text[3].split()| where {$_}\nif ($new[6] -eq \'0\'){\n\t.\scoring_engine.exe\n}')
    q.close()
    subprocess.Popen([r'Run.bat'])
    os.remove('Run.bat')


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

'''
f = open('install.bat', 'x')
f.write('pyinstaller -y -F -w --add-data "C:/Users/CyberPatriot/Desktop/Scoring_engine/balloontip.py";"." "C:/Users/CyberPatriot/Desktop/Scoring_engine/scoring_engine.py"')
f.close()
subprocess.Popen([r'install.bat'])
time.sleep(15)
os.remove('install.bat')
'''