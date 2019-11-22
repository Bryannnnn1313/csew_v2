import os
import subprocess


def autoTasks():
    f = open('Run.bat', 'x')
    f.write('@echo off\nschtasks /create /SC ONSTART /TN ScoringEngine /TR C:\\CyberPatriot\\RunScoring.bat /RL HIGHEST')
    f.close()
    r = open(r'C:\\CyberPatriot\\RunScoring.bat', 'x')
    r.write('@echo off\ncd C:\\CyberPatriot\npython scoring_engine.py')
    r.close()
    subprocess.Popen([r'Run.bat'])
    os.remove('Run.bat')
