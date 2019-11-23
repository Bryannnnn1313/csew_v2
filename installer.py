import os
import subprocess


def autoTasks():
    f = open('Run.bat', 'x')
    f.write('@echo off\nschtasks /create /SC ONSTART /TN ScoringEngine /TR C:\\CyberPatriot\\RunScoring.bat /RL HIGHEST\nschtasks/create /SC MINUTE /MO 2 /TN C:\\CyberPatriot\\RepeatScoring.ps1 /RL HIGHEST')
    f.close()
    r = open(r'C:\\CyberPatriot\\RunScoring.bat', 'x')
    r.write('@echo off\ncd C:\\CyberPatriot\n.\scoring_engine.exe')
    r.close()
    q = open(r"C:\\CyberPatriot\\RepeatScoring.ps1", 'w+')
    q.write('Get-Process WinStore.app > test.txt\n$Text = Get-Content -Path C:\\Users\\CyberPatriot\\test.txt\n$Text.GetType() | Format-Table -AutoSize\n$new = $Text[3].split()| where {$_}\nif ($new[6] -eq '0'){\n\t.\scoring_engine.exe\n}')
    q.close()
    subprocess.Popen([r'Run.bat'])
    os.remove('Run.bat')
