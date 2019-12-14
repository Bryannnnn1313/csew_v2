import os
# scripCont = {} # {1 : [option : 'OPTIONNAME', script : 'SCRIPTCODE', language : 'bat/ps1'], 2 : [option : 'OPTIONNAME', script : 'SCRIPTCODE', language : 'bat/ps1'], ....}
optionCont = {}  # {1 : [option : 'OPTIONNAME', scriptout : (line1, line2, ...)], 2 : [option : 'OPTIONNAME', scriptout : (line1, line2, ...)], ....}
ps1script = ''
batscript = '@echo 0ff\n'


def setup(optionName, scriptCode, lang):
    global ps1script, batscript
    next = str(len(optionCont))
    # scripCont.update({next: {'option': optionName, 'script': scriptCode, 'language': lang}})
    optionCont.update({next: {'option': optionName, 'scriptout': ''}})
    if lang == 'ps1':
        ps1script += 'echo ##' + optionName + '## >> testout.cfg\n' + scriptCode + '\n'
    elif lang == 'bat':
        batscript += 'echo ##' + optionName + '## >> testout.cfg\n' + scriptCode + '\n'


def run():
    global ps1script, batscript
    if ps1script != '':
        batscript += 'Powershell.exe -Command "& {Start-Process Powershell.exe -ArgumentList \'-ExecutionPolicy Bypass -File "test.ps1"\' -Verb RunAs -Wait -WindowStyle Hidden}"\n'
        p = open('test.ps1', 'w+')
        p.write(str(ps1script))
        p.close()
    if batscript != '':
        b = open('test.bat', 'w+')
        b.write(batscript)
        b.close()
    f = open('invisible.vbs', 'w+')
    f.write('CreateObject("Wscript.Shell").Run """" & WScript.Arguments(0) & """", 0, False')
    f.close()
    os.system('wscript.exe "invisible.vbs" "test.bat"')

