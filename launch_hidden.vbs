Option Explicit
' ============================================================================
' HL AI Trader v1 - Windowless Stealth Launcher (launch_hidden.vbs)
' Directory: e:\hl-ai-trader-auto (Strictly isolated from e:\gmo-ai-trader-auto)
' Forces PYTHONDONTWRITEBYTECODE=1 (-B) and SW_HIDE (0, WaitOnReturn=False)
' ============================================================================

Dim shell, fso, env, scriptDir, venvPythonw, venvPython, pythonExe, targetScript, extraArgs, i, argVal, cmd
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
Set env = shell.Environment("PROCESS")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = scriptDir

' Enforce bytecode suppression, UTF-8 I/O, and isolated Git config
env("PYTHONDONTWRITEBYTECODE") = "1"
env("PYTHONUTF8") = "1"
env("GIT_CONFIG_GLOBAL") = fso.BuildPath(scriptDir, ".hl_gitconfig")

venvPythonw = fso.BuildPath(scriptDir, ".venv\Scripts\pythonw.exe")
venvPython = fso.BuildPath(scriptDir, ".venv\Scripts\python.exe")
If fso.FileExists(venvPythonw) Then
    pythonExe = """" & venvPythonw & """"
ElseIf fso.FileExists(venvPython) Then
    pythonExe = """" & venvPython & """"
Else
    pythonExe = "pythonw.exe"
End If

If WScript.Arguments.Count > 0 Then
    targetScript = WScript.Arguments(0)
Else
    targetScript = fso.BuildPath(scriptDir, "watchdog.py")
End If

extraArgs = ""
If WScript.Arguments.Count > 1 Then
    For i = 1 To WScript.Arguments.Count - 1
        argVal = WScript.Arguments(i)
        If InStr(argVal, " ") > 0 Then
            extraArgs = extraArgs & " """ & argVal & """"
        Else
            extraArgs = extraArgs & " " & argVal
        End If
    Next
End If

cmd = pythonExe & " -B """ & targetScript & """" & extraArgs

' WindowStyle = 0 (SW_HIDE: completely invisible), WaitOnReturn = False
shell.Run cmd, 0, False
WScript.Quit 0
