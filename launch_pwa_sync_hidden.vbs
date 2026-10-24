Option Explicit
' ============================================================================
' HL AI Trader v1 - Windowless Stealth PWA Git Sync Launcher (launch_pwa_sync_hidden.vbs)
' Directory: e:\hl-ai-trader-auto (Strictly isolated from e:\gmo-ai-trader-auto)
' Forces PYTHONDONTWRITEBYTECODE=1 (-B) and SW_HIDE (0, WaitOnReturn=False)
' ============================================================================

Dim shell, fso, env, scriptDir, venvPythonw, venvPython, pythonExe, targetScript, cmd
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
Set env = shell.Environment("PROCESS")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = scriptDir

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

targetScript = fso.BuildPath(scriptDir, "src\pwa_git_sync_worker.py")
cmd = pythonExe & " -B """ & targetScript & """"

' WindowStyle = 0 (SW_HIDE: completely invisible), WaitOnReturn = False
shell.Run cmd, 0, False
WScript.Quit 0
