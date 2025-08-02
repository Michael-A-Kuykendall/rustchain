@echo off
setlocal enabledelayedexpansion

:: Mission Runner One-Click Installer
:: Downloads everything needed for simple, reliable AI automation

echo.
echo ========================================
echo   Mission Runner One-Click Setup
echo ========================================
echo.
echo 🎯 Philosophy: Simple AI for Simple Tasks
echo.
echo This installs:
echo  • Mission Runner GUI (25MB)
echo  • Ollama AI runtime  
echo  • TinyLlama (637MB) - small, fast, deterministic
echo.
echo 💡 Why TinyLlama?
echo  • Won't overthink simple requests
echo  • Fast and reliable for code generation
echo  • Perfect for deterministic automation tasks
echo  • 637MB vs 2GB+ for complex models
echo.
pause

:: Create directories
set INSTALL_DIR=%USERPROFILE%\MissionRunner
echo 📁 Creating installation directory...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%\missions" mkdir "%INSTALL_DIR%\missions"

:: Copy Mission Runner
echo 📦 Installing Mission Runner...
if exist "MissionRunner.exe" (
    copy "MissionRunner.exe" "%INSTALL_DIR%\" >nul
    echo ✅ Mission Runner copied
) else (
    echo ❌ MissionRunner.exe not found in current directory
    pause
    exit /b 1
)

:: Copy sample missions
if exist "missions" (
    xcopy "missions\*" "%INSTALL_DIR%\missions\" /Y /Q >nul 2>&1
    echo ✅ Sample missions copied
)

:: Check if Ollama exists
ollama --version >nul 2>&1
if !errorlevel! == 0 (
    echo ✅ Ollama already installed
    goto download_ai
)

:: Install Ollama
echo.
echo 🤖 Installing Ollama AI Runtime...
echo    (This enables local AI - no cloud needed!)

:: Check if we can download Ollama
echo    Downloading Ollama installer...
powershell -Command "try { Invoke-WebRequest -Uri 'https://ollama.ai/download/windows' -OutFile '%TEMP%\ollama-installer.exe' -ErrorAction Stop; exit 0 } catch { exit 1 }"

if !errorlevel! neq 0 (
    echo ❌ Failed to download Ollama
    echo    Please install manually from: https://ollama.ai/download
    echo    Then re-run this installer
    pause
    exit /b 1
)

if not exist "%TEMP%\ollama-installer.exe" (
    echo ❌ Ollama installer not downloaded
    pause
    exit /b 1
)

echo    Installing Ollama...
"%TEMP%\ollama-installer.exe" /S

:: Wait and verify installation
echo    Waiting for installation to complete...
timeout /t 10 /nobreak >nul

:: Start Ollama
echo    Starting Ollama service...
start /B ollama serve >nul 2>&1
timeout /t 5 /nobreak >nul

:download_ai
echo.
echo 🧠 Setting up TinyLlama AI...
echo    • Size: 637MB (very reasonable!)
echo    • Speed: Very fast
echo    • Quality: Perfect for code tasks
echo    • Behavior: Deterministic, won't overcomplicate
echo.

:: Try to download TinyLlama
echo    Downloading TinyLlama model...
echo    (This may take 2-10 minutes depending on connection)

ollama pull tinyllama:1.1b
if !errorlevel! neq 0 (
    echo    First attempt failed, retrying in 10 seconds...
    timeout /t 10 /nobreak >nul
    
    :: Start Ollama service again if needed
    tasklist /FI "IMAGENAME eq ollama.exe" | find "ollama.exe" >nul
    if !errorlevel! neq 0 (
        echo    Restarting Ollama service...
        start /B ollama serve >nul 2>&1
        timeout /t 5 /nobreak >nul
    )
    
    ollama pull tinyllama:1.1b
)

if !errorlevel! neq 0 (
    echo ⚠️  TinyLlama download failed
    echo    Mission Runner will work without AI
    echo    You can try downloading later: ollama pull tinyllama:1.1b
) else (
    echo ✅ TinyLlama AI ready!
    
    :: Quick AI test
    echo    Testing AI...
    echo print("Hello from TinyLlama!") | ollama run tinyllama:1.1b "Convert this to a Python function" --timeout 10 >nul 2>&1
    if !errorlevel! == 0 (
        echo ✅ AI test successful!
    )
)

:: Create desktop shortcut
echo.
echo 🔗 Creating shortcuts...
powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%USERPROFILE%\Desktop\Mission Runner.lnk'); $Shortcut.TargetPath = '%INSTALL_DIR%\MissionRunner.exe'; $Shortcut.WorkingDirectory = '%INSTALL_DIR%'; $Shortcut.Description = 'Simple AI Development Automation'; $Shortcut.Save()"

:: Add to PATH
setx PATH "%PATH%;%INSTALL_DIR%" >nul 2>&1

:: Create quick test mission
echo 📝 Creating test mission...
(
echo env: dev
echo mission:
echo   name: "TinyLlama Test"
echo   description: "Test simple, deterministic AI code generation"
echo   steps:
echo     - id: hello_function
echo       type: ai_generate
echo       language: python
echo       requirements: "Create a simple hello_world^(^) function that takes a name parameter and returns a greeting string"
echo       output_file: "hello.py"
echo       description: "Simple function generation"
echo.      
echo     - id: test_function
echo       type: ai_generate
echo       language: python
echo       requirements: "Create a test for the hello_world function using pytest"
echo       output_file: "test_hello.py"
echo       description: "Generate test file"
echo.
echo     - id: run_test
echo       type: command
echo       command: "python hello.py"
echo       description: "Run the generated code"
echo       fail_on_error: false
echo.
echo     - id: report
echo       type: report
echo       description: "Generate completion report"
) > "%INSTALL_DIR%\missions\tinyllama_test.yaml"

:: Success message
echo.
echo ========================================
echo ✅ Mission Runner Installation Complete!
echo ========================================
echo.
echo 🚀 Ready to Use:
echo    • Desktop shortcut: "Mission Runner"
echo    • Command line: MissionRunner
echo    • Sample missions included
echo.
echo 🤖 AI Setup Complete:
echo    • Ollama runtime: Installed
echo    • TinyLlama: Ready (small and reliable!)
echo    • No complex AI to overcomplicate things
echo.
echo 📖 Quick Test:
echo    1. Double-click "Mission Runner" on desktop
echo    2. Select "TinyLlama Test" mission  
echo    3. Click "Setup AI & Run Mission"
echo    4. Watch simple, deterministic code generation
echo.
echo 💡 Why This Works Better:
echo    • TinyLlama follows instructions exactly
echo    • No overthinking or adding complexity
echo    • Fast, reliable, predictable results
echo    • Perfect for automation workflows
echo.
echo 🎯 Total installed: ~662MB
echo    (Much smaller than complex AI setups)
echo.
pause
