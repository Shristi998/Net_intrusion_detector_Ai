@echo off
set PYTHONIOENCODING=utf-8
start "Detector" cmd /c python -c "import sys; f = open('output.txt', 'w'); f.write(str(sys.argv)); f.close()" -i "Ethernet 2"
