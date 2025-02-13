import os

os.chdir("src")
os.system("pip install -r requirements.txt")
os.system("start cmd.exe /c python app.py")
os.system("start cmd.exe /c python backup.py")
