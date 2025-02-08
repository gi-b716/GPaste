# backup.py - 数据库备份脚本
import subprocess
from datetime import datetime

def backup():
    timestamp = datetime.now().strftime('%Y%m%d-%H%M')
    filename = f"backup_{timestamp}.sql"
    
    cmd = [
        'mysqldump',
        '--user=your_username',
        '--password=your_password',
        'clipboard_db'
    ]
    
    with open(filename, 'w') as f:
        subprocess.run(cmd, stdout=f, check=True)
    
    print(f"备份完成：{filename}")

if __name__ == '__main__':
    backup()