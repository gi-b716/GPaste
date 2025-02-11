# backup.py - 数据库备份脚本
import subprocess, os
from datetime import datetime, timedelta
import time

BACKUP_TIME = 45

def backup():
    timestamp = datetime.now().strftime('%Y%m%d-%H%M')
    filename = f"./backup/backup_{timestamp}.sql"
    
    cmd = [
        'mysqldump',
        '--user={0}'.format(os.environ['SQL_USERNAME']),
        '--password={0}'.format(os.environ['SQL_PASSWORD']),
        'clipboard_db'
    ]
    
    with open(filename, 'w') as f:
        subprocess.run(cmd, stdout=f, check=True)
    
    print(f"备份完成：{filename}\n下一次备份：{datetime.now() + timedelta(seconds=BACKUP_TIME)}")

if __name__ == '__main__':
    while True:
        backup()
        time.sleep(BACKUP_TIME*60)
