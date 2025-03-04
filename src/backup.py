# backup.py - 数据库备份脚本
import subprocess, os
from datetime import datetime, timedelta
import time, logging

logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)
logFormatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logFile = logging.FileHandler("log/backup_{0}.log".format(time.strftime("%Y-%m-%d_%H-%M-%S",time.localtime(time.time()))), encoding="utf-8")
logFile.setLevel(logging.DEBUG)
logFile.setFormatter(logFormatter)
logger.addHandler(logFile)

BACKUP_TIME = 45
MAX_BACKUP = 100

def backup():
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    filename = f"./backup/backup_{timestamp}.sql"
    
    cmd = [
        'mysqldump',
        '--user={0}'.format(os.environ['SQL_USERNAME']),
        '--password={0}'.format(os.environ['SQL_PASSWORD']),
        'clipboard_db'
    ]
    
    with open(filename, 'w') as f:
        subprocess.run(cmd, stdout=f, check=True)
    
    print(f"备份完成：{filename}\n下一次备份：{datetime.now() + timedelta(minutes=BACKUP_TIME)}")
    logger.info(f"备份完成：{filename}\n下一次备份：{datetime.now() + timedelta(minutes=BACKUP_TIME)}")

def cleanup():
    backups = sorted(os.listdir('./backup'))
    if len(backups) > MAX_BACKUP:
        for i in range(len(backups) - MAX_BACKUP):
            os.remove(f'./backup/{backups[i]}')
            print(f"删除备份：{backups[i]}")
            logger.info(f"删除备份：{backups[i]}")

if __name__ == '__main__':
    while True:
        cleanup()
        backup()
        time.sleep(BACKUP_TIME*60)
