# GPaste

## 安装

确保本地具有 `mysql` 与 `python`。

使用 `pip` 安装 `src/requirements.txt` 中的依赖。

创建名为 `clipboard-db` 的数据库，在环境变量中新建一项 `SQL_USERNAME` 填写连接用户名，`SQL_PASSWORD` 填写连接密码。运行 `src` 目录下的 `utils.py init_db` 初始化数据库。

## 运行

运行 `app.py`，启动剪贴板。通过 `WSGI` 与 `DEBUG` 两个常量控制服务器。

运行 `backup.py` 执行数据库自动备份，默认时间为 45 分钟一次，你可以修改这个值。你也可以修改最大备份数量。

请通过 `SYSTEM_USER` 常量设置一个用户为系统用户。

你可以通过调用 `src/utils.py get_admin <user_id>` 给予指定用户管理员。
