# GPaste

## 安装

确保本地具有 `mysql` 与 `python`。

使用 `pip` 安装 `src/requirements.txt` 中的依赖。

创建名为 `clipboard-db` 的数据库，在环境变量中新建一项 `SQL_USERNAME` 填写连接用户名，`SQL_PASSWORD` 填写连接密码。运行 `src` 目录下的 `init.py` 初始化数据库。

## 运行

运行 `app.py`，启动剪贴板。调试模式默认为开，你可以在代码里关闭它。

运行 `backup.py` 执行数据库自动备份，默认时间为 45 分钟一次，你可以修改这个值。

系统会默认将第一个用户设为超级管理员。`app.py` 中维护了一个 `ROOT_USER` 列表，你可以在里面管理超级管理员。

又或者，你可以通过调用 `src/get_admin.py <user_id>` 给予指定用户管理员。
