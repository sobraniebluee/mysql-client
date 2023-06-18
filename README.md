<h1>Mysql Client</h1>

My simple implementation of <a href="https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html">Mysql Client/Server Protocol</a>

Support connect only via unix_sockets and doesnt't implemented SSL

Example:

```py 
    from src.connector import MySqlConnector

    mysql = MySqlConnector(username="root",
                           password="",
                           database="chat",
                           autocommit=False)
    mysql.connect()

    mysql.begin()
    affected_rows = mysql.query("INSERT INTO test VALUES (NULL, 'hello')")  # return affected rows
    mysql.commit()
    mysql.query("SELECT * FROM test")
    print(mysql.fetchall())
```
