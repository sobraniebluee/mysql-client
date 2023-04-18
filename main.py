from src.connector import MySqlConnector


if __name__ == "__main__":
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


