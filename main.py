from src.connector import MySqlConnector


if __name__ == "__main__":
    mysql = MySqlConnector(username="root",
                           password="",
                           database="chat",
                           autocommit=False)
    mysql.connect()
    # mysql.begin()
    # mysql.commit()
    # mysql.query("DROP TABLE IF EXISTS test")
    mysql.begin()
    # a_r = mysql.query("CREATE TABLE test (id INT NOT NULL PRIMARY KEY AUTO_INCREMENT, name VARCHAR(32))")
    affected_rows = mysql.query("INSERT INTO test VALUES (NULL, 'hello')")
    print(affected_rows)
    mysql.commit()
    mysql.query("SELECT * FROM test")



