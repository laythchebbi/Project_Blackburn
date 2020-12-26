#pip install mysql-connector-python

#Create connection

import mysql.connector

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    password=""
)
print(mydb)
mydb.close()
