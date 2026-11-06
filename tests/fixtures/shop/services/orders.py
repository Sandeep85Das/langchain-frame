import sqlite3


def for_customer(name):
    db = sqlite3.connect("shop.db")
    cur = db.cursor()
    cur.execute("SELECT * FROM orders WHERE customer = '" + name.strip() + "'")
    return cur.fetchall()
