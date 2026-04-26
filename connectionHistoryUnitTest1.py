
connection1 = 0
connection2 = 0
connection3 = 0

connectionsArray = [connection1, connection2, connection3]


def fullyClearConnectionArray():
    global connectionsArray
    connectionsArray = []


def testFullyClearConnectionArray():
    fullyClearConnectionArray()
    assert connectionsArray == []


if __name__ == "__main__":
    testFullyClearConnectionArray()