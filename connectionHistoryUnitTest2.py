
connection1 = 0
connection2 = 0
connection3 = 0

connectionsArray = [connection1, connection2, connection3]


def clearOldestConnections(numConnections = 1):
    for number in range(numConnections):
        global connectionsArray
        connectionsArray.pop()


def testClearOldestConnections():
    clearOldestConnections()
    global connectionsArray
    assert connectionsArray == [connection1, connection2]


if __name__ == "__main__":

    testClearOldestConnections()