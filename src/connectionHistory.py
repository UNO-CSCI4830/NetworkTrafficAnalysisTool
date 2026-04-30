import datetime
import main



todaysDate = datetime.datetime.today()

storingPeriod = datetime.timedelta.days(30)

expirationDate = todaysDate - storingPeriod

connectionsArray = []

id = 0

#This should be run frequently to keep stored list current
def getConnections():
    global connectionsArray
    connections = main.connections

    for connection in connections:
        id += 1
        formattedConnection = [connection, todaysDate, id]
        connectionsArray.append(formattedConnection)
    
    


#This can be run on the order of once a day
def checkExpiration():
    global connectionsArray
    global expirationDate
    for connection in connectionsArray:
        if connection[1] < expirationDate:
            clearSpecificConnection(connection[2])
        
    


#This can be run on the order of once a day
#This throws an error and alerts the user if the size of connections array exceeds 10,000 connections. This is a large number of connections, but still a relitively small amount of storage space. Since each individual connection is only a few bytes of data, storing this # will not be a problem. If left to run unchecked, it could(potentially but not likely) use a ridiculous amount of data while storing an unnecesary number of past connections. 
def checkSizeConnectionsArray(connectionsArray):
    if len(connectionsArray) > 10000:
        raise Exception("Array has exceeded maximum number of connections and an action must be taken.")
    
    else:
        print(f"Array is storing a suitable number of connections, currently storing the last {len(connectionsArray)} connections from the last 30 days.")
    



def fullyClearConnectionArray():
    global connectionsArray
    connectionsArray = []


#Takes in a certain number as a parameter and removes the oldest connections up to that number of connections.
def clearOldestConnections(numConnections = 1000):
    for number in numConnections:
        global connectionsArray
        connectionsArray.pop()
    


#Removes specific connection log based off of its ID
def clearSpecificConnection(id):
    global connectionsArray
    for connection in connectionsArray:
        if connection[2] == id:
            connectionsArray.remove(connection)

def printArrayForUser():
    global connectionsArray
    for connection in connectionsArray:
        print(f"Connection: {connection[0]}, Date: {connection[1]}, Unique Connection ID: {connection[2]}")


        
    

