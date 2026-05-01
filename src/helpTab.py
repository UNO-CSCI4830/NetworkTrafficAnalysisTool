import tkinter


pages = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
pageInformation = ["This is the info for page 1", "This is the info for page 2", "This is the info for page 3", "This is the info for page 4", "This is the info for page 5", "This is the info for page 6", "This is the info for page 7", "This is the info for page 8", "This is the info for page 9", "This is the info for page 10", ]

counter = 0



# This function can be called at the press of some button and will generate a window with help information.

def createPopupHelpWindow():
    try:
        global pages
        global counter

        popupWindow = tkinter.Toplevel()
        popupWindow.title("Help Tab")
        popupWindow.geometry("500x400")
        popupWindow.resizable(True, True)

        Page1Info = tkinter.Label(popupWindow, text=f"This is help page {pages[counter]}.", font = (20), height = 10)
        PageHelpInfo = tkinter.Label(popupWindow, text=f"{pageInformation[counter]}.", font = (10), wraplength=400)

        #I have to use lambda syntax in order to pass a function with parameters to a button, otherwise its not needed
        Page1Button = tkinter.Button(popupWindow, text="Next Page", width = 12, font = ("bold"), command = lambda: nextPage(popupWindow))
        exitButton = tkinter.Button(popupWindow, text="Close Help Tab", width = 12, font = ("bold"), command = popupWindow.destroy)

        Page1Info.pack()
        PageHelpInfo.pack()
        Page1Button.pack(side = "left", padx = 50)
        exitButton.pack(side = "right", padx = 50)



        #This line keeps the window open, otherwise it closes after 1 frame.
        popupWindow.wait_window()


    except Exception:

        Page1Info = tkinter.Label(popupWindow, text=f"This is the final help page.", font = (20), height = 10)

        #I have to use lambda syntax in order to pass a function with parameters to a button, otherwise its not needed
        
        exitButton = tkinter.Button(popupWindow, text="Close Help Tab", width = 12, font = ("bold"), command = popupWindow.destroy)

        Page1Info.pack()
        
        exitButton.pack(side = "bottom", pady = 20)



        #This line keeps the window open, otherwise it closes after 1 frame.
        popupWindow.wait_window()


def nextPage(window):
    global counter
    counter += 1
    window.destroy()
    createPopupHelpWindow()
    print("hello World")


if __name__ == "__main__":
    #Tkinter automatically creates a smaller window, the "root" window. Even when I create my custom one, so these next lines are to remove that window.
    rootWindow = tkinter.Tk()
    rootWindow.withdraw()
    createPopupHelpWindow()
