import ctypes






# This function can be called at the press of some button and will generate a window with help information.

def createPopupHelpWindow(){
    ctypes.windll.user32.MessageBoxW(0, "Your message here", "Popup Title", 0)
}


if __name__ == "main"{
    createPopupHelpWindow()
}