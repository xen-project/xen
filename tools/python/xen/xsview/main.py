from xsviewer import *
from qt import *

def main(args):
    app = QApplication(args)
    mainwin = XSViewer(app)
    mainwin.show()
    app.connect(app, SIGNAL("lastWindowClosed()"),
                app, SLOT("quit()"))
    app.exec_loop()
