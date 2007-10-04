from qt import *

import xen.lowlevel.xs

class XSViewer(QMainWindow):
    
    def __init__(self, app):
        apply(QMainWindow.__init__, (self,))
        
        self.setCaption('XenStore Viewer')

        self.new_node = QAction(self, 'New Node')
        self.new_node.setText('New Node...')
        self.connect(self.new_node, SIGNAL('activated()'),
                     self.do_new_node)
        
        self.rm_node = QAction(self, 'Remove Node')
        self.rm_node.setText('Remove Node')
        self.connect(self.rm_node, SIGNAL('activated()'),
                     self.do_rm_node)

        self.refresh = QAction(self, 'Refresh')
        self.refresh.setText('Refresh')
        self.connect(self.refresh, SIGNAL('activated()'),
                     self.do_refresh)
 
        self.file_menu = QPopupMenu(self)
        self.new_node.addTo(self.file_menu)
        self.rm_node.addTo(self.file_menu)
        self.refresh.addTo(self.file_menu)


        self.about = QAction(self, 'About')
        self.about.setText('About...')
        self.connect(self.about, SIGNAL('activated()'),
                     self.do_about)

        self.help_menu = QPopupMenu(self)
        self.about.addTo(self.help_menu)

        self.menubar = QMenuBar(self)
        self.menubar.insertItem('&File', self.file_menu)
        self.menubar.insertItem('&Help', self.help_menu)

        self.vbox = QVBox(self)
        self.setCentralWidget(self.vbox)

        self.xs_tree = QListView(self.vbox)
        self.xs_tree.addColumn('Key')
        self.xs_tree.setRootIsDecorated(1)
        self.xs_tree.connect(self.xs_tree, SIGNAL('selectionChanged(QListViewItem*)'), self.showValue)

        self.info_box = QHBox(self.vbox)
        self.info_box.setMargin(2)
        self.info_box.setSpacing(2)
        self.info_label = QLabel(self.info_box)
        self.info_label.setText('Value')
        self.info = QLineEdit(self.info_box)
        self.setval = QPushButton(self.info_box)
        self.setval.setText('Set')
        self.setval.connect(self.setval, SIGNAL('clicked()'), self.setValue)

        self.xs_handle = xen.lowlevel.xs.xs()

        self.showtree()


    def showtree(self):
        xstransact = self.xs_handle.transaction_start()
        self.walktree(xstransact, '/', '/', self.xs_tree)
        self.xs_handle.transaction_end(xstransact)

    def walktree(self, trans, node, subdir_prepend, parent_widget):

        ents = self.xs_handle.ls(trans, node)
        if ents == None:
            return

        for e in ents:
            i = QListViewItem(parent_widget, e)
            i.full_path = subdir_prepend + e
            self.walktree(trans, i.full_path, i.full_path + '/', i)

    
    def showValue(self, item):
        trans = self.xs_handle.transaction_start()
        val = self.xs_handle.read(trans, item.full_path)
        self.info.setText(val)
        self.xs_handle.transaction_end(trans)


    def setValue(self):
        trans = self.xs_handle.transaction_start()
        item = self.xs_tree.currentItem()
        newval = str(self.info.text())

        self.xs_handle.write(trans, item.full_path, newval)

        self.xs_handle.transaction_end(trans)


    def do_refresh(self):
        self.xs_tree.clear()
        self.info.clear()
        self.showtree()

    def do_new_node(self):
        dia = QDialog(self)
        dia.setCaption('Create new node')

        vbox = QVBox(dia)

        setting_hbox = QHBox(vbox)
        
        path_label = QLabel(setting_hbox)
        path_label.setText('Node path')
        path = QLineEdit(setting_hbox)
        
        value_label = QLabel(setting_hbox)
        value_label.setText('Node value')
        val = QLineEdit(setting_hbox)

        button_hbox = QHBox(vbox)

        set = QPushButton(button_hbox)
        set.setText('Set')
        self.connect(set, SIGNAL('clicked()'), dia, SLOT('accept()'))

        cancel = QPushButton(button_hbox)
        cancel.setText('Cancel')
        self.connect(cancel, SIGNAL('clicked()'), dia, SLOT('reject()'))

        setting_hbox.adjustSize()
        button_hbox.adjustSize()
        vbox.adjustSize()

        if dia.exec_loop() == QDialog.Accepted:
            trans = self.xs_handle.transaction_start()
            self.xs_handle.write(trans, str(path.text()), str(val.text()))
            
            self.xs_handle.transaction_end(trans)

            self.do_refresh()
        
        # nothing to set.

    def do_rm_node(self):
        trans = self.xs_handle.transaction_start()
        item = self.xs_tree.currentItem()
        newval = str(self.info.text())

        self.xs_handle.rm(trans, item.full_path)

        self.xs_handle.transaction_end(trans)

        self.do_refresh()

    def do_about(self):
        about_dia = QMessageBox(self)
        about_dia.setIcon(QMessageBox.Information)

        about_dia.setCaption('About XenStore Viewer')
        about_dia.setText('XenStore Viewer\n'
                          'by Mark Williamson <mark.williamson@cl.cam.ac.uk>')

        about_dia.exec_loop()
        
        
