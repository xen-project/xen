import socket

from xen.web import protocol, unix

from xen.xend.XendLogging import log
from xen.xend import XendNode
from xen.xend import XendOptions

UDEV_EVENT_PATH = '\0/org/xen/xend/udev_event'

class UdevEventProtocol(protocol.Protocol):

    def __init__(self):
        protocol.Protocol.__init__(self)

    def dataReceived(self, data):
        udev_event = {}
        for entry in data.split('\0'):
            try:
                opt, val = entry.split("=")
                udev_event[opt] = val
            except (TypeError, ValueError):
                pass
        if udev_event.get('ACTION', None) is None:
            log.warn("Invalid udev event received")
            return

        log.debug("udev event received: %s", udev_event)

        self._process_event(udev_event)

    def _process_event(self, udev_event):
        try:
            if (udev_event.get('SUBSYSTEM', None) == 'pci'):
                pci_name = udev_event.get('PCI_SLOT_NAME', None)
                if (udev_event['ACTION'] == 'add'):
                    log.info("Adding pci device %s", pci_name)
                    XendNode.instance().add_PPCI(pci_name)
                elif (udev_event['ACTION'] == 'remove'):
                    log.info("Removing pci device %s", pci_name)
                    XendNode.instance().remove_PPCI(pci_name)

            elif (udev_event.get('SUBSYSTEM', None) == 'scsi'):
                hctl = None
                devpath = udev_event.get('DEVPATH', None)
                if devpath:
                    hctl = devpath.split('/')[-1]
                    if len(hctl.split(':')) != 4:
                        hctl = None
                if hctl is None:
                    # By any possibility, if an HCTL isn't gotten from
                    # the udev event, the udev event is ignored.
                    log.warn("Invalid udev event about scsi received")
                    return

                if (udev_event['ACTION'] == 'add'):
                    log.info("Adding scsi device %s", hctl)
                    XendNode.instance().add_PSCSI(hctl)
                elif (udev_event['ACTION'] == 'remove'):
                    log.info("Removing scsi device %s", hctl)
                    XendNode.instance().remove_PSCSI(hctl)

            elif (udev_event.get('SUBSYSTEM', None) == 'usb'):
                busid = udev_event.get('KERNEL', None)
                if busid:
                    if len(busid.split(':')) != 2:
                        return
                if (udev_event['ACTION'] == 'add'):
                    log.info("Adding usb device %s", busid)
                    XendNode.instance().add_usbdev(busid)
                elif (udev_event['ACTION'] == 'remove'):
                    log.info("Removing usb device %s", busid)
                    XendNode.instance().remove_usbdev(busid)

            elif (udev_event.get('SUBSYSTEM', None) == 'net'):
                interface = udev_event.get('INTERFACE', None)
                if (udev_event['ACTION'] == 'add'):
                    log.info("Adding net device %s", interface)
                    XendNode.instance().add_network(interface)
                elif (udev_event['ACTION'] == 'remove'):
                    log.info("Removing net device %s", interface)
                    XendNode.instance().remove_network(interface)

        except Exception, e:
            log.warn("error while processing udev event(): %s" % str(e))


def listenUdevEvent():
    xoptions = XendOptions.instance()
    if xoptions.get_xend_udev_event_server():
        unix.UnixDgramListener(UDEV_EVENT_PATH, UdevEventProtocol)

