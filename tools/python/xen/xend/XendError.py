
class XendError(ValueError):
    
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

class VmError(XendError):
    """Vm construction error."""

    pass

