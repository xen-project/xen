
#include <stdio.h>
#include "libxl.h"

int main(int argc, char **argv)
{
    libxl_domain_type libxl_domain_type_val;
    libxl_device_model_version libxl_device_model_version_val;
    libxl_console_type libxl_console_type_val;
    libxl_console_backend libxl_console_backend_val;
    libxl_disk_format libxl_disk_format_val;
    libxl_disk_backend libxl_disk_backend_val;
    libxl_nic_type libxl_nic_type_val;
    libxl_action_on_shutdown libxl_action_on_shutdown_val;
    libxl_event_type libxl_event_type_val;
    libxl_button libxl_button_val;
    int rc;

    printf("libxl_domain_type -- to string:\n");
    printf("\tFV = %d = \"%s\"\n", LIBXL_DOMAIN_TYPE_FV, libxl_domain_type_to_string(LIBXL_DOMAIN_TYPE_FV));
    printf("\tPV = %d = \"%s\"\n", LIBXL_DOMAIN_TYPE_PV, libxl_domain_type_to_string(LIBXL_DOMAIN_TYPE_PV));

    printf("libxl_domain_type -- from string:\n");
    libxl_domain_type_val = -1;
    rc = libxl_domain_type_from_string("FV", &libxl_domain_type_val);
    printf("\tFV = \"%s\" = %d (rc %d)\n", "FV", libxl_domain_type_val, rc);
    libxl_domain_type_val = -1;
    rc = libxl_domain_type_from_string("pV", &libxl_domain_type_val);
    printf("\tPV = \"%s\" = %d (rc %d)\n", "pV", libxl_domain_type_val, rc);
    libxl_domain_type_val = -1;
    rc = libxl_domain_type_from_string("an InVALId VALUE", &libxl_domain_type_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "an InVALId VALUE", libxl_domain_type_val, rc);

    printf("libxl_device_model_version -- to string:\n");
    printf("\tQEMU_XEN_TRADITIONAL = %d = \"%s\"\n", LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL, libxl_device_model_version_to_string(LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN_TRADITIONAL));
    printf("\tQEMU_XEN = %d = \"%s\"\n", LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN, libxl_device_model_version_to_string(LIBXL_DEVICE_MODEL_VERSION_QEMU_XEN));

    printf("libxl_device_model_version -- from string:\n");
    libxl_device_model_version_val = -1;
    rc = libxl_device_model_version_from_string("QEmU_Xen_TrAdiTioNAl", &libxl_device_model_version_val);
    printf("\tQEMU_XEN_TRADITIONAL = \"%s\" = %d (rc %d)\n", "QEmU_Xen_TrAdiTioNAl", libxl_device_model_version_val, rc);
    libxl_device_model_version_val = -1;
    rc = libxl_device_model_version_from_string("QemU_xen", &libxl_device_model_version_val);
    printf("\tQEMU_XEN = \"%s\" = %d (rc %d)\n", "QemU_xen", libxl_device_model_version_val, rc);
    libxl_device_model_version_val = -1;
    rc = libxl_device_model_version_from_string("aN InVALiD vaLUE", &libxl_device_model_version_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "aN InVALiD vaLUE", libxl_device_model_version_val, rc);

    printf("libxl_console_type -- to string:\n");
    printf("\tSERIAL = %d = \"%s\"\n", LIBXL_CONSOLE_TYPE_SERIAL, libxl_console_type_to_string(LIBXL_CONSOLE_TYPE_SERIAL));
    printf("\tPV = %d = \"%s\"\n", LIBXL_CONSOLE_TYPE_PV, libxl_console_type_to_string(LIBXL_CONSOLE_TYPE_PV));

    printf("libxl_console_type -- from string:\n");
    libxl_console_type_val = -1;
    rc = libxl_console_type_from_string("SErIaL", &libxl_console_type_val);
    printf("\tSERIAL = \"%s\" = %d (rc %d)\n", "SErIaL", libxl_console_type_val, rc);
    libxl_console_type_val = -1;
    rc = libxl_console_type_from_string("pv", &libxl_console_type_val);
    printf("\tPV = \"%s\" = %d (rc %d)\n", "pv", libxl_console_type_val, rc);
    libxl_console_type_val = -1;
    rc = libxl_console_type_from_string("An InvAlID valuE", &libxl_console_type_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "An InvAlID valuE", libxl_console_type_val, rc);

    printf("libxl_console_backend -- to string:\n");
    printf("\tXENCONSOLED = %d = \"%s\"\n", LIBXL_CONSOLE_BACKEND_XENCONSOLED, libxl_console_backend_to_string(LIBXL_CONSOLE_BACKEND_XENCONSOLED));
    printf("\tIOEMU = %d = \"%s\"\n", LIBXL_CONSOLE_BACKEND_IOEMU, libxl_console_backend_to_string(LIBXL_CONSOLE_BACKEND_IOEMU));

    printf("libxl_console_backend -- from string:\n");
    libxl_console_backend_val = -1;
    rc = libxl_console_backend_from_string("XENCoNSoleD", &libxl_console_backend_val);
    printf("\tXENCONSOLED = \"%s\" = %d (rc %d)\n", "XENCoNSoleD", libxl_console_backend_val, rc);
    libxl_console_backend_val = -1;
    rc = libxl_console_backend_from_string("iOEmU", &libxl_console_backend_val);
    printf("\tIOEMU = \"%s\" = %d (rc %d)\n", "iOEmU", libxl_console_backend_val, rc);
    libxl_console_backend_val = -1;
    rc = libxl_console_backend_from_string("an INvAliD VALuE", &libxl_console_backend_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "an INvAliD VALuE", libxl_console_backend_val, rc);

    printf("libxl_disk_format -- to string:\n");
    printf("\tUNKNOWN = %d = \"%s\"\n", LIBXL_DISK_FORMAT_UNKNOWN, libxl_disk_format_to_string(LIBXL_DISK_FORMAT_UNKNOWN));
    printf("\tQCOW = %d = \"%s\"\n", LIBXL_DISK_FORMAT_QCOW, libxl_disk_format_to_string(LIBXL_DISK_FORMAT_QCOW));
    printf("\tQCOW2 = %d = \"%s\"\n", LIBXL_DISK_FORMAT_QCOW2, libxl_disk_format_to_string(LIBXL_DISK_FORMAT_QCOW2));
    printf("\tVHD = %d = \"%s\"\n", LIBXL_DISK_FORMAT_VHD, libxl_disk_format_to_string(LIBXL_DISK_FORMAT_VHD));
    printf("\tRAW = %d = \"%s\"\n", LIBXL_DISK_FORMAT_RAW, libxl_disk_format_to_string(LIBXL_DISK_FORMAT_RAW));
    printf("\tEMPTY = %d = \"%s\"\n", LIBXL_DISK_FORMAT_EMPTY, libxl_disk_format_to_string(LIBXL_DISK_FORMAT_EMPTY));

    printf("libxl_disk_format -- from string:\n");
    libxl_disk_format_val = -1;
    rc = libxl_disk_format_from_string("uNKnOWn", &libxl_disk_format_val);
    printf("\tUNKNOWN = \"%s\" = %d (rc %d)\n", "uNKnOWn", libxl_disk_format_val, rc);
    libxl_disk_format_val = -1;
    rc = libxl_disk_format_from_string("QcoW", &libxl_disk_format_val);
    printf("\tQCOW = \"%s\" = %d (rc %d)\n", "QcoW", libxl_disk_format_val, rc);
    libxl_disk_format_val = -1;
    rc = libxl_disk_format_from_string("qcOW2", &libxl_disk_format_val);
    printf("\tQCOW2 = \"%s\" = %d (rc %d)\n", "qcOW2", libxl_disk_format_val, rc);
    libxl_disk_format_val = -1;
    rc = libxl_disk_format_from_string("vhd", &libxl_disk_format_val);
    printf("\tVHD = \"%s\" = %d (rc %d)\n", "vhd", libxl_disk_format_val, rc);
    libxl_disk_format_val = -1;
    rc = libxl_disk_format_from_string("raw", &libxl_disk_format_val);
    printf("\tRAW = \"%s\" = %d (rc %d)\n", "raw", libxl_disk_format_val, rc);
    libxl_disk_format_val = -1;
    rc = libxl_disk_format_from_string("EmpTy", &libxl_disk_format_val);
    printf("\tEMPTY = \"%s\" = %d (rc %d)\n", "EmpTy", libxl_disk_format_val, rc);
    libxl_disk_format_val = -1;
    rc = libxl_disk_format_from_string("aN INvAlId vAluE", &libxl_disk_format_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "aN INvAlId vAluE", libxl_disk_format_val, rc);

    printf("libxl_disk_backend -- to string:\n");
    printf("\tUNKNOWN = %d = \"%s\"\n", LIBXL_DISK_BACKEND_UNKNOWN, libxl_disk_backend_to_string(LIBXL_DISK_BACKEND_UNKNOWN));
    printf("\tPHY = %d = \"%s\"\n", LIBXL_DISK_BACKEND_PHY, libxl_disk_backend_to_string(LIBXL_DISK_BACKEND_PHY));
    printf("\tTAP = %d = \"%s\"\n", LIBXL_DISK_BACKEND_TAP, libxl_disk_backend_to_string(LIBXL_DISK_BACKEND_TAP));
    printf("\tQDISK = %d = \"%s\"\n", LIBXL_DISK_BACKEND_QDISK, libxl_disk_backend_to_string(LIBXL_DISK_BACKEND_QDISK));

    printf("libxl_disk_backend -- from string:\n");
    libxl_disk_backend_val = -1;
    rc = libxl_disk_backend_from_string("unKNOWN", &libxl_disk_backend_val);
    printf("\tUNKNOWN = \"%s\" = %d (rc %d)\n", "unKNOWN", libxl_disk_backend_val, rc);
    libxl_disk_backend_val = -1;
    rc = libxl_disk_backend_from_string("pHY", &libxl_disk_backend_val);
    printf("\tPHY = \"%s\" = %d (rc %d)\n", "pHY", libxl_disk_backend_val, rc);
    libxl_disk_backend_val = -1;
    rc = libxl_disk_backend_from_string("taP", &libxl_disk_backend_val);
    printf("\tTAP = \"%s\" = %d (rc %d)\n", "taP", libxl_disk_backend_val, rc);
    libxl_disk_backend_val = -1;
    rc = libxl_disk_backend_from_string("QdIsK", &libxl_disk_backend_val);
    printf("\tQDISK = \"%s\" = %d (rc %d)\n", "QdIsK", libxl_disk_backend_val, rc);
    libxl_disk_backend_val = -1;
    rc = libxl_disk_backend_from_string("AN InValID VALue", &libxl_disk_backend_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "AN InValID VALue", libxl_disk_backend_val, rc);

    printf("libxl_nic_type -- to string:\n");
    printf("\tIOEMU = %d = \"%s\"\n", LIBXL_NIC_TYPE_IOEMU, libxl_nic_type_to_string(LIBXL_NIC_TYPE_IOEMU));
    printf("\tVIF = %d = \"%s\"\n", LIBXL_NIC_TYPE_VIF, libxl_nic_type_to_string(LIBXL_NIC_TYPE_VIF));

    printf("libxl_nic_type -- from string:\n");
    libxl_nic_type_val = -1;
    rc = libxl_nic_type_from_string("ioemU", &libxl_nic_type_val);
    printf("\tIOEMU = \"%s\" = %d (rc %d)\n", "ioemU", libxl_nic_type_val, rc);
    libxl_nic_type_val = -1;
    rc = libxl_nic_type_from_string("vIf", &libxl_nic_type_val);
    printf("\tVIF = \"%s\" = %d (rc %d)\n", "vIf", libxl_nic_type_val, rc);
    libxl_nic_type_val = -1;
    rc = libxl_nic_type_from_string("aN invAlid vaLuE", &libxl_nic_type_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "aN invAlid vaLuE", libxl_nic_type_val, rc);

    printf("libxl_action_on_shutdown -- to string:\n");
    printf("\tDESTROY = %d = \"%s\"\n", LIBXL_ACTION_ON_SHUTDOWN_DESTROY, libxl_action_on_shutdown_to_string(LIBXL_ACTION_ON_SHUTDOWN_DESTROY));
    printf("\tRESTART = %d = \"%s\"\n", LIBXL_ACTION_ON_SHUTDOWN_RESTART, libxl_action_on_shutdown_to_string(LIBXL_ACTION_ON_SHUTDOWN_RESTART));
    printf("\tRESTART_RENAME = %d = \"%s\"\n", LIBXL_ACTION_ON_SHUTDOWN_RESTART_RENAME, libxl_action_on_shutdown_to_string(LIBXL_ACTION_ON_SHUTDOWN_RESTART_RENAME));
    printf("\tPRESERVE = %d = \"%s\"\n", LIBXL_ACTION_ON_SHUTDOWN_PRESERVE, libxl_action_on_shutdown_to_string(LIBXL_ACTION_ON_SHUTDOWN_PRESERVE));
    printf("\tCOREDUMP_DESTROY = %d = \"%s\"\n", LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY, libxl_action_on_shutdown_to_string(LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_DESTROY));
    printf("\tCOREDUMP_RESTART = %d = \"%s\"\n", LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_RESTART, libxl_action_on_shutdown_to_string(LIBXL_ACTION_ON_SHUTDOWN_COREDUMP_RESTART));

    printf("libxl_action_on_shutdown -- from string:\n");
    libxl_action_on_shutdown_val = -1;
    rc = libxl_action_on_shutdown_from_string("DESTRoy", &libxl_action_on_shutdown_val);
    printf("\tDESTROY = \"%s\" = %d (rc %d)\n", "DESTRoy", libxl_action_on_shutdown_val, rc);
    libxl_action_on_shutdown_val = -1;
    rc = libxl_action_on_shutdown_from_string("rEsTarT", &libxl_action_on_shutdown_val);
    printf("\tRESTART = \"%s\" = %d (rc %d)\n", "rEsTarT", libxl_action_on_shutdown_val, rc);
    libxl_action_on_shutdown_val = -1;
    rc = libxl_action_on_shutdown_from_string("rEsTart_RenAmE", &libxl_action_on_shutdown_val);
    printf("\tRESTART_RENAME = \"%s\" = %d (rc %d)\n", "rEsTart_RenAmE", libxl_action_on_shutdown_val, rc);
    libxl_action_on_shutdown_val = -1;
    rc = libxl_action_on_shutdown_from_string("pRESeRve", &libxl_action_on_shutdown_val);
    printf("\tPRESERVE = \"%s\" = %d (rc %d)\n", "pRESeRve", libxl_action_on_shutdown_val, rc);
    libxl_action_on_shutdown_val = -1;
    rc = libxl_action_on_shutdown_from_string("CoRedUMp_DEsTROy", &libxl_action_on_shutdown_val);
    printf("\tCOREDUMP_DESTROY = \"%s\" = %d (rc %d)\n", "CoRedUMp_DEsTROy", libxl_action_on_shutdown_val, rc);
    libxl_action_on_shutdown_val = -1;
    rc = libxl_action_on_shutdown_from_string("coREDUMp_RestArt", &libxl_action_on_shutdown_val);
    printf("\tCOREDUMP_RESTART = \"%s\" = %d (rc %d)\n", "coREDUMp_RestArt", libxl_action_on_shutdown_val, rc);
    libxl_action_on_shutdown_val = -1;
    rc = libxl_action_on_shutdown_from_string("An InvAliD valUe", &libxl_action_on_shutdown_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "An InvAliD valUe", libxl_action_on_shutdown_val, rc);

    printf("libxl_event_type -- to string:\n");
    printf("\tDOMAIN_DEATH = %d = \"%s\"\n", LIBXL_EVENT_TYPE_DOMAIN_DEATH, libxl_event_type_to_string(LIBXL_EVENT_TYPE_DOMAIN_DEATH));
    printf("\tDISK_EJECT = %d = \"%s\"\n", LIBXL_EVENT_TYPE_DISK_EJECT, libxl_event_type_to_string(LIBXL_EVENT_TYPE_DISK_EJECT));

    printf("libxl_event_type -- from string:\n");
    libxl_event_type_val = -1;
    rc = libxl_event_type_from_string("doMAIN_DeAth", &libxl_event_type_val);
    printf("\tDOMAIN_DEATH = \"%s\" = %d (rc %d)\n", "doMAIN_DeAth", libxl_event_type_val, rc);
    libxl_event_type_val = -1;
    rc = libxl_event_type_from_string("DIsk_EJECT", &libxl_event_type_val);
    printf("\tDISK_EJECT = \"%s\" = %d (rc %d)\n", "DIsk_EJECT", libxl_event_type_val, rc);
    libxl_event_type_val = -1;
    rc = libxl_event_type_from_string("aN INVAlID Value", &libxl_event_type_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "aN INVAlID Value", libxl_event_type_val, rc);

    printf("libxl_button -- to string:\n");
    printf("\tPOWER = %d = \"%s\"\n", LIBXL_BUTTON_POWER, libxl_button_to_string(LIBXL_BUTTON_POWER));
    printf("\tSLEEP = %d = \"%s\"\n", LIBXL_BUTTON_SLEEP, libxl_button_to_string(LIBXL_BUTTON_SLEEP));

    printf("libxl_button -- from string:\n");
    libxl_button_val = -1;
    rc = libxl_button_from_string("poWer", &libxl_button_val);
    printf("\tPOWER = \"%s\" = %d (rc %d)\n", "poWer", libxl_button_val, rc);
    libxl_button_val = -1;
    rc = libxl_button_from_string("SLEEP", &libxl_button_val);
    printf("\tSLEEP = \"%s\" = %d (rc %d)\n", "SLEEP", libxl_button_val, rc);
    libxl_button_val = -1;
    rc = libxl_button_from_string("An InvAlid VALUe", &libxl_button_val);
    printf("\tAN INVALID VALUE = \"%s\" = %d (rc %d)\n", "An InvAlid VALUe", libxl_button_val, rc);

return 0;
}
