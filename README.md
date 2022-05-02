# SophosCentralAPI-DisableTP
Disable Tamper Protection using Sophos Central API

SophosAPI_export.py -> disable tamper protection using API for selected endpoints

    input the client ID
    input the client secret
    the deviceID.csv is dump from sophos central
    keep only the devices you want to change the tamper protection status and save it as report.csv in the same working directory
    input 'y' to start the modification

SophosAPI_test.py -> query endpoint status from the sophos central through API

SophosAPI_changeTP.py -> for customer that with deviceID report ready and change tamper protection
