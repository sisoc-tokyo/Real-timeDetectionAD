import csv
import io
import InputLog

class SignatureDetector:

    __logs = {}

    def __init__(self):
        print("constructor called")

    def is_attack(self):
        print("is_attack called")

    @staticmethod
    def signature_detect(datetime, eventid, accountname, clientaddr, servicename, processname, objectname):
        """ Detect attack using signature based detection.
        :param datetime: Datetime of the event
        :param eventid: EventID
        :param accountname: Accountname
        :param clientaddr: Source IP address
        :param servicename: Service name
        :param processname: Process name(command name)
        :param objectname: Object name
        :return : True(1) if attack, False(0) if normal
        """

        inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname)
        return SignatureDetector.signature_detect(inputLog)

    @staticmethod
    def signature_detect(inputLog):
        """ Detect attack using signature based detection.
        :param inputLog: InputLog object of the event
        :return : True(1) if attack, False(0) if normal
        """
        is_attack=False
        inputLog = inputLog
        SignatureDetector.__logs.setdefault(accountname,[]).append(inputLog)
        return is_attack

    @staticmethod
    def get_logs():
        keys=SignatureDetector.__logs.keys()
        for key in keys:
            print(key+":")
            logs=SignatureDetector.__logs[key]
            for log in logs:
                print("    "+log.get_datetime())
                print("    " + log.get_eventid())
                print("    " + log.get_accountname())
                print("    " + log.get_servicename())
                print("    " + log.get_processname())
                print("    " + log.get_objectname())

csv_file = io.open("./log.csv", mode="r", encoding="utf-8")
f = csv.DictReader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)
for row in f:
    datetime=row.get("datetime")
    eventid=row.get("eventid")
    accountname=row.get("accountname")
    clientaddr=row.get("clientaddr")
    servicename=row.get("servicename")
    processname=row.get("processname")
    objectname=row.get("objectname")

    # To specify parameter as Object
    inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname)
    SignatureDetector.signature_detect(inputLog)

    # To specify parameter as string text
    #SignatureDetector.signature_detect(datetime, eventid, accountname, clientaddr, servicename, processname, objectname);


SignatureDetector.get_logs()
