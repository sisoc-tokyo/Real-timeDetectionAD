import csv
import io
import pandas as pd
import InputLog

class SignatureDetector:

    EVENT_TGT = "4768"
    EVENT_ST="4769"

    df=pd.DataFrame(data=None, index=None, columns=["datetime","eventid","accountname","clientaddr","servicename","processname","objectname"], dtype=None, copy=False)

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

        if (inputLog.get_eventid()==SignatureDetector.EVENT_ST) :
            is_attack=SignatureDetector.hasNoTGT(inputLog)

        series = pd.Series([inputLog.get_datetime(),inputLog.get_eventid(),inputLog.get_accountname(),inputLog.get_clientaddr(),
                      inputLog.get_servicename(),inputLog.get_processname(),inputLog.get_objectname()], index=SignatureDetector.df.columns)
        SignatureDetector.df=SignatureDetector.df.append(series, ignore_index = True)

        if is_attack:
            return "attack"
        else:
            return "normal"

    @staticmethod
    def hasNoTGT(inputLog):
        logs=SignatureDetector.df[(SignatureDetector.df.accountname == inputLog.get_accountname())
                                  &(SignatureDetector.df.clientaddr==inputLog.get_clientaddr())
                                  & ((SignatureDetector.df.eventid) == int(SignatureDetector.EVENT_TGT))
        ]
        if len(logs)==0:
            return True
        else:
            return False


SignatureDetector.df = pd.read_csv("./logs.csv")
print(SignatureDetector.df)

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
    print(SignatureDetector.signature_detect(inputLog))

    # To specify parameter as string text
    #SignatureDetector.signature_detect(datetime, eventid, accountname, clientaddr, servicename, processname, objectname);


#print(SignatureDetector.df)

