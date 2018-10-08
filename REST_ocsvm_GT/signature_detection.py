import csv
import io
import pandas as pd
import InputLog

class SignatureDetector:

    EVENT_TGT = "4768"
    EVENT_ST="4769"
    EVENT_PRIV = "4672"
    EVENT_PROCESS = "4688"
    EVENT_PRIV_SERVICE = "4673"
    EVENT_PRIV_OPE = "4674"
    EVENT_SHARE = "5140"
    SYSTEM_DIR = "c:\windows";
    PSEXESVC = "psexesvc";
    ADMINSHARE="\c$"

    df=pd.DataFrame(data=None, index=None, columns=["datetime","eventid","accountname","clientaddr","servicename","processname","objectname"], dtype=None, copy=False)
    df_admin = pd.DataFrame(data=None, index=None, columns=[ "accountname"], dtype=None, copy=False)
    df_cmd = pd.DataFrame(data=None, index=None, columns=["processname"], dtype=None, copy=False)


    def __init__(self):
        print("constructor called")

    def is_attack(self):
        print("is_attack called")

    @staticmethod
    def signature_detect(datetime, eventid, accountname, clientaddr, servicename, processname, objectname,sharedname):
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

        inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname,sharedname)
        return SignatureDetector.signature_detect(inputLog)

    @staticmethod
    def signature_detect(inputLog):
        """ Detect attack using signature based detection.
        :param inputLog: InputLog object of the event
        :return : True(1) if attack, False(0) if normal
        """

        #print(SignatureDetector.df)

        #SignatureDetector.df["accountname"] = SignatureDetector.df["accountname"].str.lower()

        is_attack=False

        if (inputLog.get_eventid()==SignatureDetector.EVENT_ST) :
            is_attack=SignatureDetector.hasNoTGT(inputLog)

        elif (inputLog.get_eventid() == SignatureDetector.EVENT_PRIV):
            is_attack =SignatureDetector.isNotAdmin(inputLog)

        elif (inputLog.get_eventid() == SignatureDetector.EVENT_PRIV_OPE
                or inputLog.get_eventid() == SignatureDetector.EVENT_PRIV_SERVICE
                or inputLog.get_eventid() == SignatureDetector.EVENT_PROCESS):
            is_attack = SignatureDetector.isSuspiciousProcess(inputLog)

        elif (inputLog.get_eventid() == SignatureDetector.EVENT_SHARE):
            is_attack =SignatureDetector.isAdminshare(inputLog)

        series = pd.Series([inputLog.get_datetime(),inputLog.get_eventid(),inputLog.get_accountname(),inputLog.get_clientaddr(),
                      inputLog.get_servicename(),inputLog.get_processname(),inputLog.get_objectname()], index=SignatureDetector.df.columns)
        SignatureDetector.df=SignatureDetector.df.append(series, ignore_index = True)

        if is_attack:
            return "attack"
        else:
            return "normal"

    @staticmethod
    def hasNoTGT(inputLog):
        SignatureDetector.df["eventid"]=SignatureDetector.df["eventid"].astype(str)
        logs=SignatureDetector.df[(SignatureDetector.df.accountname == inputLog.get_accountname())
                                  &(SignatureDetector.df.clientaddr==inputLog.get_clientaddr())
                                  & (SignatureDetector.df.eventid == SignatureDetector.EVENT_TGT)
        ]
        if len(logs)==0:
            print("No TGT")
            return True
        else:
            return False

    @staticmethod
    def isNotAdmin(inputLog):
        logs = SignatureDetector.df_admin[(SignatureDetector.df_admin.accountname == inputLog.get_accountname())]
        if len(logs) == 0:
            print("is not contained admin list")
            return True
        else:
            return False

    @staticmethod
    def isSuspiciousProcess(inputLog):

        logs = SignatureDetector.df[(SignatureDetector.df.accountname == inputLog.get_accountname())
                                    & (SignatureDetector.df.eventid == SignatureDetector.EVENT_ST)
                                    ]
        clientaddr=logs.tail(1).clientaddr.values[0]
        inputLog.set_clientaddr(clientaddr)

        if inputLog.get_processname().find(SignatureDetector.SYSTEM_DIR)==-1:
            print("Suspicious process")
            return True
        cmds=inputLog.get_processname().split("\\")
        cmd=cmds[len(cmds)-1]
        logs = SignatureDetector.df_cmd[SignatureDetector.df_cmd.processname.str.contains(cmd)]
        if len(logs)>0:
            print("Suspicious process")
            return True

        if inputLog.get_objectname().find(SignatureDetector.PSEXESVC)>=0:
            print("Suspicious process")
            return True

        return False

    @staticmethod
    def isAdminshare(inputLog):
        if inputLog.get_sharedname().find(SignatureDetector.ADMINSHARE)>=0:
            print("Suspicious process")
            return True

        return False


SignatureDetector.df = pd.read_csv("./logs.csv")
#print(SignatureDetector.df)

SignatureDetector.df_admin = pd.read_csv("./admin.csv")

SignatureDetector.df_cmd = pd.read_csv("./command.csv")


csv_file = io.open("./log2.csv", mode="r", encoding="utf-8")
f = csv.DictReader(csv_file, delimiter=",", doublequote=True, lineterminator="\r\n", quotechar='"', skipinitialspace=True)
for row in f:
    datetime=row.get("datetime")
    eventid=row.get("eventid")
    accountname=row.get("accountname").lower()
    clientaddr=row.get("clientaddr")
    servicename=row.get("servicename").lower()
    processname=row.get("processname").lower()
    objectname=row.get("objectname").lower()
    sharedname = row.get("sharedname").lower()

    # To specify parameter as Object
    inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname,sharedname)
    print(SignatureDetector.signature_detect(inputLog))
    #print(inputLog.get_clientaddr())

    # To specify parameter as string text
    #SignatureDetector.signature_detect(datetime, eventid, accountname, clientaddr, servicename, processname, objectname);


#print(SignatureDetector.df)

