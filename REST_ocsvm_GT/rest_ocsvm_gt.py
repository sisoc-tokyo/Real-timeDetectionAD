from sklearn.externals import joblib
import pandas as pd
import numpy as np
import urllib.parse
from flask import Flask, jsonify, request
from machine_learning import ML
from signature_detection import SignatureDetector
import InputLog
import send_alert
app = Flask(__name__)

clf_4674 = joblib.load('ocsvm_gt_4674.pkl')
base_dummies_4674 = pd.read_csv('data_dummies_4674.csv')
clf_4688 = joblib.load('ocsvm_gt_4688.pkl')
base_dummies_4688 = pd.read_csv('data_dummies_4688.csv')

SignatureDetector.df_admin = pd.read_csv("./admin.csv")
SignatureDetector.df_cmd = pd.read_csv("./command.csv")


# If you run this code on the other computer, you might need to remove commentout below.
# Sometimes mode.predict function does not load correctly.
# import numpy as ap
# X = np.zeros((10, max_len))
# model.predict(X, batch_size=32)

@app.route('/preds', methods=['POST'])
def preds():
    # loading
    response = jsonify()
    datetime = request.form.get('datetime',None)
    eventid = request.form.get('eventid',None)
    org_accountname = request.form.get('accountname',None)
    clientaddr = request.form.get('clientaddr',None)
    servicename = request.form.get('servicename',None)
    processname = request.form.get('processname',None)
    objectname = request.form.get('objectname',None)
    sharedname = request.form.get('sharedname',None)

    datetime = datetime.strip("'")
    eventid = eventid.strip("'")
    if org_accountname != None:
        accountname = org_accountname.strip("'")
        accountname = accountname.lower()
        if accountname=='dcexample.com':
            print("before:"+org_accountname)
        accountname = accountname.split('@')[0]

    if clientaddr != None:
        clientaddr = clientaddr.strip("'")
    if servicename != None:
        servicename = servicename.strip("'")
        servicename = servicename.lower()
    if processname != None:
        processname = processname.strip("'")
        processname = processname.lower()
    if objectname != None:
        objectname = objectname.strip("'")
        objectname = objectname.lower()
    if sharedname != None:
        sharedname = sharedname.strip("'")
        sharedname = sharedname.lower()

    # To specify parameter as Object
    inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname)
    # update start by gam
    result = SignatureDetector.signature_detect(inputLog)

    # update end
    clientaddr = inputLog.get_clientaddr()
    processname=inputLog.get_processname()

    print(inputLog.get_eventid()+","+inputLog.get_accountname()+","+inputLog.get_clientaddr()+","+inputLog.get_processname())

    if result == SignatureDetector.RESULT_CMD:
        result = ML.preds(eventid, accountname, processname, objectname, base_dummies_4674, clf_4674, base_dummies_4688, clf_4688)
    if (result != SignatureDetector.RESULT_NORMAL and result != ML.RESULT_WARN):
        send_alert.Send_alert(result, datetime, eventid, accountname, clientaddr, servicename, processname, objectname, sharedname)

    return result

if __name__ == '__main__':
    app.run(host='0.0.0.0')
