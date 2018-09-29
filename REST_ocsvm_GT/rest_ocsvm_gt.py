from sklearn.externals import joblib
import pandas as pd
import numpy as np
import urllib.parse
from flask import Flask, jsonify, request
from machine_learning import ML
from signature_detection import SignatureDetector
from InputLog import InputLog
app = Flask(__name__)

clf = joblib.load('ocsvm_gt.pkl')
base_dummies = pd.read_csv('data_dummies.csv')

# add start by gam
df_admin = pd.read_csv("./admin.csv")
df_cmd = pd.read_csv("./command.csv")
# add end


# If you run this code on the other computer, you might need to remove commentout below.
# Sometimes mode.predict function does not load correctly.
# import numpy as ap
# X = np.zeros((10, max_len))
# model.predict(X, batch_size=32)

@app.route('/preds', methods=['POST'])
def preds():
    # loading
    response = jsonify()
    datetime = request.form.get('date',None)
    eventid = request.form.get('event_id',None)
    accountname = request.form.get('account',None)
    clientaddr = request.form.get('ip',None)
    servicename = request.form.get('service',None)
    processname = request.form.get('process',None)
    objectname = request.form.get('objectname',None)

    # To specify parameter as Object
    inputLog = InputLog.InputLog(datetime, eventid, accountname, clientaddr, servicename, processname, objectname)
    # update start by gam
    sig_result = SignatureDetector.signature_detect(inputLog,df_admin,df_cmd)
    # update end
    clientaddr = inputLog.get_clientaddr()

    if sig_result == 'attack':
        ai_result = ML.preds(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, base_dummies, clf)
        return ai_result

    return 'normal'

if __name__ == '__main__':
    app.run(host='0.0.0.0')
