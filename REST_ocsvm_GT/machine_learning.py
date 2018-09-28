import pandas as pd
import numpy as np
from flask import jsonify

class ML:
    @staticmethod
    def preds(eventid, accountname, clientaddr, servicename, processname, objectname, base_dummies, clf):
        # loading
        response = jsonify()
        new_data = []
        new_data.append('account_' + str(accountname))
        new_data.append('ip_' + str(clientaddr))
        new_data.append('service_' + str(servicename))
        new_data.append('process_' + str(processname))
        new_data.append('objectname_' + str(objectname))

        base_df = pd.DataFrame(columns=base_dummies.columns[2:-3])
        base_df.loc[0] = 0

        for colname in new_data:
             if colname in base_df.columns:
                 base_df[colname][0] = 1
        base_df['eventID'][0] = eventid
        base_df = base_df.astype(np.int32)

        pred_data = base_df.values

        result = clf.predict(pred_data)
        if result == 1:
            print('normal')
            response.status_code = 201
            response = 'normal'
        elif result == -1:
            print('outlier')
            response.status_code = 202
            response = 'attack'

        # save
        # with open('request.log', mode='a') as f:
        #     f.write(str(response.status_code) + str(prediction) + ',' + str(reqstr) + '\n')

        return response