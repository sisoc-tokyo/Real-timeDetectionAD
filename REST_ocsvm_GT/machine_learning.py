import pandas as pd
import numpy as np
from flask import jsonify

class ML:
    @staticmethod
    def preds(datetime, eventid, accountname, clientaddr, servicename, processname, objectname, base_dummies_4674, clf_4674, base_dummies_4688, clf_4688):
        # loading
        response = jsonify()
        new_data = []
        if accountname != None:
            accountname = accountname.lower()
            new_data.append('account_' + str(accountname))
        new_data.append('ip_' + str(clientaddr))
        new_data.append('service_' + str(servicename))
        new_data.append('process_' + str(processname))
        new_data.append('objectname_' + str(objectname))

        base_df_4674 = pd.DataFrame(columns=base_dummies_4674.columns[2:-3])
        base_df_4674.loc[0] = 0
        base_df_4688 = pd.DataFrame(columns=base_dummies_4688.columns[2:-3])
        base_df_4688.loc[0] = 0

        for colname in new_data:
            if colname in base_df_4674.columns:
                base_df_4674[colname][0] = 1
            if colname in base_df_4688.columns:
                base_df_4688[colname][0] = 1

        if eventid == '4674':
            base_df_4674['eventID'][0] = '4674'
            base_df_4674 = base_df_4674.astype(np.int32)
            pred_data = base_df_4674.values
            result = clf_4674.predict(pred_data)
            if result == 1:
                print('ML_4674_normal')
                response.status_code = 201
                response = 'normal'
            elif result == -1:
                print('outlier')
                response.status_code = 202
                response = 'outlier'

        if eventid == '4688':
            base_df_4688['eventID'][0] = '4688'
            base_df_4688 = base_df_4688.astype(np.int32)
            pred_data = base_df_4688.values
            result = clf_4688.predict(pred_data)
            if result == 1:
                print('ML_normal')
                response.status_code = 201
                response = 'normal'
            elif result == -1:
                print('outlier')
                response.status_code = 202
                response = 'outlier'

        # save
        # with open('request.log', mode='a') as f:
        #     f.write(str(response.status_code) + str(prediction) + ',' + str(reqstr) + '\n')

        return response