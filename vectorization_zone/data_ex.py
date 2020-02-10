import numpy as np 
import pandas as pd

df = pd.read_csv("./data.csv", dtype=str)
df_copy = df.copy()
new_df = pd.DataFrame(columns=['filename_A', "store_A","put_A","wrtmp_A","loadg_A","storeg_A","cas_A","sucessors_A","predecessors_A",'filename_B', "store_B","put_B","wrtmp_B","loadg_B","storeg_B","cas_B","sucessors_B","predecessors_B"])

counter = 0

for index, row in df.iterrows():
    df_copy = df_copy.drop(index)
    for an_index, an_row in df_copy.iterrows():
        new_df = new_df.append({'filename_A':row['filename'],
                       "store_A":row['store'],
                       "put_A":row['put'],
                       "wrtmp_A":row['wrtmp'],
                       "loadg_A":row['loadg'],
                       "storeg_A":row['storeg'],
                       "cas_A":row['cas'],
                       "sucessors_A":row['sucessors'],
                       "predecessors_A":row['predecessors'],
                       'filename_B':an_row['filename'],
                       "store_B":an_row['store'],
                       "put_B":an_row['put'],
                       "wrtmp_B":an_row['wrtmp'],
                       "loadg_B":an_row['loadg'],
                       "storeg_B":an_row['storeg'],
                       "cas_B":an_row['cas'],
                       "sucessors_B":an_row['sucessors'],
                       "predecessors_B":an_row['predecessors']
        }, ignore_index=True)
        print(counter)
        counter+=1
new_df.to_csv("./data_ex.csv", sep=',')