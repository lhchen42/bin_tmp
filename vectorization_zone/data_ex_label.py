import numpy as np 
import pandas as pd

df = pd.read_csv("./data_ex.csv", dtype=str)
labels = []
# df = df.head(n=500)
counter = 0
for index, row in df.iterrows():
    if (row['filename_A'].split('_')[-1] == row['filename_B'].split('_')[-1]):
        labels.append(1)
    else:
        labels.append(0)
    counter+=1
    print(counter)

df['output'] = labels
df.to_csv("./data_ex_labeled.csv", sep=',')