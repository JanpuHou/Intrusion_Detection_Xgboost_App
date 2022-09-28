import pandas as pd
import numpy as np
from sklearn.preprocessing import OneHotEncoder
import datetime as dt
import streamlit as st
import matplotlib.pyplot as plt
from PIL import Image, ImageOps
import xgboost as xgb

st.set_page_config(
     page_title="Network Intrustion Detection System",
     page_icon="🧊",
     layout="wide",
     initial_sidebar_state="expanded",
     menu_items={
         'About': "https://www.caloudi.com/"
     }
 )
st.title("AI-Assisted Network Intrustion Detection System")

image = Image.open('app_ids.jpg')
# st.image(image, caption='How This App Interpret Your Network Profile')
st.image(image,"Upload a Network Triffic Profile for Intrusion Detection" )


option = st.selectbox(
     'Which Network Traffic Profile You Likt to Monitor?',
     ('Normal','Network_Customer_Serivice', 'Network_Factory_A', 'Network_Remote_Site_B', 'Go to Browse files'))
st.write('You selected:', option)
 

uploaded_file = st.file_uploader("Choose a Network Traffic Profile file ...", type="csv") 
 
if uploaded_file is None:
    dfx = pd.read_csv(r'normal_data.csv', header=None)
else:
    dfx = pd.read_csv(uploaded_file)
    st.write(dfx)
      

uncode_df=dfx

model = xgb.XGBClassifier()
model.load_model("my_xgboost_model.txt")



def encode_network_data(dfx):
    df = pd.read_csv(r'kddcup_data.csv', header=None)
    df.columns = [
    'duration',
    'protocol_type',
    'service',
    'flag',
    'src_bytes',
    'dst_bytes',
    'land',
    'wrong_fragment',
    'urgent',
    'hot',
    'num_failed_logins',
    'logged_in',
    'num_compromised',
    'root_shell',
    'su_attempted',
    'num_root',
    'num_file_creations',
    'num_shells',
    'num_access_files',
    'num_outbound_cmds',
    'is_host_login',
    'is_guest_login',
    'count',
    'srv_count',
    'serror_rate',
    'srv_serror_rate',
    'rerror_rate',
    'srv_rerror_rate',
    'same_srv_rate',
    'diff_srv_rate',
    'srv_diff_host_rate',
    'dst_host_count',
    'dst_host_srv_count',
    'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate',
    'dst_host_srv_serror_rate',
    'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate']

    oe_protocol = OneHotEncoder()
    oe_results = oe_protocol.fit_transform(df[["protocol_type"]])
    oe_dfx = oe_protocol.transform(dfx[["protocol_type"]])
    dfx1_P=pd.DataFrame(oe_dfx.toarray(), columns=oe_protocol.categories_)
#print(dfx1_P.head())
    dfx = dfx.join(dfx1_P)
#print(dfx.head())

    oe_service = OneHotEncoder()
    oe_results = oe_service.fit_transform(df[["service"]])
    oe_dfx = oe_service.transform(dfx[["service"]])
    dfx1_S=pd.DataFrame(oe_dfx.toarray(), columns=oe_service.categories_)
#print(dfx1_S.head())
    dfx = dfx.join(dfx1_S)
#print(dfx.head())


    oe_flag = OneHotEncoder()
    oe_results = oe_flag.fit_transform(df[["flag"]])
    oe_dfx = oe_flag.transform(dfx[["flag"]])
    dfx1_F=pd.DataFrame(oe_dfx.toarray(), columns=oe_flag.categories_)
#print(dfx1_S.head())
    dfx = dfx.join(dfx1_F)
#print(dfx.head())
    dfx=dfx.drop(['protocol_type','service','flag'], axis=1)
    return dfx


dfx.columns = [
    'duration',
    'protocol_type',
    'service',
    'flag',
    'src_bytes',
    'dst_bytes',
    'land',
    'wrong_fragment',
    'urgent',
    'hot',
    'num_failed_logins',
    'logged_in',
    'num_compromised',
    'root_shell',
    'su_attempted',
    'num_root',
    'num_file_creations',
    'num_shells',
    'num_access_files',
    'num_outbound_cmds',
    'is_host_login',
    'is_guest_login',
    'count',
    'srv_count',
    'serror_rate',
    'srv_serror_rate',
    'rerror_rate',
    'srv_rerror_rate',
    'same_srv_rate',
    'diff_srv_rate',
    'srv_diff_host_rate',
    'dst_host_count',
    'dst_host_srv_count',
    'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate',
    'dst_host_srv_serror_rate',
    'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate']
print(dfx.head())
print(dfx.shape)

dfx=encode_network_data(dfx)
print(dfx.head())
print(dfx.shape)
x_columns = dfx.columns
x = dfx[x_columns].values


labels=['back.' ,'buffer_overflow.' ,'ftp_write.', 'guess_passwd.', 'imap.','ipsweep.' ,'land.', 'loadmodule.', 'multihop.' ,'neptune.', 'nmap.' ,'normal.','perl.' ,'phf.' ,'pod.', 'portsweep.', 'rootkit.', 'satan.', 'smurf.', 'spy.','teardrop.' ,'warezclient.', 'warezmaster.']         
pred = model.predict(x)

for i in range(5):
    my_list=pred[i].tolist()
    indx=my_list.index(max(my_list))
    ts=(dt.datetime.now())
    if indx == 11: 
       st.write(ts, 'Your Network Behavor Normal Now........')
    else:
       st.write(ts,'Act Now!!! Your network is under ',labels[indx],' ATTACK!')
       st.error('Warning::Your Network is under ATTACK!')
       
       
df=uncode_df




# Look at the numerical data
fig = plt.figure()
 
plt.plot(df['src_bytes'].head(1500)/df['src_bytes'].head(1500).max(),'r',label='scr_bytes')
# axs[0, 0].set_title('F5: scr_bytes')
plt.plot(df['dst_bytes'].head(1500)/df['dst_bytes'].head(1500).max(),'g',label='dst_bytes')
# axs[0, 1].set_title('F6: dst_bytes')
plt.plot(df['dst_host_count'].head(1500)/df['dst_host_count'].head(1500).max(),'b',label='dst_host_count')
# axs[1, 0].set_title('F31: dst_host_count')
plt.plot(df['dst_host_same_src_port_rate'].head(1500)/df['dst_host_same_src_port_rate'].head(1500).max(),'black',label='dst_host_same_src_port_rat')
# axs[1, 1].set_title('F36: dst_host_same_src_port_rat')
# plt.title(xlabel='Time(Minutes)', ylabel='Enterprise Network Log')
plt.ylim([0,1.2])
plt.legend()  
plt.title('Data Samples from Network Traffic Profile: Numerical Features')
#plt.show()
st.write(fig)          