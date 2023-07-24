from flask import Flask, render_template, request
import joblib
import smtplib
import pandas as pd
from sklearn.preprocessing import LabelEncoder

encoder = LabelEncoder()
app = Flask(__name__, template_folder='templates')
model = joblib.load('fsm.pkl')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['userfile']
        data = pd.read_csv(file)

        col_names = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land',
                     'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
                     'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
                     'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
                     'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
                     'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
                     'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
                     'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
                     'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate']
        data.columns = col_names
        data['protocol_type'] = encoder.fit_transform(data['protocol_type'])
        data['service'] = encoder.fit_transform(data['service'])
        data['flag'] = encoder.fit_transform(data['flag'])
        col_drop = ['count', 'srv_count', 'serror_rate', 'dst_host_same_src_port_rate', 'dst_host_count']
        data = data.drop(col_drop, axis=1)
        col_drop1 = ['num_outbound_cmds', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'wrong_fragment', 'srv_serror_rate']
        data = data.drop(col_drop1, axis=1)
        reduced = 100000
        da = data.head(reduced)
        predictions = model.predict(da)

        anomaly_count = 0
        normal_data = 0
        normal_details = []  
        anomaly_details = []
        features = []
        encoding_mapping = {
            0: 'dos',
            1: 'normal',
            2: 'probe',
            3: 'r21',
            4: 'u2r'
        }
        y_Predictions = [encoding_mapping[pred] for pred in predictions]

        for i in range(len(y_Predictions)):
            if y_Predictions[i] != 'normal':
                anomaly_count += 1
                anomaly_features = " ".join(str(data.iloc[i]))
                predicted_attack_type = str(y_Predictions[i])

                anomaly_details.append(str(anomaly_features) + "\nAttack Type: " + predicted_attack_type)
                row_data = list(data.iloc[i]) + [predicted_attack_type]
                features.append(row_data)

            elif y_Predictions[i] == 'normal':
                normal_data += 1
                row_data = list(data.iloc[i]) + [str(y_Predictions[i])]
                normal_details.append(row_data)
        if anomaly_count >= 1:
            send_email(anomaly_details)

        features = pd.DataFrame(features, columns=list(da.columns) + ['Attack'])

        
        file_name = 'data2.csv'
        features.to_csv(file_name, index=False)

        
        print("Anomaly Count:", anomaly_count)
        return render_template('result.html', anomaly_count=anomaly_count, features=features, normal_details=normal_details)

    else:
        return render_template('index.html')


def send_email(anomaly_details):
    sender_email = 'spraveen.961435@gmail.com'
    sender_password = '' #password
    receiver_email = 'praveen.spk8247@gmail.com'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587

    subject = 'Anomalies Detected'
    body = '**ALERT**\n\n Anomalies have been detected. Here are the details:\n\n' + '\n\n'.join(anomaly_details)

    message = f'Subject: {subject}\n\n{body}'

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, message)
            print('Email sent successfully.')
    except smtplib.SMTPException as e:
        print(f'Error sending email: {e}')


if __name__ == '__main__':
    app.run(debug=True)
