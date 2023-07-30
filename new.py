from flask import Flask, render_template, request, send_file
import joblib
import smtplib
import pandas as pd
from datetime import datetime
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('agg')
from sklearn.preprocessing import LabelEncoder

encoder = LabelEncoder()
app = Flask(__name__, template_folder='templates')
model = joblib.load('RandomForest.pkl')

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
        reduced=9000
        da=data.head(reduced)
        predictions = model.predict(da)

        anomaly_count = 0
        normal_data = 0
        normal_details = []  
        anomaly_details = []
        features = []
        anomaly_counts_over_time = []
        anomaly_counts_over_time1 = []
        anomaly_timestamps = []  
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
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                anomaly_timestamps.append(timestamp)  
                anomaly_counts_over_time1.append(anomaly_count)
                features1 = pd.DataFrame([row_data], columns=list(da.columns) + ['Attack'])
                features1['Time'] = timestamp
                features.append(features1)
                anomaly_counts_over_time.append(anomaly_count)
                file_name = 'data1.csv'
                final_features_df = pd.concat(features, ignore_index=True)
                final_features_df.to_csv(file_name, index=False)
               
            elif y_Predictions[i] == 'normal':
                normal_data += 1
                row_data = list(data.iloc[i]) + [str(y_Predictions[i])]
                normal_details.append(row_data)
        if anomaly_count >= 1:
            send_email(anomaly_details)

       
        

        
        print("Anomaly Count:", anomaly_count)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        anomaly_timestamps.append(timestamp)  
        anomaly_counts_over_time1.append(anomaly_count)
        def anomaly_chart():
            plt.figure(figsize=(80, 40))
            plt.plot(anomaly_timestamps, anomaly_counts_over_time1, marker='o')
            plt.xlabel('Time ')
            plt.ylabel('Number of Anomalies')
            plt.title('Anomalies Over Time')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.show()

            chart_file = '../anomalies_vs_time_chart.png'
            plt.savefig(chart_file)

            return chart_file
        chart_file_path = anomaly_chart()
        return render_template('result.html', anomaly_count=anomaly_count, features=features, normal_details=normal_details,chart_file_path=chart_file_path )

    else:
        return render_template('index.html')
@app.route('/preprocessed', methods=['GET', 'POST'])
def preprocessed():
    if request.method == 'POST':
        file = request.files['userfile2']
        data1 = pd.read_csv(file)
     
        predictions1 = model.predict(data1)

        anomaly_count1 = 0
        normal_data1 = 0
        normal_details1 = []  
        anomaly_details1 = []
        features1 = []
        encoding_mapping = {
            0: 'dos',
            1: 'normal',
            2: 'probe',
            3: 'r21',
            4: 'u2r'
        }
        y_Predictions = [encoding_mapping[pred] for pred in predictions1]
        
        for i in range(len(y_Predictions)):
            if y_Predictions[i] != 'normal':
                anomaly_count1 += 1
                anomaly_features = " ".join(str(data1.iloc[i]))
                predicted_attack_type = str(y_Predictions[i])

                anomaly_details1.append(str(anomaly_features) + "\nAttack Type: " + predicted_attack_type)
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                row_data = list(data1.iloc[i]) + [predicted_attack_type,timestamp]
                features1.append(row_data)

            elif y_Predictions[i] == 'normal':
                normal_data1 += 1
                row_data = list(data1.iloc[i]) + [str(y_Predictions[i])]
                normal_details1.append(row_data)
        if anomaly_count1 >= 1:
            send_email(anomaly_details1)
           
        features1 = pd.DataFrame(features1, columns=list(data1.columns) + ['Attack', 'Time'])

       
        file_name = 'data2.csv'
        features1.to_csv(file_name, index=False)

        
        print("Anomaly Count:", anomaly_count1)
        anomaly_data = [(timestamp, anomaly_count1)]
        print(anomaly_data)
        def anomaly_chart():
            timestamps = [data[0] for data in anomaly_data]
            anomaly_counts = [data[1] for data in anomaly_data]
        
            plt.figure(figsize=(10, 6))
            plt.plot(timestamps, anomaly_counts, color='blue', label='Anomalies')

            plt.xlabel('Time')
            plt.ylabel('Number of Anomalies')
            plt.title('Anomalies vs. Time')
            plt.grid(True)
            plt.xticks(rotation=45)
            plt.autoscale(enable=True, axis='both', tight=True)
            plt.tight_layout()
            chart_file = '../anomalies_vs_time_chart.png'
            plt.savefig(chart_file)

            return chart_file
        chart_file_path = anomaly_chart()
        return render_template('result1.html', anomaly_count1=anomaly_count1, features1=features1, normal_details1=normal_details1,chart_file_path=chart_file_path)

    else:
        return render_template('index.html')
@app.route('/download_data1', methods=['POST'])
def download_data1():
    file_path = 'data1.csv'
    response = send_file(file_path, as_attachment=True)   
    return response
@app.route('/download_data2', methods=['POST'])
def download_data2():
    file_path = 'data2.csv'
    response = send_file(file_path, as_attachment=True)   
    return response
@app.route('/display_chart')
def display_chart():
    chart_file_path = '../anomalies_vs_time_chart.png'
    return send_file(chart_file_path, mimetype='image/png')

def send_email(anomaly_details):
    sender_email = 'spraveen.961435@gmail.com'
    sender_password = '' 
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