from flask import Flask, render_template, request
import joblib
import smtplib
import numpy as np

app = Flask(__name__,template_folder='templates')
model = joblib.load('fsm.pkl')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.form['input_data']
        data = [float(val) for val in data.split()]
        data = np.array(data).reshape(1, -1)
        predictions = model.predict(data)

        anomaly_count = 0
        anomaly_details = []

        for i in range(len(predictions)):
            if predictions[i] != 'normal':
                anomaly_count += 1
                anomaly_features = " ".join(str(val) for val in data[i])
                predicted_attack_type = str(predictions[i])
                

                print("Anomaly Detected!")
                print("Anomaly Features:", anomaly_features)
                print("Attack Type:", predicted_attack_type)

                anomaly_details.append(str(anomaly_features) + "\nAttack Type: " + predicted_attack_type)

            if anomaly_count == 5:
                send_email(anomaly_details)
                break

        return render_template('result.html', anomaly_count=anomaly_count)
    else:
        return render_template('index.html')

def send_email(anomaly_details):
    sender_email = 'spravee.961435@gmail.com'
    sender_password = 'jigysdccerladvzl'
    receiver_email = 'praveen.spk8247@gmail.com'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587

    subject = 'Anomalies Detected'
    body = 'Anomalies have been detected. Here are the details:\n\n' + '\n\n'.join(anomaly_details)

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