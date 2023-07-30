import joblib
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import time

data = pd.read_csv("f_processed.csv")
reduced = 9000
da = data.head(reduced)
model = joblib.load('RandomForest.pkl')

start_time = time.time()  

predictions = model.predict(da)
anomaly_data = []
anomaly_timestamps = []  

encoding_mapping = {
    0: 'dos',
    1: 'normal',
    2: 'probe',
    3: 'r21',
    4: 'u2r'
}
y_Predictions = [encoding_mapping[pred] for pred in predictions]
anomaly_count = 0
anomaly_counts_over_time = []  
for i in range(len(y_Predictions)):
    if y_Predictions[i] != 'normal':
        anomaly_count += 1
        anomaly_features = " ".join(str(data.iloc[i]))
        predicted_attack_type = str(y_Predictions[i])

        row_data = list(data.iloc[i]) + [predicted_attack_type]

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        anomaly_timestamps.append(timestamp)  

        

        anomaly_counts_over_time.append(anomaly_count)  

end_time = time.time() 
prediction_time = end_time - start_time

print(f"Time taken for predictions: {prediction_time:.2f} seconds")
print(anomaly_count)

plt.plot(anomaly_timestamps, anomaly_counts_over_time, marker='o')
plt.xlabel('Time ')
plt.ylabel('Number of Anomalies')
plt.title('Anomalies Over Time')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()
