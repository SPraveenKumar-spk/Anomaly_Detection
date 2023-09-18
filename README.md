# Network Communication Anomaly Detection

Network Communication Anomaly Detection System is used to detect the abnormalities or anomalies present in the network. This system is developed using machine learning techniques. This is the prototype of network anomaliy detection system, in which it can be used for both processed data and un-processed data.
This system can be implemented in smart industries to dectect the anomalies in the network connected systems like  PLC's(Programmable Logic Controller) etc. This is an useful tool as it detects the anomlies generated in a network which enhances the network Security, Integrity, Availability. 

# Dataset

KDD - CUP dataset is used to implement it. The dataset includes various features extracted from the network traffic, such as protocol type, service, source and 
destination IP addresses, source and destination ports, and more. The goal of the KDD Cup dataset is to detect network intrusions or attacks. It consists of both normal connections and 
instances representing different types of attacks, including Denial of Service (DoS), User to Root (U2R), Remote to Local (R2L), and Probing attacks.

# Machine Learning Algorithms

As the Anomalies detection is concerned with classification, used the machine learning algorithms of Decision Tree Classifier, Random Forest Classifier and Naive Bayes.
The accuracy of algorithms are as follows :
		Random Forest Classifier : 99%
		Decision Tree Classifier : 99%
		Naive Bayes		           : 89%

# Implementation

The "Network Communication Anomaly Detection " system is implemented using Random Forest Classifier algorithm. The system is developed in such a way that whenever
the anomalies are found within a network it generates an email notification which includes details of anomaly type along with its features. 
A csv file system is created in which it stores all the anomaly details like its type, features and time of generation. Additionally, Graph visualization system is developed in which it plots the line graph between time and no. of anomalies generated over that particular time.

# Outcomes

** Anomaly Detection
** Email Notification;
** CSV file;
** Graph Visuals
