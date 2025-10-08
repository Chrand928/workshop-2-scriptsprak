import csv

with open("network_incidents.csv", encoding="utf-8") as file:
    network_incidents = list(csv.DictReader(file))

