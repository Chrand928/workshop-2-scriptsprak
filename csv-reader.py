import csv
from collections import defaultdict


def ticket_processor(network_incidents):
    tickets = []
    with open(network_incidents, mode="r", encoding="utf-8") as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            tickets.append(row)

    # Creates a centralized datastructure that we can point back to throughout the code 
    data = {
        'tickets': tickets,
        'severity_counts': defaultdict(int),
        'high_impact_incidents': [],
        'top_expensive_incidents': [],
        'sites': defaultdict(lambda: {'incident_count': 0, 'total_cost': 0.0, 'resolution_times': []}),
        'categories': defaultdict(lambda: {'incident_count': 0, 'total_impact': 0.0}),
        'unique_weeks': sorted({ticket['week_number'] for ticket in tickets}),
        'unique_sites': sorted({ticket['site'] for ticket in tickets}),
    }

    
    for ticket in data["tickets"]: 
    
        # Counts amount of tickets and sorts by severity level
        data["severity_counts"][ticket["severity"]] += 1

        # Adds incidents that affect more than 100 users
        affected_users = ticket.get("affected_users", "0")
        if affected_users and int(affected_users) > 100:
            data ["high_impact_incidents"].append(ticket)
        
        # Adds cost for each incident
        cost_swe = ticket["cost_sek"]
        cost = parse_swedish_cost(cost_swe)
        ticket["cost"] = cost

    return data

# Adds code to convert into swedish numbering to be used 
def parse_swedish_cost(cost_swe):
    cost_swe = cost_swe.replace(" ", "").replace(",", ".")
    return float(cost_swe)


network_incidents = "network_incidents.csv"
data = ticket_processor(network_incidents)