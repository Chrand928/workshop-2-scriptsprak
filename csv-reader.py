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
        "tickets": tickets,
        "severity_counts": defaultdict(int),
        "formatted_severity_counts": {},
        "high_impact_incidents": [],
        "top_expensive_incidents": [],
        "sites": {},
        "categories": defaultdict(lambda: {"incident_count": 0, "total_impact": 0.0}),
        "unique_weeks": sorted({ticket["week_number"] for ticket in tickets}),
        "unique_sites": sorted({ticket["site"] for ticket in tickets}),
    }

    # Severity order added going from highest to lowest
    severity_order = ["critical", "high", "medium", "low"]
    
    for ticket in data["tickets"]: 
    
        # Counts amount of tickets and sorts by severity level
        severity = ticket["severity"].lower()
        data["severity_counts"][ticket["severity"]] += 1

        # Adds incidents that affect more than 100 users
        affected_users = ticket.get("affected_users", "0")
        if affected_users and int(affected_users) > 100:
            data ["high_impact_incidents"].append(ticket)
        
        # Adds cost for each incident
        cost_swe = ticket["cost_sek"]
        cost = parse_swedish_cost(cost_swe)
        ticket["cost"] = cost

        # Collect the information on the 5 most expensive incidents
        data["top_expensive_incidents"].append((ticket, cost))

        # Collect information by site
        site = ticket["site"]
        if site not in data["sites"]:
            data["sites"][site] = {'incident_count': 0, 'total_cost': 0.0, 'resolution_times': [], 'weeks': set()}

        data["sites"][site]["incident_count"] += 1
        data["sites"][site]["total_cost"] += cost
        data["sites"][site]["resolution_times"].append(int(ticket["resolution_minutes"]))
        data["sites"][site]["weeks"].add(ticket["week_number"])

        # Collect information by category
        category = ticket["category"]
        data["categories"][category]["incident_count"] += 1
        data["categories"][category]["total_impact"] += float(ticket["impact_score"])

    # Adds formattting to sort severity and capitalie the first letters
    for severity in severity_order:
        count = data["severity_counts"].get(severity, 0)
        formatted_severity = severity.capitalize()
        data["formatted_severity_counts"][formatted_severity] = count

    # Sorts the 5 most expensive incidents to be used in the code above
    data["top_expensive_incidents"].sort(key=lambda top: top[1], reverse=True)
    data["top_expensive_incidents"] = data["top_expensive_incidents"][:5]
    
    return data

# Adds code to convert into swedish numbering to be used 
def parse_swedish_cost(cost_swe):
    cost_swe = cost_swe.replace(" ", "").replace(",", ".")
    return float(cost_swe)

# Helps read and process the data
network_incidents = "network_incidents.csv"
data = ticket_processor(network_incidents)


# Writes Site and analysisperiod information from the data to a report
with open("analysis_report.txt", "w", encoding="utf-8") as report_file:
    report_file.write("SITES OCH ANALYSVECKOR\n--------------------\n")
    for site in data["unique_sites"]:
        weeks = sorted(data["sites"][site]["weeks"])
        report_file.write(f"Site: {site}\nAnalysveckor: v.{", v.".join(weeks)}\n\n")

    # Counts total amount of incidents per severity ***(Behöver fixa lite mer för att sortera listan och formatera lite....)
    report_file.write("INCIDENTS PER SEVERITY\n--------------------\n")
    for severity, count in data["formatted_severity_counts"].items():
        report_file.write(f"{severity.ljust(10)}-->   {count} incidents\n")





