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
        "categories": defaultdict(lambda: {"incident_count": 0, "total_impact": 0.0, "impact_scores": []}),
        "unique_weeks": sorted({ticket["week_number"] for ticket in tickets}),
        "unique_sites": sorted({ticket["site"] for ticket in tickets}),
        "severity_resolution_times": defaultdict(list),
    }

    # Severity order added going from highest to lowest
    severity_order = ["critical", "high", "medium", "low"]
    
    # Sets total cost starting value to 0
    total_cost = 0.0

    for ticket in data["tickets"]: 
    
        # Counts amount of tickets and sorts by severity level
        severity = ticket["severity"].lower()
        data["severity_counts"][ticket["severity"]] += 1
        # Adds key for resolution time per severity
        data["severity_resolution_times"][severity].append(int(ticket["resolution_minutes"]))

        # Adds incidents that affect more than 100 users
        affected_users = ticket.get("affected_users", "0")
        if affected_users and int(affected_users) > 100:
            data ["high_impact_incidents"].append(ticket)
        
        # Adds cost for each incident and total cost
        cost_swe = ticket["cost_sek"]
        cost = parse_swedish_cost(cost_swe)
        ticket["cost"] = cost
        total_cost += cost

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
        data["categories"][category]["impact_scores"].append(float(ticket["impact_score"]))

    # Adds formattting to sort severity and capitalie the first letters
    for severity in severity_order:
        count = data["severity_counts"].get(severity, 0)
        formatted_severity = severity.capitalize()
        data["formatted_severity_counts"][formatted_severity] = count

    # Sorts the 5 most expensive incidents to be used in the code above
    data["top_expensive_incidents"].sort(key=lambda top_exp: top_exp[1], reverse=True)
    data["top_expensive_incidents"] = data["top_expensive_incidents"][:5]
    
    # Sorts high_impact_incidents with most affected users highest up on the list
    data["high_impact_incidents"].sort(key=lambda hi_imp: int(hi_imp.get("affected_users", 0)), reverse=True)
    
    # Total cost formatted 
    data["total_cost_formatted"] = format_swedish_total(total_cost)

    # Counts average resolution time of severity
    data["avg_resolution_time"] = {}
    for severity in severity_order:
        resolution_times = data["severity_resolution_times"].get(severity, [])
        if resolution_times:
            avg_time = sum(resolution_times) / len(resolution_times)
            data["avg_resolution_time"][severity.capitalize()] = avg_time
        else:
            data["avg_resolution_time"][severity.capitalize()] = 0

    return data

# Adds code to convert into swedish numbering to be used 
def parse_swedish_cost(cost_swe):
    cost_swe = cost_swe.replace(" ", "").replace(",", ".")
    return float(cost_swe)

def format_swedish_total(cost_float):
    cost_str = "{:,.2f}".format(cost_float)
    cost_str = cost_str.replace(",", "X").replace(".", ",").replace("X", " ")
    return cost_str

# Helps read and process the data
network_incidents = "network_incidents.csv"
data = ticket_processor(network_incidents)


# Writes Site and analysisperiod information from the data to a report
with open("incident_analysis.txt", "w", encoding="utf-8") as report_file:
    report_file.write("SITES OCH ANALYSVECKOR\n--------------------\n")
    for site in data["unique_sites"]:
        weeks = sorted(data["sites"][site]["weeks"])
        report_file.write(f"Site: {site}\nAnalysveckor: v.{", v.".join(weeks)}\n\n")

    # Writes total amount of incidents per severity to report
    report_file.write("INCIDENTER PER SEVERITY-NIVÅ\n--------------------\n")
    for severity, count in data["formatted_severity_counts"].items():
        report_file.write(f"{severity.ljust(10)}-->   {count} incidents\n")

    # Writes highest impact incidents to report
    report_file.write("\nINCIDENTER SOM PÅVERKAT FLER ÄN 100 ANVÄNDARE\n--------------------\n")
    for ticket in data["high_impact_incidents"]:
        report_file.write(f"Ticket ID: {ticket["ticket_id"].ljust(15)} Site: {ticket["site"].ljust(15)} Affected Users: {ticket["affected_users"].ljust(5)}\n")

    # Writes TOP 5 most expensive incidents to report
    report_file.write("\nDE 5 DYRASTE INCIDENTERNA\n--------------------\n")
    for top_5, (ticket, cost) in enumerate(data["top_expensive_incidents"], 1):
        report_file.write(f"{top_5}. Ticket ID: {ticket["ticket_id"].ljust(15)} Kostnad: {ticket["cost_sek"].ljust(10)}SEK\n")

    # Writes Total cost of incidents to report
    report_file.write("\nTOTALKOSTNAD FÖR INCIDENTER\n--------------------\n")
    report_file.write(f"Totalkostnad: {data["total_cost_formatted"]} SEK\n")

    # Writes average resolution time to report
    report_file.write("\nGENOMSNITTLIG RESOLUTION TIME PER SEVERITY-NIVÅ\n--------------------\n")
    for severity, avg_time in data["avg_resolution_time"].items():
        report_file.write(f"{severity.ljust(10)}-->   {avg_time:.2f} minuter\n")

    # Writes Summary per site to report
    report_file.write("\nÖVERSIKT PER SITE\n--------------------\n")
    for site in data ["unique_sites"]:
        site_data = data["sites"][site]
        avg_resolution_time = sum(site_data["resolution_times"]) / len(site_data["resolution_times"]) if site_data["resolution_times"] else 0
        report_file.write(f"{site}:\n")
        report_file.write(f" Antal incidenter: {site_data["incident_count"]}\n")
        report_file.write(f" Totalkostnad: {format_swedish_total(site_data["total_cost"])} SEK\n")
        report_file.write(f" Genomsnittlig resolution tid: {avg_resolution_time:.2f} minuter\n\n")
 
    # 
    report_file.write("\nINCIDENTS PER CATEGORY - GENOMSNITTLIG IMPACT\n--------------------\n")
    for category, category_data in data["categories"].items():
        avg_impact_score = sum(category_data["impact_scores"]) /len(category_data["impact_scores"]) if category_data["impact_scores"] else 0
        formatted_category = category.capitalize()
        report_file.write(f"{formatted_category.ljust(14)}{avg_impact_score:.2f}   Antal incidenter {category_data["incident_count"]}\n")
                          
# CSV Writer that creates a csv file "incidents_by_site.csv" including Total Cost
def write_incidents_by_site_to_csv(data, output_filename="incidents_by_site.csv"):
    with open(output_filename, mode="w", encoding="utf-8", newline="") as csv_file:
        fieldnames = ["Site", "Antal Incidenter", "Totalkostnad (SEK)", "Genomsnittlig Resolution Tid (minuter)"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        writer.writeheader()
        for site in data["unique_sites"]:
            site_data = data["sites"][site]
            avg_resolution_time = (sum(site_data["resolution_times"]) / len(site_data["resolution_times"]) if site_data["resolution_times"] else 0)
            
            writer.writerow({
                "Site": site,
                "Antal Incidenter": site_data["incident_count"],
                "Totalkostnad (SEK)": format_swedish_total(site_data["total_cost"]), 
                "Genomsnittlig Resolution Tid (minuter)": f"{avg_resolution_time:.2f}"
            })
write_incidents_by_site_to_csv(data)
