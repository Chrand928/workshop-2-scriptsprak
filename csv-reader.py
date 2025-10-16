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
        "incidents_per_device": defaultdict(int),
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

        # Collect incident information by site and severity
        site = ticket["site"]
        if site not in data["sites"]:
            data["sites"][site] = {"incident_count": 0, "total_cost": 0.0, "resolution_times": [], "weeks": set()}

        data["sites"][site]["incident_count"] += 1
        data["sites"][site]["total_cost"] += cost
        data["sites"][site]["resolution_times"].append(int(ticket["resolution_minutes"]))
        data["sites"][site]["weeks"].add(ticket["week_number"])

        # Collect information by category
        category = ticket["category"]
        data["categories"][category]["incident_count"] += 1
        data["categories"][category]["total_impact"] += float(ticket["impact_score"])
        data["categories"][category]["impact_scores"].append(float(ticket["impact_score"]))

        # Counts incidents per device to be used in Executive Summary
        device_hostname = ticket.get("device_hostname", "N/A")
        if device_hostname != "N/A":
            data["incidents_per_device"][device_hostname] += 1

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

    # Collects Executive Summary data on the device with the most incidents
    if data["incidents_per_device"]:
        most_incidents_device = max(data["incidents_per_device"].items(), key=lambda x: x[1])
        data["most_incidents_device_id"] = most_incidents_device[0]
        data["most_incidents_device_count"] = most_incidents_device[1]
    else:
        data["most_incidents_device_id"] = "N/A"
        data["most_incidents_device_count"] = 0

    # Collects Executive Summary data on the most expensive incident
    data["most_expensive_incident"] = data["top_expensive_incidents"][0] if data["top_expensive_incidents"] else (None, 0)
    data["highest_cost"] = format_swedish_total(data["most_expensive_incident"][1]) if data["most_expensive_incident"][0] else "0,00"
    data["most_expensive_ticket_id"] = data["most_expensive_incident"][0]["ticket_id"] if data["most_expensive_incident"][0] else "N/A"
    data["most_expensive_site"] = data["most_expensive_incident"][0]["site"] if data["most_expensive_incident"][0] else "N/A"

    # Collects Executive Summary data about sites with no critical incidents
    data["sites_without_critical"] = [
        site for site in data["unique_sites"]
        if not any(
            ticket["severity"].lower() == "critical" and ticket["site"] == site
            for ticket in data["tickets"]
        )
    ]

    # Collects Executive Summary data on problem devices from last week
    problem_devices_threshold = 3
    problem_devices_this_week = [site for site in data["sites"] if data["sites"][site]["incident_count"] > problem_devices_threshold]
    data["problem_devices_count"] = len(problem_devices_this_week)

    # Collects device info to be used in the problem_devices.csv report
    data["device_info"] = {}

    for ticket in data["tickets"]:
        device_hostname = ticket.get("device_hostname", "N/A")
        if device_hostname == "N/A":
            continue

        if device_hostname.startswith("SW-"):
            device_type = "Switch"
        elif device_hostname.startswith("AP-"):
            device_type = "Access Point"
        elif device_hostname.startswith("RT-"):
            device_type = "Router"
        elif device_hostname.startswith("FW-"):
            device_type = "Firewall"
        elif device_hostname.startswith("LB-"):
            device_type = "Load Balancer"
        else:
            device_type = "Unknown"

        if device_hostname not in data["device_info"]:
            data["device_info"][device_hostname] = {
                "site": ticket["site"],
                "device_type": device_type,
                "incident_count": 0,
                "severity_scores": [],
                "total_cost": 0.0,
                "affected_users": []
            }

        data["device_info"][device_hostname]["incident_count"] += 1
        data["device_info"][device_hostname]["severity_scores"].append(ticket["severity"])
        data["device_info"][device_hostname]["total_cost"] += parse_swedish_cost(ticket["cost_sek"])

        affected_users = ticket.get("affected_users", "0")
        if affected_users and affected_users.isdigit():
            data["device_info"][device_hostname]["affected_users"].append(int(affected_users))

    for device_hostname in data["device_info"]:
        device_data = data["device_info"][device_hostname]

        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        avg_severity_score = sum(severity_scores.get(severity.lower(), 0) for severity in device_data["severity_scores"]) / len(device_data["severity_scores"]) if device_data["severity_scores"] else 0
        device_data["avg_severity_score"] = avg_severity_score

        device_data["avg_affected_users"] = sum(device_data["affected_users"]) / len(device_data["affected_users"]) if device_data["affected_users"] else 0

    current_week = max(int(ticket["week_number"]) for ticket in data["tickets"])
    last_week = current_week - 1

    for device_hostname in data["device_info"]:
        device_data = data["device_info"][device_hostname]
        device_data["in_last_weeks_warnings"] = any(ticket["device_hostname"] == device_hostname and int(ticket["week_number"]) == last_week for ticket in data["tickets"]
        )

    # Collects cost information and impact scores to be added to "cost_analysis.csv" file
    data["weekly_cost_analysis"] = {}

    for ticket in data["tickets"]:
        week_number = ticket["week_number"]

        if week_number not in data["weekly_cost_analysis"]:
            data["weekly_cost_analysis"][week_number] = {
                "total_cost": 0.0,
                "impact_scores": []
            }

        data["weekly_cost_analysis"][week_number]["total_cost"] += parse_swedish_cost(ticket["cost_sek"])
        data["weekly_cost_analysis"][week_number]["impact_scores"].append(float(ticket["impact_score"]))

    for week_number in data["weekly_cost_analysis"]:
        impact_scores = data["weekly_cost_analysis"][week_number]["impact_scores"]
        avg_impact_score = sum(impact_scores) / len(impact_scores) if impact_scores else 0
        data["weekly_cost_analysis"][week_number]["avg_impact_score"] = avg_impact_score


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

with open("incident_analysis.txt", "w", encoding="utf-8") as report_file:
    
    # Adds static header to the report
    report_file.write(f"="*35 + "\nIncident Analysis - Oktober 2025\n" + "="*35 + "\n")

    # Adds Executive Summary to the report
    report_file.write("\nEXECUTIVE SUMMARY\n-----------------\n")
    report_file.write(f"⚠ KRITISKT: {data["most_incidents_device_id"]} har {data["most_incidents_device_count"]} incidenter\n")
    report_file.write(f"⚠ KOSTNAD: Dyraste incident: {data["highest_cost"]} SEK ({data["most_expensive_ticket_id"]}, {data["most_expensive_site"]})\n")
    report_file.write(f"⚠ {data["problem_devices_count"]} enheter från förra veckans \"problem devices\" har genererat incidents\n")

    # Critical incident status message across all sites
    if data["sites_without_critical"]:
        message = f"✓ POSITIVT: Inga critical incidents på {", ".join(data["sites_without_critical"])}\n"
    else:
        message = "⚠ KRITISKT: Alla sites har critical incidents som behöver hanteras\n"
    report_file.write(message)

    # Writes Site and analysisperiod information from the data to the report
    report_file.write("\nSITES OCH ANALYSVECKOR\n--------------------\n")
    for site in data["unique_sites"]:
        weeks = sorted(data["sites"][site]["weeks"])
        report_file.write(f"Site: {site}\nAnalysveckor: v.{", v.".join(weeks)}\n\n")

    # Writes total amount of incidents per severity to the report
    report_file.write("INCIDENTER PER SEVERITY-NIVÅ\n--------------------\n")
    for severity, count in data["formatted_severity_counts"].items():
        report_file.write(f"{severity.ljust(10)}-->   {count} incidents\n")

    # Writes highest impact incidents to the report
    report_file.write("\nINCIDENTER SOM PÅVERKAT FLER ÄN 100 ANVÄNDARE\n--------------------\n")
    for ticket in data["high_impact_incidents"]:
        report_file.write(f"Ticket ID: {ticket["ticket_id"].ljust(15)} Site: {ticket["site"].ljust(15)} Affected Users: {ticket["affected_users"].ljust(5)}\n")

    # Writes TOP 5 most expensive incidents to the report
    report_file.write("\nDE 5 DYRASTE INCIDENTERNA\n--------------------\n")
    for top_5, (ticket, cost) in enumerate(data["top_expensive_incidents"], 1):
        report_file.write(f"{top_5}. Ticket ID: {ticket["ticket_id"].ljust(15)} Kostnad: {ticket["cost_sek"].ljust(10)}SEK\n")

    # Writes Total cost of incidents to the report
    report_file.write("\nTOTALKOSTNAD FÖR INCIDENTER\n--------------------\n")
    report_file.write(f"Totalkostnad: {data["total_cost_formatted"]} SEK\n")

    # Writes average resolution time to the report
    report_file.write("\nGENOMSNITTLIG RESOLUTION TIME PER SEVERITY-NIVÅ\n--------------------\n")
    for severity, avg_time in data["avg_resolution_time"].items():
        report_file.write(f"{severity.ljust(10)}-->   {avg_time:.2f} minuter\n")

    # Writes Summary per site to the report
    report_file.write("\nÖVERSIKT PER SITE\n--------------------\n")
    for site in data ["unique_sites"]:
        site_data = data["sites"][site]
        avg_resolution_time = sum(site_data["resolution_times"]) / len(site_data["resolution_times"]) if site_data["resolution_times"] else 0
        report_file.write(f"{site}:\n")
        report_file.write(f" Antal incidenter: {site_data["incident_count"]}\n")
        report_file.write(f" Totalkostnad: {format_swedish_total(site_data["total_cost"])} SEK\n")
        report_file.write(f" Genomsnittlig resolution tid: {avg_resolution_time:.2f} minuter\n\n")
 
    # Writes Average Impact of Incidents to the report
    report_file.write("\nINCIDENTS PER CATEGORY - GENOMSNITTLIG IMPACT\n--------------------\n")
    report_file.write("Kategori      AVG Impact  Antal Incidenter\n")
    for category, category_data in data["categories"].items():
        avg_impact_score = sum(category_data["impact_scores"]) / len(category_data["impact_scores"]) if category_data["impact_scores"] else 0
        formatted_category = category.capitalize()
        report_file.write(f"{formatted_category.ljust(14)}{avg_impact_score:.2f}        {category_data["incident_count"]}\n")

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

# CSV Writer that creates a csv file "problem_devices.csv"
def write_device_summary_to_csv(data, output_filename="problem_devices.csv"):
    with open(output_filename, mode="w", encoding="utf-8", newline="") as csv_file:
        fieldnames = [
            "device_hostname",
            "site",
            "device_type",
            "incident_count",
            "avg_severity_score",
            "total_cost_sek",
            "avg_affected_users", 
            "in_last_weeks_warnings"
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for device_hostname, device_data in data["device_info"].items():
            writer.writerow({
                "device_hostname": device_hostname,
                "site": device_data["site"],
                "device_type": device_data["device_type"],
                "incident_count": device_data["incident_count"],
                "avg_severity_score": f"{device_data['avg_severity_score']:.2f}",
                "total_cost_sek": format_swedish_total(device_data["total_cost"]),
                "avg_affected_users": f"{device_data['avg_affected_users']:.2f}", 
                "in_last_weeks_warnings": device_data["in_last_weeks_warnings"]
            })
write_device_summary_to_csv(data)

def write_cost_analysis_to_csv(data, output_filename="cost_analysis.csv"):
    with open(output_filename, mode="w", encoding="utf-8", newline="") as csv_file:
        fieldnames = [
            "week_number",
            "total_cost_sek",
            "avg_impact_score"
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        # Sortera veckonummer för att få en kronologisk ordning
        sorted_weeks = sorted(data["weekly_cost_analysis"].keys())

        for week_number in sorted_weeks:
            week_data = data["weekly_cost_analysis"][week_number]
            writer.writerow({
                "week_number": week_number,
                "total_cost_sek": format_swedish_total(week_data["total_cost"]),
                "avg_impact_score": f"{week_data['avg_impact_score']:.2f}"
            })
write_cost_analysis_to_csv(data)

