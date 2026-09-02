import database

database.initialize_database()

print("\nRecent flows:")

flows = database.get_recent_flows(10)

for flow in flows:

    print(flow)


print("\nThreat history:")

threats = database.get_threat_history(10)

for threat in threats:

    print(threat)
