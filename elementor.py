import requests
from requests.api import head
from datetime import datetime, timedelta
import sqlite3

# read in the request1.csv file line by line
# for each line (URL) 
# check if it's in the db/results object and the last_updated_time was less than 15 minutes ago
# if not query to virustotal for the URL
# store url, id,

api_key = "4b4018b73b73af615eb4de7f3a49c7bc29860bf90110eb4bd37d55b684758e88"
url_target = "https://www.virustotal.com/api/v3/urls"
post_headers = {
    "Accept": "application/json",
    "x-apikey": api_key,
    "Content-Type": "application/x-www-form-urlencoded"
}
analysis_id_target_prefix = "https://www.virustotal.com/api/v3/analyses/"


url_ids = dict()
url_ratings = dict()
url_results = dict()
url_last_updated_time = dict()

# db_connection = sqlite3.connect(r"python_workspace/elementorTest/urls.db")

with open("python_workspace/elementorTest/request1.csv") as url_source_file:
    for line in url_source_file:
        url_ids[line.rstrip()] = ""
        url_ratings[line.rstrip()] = dict()
        url_results[line.rstrip()] = ""
        url_last_updated_time[line.rstrip()] = None

for url in url_ids.keys():
    current_time = datetime.now()

    # check that we don't have updated data for url
    if url_last_updated_time[url] == None or (current_time - url_last_updated_time[url]).total_seconds()/60 > 15:
        target_url = "url=" + url
        post_response = requests.request("POST", url_target, data=target_url, headers=post_headers)

        # capture the id for use in the next query
        url_id = post_response.json()["data"]["id"]

        url_ids[url] = url_id

        analysis_id_target = analysis_id_target_prefix + url_id

        get_headers = {
            "Accept": "application/json",
            "x-apikey": api_key
        }
        get_response = requests.request("GET", analysis_id_target, headers=get_headers)
        url_analysis_stats = get_response.json()["data"]["attributes"]["stats"]

        url_ratings[url] = url_analysis_stats

        url_last_updated_time[url] = datetime.now()

        if url_analysis_stats["malicious"] > 0:
            url_results[url] = "risk"
        else:
            url_results[url] = "safe"

print(url_ids)
print(url_ratings)
print(url_results)
print(url_last_updated_time)