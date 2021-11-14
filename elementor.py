import requests
from requests.api import head


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

with open("python_workspace/elementorTest/request1.csv") as url_source_file:
    for line in url_source_file:
        url_ids[line.rstrip()] = ""
        url_ratings[line.rstrip()] = dict()

for url in url_ids.keys():
    target_url = "url=" + url
    post_response = requests.request("POST", url_target, data=target_url, headers=post_headers)

    # capture the id for use in the next query
    url_id = post_response.json()["data"]["id"]

    url_ids[url] = url_id

    analysis_id_target = analysis_id_target_prefix + url_id
    print(analysis_id_target)
    get_headers = {
        "Accept": "application/json",
        "x-apikey": api_key
    }
    get_response = requests.request("GET", analysis_id_target, headers=get_headers)
    url_analysis_stats = get_response.json()["data"]["attributes"]["stats"]

    url_ratings[url] = url_analysis_stats

print(url_ids)
print(url_ratings)

# SQL Question:
# SELECT employee_id, MAX(salary) FROM employees GROUP BY department_id
# SELECT employee_id, salary FROM employees ORDER BY department_id, salary