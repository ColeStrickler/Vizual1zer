import requests
from bs4 import BeautifulSoup
import json


base_website = "https://attack.mitre.org"



user_agent_header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"}
response = requests.get("https://attack.mitre.org/groups/", headers=user_agent_header)

soup = BeautifulSoup(response.text, "html.parser")

dict = {}
group_dict = {}
group_links = []
technique_links = []

group_list = soup.find("tbody").find_all("td")

for i in range(len(group_list)):
    if i % 4 == 1:
        group = group_list[i].find('a').text.strip()
        dict[group] = {}
        group_dict[group] = group_list[i].find('a')['href']
        group_links.append(group_list[i].find('a')['href'])



for group in group_dict:
    link = group_dict[group]
    print(f"{group} : {link}")
#for link in group_links:
    response = requests.get(base_website + link, headers=user_agent_header)
    # print(base_website + link)
    soup = BeautifulSoup(response.text, "html.parser")
    group_techniques = soup.find("tbody").find_all("tr")
    if len(group_techniques[0].find_all('td')) < 4:
        group_techniques = soup.find_all("tbody")[1].find_all("tr")
    for i in range(len(group_techniques)):
        domain = group_techniques[i].find_all("td")
        if domain[0].text.strip() == "Enterprise":
            if len(domain) == 4:  # extract only technique
                technique_link = domain[2].find('a')['href']
                response = requests.get(base_website + technique_link, headers=user_agent_header)
                soup = BeautifulSoup(response.text, "html.parser")
                technique = soup.find('h1').text.strip()
                data_src_list = soup.find_all("tbody")[-1].find_all("tr")
                print(f"{group} : {technique}")
                dict[group][technique] = {}
                for src in data_src_list:
                    source = src.find_all("td")[2].text.strip()
                    if len(source) > 35:
                        continue
                    print(f"SOURCE: {source}")
                    try:
                        dict[group][technique]["Data Sources"] = {}
                        dict[group][technique]["Data Sources"][source] = {}
                    except Exception as e:
                        print(e)


            elif len(domain) == 5:
                technique_link = domain[1].find('a')['href']
                response = requests.get(base_website + technique_link, headers=user_agent_header)
                soup = BeautifulSoup(response.text, "html.parser")
                technique = soup.find('h1').text.strip()
                tech_data_src_list = soup.find_all("tbody")[-1].find_all("tr")
                sub_technique_link = domain[2].find('a')['href']
                response = requests.get(base_website + sub_technique_link, headers=user_agent_header)
                soup = BeautifulSoup(response.text, "html.parser")
                sub_technique = soup.find('ol').find_all('li')[4].text
                sub_data_src_list = soup.find_all("tbody")[-1].find_all("tr")
                print(f"{group} : {technique} : {sub_technique}")
                try:
                    dict[group][technique][sub_technique] = {}
                    dict[group][technique][sub_technique]["Data Sources"] = {}
                except Exception as e:
                    dict[group][technique] = {}
                    dict[group][technique]["Data Sources"] = {}
                    dict[group][technique][sub_technique] = {}
                    dict[group][technique][sub_technique]["Data Sources"] = {}

                for src in tech_data_src_list:
                    source = src.find_all("td")[2].text.strip()
                    if len(source) > 35:
                        continue
                    print(f"SOURCE: {source}")
                    try:
                        dict[group][technique]["Data Sources"][source] = {}
                    except Exception as e:
                        try:
                            dict[group][technique]["Data Sources"] = {}
                            dict[group][technique]["Data Sources"][source] = {}
                        except Exception as e:
                            print(e)

                for src in sub_data_src_list:
                    source = src.find_all("td")[2].text.strip()
                    if len(source) > 35:
                        continue
                    print(f"SOURCE: {source}")
                    dict[group][technique][sub_technique]["Data Sources"][source] = {}


data = json.dumps(dict, indent=4)

with open("ThreatGroups.json", "w") as f:
    f.write(data)

print(data)