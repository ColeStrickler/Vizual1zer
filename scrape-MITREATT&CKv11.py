from bs4 import BeautifulSoup
import requests
import json

base_website = "https://attack.mitre.org"

user_agent_header = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36"}
response = requests.get("https://attack.mitre.org/tactics/enterprise/", headers=user_agent_header)

soup = BeautifulSoup(response.text, 'html.parser')

tactics = []
sub_technique_links = []
tactics_links = []
mitre_dict = {}
has_subtechniques = False

# Iterate over tactics
list = soup.find("tbody").find_all("td")
for i in range(len(list)):
    if i % 3 == 1:
        # extract name and links of tactics from main page
        scraped_tactic = list[i].text.strip()
        scraped_link = list[i].find('a')['href']

        # add each tactic to the main dictionary data store, and append the links to a list for later search
        mitre_dict[scraped_tactic] = {}
        tactics_links.append(scraped_link)
        tactics.append(scraped_tactic)
    #  print(f"{list[i].text.strip()}: {list[i].find('a')['href']}")


# go to each tactic link and grab their techniques and sub techniques
for dir in tactics_links:
    #if dir == '/tactics/TA0043':
    technique_links = []
    sub_technique_links = []
    response = requests.get(base_website + dir, headers=user_agent_header)
    soup = BeautifulSoup(response.text, 'html.parser')
    # extract all TRs which hold the techniques and sub techniques
    list = soup.find("tbody").find_all("tr", {"class": "technique"})
    # extract the title/technique
    og_title = soup.find("h1").text.strip()
    print(f'TECHNIQUE: {og_title}')
    for i in range(len(list)):
        # parse TRs by CSS class, technique links in one list, sub techniques into another list
        if list[i]['class'][0] == "technique":
            technique = list[i].find_all("td")[1].text.strip()
            technique_link = list[i].find_all("td")[1].find("a")["href"]
            print(technique_link)
            technique_links.append(technique_link)
            mitre_dict[og_title][technique] = {}
            mitre_dict[og_title][technique]["Data Sources"] = {}
        elif list[i]['class'][0] == "sub":
            sub_technique = list[i].find_all("td")[2].text.strip()
            sub_technique_link = list[i].find_all("td")[2].find("a")["href"]
            sub_technique_links.append(sub_technique_link)
            mitre_dict[og_title][technique][sub_technique] = {}
            mitre_dict[og_title][technique][sub_technique]["Data Sources"] = {}
    print(sub_technique_links)
    # go to each sub technique page and grab their data sources
    for link in sub_technique_links:
        response = requests.get(base_website + link, headers=user_agent_header)
        if "Deprecation Warning" in response.text:
            pass
        else:
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.find("h1").text.strip().split(":\n")[1].strip()
            title0 = soup.find("h1").text.strip().split(":\n")[0].strip()

            data = soup.find_all("tr", {"class": "datasource"})
            if len(data) > 0:
                for row in data:
                    td_list = row.find_all("td")
                    # some pages are missing information or have a dissimilar DOM so having Try/Except blocks is necessary
                    try:
                        data_source = td_list[1].find("a").text
                        data_component = td_list[2].find("a").text
                        print(f"Technique: {title0}, Sub-Technique: {title}, Tactic: {og_title}, Data Source: {data_source}, DataComponent: {data_component}")
                        try:
                            # tactic_title to og_title
                            mitre_dict[og_title][title0][title]["Data Sources"][data_source][data_component] = ""
                        except Exception as e:
                            mitre_dict[og_title][title0][title]["Data Sources"].update({data_source: {}})
                            mitre_dict[og_title][title0][title]["Data Sources"][data_source][data_component] = ""
                    except Exception as e:
                        data_component = td_list[2].find("a").text
                        print(f"Technique: {title0}, Sub-Technique: {title}, Tactic: {og_title}, Data Source: {data_source}, DataComponent: {data_component}")
                        try:
                            mitre_dict[og_title][title0][title]["Data Sources"][data_source][data_component] = ""
                        except Exception as e:
                            mitre_dict[og_title][title0][title]["Data Sources"].update({data_source: {}})
                            mitre_dict[og_title][title0][title]["Data Sources"][data_source][data_component] = ""



    # now run through the techniques
    for link in technique_links:
        response = requests.get(base_website + link, headers=user_agent_header)
        if "Deprecation Warning" in response.text:
            pass
        else:
            soup = BeautifulSoup(response.text, 'html.parser')
            title0 = soup.find("h1").text.strip()

            data = soup.find_all("tr", {"class": "datasource"})
            if len(data) > 0:
                for row in data:
                    td_list = row.find_all("td")
                    # some pages are missing information or have a dissimilar DOM so having Try/Except blocks is necessary
                    try:
                        data_source = td_list[1].find("a").text
                        data_component = td_list[2].find("a").text
                        print(f"Technique: {title0}, Sub-Technique: N/A, Tactic: {og_title}, Data Source: {data_source}, DataComponent: {data_component}")
                        try:
                            # tactic_title to og_title
                            mitre_dict[og_title][title0]["Data Sources"][data_source][data_component] = ""
                        except Exception as e:
                            mitre_dict[og_title][title0]["Data Sources"].update({data_source: {}})
                            mitre_dict[og_title][title0]["Data Sources"][data_source][data_component] = ""
                    except Exception as e:
                        data_component = td_list[2].find("a").text
                        print(f"Technique: {title0}, Sub-Technique: N/A, Tactic: {og_title}, Data Source: {data_source}, DataComponent: {data_component}")
                        try:
                            mitre_dict[og_title][title0]["Data Sources"][data_source][data_component] = ""
                        except Exception as e:
                            mitre_dict[og_title][title0]["Data Sources"].update({data_source: {}})
                            mitre_dict[og_title][title0]["Data Sources"][data_source][data_component] = ""




dict = json.dumps(mitre_dict, indent=4)
with open("Mitre_Dataset.json", "w") as f:
    f.write(dict)
print(dict)