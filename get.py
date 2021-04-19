#!/usr/bin/python3

from urllib.request import Request, urlopen
import json
import base64
import configparser
from cryptography.fernet import Fernet

# Unencrypt password
def decrypt_pass(pass_enc):
  f = open("./cipher.key")
  key = f.readline().encode("utf-8")
  f.close()
  cipher_suite = Fernet(key)
  unenc = ( cipher_suite.decrypt(pass_enc.encode("utf-8"))).decode("utf-8")
  return unenc

# Run an API request and dump data to file
def get_data(url, auth, file):
  req = Request(url)
  req.add_header("Authorization",auth)
  resp = urlopen(req).read()
  f = open(json_dir + "/" + file, "w")
  f.write(str(resp.decode("utf-8")))
  f.close()
  return(json.loads(resp))
  
conf = configparser.RawConfigParser()
conf.read("grafana-sync.conf")

source   = conf["grafana"]["source"]
source_username = conf["grafana"]["source_username"]
source_password = decrypt_pass(conf["grafana"]["source_password"])
source_apikey   = conf["grafana"]["source_apikey"]
target_username = conf["grafana"]["target_username"]
target_password = decrypt_pass(conf["grafana"]["target_password"])
target_apikey   = conf["grafana"]["target_apikey"]
json_dir = conf["grafana"]["json_dir"]
source_auth = str(base64.b64encode(bytes('%s:%s' % (source_username,source_password), "utf-8")),"ascii").strip()
target_auth = str(base64.b64encode(bytes('%s:%s' % (target_username,target_password), "utf-8")),"ascii").strip()

# Get Users
users = get_data(source + "/users","Basic " + source_auth, "users.json")

# Get Teams
teams = get_data(source + "/teams/search?query=","Bearer " + source_apikey, "teams.json")

# Get Team Members
team_members = get_data(source + "/teams/*/members","Bearer " + source_apikey, "team_members.json")

# Get Datasources
datasources = get_data(source + "/datasources","Bearer " + source_apikey, "datasources.json")

# Get Folders and iterate through each one to get permissions
folders = get_data(source + "/folders","Bearer " + source_apikey, "/folders.json")
permissions = {}
for folder in folders :
  uid = folder["uid"]
  permission = get_data(source + "/folders/" + uid + "/permissions","Bearer " + source_apikey, "temp.json")
  permissions[uid] = json.dumps(permission)
f = open(json_dir + "/folder_permissions.json", "w")
f.write(json.dumps(permissions))
f.close()

# Get Dashboards
permissions = {}
dashboards = []
dashboard_list = get_data(source + "/search?query=&type=dash-db","Bearer " + source_apikey, "dashboard_list.json")
for dashboard in dashboard_list:
  id = str(dashboard["id"])
  uid = dashboard["uid"]
  permission = get_data(source + "/dashboards/id/" + id + "/permissions","Bearer " + source_apikey, "temp.json")
  permissions[id] = json.dumps(permission)
  dashboard = get_data(source + "/dashboards/uid/" + uid,"Bearer " + source_apikey, "temp.json")
  dashboards.append(dashboard)

f = open(json_dir + "/dashboards.json", "w")
f.write(str(json.dumps(dashboards)))
f.close()
f = open(json_dir + "/dashboard_permissions.json", "w")
f.write(str(permissions))
f.close()
