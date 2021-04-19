#!/usr/bin/python3
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
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

 # Run an API request and return JSON
def get_data(url, auth):
  req = Request(url)
  req.add_header("Authorization",auth)
  resp = urlopen(req).read()
  return(json.loads(resp))

# Post/Put data to the API
def put_data(url, auth, method, data):
  data = json.dumps(data)
  req = Request(url = url, data = bytes(data.encode("utf-8")), method = method)
  req.add_header('Content-Type', 'application/json; charset=utf-8')
  req.add_header("Authorization",auth)
  resp = urlopen(req).read()
  return(str(resp))

# Read a file and return JSON
def read_file(file):
  f = open(json_dir + "/" + file, "r")
  data = f.read()
  f.close()
  json_data = json.loads(data)
  return(json_data)
  
# Read in the conf file
conf = configparser.RawConfigParser()
conf.read("grafana-sync.conf")

source   = conf["grafana"]["source"]
target   = conf["grafana"]["source"]
username = conf["grafana"]["username"]
password = decrypt_pass(conf["grafana"]["password"])
apikey   = conf["grafana"]["apikey"]
json_dir = conf["grafana"]["json_dir"]

# Build up basic auth encoded string
auth = str(base64.b64encode(bytes('%s:%s' % (username,password), "utf-8")),"ascii").strip()

# Sync Datasources
print("Syncing Datasources")
datasources_in = read_file("datasources.json")   # Dump from source server
datasources_out = get_data(target + "/datasources","Bearer " + apikey)
# Now store a mapping of each team id as found on this server
datasources_out_map = {}
for datasource in datasources_out:
  name = datasource["name"]
  datasources_out_map[name] = datasource["id"]

for datasource in datasources_in:
  name = datasource["name"]
  # Datasource doesn't exist in target system so create it
  if name not in datasources_out_map:
    del datasource["id"]
    try : 
      put_data(target + "/datasources", "Bearer " + apikey, "POST", datasource)
      print("%s datasource created successfully" % name)
    except Exception as e:
      print("%s datasource could not be created" % name)
      print(json.dumps(datasource))
  # Datasource already exists so update it
  else :
    id_out = datasources_out_map[name]
    datasource["id"] = id_out
    try : 
      put_data(target + "/datasources/" + str(id_out), "Bearer " + apikey, "PUT", datasource)
      print("%s datasource updated successfully" % name)
    except Exception as e:
      print("%s datasource could not be updated" % name)
      print(json.dumps(datasource))

# Sync Teams 
print("Syncing Teams")
teams_in = read_file("teams.json")   # Dump from source server
teams_out = get_data(target + "/teams/search?query=", "Bearer " + apikey)  # Get this server
# Now store a mapping of each team id as found on this server
teams_out_map = {}
for team in teams_out["teams"]:
  teams_out_map[team["name"]] = team["id"]

teams_in_id = {}   # Keep a team mapping for later on
for team in teams_in["teams"]:
  name = team["name"]
  teams_in_id[team["id"]] = name    # Store ID to name mapping
  del team["id"]   # Can't specify the id in the JSON
  # Do we have a match for this team?
  try:
    id_out = teams_out_map[name]  # Yes
    print(name + " : Update existing")
    put_data(target + "/teams/" + str(id_out), "Bearer " + apikey, "PUT", team)
  except:
    print(name + " : Create New")
    put_data(target + "/teams", "Bearer " + apikey, "POST", team)


# Sync Users
print("Syncing Users")
users_in = read_file("users.json")   # Dump from source server
users_out = get_data(target + "/users", "Basic " + auth)  # Get this server
# Now store a mapping of each team id as found on this server
users_out_map = {}
for user in users_out:
  users_out_map[user["login"]] = user["id"]

users_in_id = {}    # Keep user to id mapping for later
for user in users_in:   
  login = user["login"]
  users_in_id[user["id"]] = login
  if login == "admin":    # Ignore built-in admin user
    continue
  del user["id"]   # Can't specify the id in the JSON
  # Do we have a match for this user?
  try:
    id_out = users_out_map[login]  # Yes
    print(login + " : Update existing")
    put_data(target + "/users/" + str(id_out), "Basic " + auth , "PUT", user)
  except:
    print("\n" + login + " : Create New")
    user["password"] = "trev"
    print(user)
    put_data(target + "/admin/users", "Basic " + auth, "POST", user)

# Add users to teams
print("Adding users to teams")
members_in = read_file("team_members.json")
for member in members_in:
  login = member["login"]
  if login in users_out_map :
    try:
      id_out = users_out_map[login] 
      team_in_id = member["teamId"]
      team_name = teams_in_id[team_in_id]
      team_out_id = teams_out_map[team_name]
      doc = { "userId" : id_out }
      put_data(target + "/teams/" + str(team_out_id) + "/members", "Basic " + auth , "POST", doc)
      print("Adding %s to %s" % ( login,team_name) )
    except:
      pass


# Sync Folders
print("Syncing Folders")
folders_in = read_file("folders.json")
folders_out =  get_data(target + "/folders","Bearer " + apikey)
folders_out_uid_map = {}
folders_out_id_map = {}
for folder in folders_out:
  folders_out_uid_map[folder["uid"]] = folder["id"]
  folders_out_id_map[folder["id"]] = folder["uid"]

folders_in_id_map = {}  
folders_in_uid_map = {}  
for folder in folders_in:
  name = folder["title"]
  uid = folder["uid"]
  folders_in_uid_map[folder["uid"]] = folder["id"]
  folders_in_id_map[folder["id"]] = uid
  del folder["id"]   # Can't specify the id in the JSON
  if uid in folders_out_uid_map:
    print(name + " : Update existing")
    try:
      put_data(target + "/folders/" + uid, "Bearer " + apikey, "PUT", folder)
    except:
      pass
  else:
    print(name + " : Create New")
    put_data(target + "/folders", "Bearer " + apikey, "POST", folder)


# Sync Folder Permissions
print("Syncing Folder Permissions")
folderPerms_in = read_file("folder_permissions.json")
folderPerms_out = {}
folders = get_data(target + "/folders","Bearer " + apikey)
for folder in folders :
  uid = folder["uid"]
  permission = get_data(target + "/folders/" + uid + "/permissions","Bearer " + apikey)
  folderPerms_out[uid] = permission

for uid in folderPerms_in:
  permissions = json.loads(folderPerms_in[uid])
  permission_set = []   # Use this to build the set of permissions for a given folder
  permission_list = {}  # This is the final JSON we'll post
  name = ""             # Friendly name of the folder
  for permission in permissions:
    new_permission = {}
    team_in_id = permission["teamId"]
    user_in_id = permission["userId"]
    name = permission["title"]
    if user_in_id != 0 :
      user_name = users_in_id[user_in_id]
      user_out_id = users_out_map[user_name]
      new_permission = { "userId": user_out_id , "permission" : permission["permission"]}
    elif team_in_id != 0:
      team_name = teams_in_id[team_in_id]
      team_out_id = teams_out_map[team_name]
      new_permission = { "teamId": team_out_id, "permission" : permission["permission"] }
    else :
      new_permission = { "role": permission["role"], "permission":permission["permission"] }
    permission_set.append(new_permission)
  permission_list["items"] = permission_set
  try:
    put_data(target + "/folders/" + uid + "/permissions", "Bearer " + apikey, "POST", permission_list)
    print("%s Success permissions" % name)
  except :
    print("%s Unable to apply permissions" % name)

# Sync Dashboards
print("Syncing Dashboards")
dashboards_in_inventory = read_file("dashboard_list.json")
dashboards_in = read_file("dashboards.json")
dashboards_out = get_data(target +  "/search?query=&type=dash-db" ,"Bearer " + apikey)
dashboards_target = {}
for dashboard in dashboards_out:
  dashboards_target[dashboard["uid"]] = dashboard["id"]   
  


for dashboard in dashboards_in_inventory:
  uid = dashboard["uid"]
  name = dashboard["title"]
  folder_in = dashboard["folderId"]
  folder_in_uid = folders_in_id_map[folder_in]
  folder_out_id = folders_out_uid_map[folder_in_uid]
  del dashboard["id"]
  dashboard["folderId"] = folder_out_id
  if uid not in dashboards_target :
    print("%s doesn't exists" % name)
    try:
      dashboard_out = {}
      dashboard_out["folderId"] = folder_out_id
      dashboard_out["overwrite"] = True
      dashboard_out["dashboard"] = dashboard
      put_data(target + "/dashboards/db", "Bearer " + apikey, "POST", dashboard_out)
      print("%s Success Dashboard Created" % name)
    except Exception as e:
      print("%s Unable to Create Dashboard" % name)
      print(json.dumps(dashboard_out))
      print(e)
  
for dashboard in dashboards_in:
#  print(json.dumps(dashboard))
  name = dashboard["dashboard"]["title"]
  dash_uid_in = dashboard["dashboard"]["uid"] 
  dash_id_out = dashboards_target[dash_uid_in]

  folder_in_id = dashboard["meta"]["folderId"]
  folder_in_uid = folders_in_id_map[folder_in_id]
  folder_out_id = folders_out_uid_map[folder_in_uid]
  dashboard["dashboard"]["id"] = dash_id_out
  dashboard["folderId"] = folder_out_id
  dashboard["overwrite"] = True
  del dashboard["meta"]

  #print("FolderInId:%s FolderOutId:%s  UIDIn:%s"  % (folder_in_id, folder_out_id, folder_in_uid))
  try:
    put_data(target + "/dashboards/db", "Bearer " + apikey, "POST", dashboard)
    print("%s Success Dashboard Updated" % name)
  except Exception as e:
    print("%s Unable to Update Dashboard" % name)
    print(json.dumps(dashboard))
    print(e)
    
