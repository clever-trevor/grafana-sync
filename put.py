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

# Read a file containing JSON and return contents as JSON structure
def read_file(file):
  f = open(json_dir + "/" + file, "r")
  data = f.read()
  f.close()
  json_data = json.loads(data)
  return(json_data)
 
# Read in the conf file that drives this script
conf = configparser.RawConfigParser()
conf.read("grafana-sync.conf")

source   = conf["grafana"]["source"]
target   = conf["grafana"]["target"]
source_username = conf["grafana"]["source_username"]
source_password = decrypt_pass(conf["grafana"]["source_password"])
source_apikey   = conf["grafana"]["source_apikey"]
target_username = conf["grafana"]["target_username"]
target_password = decrypt_pass(conf["grafana"]["target_password"])
target_apikey   = conf["grafana"]["target_apikey"]
json_dir = conf["grafana"]["json_dir"]

# Build up basic auth encoded string
source_auth = str(base64.b64encode(bytes('%s:%s' % (source_username,source_password), "utf-8")),"ascii").strip()
target_auth = str(base64.b64encode(bytes('%s:%s' % (target_username,target_password), "utf-8")),"ascii").strip()

############################################################
# Sync Datasources
############################################################
print("Syncing Datasources")
datasources_in = read_file("datasources.json")   # Dump from source server
datasources_out = get_data(target + "/datasources","Bearer " + target_apikey)

# Build dictionary of target datasource name to id mappings
datasources_out_map = {}
for datasource in datasources_out:
  name = datasource["name"]
  datasources_out_map[name] = datasource["id"]

# Process each datasource from input, and decide whether to create (POST) or update (PUT) 
# on the target system (after translating the datasource id)
for datasource in datasources_in:
  name = datasource["name"]

  # Datasource doesn't exist in target system so create it
  if name not in datasources_out_map:
    del datasource["id"]
    try : 
      put_data(target + "/datasources", "Bearer " + target_apikey, "POST", datasource)
      print(" %s datasource created successfully" % name)
    except Exception as e:
      print(" %s datasource could not be created" % name)
      print(" %s" % json.dumps(datasource))
  # Datasource already exists so update it
  else :
    id_out = datasources_out_map[name]
    datasource["id"] = id_out
    try : 
      put_data(target + "/datasources/" + str(id_out), "Bearer " + target_apikey, "PUT", datasource)
      print(" %s datasource updated successfully" % name)
    except Exception as e:
      print(" %s datasource could not be updated" % name)
      print(" %s" % json.dumps(datasource))

############################################################
# Sync Teams 
############################################################
print("Syncing Teams")
teams_in = read_file("teams.json")   # Dump from source server
teams_out = get_data(target + "/teams/search?query=", "Bearer " + target_apikey)  # Get this server
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
    print(" %s : Update existing" % name)
    put_data(target + "/teams/" + str(id_out), "Bearer " + target_apikey, "PUT", team)
  except:
    print(" %s : Create New" % name)
    put_data(target + "/teams", "Bearer " + target_apikey, "POST", team)


############################################################
# Sync Users
############################################################
print("Syncing Users")
users_in = read_file("users.json")   # Dump from source server
users_out = get_data(target + "/users", "Basic " + target_auth)  # Get this server
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
    print(" %s : Update existing" % login)
    put_data(target + "/users/" + str(id_out), "Basic " + target_auth , "PUT", user)
  except:
    print(" %s : Create New" % login)
    user["password"] = "trev"
    print(" %s" % user)
    put_data(target + "/admin/users", "Basic " + target_auth, "POST", user)

############################################################
# Add users to teams
############################################################
print("Syncing users to teams")
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
      put_data(target + "/teams/" + str(team_out_id) + "/members", "Basic " + target_auth , "POST", doc)
      print(" Adding %s to %s" % ( login,team_name) )
    except:
      pass

############################################################
# Sync Folders
############################################################
print("Syncing Folders")
folders_in = read_file("folders.json")
folders_out =  get_data(target + "/folders","Bearer " + target_apikey)
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
    print(" %s : Update existing" % name)
    try:
      put_data(target + "/folders/" + uid, "Bearer " + target_apikey, "PUT", folder)
    except:
      pass
  else:
    print(" %s : Create New" % name)
    put_data(target + "/folders", "Bearer " + target_apikey, "POST", folder)



############################################################
# Sync Folder Permissions
############################################################
print("Syncing Folder Permissions")
folderPerms_in = read_file("folder_permissions.json")
folderPerms_out = {}
folders = get_data(target + "/folders","Bearer " + target_apikey)
for folder in folders :
  uid = folder["uid"]
  permission = get_data(target + "/folders/" + uid + "/permissions","Bearer " + target_apikey)
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
    put_data(target + "/folders/" + uid + "/permissions", "Bearer " + target_apikey, "POST", permission_list)
    print(" %s Success permissions" % name)
  except :
    print(" %s Unable to apply permissions" % name)

############################################################
# Sync Dashboards
############################################################
print("Syncing Dashboards")
# Get inventory from target system and build dictionary of ID vs UID
dashboards_in = read_file("dashboards.json")
dashboards_out = get_data(target +  "/search?query=&type=dash-db" ,"Bearer " + target_apikey)
dashboards_target = {}
for dashboard in dashboards_out:
  dashboards_target[dashboard["uid"]] = dashboard["id"]   
 
# Now process each dashboard from the source system
dashboards_in_inventory = read_file("dashboard_list.json")
for dashboard in dashboards_in_inventory:
  uid = dashboard["uid"]
  name = dashboard["title"]
  # If no folder is defined, then it is stored under the "General" default folder (id=0)
  try:
    folder_in = dashboard["folderId"]
    folder_in_uid = folders_in_id_map[folder_in]
    folder_out_id = folders_out_uid_map[folder_in_uid]
  except :
    folder_in = 0
    folder_out_id = 0
  del dashboard["id"]
  dashboard["folderId"] = folder_out_id
  if uid not in dashboards_target :
    print(" %s doesn't exists" % name)
    try:
      dashboard_out = {}
      dashboard_out["folderId"] = folder_out_id
      dashboard_out["overwrite"] = True
      dashboard_out["dashboard"] = dashboard
      put_data(target + "/dashboards/db", "Bearer " + target_apikey, "POST", dashboard_out)
      print(" %s Success Dashboard Created" % name)
    except Exception as e:
      print(" %s Unable to Create Dashboard" % name)
      print(" %s" % json.dumps(dashboard_out))
      print(" %s" + e)
  
for dashboard in dashboards_in:
  name = dashboard["dashboard"]["title"]
  dash_in_uid = dashboard["dashboard"]["uid"] 
  try:
    dash_out_id = dashboards_target[dash_in_uid]
  except:
    dash_out_id = 0

  try:
    folder_in_id = dashboard["meta"]["folderId"]
    folder_in_uid = folders_in_id_map[folder_in_id]
    folder_out_id = folders_out_uid_map[folder_in_uid]
  except:
    folder_out_id = 0
  dashboard["dashboard"]["id"] = dash_out_id
  dashboard["folderId"] = folder_out_id
  dashboard["overwrite"] = True
  del dashboard["meta"]

  try:
    put_data(target + "/dashboards/db", "Bearer " + target_apikey, "POST", dashboard)
    print(" %s Success Dashboard Updated" % name)
  except Exception as e:
    print(" %s Unable to Update Dashboard" % name)
    print(" %s" % json.dumps(dashboard))
    print(" %s" % e)
    
############################################################
# Dashboard permissions
############################################################
# Bit messy, but we need to read in each permission, determine if the permission is :
#    - Inherited (ignore)
#    - UserID (translate source to target userid)
#    - TeamId (translate source to target teamid)
# As well, translate source dashboard ID to target Id

print("Syncing Dashboard Permissions")

# Get source permissions
permissions_in = read_file("dashboard_permissions.json")
for dashboard_in_uid in permissions_in:
  # Work out target dashboard Id
  dashboard_in_permissions = json.loads(permissions_in[dashboard_in_uid])
  dashboard_out_id = dashboards_target[dashboard_in_uid]
  # Build a list of (translated) permissions to apply
  permissions_out = []   # List of output permissions
  print(" Dashboard UID:%s" % dashboard_in_uid) 
  # Iterate through each individual permission
  for permission in dashboard_in_permissions:

    if permission["inherited"] == True:
      print("  Ignoring inherited")
      continue

    perm = "" # Empty permission

    # Permission is team related
    if permission["teamId"] != 0 :
      # Remap source team Id to target system
      team_in_id = permission["teamId"]
      team_name = teams_in_id[team_in_id]
      team_out_id = teams_out_map[team_name]
      perm = { "teamId":team_out_id,"permission":permission["permission"] }
      print("  Team:%s In:%s Out:%s" % (team_name, team_in_id,team_out_id))
    # Permission is user related
    elif permission["userId"] != 0 :
      # Remap source user Id to target system
      user_in_id = permission["userId"]
      login = users_in_id[user_in_id]
      user_out_id = users_out_map[login]
      perm = { "userId":user_out_id,"permission":permission["permission"] }
      print("  User:%s In:%s Out:%s" % (login, user_in_id,user_out_id))

    permissions_out.append(perm)   # Add permissions to list

  # Build payload JSON
  payload = { "items": permissions_out }
  print("  Final Permissions:" + str(payload))

  # Update permissions, even if there are none as this will delete on target system (as per API spec)
  try:
    put_data(target + "/dashboards/id/" + str(dashboard_out_id) + "/permissions", "Bearer " + target_apikey, "POST", payload)
    print("  Successfully loaded")
  except Exception as e:
    print("  ERROR Ddashboard permissions could not be updated")
    print("  Payload:%s" % str(payload))
    print("  %s" % e)
  

print("All Done!!")
exit()
