#!/usr/bin/python3

#######################################################################################
# This script will copy various objects from one Grafana instance to another. 
# It will cater for different internal ID's between systems so that the target system
# doesn't have to be a replica of source.  
# The script will currently synchronise :
#  - Datasources
#  - Teams 
#  - Users + Team membership
#  - Folders + Permissions
#  - Dashboards + Permissions
# The API's do not expose passwords so the first time a new datasource or local userid
# is synced, you would need to re-enter the password in the target system.
# 
# The script can be run in two modes:
#  GET - Data from the source system will be extracted and stored in a series of 
#        JSON files under the ./json subdirectory
#  SYNC - This will run the GET data and then upload this to the target system
#
# TODO : 
#    - Other Grafana objects such as notifications, etc 
#    - "Proper" sync where dashboards that have been deleted from source are also 
#      deleted from target
#    - Interrogate the "last updated" time so that newer objects are not overwritten
# 
#                               Written by Trevor Morgan
#######################################################################################

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json
import base64
import configparser
import sys
import logging
import random
import string
from cryptography.fernet import Fernet
from os import path, remove

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

# Run an API request and dump data to file
def get_and_dump_data(url, auth, file):
  resp = json.dumps(get_data(url,auth))
  f = open(json_dir + "/" + file, "w")
  f.write(str(resp))
  f.close()
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

# Get teams from target system
def get_teams_target():
  teams_out = get_data(target + "/teams/search?query=", "Bearer " + target_apikey) 
  # Build dictionary of team name to id from target system 
  for team in teams_out["teams"]:
    teams_out_map[team["name"]] = team["id"]

# Get users from target system
def get_users_target():
  users_out = get_data(target + "/users", "Basic " + target_auth)  # Get this server
  # Build dictionary of username to id from target system
  for user in users_out:
    users_out_map[user["login"]] = user["id"]

# Get datasources from target system
def get_datasources_target():
  datasources_out = get_data(target + "/datasources","Bearer " + target_apikey)
  # Build dictionary of datasource name to id on target system
  for datasource in datasources_out:
    datasources_out_map[datasource["name"]] = datasource["id"]

# Get folders from target and build mappings
def get_folders_target():
  folders_out =  get_data(target + "/folders","Bearer " + target_apikey)
  # Build dictionary of id and uid correlation on target system
  for folder in folders_out:
    folders_out_uid_map[folder["uid"]] = folder["id"]
    folders_out_id_map[folder["id"]] = folder["uid"]

# Get folders from target and build mappings
def get_permissions_target():
  folders = get_data(target + "/folders","Bearer " + target_apikey)
  # Build mapping of folder permission ID's
  for folder in folders :
    permission = get_data(target + "/folders/" + folder["uid"] + "/permissions","Bearer " + target_apikey)
    folder_out_perms[folder["uid"]] = permission

# Get dashboards from target and build mappings
def get_dashboards_target():
  dashboards_out = get_data(target +  "/search?query=&type=dash-db" ,"Bearer " + target_apikey)
  # Build mapping of dashboard ID's
  for dashboard in dashboards_out:
    dashboards_target[dashboard["uid"]] = dashboard["id"]

def get_source_data():
  # Get Users
  users = get_and_dump_data(source + "/users","Basic " + source_auth, "users.json")
  logger.info("Users data dumped to users.json")

  # Get Teams
  teams = get_and_dump_data(source + "/teams/search?query=","Bearer " + source_apikey, "teams.json")
  logger.info("Teams data dumped to teams.json")

  # Get Team Members
  team_members = get_and_dump_data(source + "/teams/*/members","Bearer " + source_apikey, "team_members.json")
  logger.info("Team Members data dumped to team_members.json")

  # Get Datasources
  datasources = get_and_dump_data(source + "/datasources","Bearer " + source_apikey, "datasources.json")
  logger.info("Datasources dumped to datasources.json")

  # Get Folders and iterate through each one to get permissions
  folders = get_and_dump_data(source + "/folders","Bearer " + source_apikey, "/folders.json")
  logger.info("Folders dumped to folders.json")
  permissions = {}
  for folder in folders :
    uid = folder["uid"]
    permission = get_and_dump_data(source + "/folders/" + uid + "/permissions","Bearer " + source_apikey, "temp.json")
    permissions[uid] = json.dumps(permission)
  f = open(json_dir + "/folder_permissions.json", "w")
  f.write(json.dumps(permissions))
  f.close()
  logger.info("Folder Permissions dumped to folder_permissions.json")

  # Get Dashboards
  permissions = {}
  dashboards = []
  dashboard_list = get_and_dump_data(source + "/search?query=&type=dash-db","Bearer " + source_apikey, "dashboard_list.json")
  logger.info("Dashboard List dumped to dashboard_list.json")
  for dashboard in dashboard_list:
    id = str(dashboard["id"])
    uid = dashboard["uid"]
    permission = get_and_dump_data(source + "/dashboards/id/" + id + "/permissions","Bearer " + source_apikey, "temp.json")
    permissions[uid] = json.dumps(permission)
    dashboard = get_and_dump_data(source + "/dashboards/uid/" + uid,"Bearer " + source_apikey, "temp.json")
    dashboards.append(dashboard)

  f = open(json_dir + "/dashboards.json", "w")
  f.write(str(json.dumps(dashboards)))
  f.close()
  logger.info("Dashboard details dumped to dashboard.json")
  f = open(json_dir + "/dashboard_permissions.json", "w")
  f.write(json.dumps(permissions))
  f.close()
  logger.info("Dashboard permissions dumped to dashboard_permissions.json")

def put_target_data():

  ############################################################
  # Sync Datasources
  ############################################################
  logger.info("Syncing Datasources")
  datasources_in = read_file("datasources.json")   # Dump from source server

  # Build dictionary of target datasource name to id mappings
  global datasources_out_map
  datasources_out_map = {}
  get_datasources_target()

  # Process each datasource from input, and decide whether to create (POST) or update (PUT)
  # on the target system (after translating the datasource id)
  for datasource in datasources_in:
    name = datasource["name"]
  
    # Datasource doesn't exist in target system so create it
    if name not in datasources_out_map:
      del datasource["id"]
      try :
        put_data(target + "/datasources", "Bearer " + target_apikey, "POST", datasource)
        logger.info(" %s Created" % name)
      except Exception as e:
        logger.error(" %s " % name)
        logger.error(" %s" % json.dumps(datasource))
    # Datasource already exists so update it
    else :
      id_out = datasources_out_map[name]
      datasource["id"] = id_out
      try :
        put_data(target + "/datasources/" + str(id_out), "Bearer " + target_apikey, "PUT", datasource)
        logger.info(" %s Updated" % name)
      except Exception as e:
        logger.error(" %s FAILED" % name)
        logger.error(" %s" % json.dumps(datasource))
  
  # Refresh datasources from target
  datasources_out_map = {}
  get_datasources_target()
  
  ############################################################
  # Sync Teams
  ############################################################
  logger.info("Syncing Teams")
  teams_in = read_file("teams.json")   # Dump from source server

  # Get Teams from target system and build dictionary of IDs
  global teams_out_map
  teams_out_map = {}
  get_teams_target()
  
  teams_in_id = {}   # Keep a team mapping for later on
  for team in teams_in["teams"]:
    name = team["name"]
    teams_in_id[team["id"]] = name    # Store ID to name mapping
    del team["id"]   # Can't specify the id in the JSON
    # Do we have a match for this team?
    try:
      id_out = teams_out_map[name]  # Yes
      logger.info(" %s : Updated existing" % name)
      put_data(target + "/teams/" + str(id_out), "Bearer " + target_apikey, "PUT", team)
    except:
      logger.info(" %s : Created New" % name)
      put_data(target + "/teams", "Bearer " + target_apikey, "POST", team)
  
  # Refresh the teams on target
  get_teams_target()
  
  ############################################################
  # Sync Users
  ############################################################
  logger.info("Syncing Users")
  users_in = read_file("users.json")   # Dump from source server
  
  # Get teams from target system and build dictionary of IDs
  global users_out_map
  users_out_map = {}
  get_users_target()
  
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
      logger.info(" %s : Updated existing" % login)
      put_data(target + "/users/" + str(id_out), "Basic " + target_auth , "PUT", user)
    except:
      logger.info(" %s : Created New" % login)
      logger.info(" %s" % user)
      # Generate a random password for new user
      pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
      user["password"] = pwd
      put_data(target + "/admin/users", "Basic " + target_auth, "POST", user)
  
  # Refresh the users from target
  get_users_target()
  
  ############################################################
  # Add users to teams
  ############################################################
  logger.info("Syncing users to teams")
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
        logger.info(" Adding %s to %s" % ( login,team_name) )
      except:
        logger.info(" %s already in %s" % ( login,team_name) )
        pass
  
  ############################################################
  # Sync Folders
  ############################################################
  logger.info("Syncing Folders")
  folders_in = read_file("folders.json")
  
  # Get folders from target and build dictionary of UIDs and IDs
  global folders_out_uid_map
  folders_out_uid_map = {}
  global folders_out_id_map
  folders_out_id_map = {}
  get_folders_target()
  
  folders_in_id_map = {}
  folders_in_uid_map = {}
  for folder in folders_in:
    name = folder["title"]
    uid = folder["uid"]
    folders_in_uid_map[folder["uid"]] = folder["id"]
    folders_in_id_map[folder["id"]] = uid
    del folder["id"]   # Can't specify the id in the JSON
    if uid in folders_out_uid_map:
      logger.info(" %s : Updated existing" % name)
      try:
        put_data(target + "/folders/" + uid, "Bearer " + target_apikey, "PUT", folder)
      except:
        pass
    else:
      logger.info(" %s : Created New" % name)
      put_data(target + "/folders", "Bearer " + target_apikey, "POST", folder)
  # Refresh folders from target
  get_folders_target()
  
  
  ############################################################
  # Sync Folder Permissions
  ############################################################
  logger.info("Syncing Folder Permissions")
  folder_in_perms = read_file("folder_permissions.json")
  # Get folder permissions from target
  global folder_out_perms
  folder_out_perms = {}
  get_permissions_target()
  
  for uid in folder_in_perms:
    permissions = json.loads(folder_in_perms[uid])
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
      logger.info(" %s Updated" % name)
    except :
      logger.error(" %s FAILED" % name)
  
  # Refresh target permissions mappings
  get_permissions_target()
  
  ############################################################
  # Sync Dashboards
  ############################################################
  logger.info("Syncing Dashboards")
  # Get inventory from target system and build dictionary of ID vs UID
  dashboards_in = read_file("dashboards.json")
  
  # Read dashboards from target and map ID's
  global dashboards_target
  dashboards_target = {}
  get_dashboards_target()
 
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
      logger.info(" %s doesn't exists" % name)
      try:
        dashboard_out = {}
        dashboard_out["folderId"] = folder_out_id
        dashboard_out["overwrite"] = True
        dashboard_out["dashboard"] = dashboard
        put_data(target + "/dashboards/db", "Bearer " + target_apikey, "POST", dashboard_out)
        logger.info(" %s Created" % name)
      except Exception as e:
        logger.error(" %s FAILED" % name)
        logger.error(" %s" % json.dumps(dashboard_out))
        logger.error(" %s" + e)
 
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
      logger.info(" %s Updated" % name)
    except Exception as e:
      logger.error(" %s FAILED" % name)
      logger.error(" %s" % json.dumps(dashboard))
      logger.error(" %s" % e)
  
  # Refresh target ID mappings
  get_dashboards_target()
  
  ############################################################
  # Dashboard permissions
  ############################################################
  # Bit messy, but we need to read in each permission, determine if the permission is :
  #    - Inherited (ignore)
  #    - UserID (translate source to target userid)
  #    - TeamId (translate source to target teamid)
  # As well, translate source dashboard ID to target Id
  
  logger.info("Syncing Dashboard Permissions")
  
  # Get source permissions
  permissions_in = read_file("dashboard_permissions.json")
  for dashboard_in_uid in permissions_in:
    # Work out target dashboard Id
    dashboard_in_permissions = json.loads(permissions_in[dashboard_in_uid])
    dashboard_out_id = dashboards_target[dashboard_in_uid]
    # Build a list of (translated) permissions to apply
    permissions_out = []   # List of output permissions
    logger.info(" Dashboard UID:%s" % dashboard_in_uid)
    # Iterate through each individual permission
    for permission in dashboard_in_permissions:
  
      if permission["inherited"] == False:
  
        # Permission is team related
        if permission["teamId"] != 0 :
          # Remap source team Id to target system
          team_in_id = permission["teamId"]
          team_name = teams_in_id[team_in_id]
          team_out_id = teams_out_map[team_name]
          perm = { "teamId":team_out_id,"permission":permission["permission"] }
          logger.info("  Team:%s Source_Id:%s Target_Id:%s" % (team_name, team_in_id,team_out_id))
          permissions_out.append(perm)   # Add permissions to list
  
        # Permission is user related
        elif permission["userId"] != 0 :
          # Remap source user Id to target system
          user_in_id = permission["userId"]
          login = users_in_id[user_in_id]
          user_out_id = users_out_map[login]
          perm = { "userId":user_out_id,"permission":permission["permission"] }
          logger.info("  User:%s Source_Id:%s Target_Id:%s" % (login, user_in_id,user_out_id))
          permissions_out.append(perm)   # Add permissions to list
 
    # Build payload JSON
    payload = { "items": permissions_out }
    logger.info("  Final Permissions:" + str(payload))
  
    # Update permissions, even if there are none as this will delete on target system (as per API spec)
    try:
      put_data(target + "/dashboards/id/" + str(dashboard_out_id) + "/permissions", "Bearer " + target_apikey, "POST", payload)
      logger.info("  Updated")
    except Exception as e:
      logger.error("  Dashboard permissions could not be updated")
      logger.error("  Payload:%s" % str(payload))
      logger.error("  %s" % e)
  
def load_config():
  global target_auth
  # Read in the conf file that drives this script
  conf = configparser.RawConfigParser()
  conf.read("grafana-sync.conf")
  global source
  source          = conf["grafana"]["source"]
  global target
  target          = conf["grafana"]["target"]
  global source_username
  source_username = conf["grafana"]["source_username"]
  global source_password
  source_password = decrypt_pass(conf["grafana"]["source_password"])
  global source_apikey
  source_apikey   = conf["grafana"]["source_apikey"]
  global target_username
  target_username = conf["grafana"]["target_username"]
  global target_password
  target_password = decrypt_pass(conf["grafana"]["target_password"])
  global target_apikey
  target_apikey   = conf["grafana"]["target_apikey"]
  global json_dir
  json_dir        = conf["grafana"]["json_dir"]
  # Build up basic auth encoded string
  global source_auth
  source_auth     = str(base64.b64encode(bytes('%s:%s' % (source_username,source_password), "utf-8")),"ascii").strip()
  global target_auth
  target_auth     = str(base64.b64encode(bytes('%s:%s' % (target_username,target_password), "utf-8")),"ascii").strip()

  # Create logger
  logfile = "grafana-sync.log"
  if path.exists(logfile):
    remove(logfile)
  global logger
  logger = logging.getLogger(__name__)
  logger.setLevel(logging.INFO)
  handler = logging.FileHandler(logfile)
  logger.addHandler(handler)
  formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt="%Y/%m/%d %H:%M:%S")
  handler.setFormatter(formatter)

def main():
  load_config()

  # Use command line argument to see how to run this script
  try :
    mode = sys.argv[1]
    logger.info("Execution MODE is %s" % mode)
    # Dump the data only
    if mode == "GET" :
      get_source_data()
    # Dump and push to target
    elif mode == "SYNC" :
      get_source_data()
      put_target_data()
    # Unknown option
    else :
      logger.warn("Need to pass in argument of GET or SYNC to run this")
    logger.info("Completed")
  except Exception as e:
    logger.warn("Need to pass in argument of GET or SYNC to run this")
    logger.warn(e)

###################################################
# Start here
###################################################
if __name__ == "__main__":
  main()

exit()
