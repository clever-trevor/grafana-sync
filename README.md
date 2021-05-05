# grafana-sync
Sync (Push) objects from one Grafana to another one

##### Early version

Python script to push various objects from a Source Grafana to a Target one.
Could be useful if you want to have a central server where all changes are made, and then sync these to other servers.

Doesn't use an modules not found in base Python3 installation.

Currently, it will sync :
* Datasources (password cannot be read so has to be entered manually on in initial sync)
* Teams
* Users (Again if you're using local users and not some external source, you will have to re-enter passwords first time)
* Add users to teams
* Folders
* Folder Permissions
* Dashboards (in correct folders)
* Dashboard Permissions

Why did I write this?  Because whilst there is a neater solution to provide a clustererd Grafana solution built around an external database, it is something that Grafana do not support and so as well as Grafana, you also have to build the clustered database and make sure if you want it highly available, you have to manage that as well.
(details here https://grafana.com/docs/grafana/latest/administration/set-up-for-high-availability/)
In short, over complex for what I wanted.
There are other sync scripts (various languages) but they didn't seem to cater for things like mismatching ID's (See the bottom section) or mapping permissions. 

So I knocked this up in Python as it's easy to work with.

You could run the script on any number of Grafana "satellite" servers and sync them from a central Grafana instance.

### To Do
* Alert Rules and Notification Channels 
* Combine "get" and "put" scripts into a single module
* Incorporate "last updated" in the dashboard queries and see if there is a way to do a bi-directional sync
* Better error handling, logging and comments
* HUGE tidy.  I wrote this whilst working out the Grafana data model, so haven't put any real thought into optimising or tidying up the script

### Setup 
* On both source and target systems, log on to Grafana and create an admin userid.  Encrypt the passwords using the steps below
* On both source and target systems, log on to Grafana and create an admin API key
* Edit the "grafana-sync.conf" file and replace variables with your own
* First, encrypt your Grafana admin password.  This is needed for User API calls using basic auth.
```
./encrypt.py
<enter password>
```
When encrypted password is shown, copy and paste into the grafana-sync.conf file.  This step will also create a file called cipher.key which is used to decrypt the password.
* Ensure the directory under the "json_dir" variable exists.  This is where dump from source Grafana will be stored and later used by the upload script

### Running the script

* Run the "get" script
```./get.py```
* If all works, there should be a bunch of json files under the ./json directory

* Run the "put" script
```./put.py```
* Any errors will be written to screen


### Complex data model
Many of the objects in Grafana have a unique Id as well as a cusomisable one.
So it's not possible just to dump and upload raw JSON, as the ID's will most certainly be mismatched.

For example, If you create dashboard "my test" on Grafana-1, it might have an ID of 1.  
If you then delete it and recreate, it will have an ID of 2. 
Unless you are starting from a replica database dump, you can't guarantee the ID will match and as many of the API Calls require the ID field, they will fail.
So the script has to do a mapping between Source (ID and UID) to Target (ID and UID) And amend the JSON fields before attempting the upload (Why the custom id's couldn't have been used throughout I don't know)

Also, any calls to the Users API cannot be done with a token.  This is because these objects are not stored within a Grafana Organisation.  Instead, you have to create an Administrative userid / password and pass these in using basic-auth....not very nice.

Because of this, I put in a simple encryption of the admin password to avoid prying eyes, but it is by no means a comprehensive solution so do build your own!
